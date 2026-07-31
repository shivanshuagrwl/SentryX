// Package dnsresolve implements SENTRYX's Phase 19 DNS-based blocking.
//
// XDP sees IPv4/IPv6 addresses, never domain names — by the time a packet
// reaches the kernel there is no DNS label left in it at all. So unlike
// every other Phase 16-21 feature, this one is entirely a user-space
// concern: periodically resolve a configured list of domains and push
// whatever addresses come back into the exact same `blocklist` map
// firewall.Block already maintains, tagged ReasonDNSBlock so `sxctl why`
// can still explain where a given block came from.
//
// Because DNS answers rotate (CDNs, load balancers, TTL expiry), this
// re-resolves on a timer and reconciles like internal/threatintel does:
// newly-resolved addresses get blocked, addresses that no longer resolve
// for any configured domain get unblocked, so the blocklist tracks
// "currently resolves to a blocked domain", not "ever resolved to one".
//
// Honest limitation, worth stating rather than overclaiming: this blocks
// *resolved IPs*, not domains themselves. A client using DoH/DoT (which
// bypasses whatever resolver this daemon itself uses), or a domain behind
// an IP-rotating CDN that rotates faster than -dns-refresh, can evade it.
package dnsresolve

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shivanshu-agarwal/sentryx/internal/firewall"
)

// Resolver periodically resolves a configured domain list and reconciles
// the results against the kernel blocklist under firewall.ReasonDNSBlock.
// It never touches blocklist entries created for any other reason.
type Resolver struct {
	fw       *firewall.Firewall
	interval time.Duration
	resolver *net.Resolver

	mu      sync.Mutex
	domains []string // configured, as given (lowercased, deduped)

	// current maps an already-blocked IP to the domain that caused it, so
	// a later refresh can tell "still needed" from "safe to unblock" and
	// so Resolutions() can answer the "why is this IP blocked" question
	// for sxctl/the dashboard without a second lookup.
	current map[string]string
}

// New builds a Resolver. Call SetDomains to configure it (an empty list
// disables the feature — Refresh then just unblocks anything the
// previous configuration had blocked), then Refresh for an immediate
// resolve and Run to keep it updated on a timer.
func New(fw *firewall.Firewall, interval time.Duration) *Resolver {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Resolver{
		fw:       fw,
		interval: interval,
		resolver: net.DefaultResolver,
		current:  make(map[string]string),
	}
}

// SetDomains replaces the configured domain list. Safe to call at any
// time, including while Run is active — the next tick (or an explicit
// Refresh) picks up the change. Domains are lowercased and deduped; an
// empty/nil list disables the feature.
func (r *Resolver) SetDomains(domains []string) {
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)

	r.mu.Lock()
	r.domains = out
	r.mu.Unlock()
}

// Domains returns the currently configured domain list.
func (r *Resolver) Domains() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.domains...)
}

// Run blocks, re-resolving every interval until stop is closed. Intended
// to be launched with `go resolver.Run(stop)` after an initial Refresh.
func (r *Resolver) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := r.Refresh(context.Background()); err != nil {
				log.Printf("dnsresolve: refresh failed: %v", err)
			}
		}
	}
}

// Refresh resolves every configured domain once and reconciles the result
// against the firewall: newly-resolved addresses are blocked, addresses
// that no longer resolve for any configured domain are unblocked (unless
// something else has since blocked them for a different reason — Unblock
// only ever removes what's actually there).
func (r *Resolver) Refresh(ctx context.Context) error {
	r.mu.Lock()
	domains := append([]string{}, r.domains...)
	r.mu.Unlock()

	fresh := make(map[string]string) // ip -> domain that resolved to it
	var resolveErrs []string

	for _, domain := range domains {
		ips, err := r.resolver.LookupIP(ctx, "ip4", domain)
		if err != nil {
			// A single domain failing to resolve (typo, transient DNS
			// outage, domain taken down) shouldn't stop the rest of the
			// list from being processed.
			resolveErrs = append(resolveErrs, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		for _, ip := range ips {
			fresh[ip.String()] = domain
		}
	}

	added, removed := 0, 0
	r.mu.Lock()
	for ip, domain := range fresh {
		if _, already := r.current[ip]; already {
			continue
		}
		r.mu.Unlock()
		err := r.fw.BlockWithReason(ip, "dns-block: "+domain, firewall.ReasonDNSBlock)
		r.mu.Lock()
		if err != nil {
			log.Printf("dnsresolve: failed to block %s (%s): %v", ip, domain, err)
			continue
		}
		added++
	}
	for ip := range r.current {
		if _, still := fresh[ip]; still {
			continue
		}
		r.mu.Unlock()
		err := r.fw.Unblock(ip)
		r.mu.Lock()
		if err != nil {
			log.Printf("dnsresolve: failed to unblock %s: %v", ip, err)
			continue
		}
		removed++
	}
	r.current = fresh
	r.mu.Unlock()
	if added > 0 || removed > 0 {
		log.Printf("dnsresolve: synced %d domain(s) (%d IP(s) added, %d removed, %d total)",
			len(domains), added, removed, len(fresh))
	}
	if len(resolveErrs) > 0 {
		return fmt.Errorf("some domains failed to resolve: %s", strings.Join(resolveErrs, "; "))
	}
	return nil
}

// Resolution is one currently-blocked-via-DNS address, paired with the
// domain that caused the block — the reverse map `sxctl dns status` and
// the dashboard use to answer "why is this IP blocked" in terms of a
// domain name instead of a bare address.
type Resolution struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

// Resolutions returns every IP currently blocked by this resolver, along
// with the domain that resolved to it.
func (r *Resolver) Resolutions() []Resolution {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Resolution, 0, len(r.current))
	for ip, domain := range r.current {
		out = append(out, Resolution{IP: ip, Domain: domain})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].IP < out[j].IP
	})
	return out
}
