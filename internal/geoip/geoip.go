// Package geoip implements SENTRYX's Phase 20 country-level blocking.
//
// XDP can't natively reason about "country" — a NIC only ever sees an IP
// address — so, same as internal/dnsresolve, the actual judgment call
// ("which countries are blocked") lives entirely in user space. What XDP
// *can* do natively and cheaply is a longest-prefix-match lookup against a
// CIDR trie (bpf/xdp_sentryx.c's geoip_blocklist, BPF_MAP_TYPE_LPM_TRIE),
// so this package's job is narrow: turn a configured list of ISO 3166-1
// alpha-2 country codes into the CIDR ranges that belong to them, and keep
// firewall.Firewall's geoip_blocklist trie in sync with that list on a
// timer — reconciling the same way internal/threatintel and
// internal/dnsresolve already do, so a country dropped from policy.yaml
// actually unblocks its ranges instead of leaving them stuck forever.
//
// Data source: ipdeny.com's public, free, no-API-key-required per-country
// CIDR "zone" files (https://www.ipdeny.com/ipblocks/), aggregated from
// the regional internet registries (ARIN/RIPE/APNIC/AFRINIC/LACNIC) and
// refreshed daily upstream. Same trust-boundary philosophy as
// threatintel.go: one named, citable, free source rather than an
// aggregation of scraped lists — a mirror or MaxMind's GeoLite2 (which
// needs a free account + license key) are reasonable swaps, this just
// avoids that signup step for a first working version.
//
// Honest limitation: this is IP-geolocation-based, which is inherently
// approximate — VPNs, satellite/mobile carrier NAT, and misallocated or
// stale registry data can all put a request on the "wrong" side of a
// country boundary. Treat it as a coarse perimeter control, not a
// guarantee.
package geoip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// ZoneURLTemplate is ipdeny.com's per-country plaintext CIDR list. %s is
// replaced with the lowercase ISO 3166-1 alpha-2 country code (e.g. "cn").
// One CIDR per line, no comments, updated daily upstream.
const ZoneURLTemplate = "https://www.ipdeny.com/ipblocks/data/countries/%s.zone"

// DefaultInterval matches the doc comment in internal/policy: country-level
// allocations change slowly, so this defaults to once a day rather than
// dnsresolve's 5-minute cadence.
const DefaultInterval = 24 * time.Hour

// Feed periodically resolves a configured list of countries to CIDR
// ranges and reconciles them against the kernel's geoip_blocklist trie
// under firewall.ReasonGeoIP. It never touches blocklist entries created
// for any other reason, and never touches CIDR ranges belonging to a
// country that isn't (or is no longer) in its configured list.
type Feed struct {
	fw       *firewall.Firewall
	interval time.Duration
	client   *http.Client

	mu        sync.Mutex
	countries []string // configured, lowercased ISO 3166-1 alpha-2, deduped+sorted

	// current maps a CIDR this feed currently has blocked to the country
	// it belongs to, so a later refresh can tell "still configured" from
	// "safe to unblock" without re-deriving it, and so CountryRanges can
	// answer "what did we actually resolve" for `sxctl geoip status`.
	current map[string]string
}

// New builds a Feed. Call SetCountries to configure it, then Refresh for
// an immediate sync and Run to keep it updated on a timer.
func New(fw *firewall.Firewall, interval time.Duration) *Feed {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Feed{
		fw:       fw,
		interval: interval,
		client:   &http.Client{Timeout: 20 * time.Second},
		current:  make(map[string]string),
	}
}

// SetCountries replaces the configured country list. Safe to call while
// Run is active — the next tick (or an explicit Refresh) picks it up.
// Codes are lowercased and deduped; an empty/nil list disables the feature.
func (f *Feed) SetCountries(countries []string) {
	seen := make(map[string]struct{}, len(countries))
	out := make([]string, 0, len(countries))
	for _, c := range countries {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)

	f.mu.Lock()
	f.countries = out
	f.mu.Unlock()
}

// Countries returns the currently configured country code list.
func (f *Feed) Countries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.countries...)
}

// Run blocks, re-syncing every interval until stop is closed. Intended to
// be launched with `go feed.Run(stop)` after an initial Refresh.
func (f *Feed) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := f.Refresh(context.Background()); err != nil {
				log.Printf("geoip: refresh failed: %v", err)
			}
		}
	}
}

// Refresh fetches the CIDR zone file for every configured country and
// reconciles the result against the firewall: newly-seen ranges get
// blocked, ranges belonging to a country that's no longer configured get
// unblocked (unless something else has since claimed that exact CIDR for
// a different reason — UnblockCIDR only ever removes what this feed
// itself put there).
func (f *Feed) Refresh(ctx context.Context) error {
	f.mu.Lock()
	countries := append([]string{}, f.countries...)
	f.mu.Unlock()

	fresh := make(map[string]string) // cidr -> country
	var fetchErrs []string

	for _, cc := range countries {
		cidrs, err := f.fetchZone(ctx, cc)
		if err != nil {
			// One country's feed being down (typo'd code, upstream
			// hiccup) shouldn't stop the rest of the list from syncing.
			fetchErrs = append(fetchErrs, fmt.Sprintf("%s: %v", cc, err))
			continue
		}
		for _, cidr := range cidrs {
			fresh[cidr] = cc
		}
	}

	added, removed := 0, 0
	f.mu.Lock()
	for cidr, cc := range fresh {
		if _, already := f.current[cidr]; already {
			continue
		}
		f.mu.Unlock()
		err := f.fw.BlockCIDR(cidr, strings.ToUpper(cc), "geoip-block: "+strings.ToUpper(cc))
		f.mu.Lock()
		if err != nil {
			log.Printf("geoip: failed to block %s (%s): %v", cidr, cc, err)
			continue
		}
		added++
	}
	for cidr := range f.current {
		if _, still := fresh[cidr]; still {
			continue
		}
		f.mu.Unlock()
		err := f.fw.UnblockCIDR(cidr)
		f.mu.Lock()
		if err != nil {
			log.Printf("geoip: failed to unblock %s: %v", cidr, err)
			continue
		}
		removed++
	}
	f.current = fresh
	f.mu.Unlock()

	if added > 0 || removed > 0 {
		log.Printf("geoip: synced %d countr(y/ies) (%d range(s) added, %d removed, %d total)",
			len(countries), added, removed, len(fresh))
	}
	if len(fetchErrs) > 0 {
		return fmt.Errorf("some countries failed to sync: %s", strings.Join(fetchErrs, "; "))
	}
	return nil
}

// fetchZone downloads and parses one country's plaintext CIDR zone file.
func (f *Feed) fetchZone(ctx context.Context, cc string) ([]string, error) {
	url := fmt.Sprintf(ZoneURLTemplate, cc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s (check the country code is a valid ISO 3166-1 alpha-2)", resp.Status)
	}

	var out []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20)) // 8MB is generous for any single country's zone file
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			// Skip malformed lines rather than failing the whole
			// country — an upstream format hiccup shouldn't take down
			// every other range that parsed fine.
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading zone file: %w", err)
	}
	return out, nil
}

// CountryRange is one currently-blocked CIDR, paired with the country it
// was resolved from — the reverse mapping `sxctl geoip status` and the
// dashboard use to explain a block in terms of a country instead of a
// bare prefix.
type CountryRange struct {
	CIDR    string `json:"cidr"`
	Country string `json:"country"`
}

// CountryForIP reports the country an IP falls under, if it matches one
// of this feed's currently-resolved CIDR ranges. Linear scan is
// deliberate and fine here — this backs Phase 26's live topology map,
// which calls it once per block event (at most a few per second), not
// once per packet; a real per-packet path would use the kernel's
// LPM-trie lookup instead (see bpf/xdp_sentryx.c's geoip_blocklist).
func (f *Feed) CountryForIP(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for cidr, cc := range f.current {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return strings.ToUpper(cc), true
		}
	}
	return "", false
}

// CountryRanges returns every CIDR range currently blocked by this feed,
// along with the country it belongs to.
func (f *Feed) CountryRanges() []CountryRange {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]CountryRange, 0, len(f.current))
	for cidr, cc := range f.current {
		out = append(out, CountryRange{CIDR: cidr, Country: strings.ToUpper(cc)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Country != out[j].Country {
			return out[i].Country < out[j].Country
		}
		return out[i].CIDR < out[j].CIDR
	})
	return out
}
