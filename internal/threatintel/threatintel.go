// Package threatintel keeps SENTRYX's blocklist seeded with known-malicious
// addresses from a public feed, without requiring an operator to curate that
// list by hand.
//
// It deliberately talks to exactly one well-known, free, machine-readable
// feed — abuse.ch's Feodo Tracker (C2 infrastructure for banking trojans /
// botnets) — rather than scraping or aggregating multiple sources. That
// keeps the trust boundary small and auditable: every IP this package ever
// blocks came from one named, citable feed, and `sxctl list` shows
// reason=threat-intel so it's never confused with a manual or anomaly-based
// block.
package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shivanshu-agarwal/sentryx/internal/firewall"
)

// FeedURL is abuse.ch's Feodo Tracker "aggressive" blocklist: plaintext,
// one IPv4 per line, comments prefixed with '#'. Free, no API key, updated
// every 5 minutes upstream. See https://feodotracker.abuse.ch/blocklist/
const FeedURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

// Feed periodically fetches a plaintext IP list and reconciles it against
// the kernel blocklist under ReasonThreatIntel. It never touches rules
// created for any other reason (manual, anomaly, rate-limit).
type Feed struct {
	fw       *firewall.Firewall
	url      string
	interval time.Duration
	client   *http.Client

	// current is the set of IPs this feed currently has blocked, so a
	// later refresh can unblock anything that rolled off the upstream
	// list instead of accumulating stale entries forever.
	current map[string]struct{}
}

// New builds a Feed. Call Refresh once for an immediate seed at boot, then
// Run to keep it updated on a timer.
func New(fw *firewall.Firewall, url string, interval time.Duration) *Feed {
	if url == "" {
		url = FeedURL
	}
	return &Feed{
		fw:       fw,
		url:      url,
		interval: interval,
		client:   &http.Client{Timeout: 15 * time.Second},
		current:  make(map[string]struct{}),
	}
}

// Run blocks, refreshing on cfg.interval until stop is closed. Intended to
// be launched with `go feed.Run(stop)` after an initial Refresh at boot.
func (f *Feed) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := f.Refresh(context.Background()); err != nil {
				log.Printf("threatintel: refresh failed: %v", err)
			}
		}
	}
}

// Refresh fetches the feed once and reconciles it against the firewall:
// newly-listed IPs are blocked, previously-listed IPs that fell off the
// feed are unblocked (unless something else has since re-blocked them for
// a different reason).
func (f *Feed) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", f.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: unexpected status %s", f.url, resp.Status)
	}

	fresh := make(map[string]struct{})
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) == nil {
			continue // feed may include CIDR/comment lines we don't handle yet
		}
		fresh[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read feed body: %w", err)
	}

	added, removed := 0, 0
	for ip := range fresh {
		if _, already := f.current[ip]; already {
			continue
		}
		if err := f.fw.BlockWithReason(ip, "threat-intel: feodo tracker C2", firewall.ReasonThreatIntel); err != nil {
			log.Printf("threatintel: failed to block %s: %v", ip, err)
			continue
		}
		added++
	}
	for ip := range f.current {
		if _, still := fresh[ip]; still {
			continue
		}
		if err := f.fw.Unblock(ip); err != nil {
			log.Printf("threatintel: failed to unblock %s: %v", ip, err)
			continue
		}
		removed++
	}

	f.current = fresh
	if added > 0 || removed > 0 {
		log.Printf("threatintel: synced feed (%d added, %d removed, %d total)", added, removed, len(fresh))
	}
	return nil
}
