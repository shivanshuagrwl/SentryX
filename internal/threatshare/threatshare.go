// Package threatshare implements SENTRYX's Phase 23 cross-daemon threat
// sharing: when one daemon in a fleet discovers a threat — a manual block,
// an anomaly-detector auto-block, a threat-intel hit, a SYN-flood
// escalation, whatever — it relays that block to every peer daemon it
// knows about, so the whole fleet reacts to something only one edge
// actually saw.
//
// This is peer-to-peer, not a star topology through `sxctl controller`,
// deliberately: `sxctl controller push` is an operator pushing policy from
// a workstation that may not even be running, on demand. Threat sharing
// needs to happen automatically, continuously, between daemons that are
// themselves always up — piping every report through a separate
// "controller" service would add a single point of failure to something
// that's supposed to make the fleet more resilient, not less. Every node
// just talks directly to the peers named in its own -threat-share-peers.
//
// Two independent halves live in this package, matching the two roles a
// daemon plays:
//
//   - Sharer (outbound): registered as the firewall's block observer, so
//     every local block this daemon makes gets POSTed to every configured
//     peer's /api/threats/report.
//   - Registry (inbound): the receiving end of that same endpoint. Applies
//     an incoming report as a local block under ReasonShared, and — this
//     is the part that keeps one bad report from poisoning the fleet
//     forever — tracks a TTL per shared block and lifts it automatically
//     once that expires.
//
// A daemon with peers configured runs both halves at once (it shares what
// it finds *and* accepts what its peers find); nothing here assumes an
// asymmetric hub/spoke relationship.
package threatshare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// DefaultTTL is how long a block relayed in from a peer stays enforced
// before this daemon automatically lifts it, absent any TTLSeconds on the
// report itself. Long enough to matter during an active incident, short
// enough that a false positive on one node doesn't permanently poison
// every other node in the fleet.
const DefaultTTL = 15 * time.Minute

// reportTimeout bounds how long a single outbound POST to one peer is
// allowed to take. Short and deliberately not configurable: a peer that's
// slow or unreachable should never make the reporting daemon itself feel
// sluggish — see Sharer.Report's fire-and-forget design below.
const reportTimeout = 5 * time.Second

// Peer is one other sentryxd this daemon relays blocks to and accepts
// reports from — the same shape `sxctl controller`'s node type uses,
// intentionally, since both are just "a sentryxd's REST API plus a token".
type Peer struct {
	URL   string
	Token string
}

// Report is what one daemon POSTs to a peer's /api/threats/report when it
// makes a local block, and what that peer decodes on the way in. Reason is
// carried as the raw firewall.Reason byte (not ReasonShared) so a receiving
// daemon's `sxctl why` can still say *why the reporting node* blocked it
// ("anomaly", "syn-flood", ...) even though this daemon enforces it under
// ReasonShared.
type Report struct {
	IP         string          `json:"ip"`
	Label      string          `json:"label,omitempty"`
	Reason     firewall.Reason `json:"reason"`
	Source     string          `json:"source"`                // the reporting daemon's -threat-share-name (or -iface)
	TTLSeconds uint32          `json:"ttl_seconds,omitempty"` // 0 means "use the receiver's DefaultTTL"
}

// Sharer is the outbound half of Phase 23: register Report as a firewall
// block observer (firewall.Firewall.SetBlockObserver) and every local
// block this daemon makes gets relayed to every configured peer.
type Sharer struct {
	peers    []Peer
	selfName string
	ttl      time.Duration
	client   *http.Client
}

// New builds a Sharer that relays to peers, identifying itself as
// selfName in every report, with ttl embedded in each report so receiving
// daemons know how long to enforce it (they may still fall back to their
// own DefaultTTL if a report arrives with TTLSeconds unset).
func New(peers []Peer, selfName string, ttl time.Duration) *Sharer {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Sharer{
		peers:    peers,
		selfName: selfName,
		ttl:      ttl,
		client:   &http.Client{Timeout: reportTimeout},
	}
}

// Report relays one local block to every configured peer. It matches
// firewall.Firewall's block-observer signature exactly, so it's meant to
// be passed directly to fw.SetBlockObserver.
//
// Fire-and-forget by design: each peer is POSTed to in its own goroutine,
// and a peer that's down, slow, or rejects the report is just logged, not
// returned as an error — nothing about the packet-drop decision that
// triggered this should ever wait on network I/O to other machines. A
// missed relay isn't silently unrecoverable either: the next block this
// daemon makes (or any anomaly re-trigger) tries again.
func (s *Sharer) Report(ip, label string, reason firewall.Reason) {
	if len(s.peers) == 0 {
		return
	}
	rep := Report{
		IP:         ip,
		Label:      label,
		Reason:     reason,
		Source:     s.selfName,
		TTLSeconds: uint32(s.ttl / time.Second),
	}
	body, err := json.Marshal(rep)
	if err != nil {
		log.Printf("threatshare: encode report for %s: %v", ip, err)
		return
	}

	for _, p := range s.peers {
		go func(p Peer) {
			req, err := http.NewRequest(http.MethodPost, p.URL+"/api/threats/report", bytes.NewReader(body))
			if err != nil {
				log.Printf("threatshare: build request to %s: %v", p.URL, err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			if p.Token != "" {
				req.Header.Set("Authorization", "Bearer "+p.Token)
			}
			resp, err := s.client.Do(req)
			if err != nil {
				log.Printf("threatshare: relay %s to %s failed: %v", ip, p.URL, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				log.Printf("threatshare: relay %s to %s: peer returned %s", ip, p.URL, resp.Status)
			}
		}(p)
	}
}

// entry is one currently-enforced shared block, tracked so Registry.Run
// knows when to lift it.
type entry struct {
	report    Report
	expiresAt time.Time
}

// Registry is the inbound half of Phase 23: the receiving end of
// /api/threats/report. It applies incoming reports as local blocks under
// ReasonShared and expires them on their own schedule, independent of
// whatever the reporting daemon does with its own copy of the block.
type Registry struct {
	fw *firewall.Firewall

	mu      sync.Mutex
	entries map[string]entry // keyed by IP
}

// NewRegistry builds a Registry bound to a live Firewall. Does nothing
// until Apply is called (from the /api/threats/report handler) and Run is
// started (to expire entries on their TTL).
func NewRegistry(fw *firewall.Firewall) *Registry {
	return &Registry{fw: fw, entries: make(map[string]entry)}
}

// Apply enforces rep locally — blocking rep.IP under ReasonShared — and
// (re)starts its TTL countdown. Calling Apply again for an IP already
// being enforced just refreshes the expiry, so a peer that keeps
// rediscovering the same active threat keeps it blocked continuously
// rather than having it flap in and out as the first report's TTL lapses.
func (reg *Registry) Apply(rep Report) error {
	label := rep.Label
	if label == "" {
		label = fmt.Sprintf("shared by %s", rep.Source)
	} else {
		label = fmt.Sprintf("%s (shared by %s)", label, rep.Source)
	}

	if err := reg.fw.BlockWithReason(rep.IP, label, firewall.ReasonShared); err != nil {
		return err
	}

	ttl := time.Duration(rep.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	reg.mu.Lock()
	reg.entries[rep.IP] = entry{report: rep, expiresAt: time.Now().Add(ttl)}
	reg.mu.Unlock()
	return nil
}

// ThreatEntry is a point-in-time view of one shared block, for `sxctl
// threats list` and the dashboard.
type ThreatEntry struct {
	IP        string    `json:"ip"`
	Label     string    `json:"label,omitempty"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`
	ExpiresAt time.Time `json:"expires_at"`
}

// List returns every shared block this daemon is currently enforcing.
func (reg *Registry) List() []ThreatEntry {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	out := make([]ThreatEntry, 0, len(reg.entries))
	for ip, e := range reg.entries {
		out = append(out, ThreatEntry{
			IP:        ip,
			Label:     e.report.Label,
			Reason:    e.report.Reason.String(),
			Source:    e.report.Source,
			ExpiresAt: e.expiresAt,
		})
	}
	return out
}

// sweepInterval is how often Run checks for expired shared blocks. Coarse
// on purpose — a shared block living a few seconds past its nominal TTL is
// harmless, and this keeps Run cheap to leave running for the daemon's
// entire lifetime.
const sweepInterval = 30 * time.Second

// Run periodically unblocks any shared entry whose TTL has lapsed, until
// stop is closed. Meant to be started once in its own goroutine
// (`go shareRegistry.Run(stopShare)`), mirroring every other background
// loop in cmd/sentryxd/main.go.
func (reg *Registry) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			reg.sweep()
		}
	}
}

func (reg *Registry) sweep() {
	now := time.Now()

	reg.mu.Lock()
	var expired []string
	for ip, e := range reg.entries {
		if now.After(e.expiresAt) {
			expired = append(expired, ip)
			delete(reg.entries, ip)
		}
	}
	reg.mu.Unlock()

	for _, ip := range expired {
		if err := reg.fw.Unblock(ip); err != nil {
			log.Printf("threatshare: expire shared block for %s: %v", ip, err)
			continue
		}
		log.Printf("threatshare: lifted expired shared block for %s", ip)
	}
}
