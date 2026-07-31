// Package topology implements Phase 26's live topology / war-room map:
// pure dashboard-feeding work, no kernel changes needed, per the roadmap.
//
// It hooks firewall.Firewall's block observer (the same mechanism Phase
// 23's threat-share Sharer uses) to learn about every new block as it
// happens, resolves a country for the blocked IP using Phase 20's GeoIP
// feed (falling back to "unknown" for blocks that aren't country-range
// hits, e.g. a manual block or an anomaly-detector auto-block), maps that
// country to an approximate lat/long via a small embedded centroid table,
// and keeps the last few hundred events in memory for the dashboard to
// stream and plot as pulsing dots.
//
// Honest limitation: a country centroid is a single representative point
// (its capital city, in this table), not the blocked IP's actual
// geolocation — good enough to show "traffic from Russia just got
// blocked" on a world map, not precise enough for anything finer-grained.
// Phase 20's own package comment already states the same caveat one level
// up (country-level GeoIP, not per-IP geolocation).
package topology

import (
	"sync"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// maxEvents bounds the in-memory ring buffer — enough history for a
// dashboard reconnect to backfill a few minutes of activity without
// unbounded growth on a long-running daemon.
const maxEvents = 500

// LatLon is a plain latitude/longitude pair.
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// Event is one geo-tagged block, ready for the dashboard's world map.
type Event struct {
	Seq       uint64    `json:"seq"` // monotonically increasing; lets a client ask "anything after N?"
	IP        string    `json:"ip"`
	Label     string    `json:"label,omitempty"`
	Reason    string    `json:"reason"`
	Country   string    `json:"country,omitempty"`   // ISO 3166-1 alpha-2, empty if unresolved
	Lat       float64   `json:"lat,omitempty"`
	Lon       float64   `json:"lon,omitempty"`
	Resolved  bool      `json:"resolved"` // false means Country/Lat/Lon are meaningless — plot nothing, or plot at a "somewhere" marker
	Timestamp time.Time `json:"timestamp"`
}

// CountryResolver answers "what country is this IP associated with, if
// any known CIDR range says so" — internal/geoip.Feed satisfies this via
// its CountryForIP method. Kept as a small interface (rather than
// importing internal/geoip directly) so this package doesn't need to know
// about GeoIP's HTTP client, refresh loop, or anything else it doesn't use.
type CountryResolver interface {
	CountryForIP(ip string) (string, bool)
}

// Recorder is the Phase 26 event feed: register Observe as a
// firewall.Firewall block observer (via AddBlockObserver) and read
// Snapshot/Since from the API layer to serve the dashboard.
type Recorder struct {
	resolver CountryResolver // may be nil if Phase 20 GeoIP isn't configured on this daemon

	mu     sync.Mutex
	seq    uint64
	events []Event // ring buffer, oldest first, capped at maxEvents
}

// New builds a Recorder. resolver may be nil — every event is then
// recorded with Resolved:false rather than failing, since not every
// daemon runs with GeoIP blocking configured.
func New(resolver CountryResolver) *Recorder {
	return &Recorder{resolver: resolver}
}

// Observe is a firewall.Firewall block-observer callback (see
// Firewall.AddBlockObserver): call it for every reason except
// ReasonShared is handled by the firewall package itself, so Observe
// doesn't need to filter that out again.
func (r *Recorder) Observe(ip, label string, reason firewall.Reason) {
	ev := Event{
		IP:        ip,
		Label:     label,
		Reason:    reason.String(),
		Timestamp: time.Now(),
	}

	if r.resolver != nil {
		if cc, ok := r.resolver.CountryForIP(ip); ok {
			if ll, ok := Centroid(cc); ok {
				ev.Country = cc
				ev.Lat, ev.Lon = ll.Lat, ll.Lon
				ev.Resolved = true
			}
		}
	}

	r.mu.Lock()
	r.seq++
	ev.Seq = r.seq
	r.events = append(r.events, ev)
	if len(r.events) > maxEvents {
		r.events = r.events[len(r.events)-maxEvents:]
	}
	r.mu.Unlock()
}

// Snapshot returns the most recent n events (or fewer if there aren't n
// yet), oldest first — used to backfill a dashboard on initial load.
func (r *Recorder) Snapshot(n int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.events) {
		n = len(r.events)
	}
	start := len(r.events) - n
	out := make([]Event, n)
	copy(out, r.events[start:])
	return out
}

// Since returns every event with Seq > afterSeq, oldest first — what the
// live SSE stream sends on each tick. Pass 0 for "everything currently
// buffered".
func (r *Recorder) Since(afterSeq uint64) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, ev := range r.events {
		if ev.Seq > afterSeq {
			out = append(out, ev)
		}
	}
	return out
}

// LatestSeq returns the highest sequence number recorded so far, i.e.
// what a fresh client should pass as its first Since cursor to only
// receive events from here on.
func (r *Recorder) LatestSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}
