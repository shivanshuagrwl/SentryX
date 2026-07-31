// Package anomaly implements SENTRYX's behavioral anomaly detector.
//
// The kernel (bpf/xdp_sentryx.c) never decides what "normal" traffic looks
// like — it just counts packets, bytes, and SYNs per source IP into the
// `activity` map. This package is where that judgment call actually lives:
// it polls the kernel's counters on a timer, keeps a lightweight per-IP
// baseline (an exponential moving average of packet rate and SYN ratio),
// and auto-blocks any source whose traffic suddenly deviates far enough
// from its own recent history — without a human ever writing a rule for
// that specific IP.
//
// This is deliberately simple statistics (EWMA + threshold), not ML. That's
// a feature, not a shortcut: it's auditable, it has no training phase, and
// every decision can be explained in one sentence ("14x its own baseline
// packet rate, sustained for 2 samples").
package anomaly

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// Config controls detection sensitivity. Sane defaults are provided by
// DefaultConfig(); tune via daemon flags/config file, not by editing code.
type Config struct {
	// PollInterval is how often the detector reads the kernel activity map.
	PollInterval time.Duration
	// MinPacketRate is a floor below which traffic is never flagged,
	// regardless of how it compares to baseline — protects low-traffic
	// IPs (e.g. going from 1pps to 5pps is a 5x spike but is noise).
	MinPacketRate float64
	// RateMultiplier: flag when current rate exceeds baseline by this
	// factor (e.g. 8 == "8x its own normal rate").
	RateMultiplier float64
	// SynRatioThreshold: flag when SYN packets / total packets exceeds
	// this ratio in a window (classic SYN-flood signature), combined
	// with MinPacketRate.
	SynRatioThreshold float64
	// ConsecutiveSamples requires the anomaly to persist across this many
	// consecutive polls before auto-blocking, to absorb one-off bursts.
	ConsecutiveSamples int
	// EWMAAlpha weights how quickly the baseline adapts (0..1). Lower is
	// slower/steadier; higher tracks recent traffic more aggressively.
	EWMAAlpha float64
	// AutoBlock, when false, only logs/records detections without
	// touching the kernel blocklist — useful for tuning thresholds
	// against real traffic before trusting the detector to act.
	AutoBlock bool
}

// DefaultConfig returns reasonable starting thresholds for a small/medium
// server. Tighten MinPacketRate/RateMultiplier for busier hosts.
func DefaultConfig() Config {
	return Config{
		PollInterval:       5 * time.Second,
		MinPacketRate:      50,
		RateMultiplier:     8,
		SynRatioThreshold:  0.9,
		ConsecutiveSamples: 2,
		EWMAAlpha:          0.3,
		AutoBlock:          true,
	}
}

// Event is a single detection, kept around in memory so the API/dashboard
// can answer "why was this flagged" without re-deriving it.
type Event struct {
	IP       string    `json:"ip"`
	Detected time.Time `json:"detected"`
	Metric   string    `json:"metric"`    // "rate" or "syn-ratio"
	Rate     float64   `json:"rate"`      // packets/sec observed
	Baseline float64   `json:"baseline"`  // this IP's EWMA baseline pps
	SynRatio float64   `json:"syn_ratio"` // SYN packets / total, this window
	Blocked  bool      `json:"blocked"`   // did the detector act on it
	Label    string    `json:"label"`     // human-readable one-line explanation
}

type ipBaseline struct {
	rateEWMA     float64
	prevPackets  uint64
	prevSyn      uint64
	prevBytes    uint64
	strikes      int // consecutive anomalous samples
	seenSamples  int
	flaggedUntil time.Time

	// lastRate/lastSynRatio are this IP's most recent per-interval
	// packet rate and SYN ratio — exposed via SynRate below so other
	// packages (e.g. `sxctl benchmark`'s SYN-flood scenario) can read
	// "what does the detector currently see for this source" instead of
	// standing up a second, duplicate per-IP counter of their own.
	lastRate     float64
	lastSynRatio float64
}

// Detector owns the polling loop and per-IP baselines.
type Detector struct {
	cfg Config
	fw  *firewall.Firewall

	mu        sync.Mutex
	baselines map[string]*ipBaseline
	events    []Event // ring buffer, most recent last

	// arpSeen tracks the last arp_alert.Count reported per source IP, so
	// pollArp only emits a new Event when a spoof alert actually changes
	// (a fresh MAC flip), not on every single poll while it sits unchanged
	// in the kernel's LRU map.
	arpSeen map[string]uint64
}

const maxEvents = 200

// New builds a Detector. It does not start polling until Run is called.
func New(fw *firewall.Firewall, cfg Config) *Detector {
	return &Detector{
		fw:        fw,
		cfg:       cfg,
		baselines: make(map[string]*ipBaseline),
		arpSeen:   make(map[string]uint64),
	}
}

// Run polls the kernel activity map every cfg.PollInterval until ctx-like
// stop channel is closed. Intended to be launched with `go d.Run(stopCh)`.
func (d *Detector) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			d.poll()
		}
	}
}

func (d *Detector) poll() {
	d.pollArp()

	snap, err := d.fw.ActivitySnapshot()
	if err != nil {
		log.Printf("anomaly: failed to read activity map: %v", err)
		return
	}

	intervalSec := d.cfg.PollInterval.Seconds()
	if intervalSec <= 0 {
		intervalSec = 1
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for ip, act := range snap {
		if net.ParseIP(ip) == nil {
			continue
		}
		bl, ok := d.baselines[ip]
		if !ok {
			bl = &ipBaseline{}
			d.baselines[ip] = bl
		}

		// Kernel counters are cumulative and never reset, so derive a
		// per-interval delta ourselves. Guard against counter resets
		// (e.g. daemon restart racing a stale snapshot) by treating a
		// negative delta as "no data this round".
		deltaPackets := safeDelta(act.Packets, bl.prevPackets)
		deltaSyn := safeDelta(act.SynPackets, bl.prevSyn)
		bl.prevPackets = act.Packets
		bl.prevSyn = act.SynPackets
		bl.prevBytes = act.Bytes
		bl.seenSamples++

		rate := float64(deltaPackets) / intervalSec
		var synRatio float64
		if deltaPackets > 0 {
			synRatio = float64(deltaSyn) / float64(deltaPackets)
		}
		bl.lastRate = rate
		bl.lastSynRatio = synRatio

		anomalous, metric := d.evaluate(bl, rate, synRatio, deltaPackets)

		if anomalous {
			bl.strikes++
		} else {
			bl.strikes = 0
			// Only let "normal" traffic pull the baseline — this stops an
			// ongoing attack from dragging its own baseline up and
			// escaping detection ("boiling the frog").
			if bl.seenSamples > 1 {
				bl.rateEWMA = ewma(bl.rateEWMA, rate, d.cfg.EWMAAlpha)
			} else {
				bl.rateEWMA = rate
			}
		}

		if anomalous && bl.strikes >= d.cfg.ConsecutiveSamples {
			d.flag(ip, metric, rate, bl.rateEWMA, synRatio)
			bl.strikes = 0 // avoid re-flagging every poll once blocked
		}
	}
}

// pollArp surfaces Phase 21's kernel-side ARP spoof detections through the
// same explainability pipeline (RecentEvents / `sxctl why` / the
// dashboard) as every other anomaly, without ever auto-blocking: ARP
// spoof detection has real false positives on legitimate DHCP
// renewal/failover, so per the Phase 21 design this is evidence for a
// human, not grounds for an automatic drop. Deduplicated against arpSeen
// so a MAC flip that's already been surfaced doesn't generate a fresh
// Event on every single poll while it sits unchanged in the kernel's LRU
// map — only a genuinely new flip (arp_alert.Count increasing) does.
func (d *Detector) pollArp() {
	alerts, err := d.fw.ArpAlerts()
	if err != nil {
		log.Printf("anomaly: failed to read arp_alerts map: %v", err)
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, a := range alerts {
		if last, ok := d.arpSeen[a.IP]; ok && last >= a.Count {
			continue // already surfaced, no new flip since last poll
		}
		d.arpSeen[a.IP] = a.Count

		label := fmt.Sprintf("arp-spoof-suspected: %s claimed by %s, previously %s (seen %dx)", a.IP, a.NewMAC, a.OldMAC, a.Count)
		ev := Event{
			IP:       a.IP,
			Detected: a.LastSeen,
			Metric:   "arp-spoof-suspected",
			Label:    label,
		}
		log.Printf("anomaly: %s", label)

		d.events = append(d.events, ev)
		if len(d.events) > maxEvents {
			d.events = d.events[len(d.events)-maxEvents:]
		}
	}
}

// evaluate applies the threshold rules and returns whether this sample
// looks anomalous, and which signal tripped.
func (d *Detector) evaluate(bl *ipBaseline, rate, synRatio float64, deltaPackets uint64) (bool, string) {
	if deltaPackets == 0 {
		return false, ""
	}
	// SYN-flood signature: high SYN ratio at meaningful volume, checked
	// independent of baseline since a flood can start on IP #1's very
	// first packets.
	if rate >= d.cfg.MinPacketRate && synRatio >= d.cfg.SynRatioThreshold {
		return true, "syn-ratio"
	}
	// Rate deviation from this IP's own baseline.
	if bl.seenSamples > 2 && rate >= d.cfg.MinPacketRate && bl.rateEWMA > 0 && rate >= bl.rateEWMA*d.cfg.RateMultiplier {
		return true, "rate"
	}
	return false, ""
}

func (d *Detector) flag(ip, metric string, rate, baseline, synRatio float64) {
	label := explain(metric, rate, baseline, synRatio)
	ev := Event{
		IP:       ip,
		Detected: time.Now(),
		Metric:   metric,
		Rate:     rate,
		Baseline: baseline,
		SynRatio: synRatio,
		Label:    label,
	}

	if d.cfg.AutoBlock {
		if err := d.fw.BlockWithReason(ip, "auto: "+label, firewall.ReasonAnomaly); err != nil {
			log.Printf("anomaly: failed to auto-block %s: %v", ip, err)
		} else {
			ev.Blocked = true
			log.Printf("anomaly: auto-blocked %s (%s)", ip, label)
		}
	} else {
		log.Printf("anomaly: detected %s (%s) [dry-run, not blocking]", ip, label)
	}

	d.events = append(d.events, ev)
	if len(d.events) > maxEvents {
		d.events = d.events[len(d.events)-maxEvents:]
	}
}

func explain(metric string, rate, baseline, synRatio float64) string {
	switch metric {
	case "syn-ratio":
		return fmt.Sprintf("SYN-flood pattern: %.0f%% SYN packets at %.0f pps", synRatio*100, rate)
	default:
		mult := 0.0
		if baseline > 0 {
			mult = rate / baseline
		}
		return fmt.Sprintf("%.0fx baseline packet rate (%.0f pps vs ~%.0f pps normal)", mult, rate, baseline)
	}
}

// RecentEvents returns the most recent detections, newest last.
func (d *Detector) RecentEvents(limit int) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	if limit <= 0 || limit > len(d.events) {
		limit = len(d.events)
	}
	out := make([]Event, limit)
	copy(out, d.events[len(d.events)-limit:])
	return out
}

// Baselines returns a point-in-time snapshot of every tracked IP's current
// EWMA baseline packet rate, for the dashboard's "what does normal look
// like" view.
func (d *Detector) Baselines() map[string]float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]float64, len(d.baselines))
	for ip, bl := range d.baselines {
		out[ip] = bl.rateEWMA
	}
	return out
}

// SynRate returns the most recently observed packet rate and SYN ratio
// for ip, as computed on the last poll — the same trigger input the
// syn-ratio anomaly signal itself uses. Returns ok=false if this IP
// hasn't been observed yet. Intended for callers (e.g. `sxctl benchmark`'s
// SYN-flood scenario) that want to report what the detector currently
// sees for a source without maintaining a second, duplicate counter.
func (d *Detector) SynRate(ip string) (rate, synRatio float64, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	bl, found := d.baselines[ip]
	if !found {
		return 0, 0, false
	}
	return bl.lastRate, bl.lastSynRatio, true
}

func safeDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func ewma(prev, sample, alpha float64) float64 {
	if prev == 0 {
		return sample
	}
	return alpha*sample + (1-alpha)*prev
}
