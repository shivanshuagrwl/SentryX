//go:build linux

// Package firewall — Linux backend. This is the original, kernel-speed
// implementation: it wraps the compiled XDP object file and exposes a
// small, safe Go API over it, and every rule change and every stats read
// on Linux goes through this file — nothing else is allowed to touch the
// eBPF maps directly.
//
// The cross-platform vocabulary (Reason, Rule, Stats, Activity, the
// Backend interface, ...) lives in types.go, which has no build
// constraint. This file supplies the concrete Firewall type that
// satisfies Backend on Linux; firewall_windows.go and firewall_darwin.go
// supply the equivalents for their platforms. See Phase 27.2 in
// SENTRYX_PHASE2_ROADMAP.md.
package firewall

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// stat slot indices — must match bpf/xdp_sentryx.c
const (
	statAllowed      = 0
	statDropped      = 1
	statBytesAllowed = 2
	statBytesDropped = 3
)

// RateBucket mirrors struct rate_bucket in the XDP program. Field order and
// sizes must match exactly, or the kernel and Go sides will disagree about
// what the bytes mean.
type RateBucket struct {
	Tokens       uint64
	LastRefillNs uint64
	LimitPPS     uint32
	_            uint32 // padding to match C struct alignment
}

// BandwidthBucket mirrors struct bandwidth_bucket in the XDP program —
// Phase 25's QoS byte-rate cap. It's a separate token bucket from
// RateBucket (tokens are bytes here, not packets) and the two are checked
// independently, so an IP can be under its packet-rate cap while still
// throttled by its byte-rate cap, or vice versa.
type BandwidthBucket struct {
	TokensBytes  uint64
	LastRefillNs uint64
	LimitKbps    uint32
	_            uint32 // padding to match C struct alignment
}

// activityRaw mirrors struct activity in the XDP program.
type activityRaw struct {
	Packets       uint64
	SynPackets    uint64
	Bytes         uint64
	WindowStartNs uint64
}

// dropInfoRaw mirrors struct drop_info in the XDP program.
type dropInfoRaw struct {
	Reason   uint8
	_        [7]uint8
	LastTsNs uint64
	Count    uint64
}

// ---- Phase 16: connection tracking ----------------------------------

// connKeyRaw mirrors struct conn_key in the XDP program byte-for-byte —
// field order/sizes/padding must match exactly (see the Phase 16 "Gotcha"
// note in SENTRYX_PHASE2_ROADMAP.md).
type connKeyRaw struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8
}

// connStateRaw mirrors struct conn_state in the XDP program.
type connStateRaw struct {
	State      uint8
	_          [3]uint8
	SynCount   uint32
	LastSeenNs uint64
}

// ---- Phase 17: SYN-cookie DDoS mitigation ----------------------------

// synCookieCfgRaw mirrors struct syn_cookie_cfg in the XDP program.
type synCookieCfgRaw struct {
	LowPPS  uint32
	HighPPS uint32
}

// synSecretRaw mirrors struct syn_secret in the XDP program.
type synSecretRaw struct {
	Cur         uint32
	Prev        uint32
	RotatedAtNs uint64
}

// ---- Phase 18: port knocking / stealth mode ---------------------------

const maxKnockSteps = 8

// knockCfgRaw mirrors struct knock_cfg in the XDP program.
type knockCfgRaw struct {
	Sequence     [maxKnockSteps]uint16
	SeqLen       uint8
	_            uint8
	OpenPort     uint16
	WindowSecond uint32
}

// ---- Phase 22: packet capture / pcap export ----------------------------

// captureCfgRaw mirrors struct capture_cfg in the XDP program.
type captureCfgRaw struct {
	Enabled uint8
	_       [7]uint8
}

// ---- Phase 20: GeoIP blocking ------------------------------------------

// geoipKeyRaw mirrors struct geoip_key in the XDP program — an LPM-trie
// key, so Prefixlen (in bits) must come first and the IP itself must stay
// in the same raw network-byte-order encoding ipToKey already uses.
type geoipKeyRaw struct {
	Prefixlen uint32
	IP        uint32
}

// ---- Phase 21: ARP spoofing detection ----------------------------------

// arpAlertRaw mirrors struct arp_alert in the XDP program.
type arpAlertRaw struct {
	OldMAC [6]byte
	NewMAC [6]byte
	TsNs   uint64
	Count  uint32
	_      uint32
}

// Firewall is a loaded, attached instance of the SENTRYX XDP program.
type Firewall struct {
	mu sync.RWMutex

	blocklist       *ebpf.Map
	blocklistV6     *ebpf.Map
	rateLimits      *ebpf.Map
	bandwidthLimits *ebpf.Map // Phase 25: QoS byte-rate cap, separate bucket from rateLimits
	activityMap     *ebpf.Map
	dropReasons     *ebpf.Map
	statsMap        *ebpf.Map

	// Phase 23/26: block observers. Fired at the end of a successful
	// BlockWithReason for every reason except ReasonShared, so a block
	// this daemon relayed in from a peer doesn't get echoed back out and
	// cause a report loop. Phase 23's threat-share Sharer and Phase 26's
	// topology Recorder both register here via AddBlockObserver, which is
	// why this is a slice rather than the single-callback field it used
	// to be — see firewall_windows.go / firewall_darwin.go, which use the
	// exact same shape.
	blockObservers []func(ip, label string, reason Reason)

	// Phase 16/17/18 maps.
	connTable     *ebpf.Map
	synCookieCfg  *ebpf.Map
	synSecret     *ebpf.Map
	synRate       *ebpf.Map
	synVerified   *ebpf.Map
	knockCfg      *ebpf.Map
	knockState    *ebpf.Map
	knockUnlocked *ebpf.Map

	// Phase 20/21 maps.
	geoBlocklist *ebpf.Map
	arpTable     *ebpf.Map
	arpAlerts    *ebpf.Map

	// Phase 22 maps. captureEvents is a BPF ringbuf, opened for streaming
	// reads by OpenCaptureReader (internal/capture), not by direct
	// Lookup/Put like every other map here.
	captureEvents *ebpf.Map
	captureCfg    *ebpf.Map

	prog       *ebpf.Program
	xdpLink    link.Link
	iface      string
	attachedAt time.Time

	// bootWallRef lets us convert the kernel's bpf_ktime_get_ns()
	// timestamps (nanoseconds since boot, CLOCK_MONOTONIC) into wall-clock
	// time.Time values for the API/CLI — captured once at Load (from
	// /proc/uptime) so every conversion afterward is just a fixed offset
	// add, not a syscall per lookup. See bootTimeToWall below.
	bootWallRef time.Time

	// rules mirrors the kernel-side blocklist with metadata Go needs
	// (label, created_at, reason) that the map itself doesn't fully store.
	rules map[string]Rule

	// geoRules mirrors the kernel-side geoip_blocklist trie the same way
	// rules mirrors blocklist — keyed by CIDR string.
	geoRules map[string]GeoRule
}

// Load compiles-in the pinned/compiled object file at objPath, attaches its
// "xdp_sentryx" program to the named interface, and returns a ready
// Firewall. Pass mode "native" for driver-level XDP or "generic" (SKB mode)
// for interfaces / drivers that don't support native XDP — useful for
// testing inside a VM.
func Load(objPath, iface string, generic bool) (*Firewall, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	prog, ok := coll.Programs["xdp_sentryx"]
	if !ok {
		return nil, fmt.Errorf("program %q not found in %s", "xdp_sentryx", objPath)
	}

	blocklist, ok := coll.Maps["blocklist"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "blocklist", objPath)
	}
	blocklistV6, ok := coll.Maps["blocklist_v6"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "blocklist_v6", objPath)
	}
	rateLimits, ok := coll.Maps["rate_limits"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "rate_limits", objPath)
	}
	// Phase 25 map.
	bandwidthLimits, ok := coll.Maps["bandwidth_limits"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "bandwidth_limits", objPath)
	}
	activityMap, ok := coll.Maps["activity"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "activity", objPath)
	}
	dropReasons, ok := coll.Maps["drop_reasons"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "drop_reasons", objPath)
	}
	statsMap, ok := coll.Maps["stats"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "stats", objPath)
	}

	// Phase 16/17/18 maps. Required just like the maps above — if the
	// loaded object file doesn't have them, it was built from an older
	// bpf/xdp_sentryx.c and the daemon should fail loudly rather than run
	// with half the feature set silently missing.
	connTable, ok := coll.Maps["conn_table"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "conn_table", objPath)
	}
	synCookieCfg, ok := coll.Maps["syn_cookie_cfg_map"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "syn_cookie_cfg_map", objPath)
	}
	synSecret, ok := coll.Maps["syn_secret_map"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "syn_secret_map", objPath)
	}
	synRate, ok := coll.Maps["syn_rate"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "syn_rate", objPath)
	}
	synVerified, ok := coll.Maps["syn_verified"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "syn_verified", objPath)
	}
	knockCfg, ok := coll.Maps["knock_cfg_map"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "knock_cfg_map", objPath)
	}
	knockState, ok := coll.Maps["knock_state"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "knock_state", objPath)
	}
	knockUnlocked, ok := coll.Maps["knock_unlocked"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "knock_unlocked", objPath)
	}

	// Phase 20/21 maps.
	geoBlocklist, ok := coll.Maps["geoip_blocklist"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "geoip_blocklist", objPath)
	}
	arpTable, ok := coll.Maps["arp_table"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "arp_table", objPath)
	}
	arpAlerts, ok := coll.Maps["arp_alerts"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "arp_alerts", objPath)
	}

	// Phase 22 maps.
	captureEvents, ok := coll.Maps["capture_events"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "capture_events", objPath)
	}
	captureCfg, ok := coll.Maps["capture_cfg_map"]
	if !ok {
		return nil, fmt.Errorf("map %q not found in %s", "capture_cfg_map", objPath)
	}

	ifce, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", iface, err)
	}

	flags := link.XDPDriverMode
	if generic {
		flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifce.Index,
		Flags:     flags,
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp to %s: %w", iface, err)
	}

	fw := &Firewall{
		blocklist:       blocklist,
		blocklistV6:     blocklistV6,
		rateLimits:      rateLimits,
		bandwidthLimits: bandwidthLimits,
		activityMap:     activityMap,
		dropReasons:     dropReasons,
		statsMap:        statsMap,
		connTable:       connTable,
		synCookieCfg:    synCookieCfg,
		synSecret:       synSecret,
		synRate:         synRate,
		synVerified:     synVerified,
		knockCfg:        knockCfg,
		knockState:      knockState,
		knockUnlocked:   knockUnlocked,
		geoBlocklist:    geoBlocklist,
		arpTable:        arpTable,
		arpAlerts:       arpAlerts,
		captureEvents:   captureEvents,
		captureCfg:      captureCfg,
		prog:            prog,
		xdpLink:         l,
		iface:           iface,
		attachedAt:      time.Now(),
		bootWallRef:     computeBootWallRef(),
		rules:           make(map[string]Rule),
		geoRules:        make(map[string]GeoRule),
	}

	// Seed the Phase 17 cookie-signing secret. Without this the kernel's
	// cookie_secret() lookup finds no entry and every cookie hash mixes in
	// 0, which is deterministic and defeats the point — a fresh random
	// value here on every daemon start (and again every SYN_SECRET_ROTATE_NS
	// from the kernel side) is what actually makes cookies unguessable.
	var randBuf [4]byte
	if _, err := rand.Read(randBuf[:]); err != nil {
		return nil, fmt.Errorf("seed syn-cookie secret: %w", err)
	}
	seed := synSecretRaw{
		Cur:         binary.BigEndian.Uint32(randBuf[:]),
		Prev:        0,
		RotatedAtNs: uint64(time.Now().UnixNano()),
	}
	if err := synSecret.Put(uint32(0), seed); err != nil {
		return nil, fmt.Errorf("seed syn-cookie secret: %w", err)
	}

	return fw, nil
}

// Close detaches the XDP program and releases the underlying map handles.
// The interface returns to normal (unfiltered) operation immediately.
func (f *Firewall) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var firstErr error
	if err := f.xdpLink.Close(); err != nil {
		firstErr = err
	}
	f.blocklist.Close()
	f.blocklistV6.Close()
	f.rateLimits.Close()
	f.bandwidthLimits.Close()
	f.activityMap.Close()
	f.dropReasons.Close()
	f.statsMap.Close()
	f.connTable.Close()
	f.synCookieCfg.Close()
	f.synSecret.Close()
	f.synRate.Close()
	f.synVerified.Close()
	f.knockCfg.Close()
	f.knockState.Close()
	f.knockUnlocked.Close()
	f.geoBlocklist.Close()
	f.arpTable.Close()
	f.arpAlerts.Close()
	f.captureEvents.Close()
	f.captureCfg.Close()
	f.prog.Close()
	return firstErr
}

// Block adds an IPv4 address to the kernel blocklist with reason
// ReasonManual. Takes effect on the very next packet from that address —
// no reload required.
func (f *Firewall) Block(ipStr, label string) error {
	return f.BlockWithReason(ipStr, label, ReasonManual)
}

// BlockWithReason is like Block but lets the caller record *why* the
// address was blocked (manual operator action, auto rate-limit escalation,
// anomaly detector, threat-intel feed, ...). The reason is what the
// dashboard and `sxctl why <ip>` surface back to a human.
func (f *Firewall) BlockWithReason(ipStr, label string, reason Reason) error {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ipStr)
	}
	if reason == ReasonNone {
		reason = ReasonManual
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if v4 := parsed.To4(); v4 != nil {
		if err := f.blocklist.Put(ipToKey(v4), uint8(reason)); err != nil {
			return fmt.Errorf("write blocklist entry: %w", err)
		}
	} else {
		// IPv6: written to the dedicated 128-bit map. Note this path does
		// not get rate limiting, activity tracking, or a stored drop
		// reason in the kernel yet (see bpf/xdp_sentryx.c) — the block
		// itself is fully enforced at line rate, but "why" queries and
		// per-IP rate limits remain IPv4-only for now.
		key, err := v6Key(parsed)
		if err != nil {
			return err
		}
		if err := f.blocklistV6.Put(key, uint8(reason)); err != nil {
			return fmt.Errorf("write ipv6 blocklist entry: %w", err)
		}
	}

	existing := f.rules[ipStr]
	f.rules[ipStr] = Rule{
		IP:             ipStr,
		Label:          label,
		Reason:         reason,
		ReasonStr:      reason.String(),
		RateLimit:      existing.RateLimit,
		BandwidthLimit: existing.BandwidthLimit,
		CreatedAt:      time.Now(),
	}

	// Phase 23/26: tell anyone listening (the threat-share Sharer, the
	// Phase 26 topology Recorder, ...) that this daemon just made a
	// block. Skipped for ReasonShared specifically — that's a block this
	// daemon just *received* from a peer, and re-reporting it would turn
	// a fan-out into an infinite loop across the fleet. observers is
	// snapshotted under f.mu below (defer f.mu.Unlock covers the copy,
	// not the calls) so a slow observer can't hold the lock; that's fine
	// because every registered observer here only enqueues async work
	// (an HTTP POST, an in-memory ring-buffer append) rather than calling
	// back into the firewall package.
	if reason != ReasonShared {
		observers := f.blockObservers
		for _, obs := range observers {
			obs(ipStr, label, reason)
		}
	}
	return nil
}

// SetBlockObserver registers fn as the *only* block observer, replacing
// any previously registered ones — kept for symmetry with
// firewall_windows.go / firewall_darwin.go's Backend implementation.
// Prefer AddBlockObserver in new code, since a daemon typically wants both
// Phase 23 threat-share and Phase 26 topology listening at once.
func (f *Firewall) SetBlockObserver(fn func(ip, label string, reason Reason)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockObservers = []func(ip, label string, reason Reason){fn}
}

// AddBlockObserver registers fn as an additional block observer, called
// at the end of every successful BlockWithReason (manual or automatic)
// except for blocks whose reason is ReasonShared. Used by Phase 23's
// cross-daemon threat sharing and Phase 26's live topology map to learn
// about new blocks without the firewall package needing to know either
// of those packages exist.
func (f *Firewall) AddBlockObserver(fn func(ip, label string, reason Reason)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockObservers = append(f.blockObservers, fn)
}

// Unblock removes an address (IPv4 or IPv6) from the kernel blocklist.
func (f *Firewall) Unblock(ipStr string) error {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ipStr)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if v4 := parsed.To4(); v4 != nil {
		key := ipToKey(v4)
		if err := f.blocklist.Delete(key); err != nil && !isNotFound(err) {
			return fmt.Errorf("delete blocklist entry: %w", err)
		}
		_ = f.dropReasons.Delete(key) // best-effort; stale explanation is harmless but noisy
	} else {
		key, err := v6Key(parsed)
		if err != nil {
			return err
		}
		if err := f.blocklistV6.Delete(key); err != nil && !isNotFound(err) {
			return fmt.Errorf("delete ipv6 blocklist entry: %w", err)
		}
	}
	delete(f.rules, ipStr)
	return nil
}

// RateLimit caps an address to limitPPS packets per second. A limit of 0
// removes any existing rate limit for that address.
func (f *Firewall) RateLimit(ipStr string, limitPPS uint32) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %q", ipStr)
	}
	key := ipToKey(ip)

	f.mu.Lock()
	defer f.mu.Unlock()

	if limitPPS == 0 {
		if err := f.rateLimits.Delete(key); err != nil && !isNotFound(err) {
			return err
		}
	} else {
		bucket := RateBucket{
			Tokens:       uint64(limitPPS),
			LastRefillNs: uint64(time.Now().UnixNano()),
			LimitPPS:     limitPPS,
		}
		if err := f.rateLimits.Put(key, bucket); err != nil {
			return err
		}
	}

	if r, ok := f.rules[ipStr]; ok {
		r.RateLimit = limitPPS
		f.rules[ipStr] = r
	}
	return nil
}

// BandwidthLimit caps an address to limitKbps kilobits per second — Phase
// 25's QoS byte-rate cap. This is a separate token bucket from RateLimit's
// packet-rate cap: the two are independent and stack, so an IP can carry
// its own -r/--rate-limit (packets/sec) and --bandwidth-kbps (kbps) caps
// at the same time. A limit of 0 removes any existing bandwidth cap for
// that address.
func (f *Firewall) BandwidthLimit(ipStr string, limitKbps uint32) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %q", ipStr)
	}
	key := ipToKey(ip)

	f.mu.Lock()
	defer f.mu.Unlock()

	if limitKbps == 0 {
		if err := f.bandwidthLimits.Delete(key); err != nil && !isNotFound(err) {
			return err
		}
	} else {
		// Seed the bucket already full (bytes/sec worth of tokens) so the
		// very first burst after setting the limit isn't throttled by an
		// artificially empty bucket — same convention RateLimit uses.
		limitBytesPerSec := uint64(limitKbps) * 1000 / 8
		bucket := BandwidthBucket{
			TokensBytes:  limitBytesPerSec,
			LastRefillNs: uint64(time.Now().UnixNano()),
			LimitKbps:    limitKbps,
		}
		if err := f.bandwidthLimits.Put(key, bucket); err != nil {
			return err
		}
	}

	if r, ok := f.rules[ipStr]; ok {
		r.BandwidthLimit = limitKbps
		f.rules[ipStr] = r
	}
	return nil
}

// List returns every currently blocked address known to the daemon.
func (f *Firewall) List() []Rule {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]Rule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, r)
	}
	return out
}

// Stats reads the live kernel-side packet counters.
func (f *Firewall) Stats() (Stats, error) {
	var allowed, dropped, bytesAllowed, bytesDropped uint64

	if err := f.statsMap.Lookup(uint32(statAllowed), &allowed); err != nil {
		return Stats{}, err
	}
	if err := f.statsMap.Lookup(uint32(statDropped), &dropped); err != nil {
		return Stats{}, err
	}
	if err := f.statsMap.Lookup(uint32(statBytesAllowed), &bytesAllowed); err != nil {
		return Stats{}, err
	}
	if err := f.statsMap.Lookup(uint32(statBytesDropped), &bytesDropped); err != nil {
		return Stats{}, err
	}

	return Stats{
		Allowed:      allowed,
		Dropped:      dropped,
		BytesAllowed: bytesAllowed,
		BytesDropped: bytesDropped,
	}, nil
}

// DropReason returns the most recent drop explanation recorded for ipStr,
// or ok=false if that address has never been dropped.
func (f *Firewall) DropReason(ipStr string) (info DropInfo, ok bool, err error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return DropInfo{}, false, fmt.Errorf("invalid IPv4 address: %q", ipStr)
	}
	key := ipToKey(ip)

	var raw dropInfoRaw
	if err := f.dropReasons.Lookup(key, &raw); err != nil {
		if isNotFound(err) {
			return DropInfo{}, false, nil
		}
		return DropInfo{}, false, err
	}

	r := Reason(raw.Reason)
	return DropInfo{
		IP:        ipStr,
		Reason:    r,
		ReasonStr: r.String(),
		LastSeen:  f.bootTimeToWall(raw.LastTsNs),
		Count:     raw.Count,
	}, true, nil
}

// ActivitySnapshot iterates the kernel's per-IP activity window and returns
// a point-in-time view. Deltas between successive snapshots are what the
// anomaly detector and the dashboard's "top active sources" panel use — the
// kernel itself never resets these counters, so callers diff themselves.
func (f *Firewall) ActivitySnapshot() (map[string]Activity, error) {
	out := make(map[string]Activity)

	it := f.activityMap.Iterate()
	var key uint32
	var raw activityRaw
	for it.Next(&key, &raw) {
		ip := keyToIP(key).String()
		var synRatio float64
		if raw.Packets > 0 {
			synRatio = float64(raw.SynPackets) / float64(raw.Packets)
		}
		out[ip] = Activity{
			IP:         ip,
			Packets:    raw.Packets,
			SynPackets: raw.SynPackets,
			Bytes:      raw.Bytes,
			SynRatio:   synRatio,
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate activity map: %w", err)
	}
	return out, nil
}

// ActiveConnections iterates the kernel's Phase 16 connection-tracking
// table and returns a point-in-time view of every tracked flow. Entries
// age out on their own (conn_table is an LRU map), so this never needs to
// be manually pruned.
func (f *Firewall) ActiveConnections() ([]Connection, error) {
	var out []Connection

	it := f.connTable.Iterate()
	var key connKeyRaw
	var raw connStateRaw
	for it.Next(&key, &raw) {
		out = append(out, Connection{
			SrcIP:    keyToIP(key.SrcIP).String(),
			DstIP:    keyToIP(key.DstIP).String(),
			SrcPort:  bePortToHost(key.SrcPort),
			DstPort:  bePortToHost(key.DstPort),
			Proto:    protoName(key.Proto),
			State:    ConnState(raw.State),
			StateStr: ConnState(raw.State).String(),
			SynCount: raw.SynCount,
			LastSeen: f.bootTimeToWall(raw.LastSeenNs),
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate conn_table: %w", err)
	}
	return out, nil
}

// SetSynCookieConfig writes the Phase 17 tiering thresholds into the
// kernel. Passing a zero-value SynCookieConfig disables the feature —
// every SYN then takes the exact pre-Phase-17 path.
func (f *Firewall) SetSynCookieConfig(cfg SynCookieConfig) error {
	raw := synCookieCfgRaw{LowPPS: cfg.LowPPS, HighPPS: cfg.HighPPS}
	if err := f.synCookieCfg.Put(uint32(0), raw); err != nil {
		return fmt.Errorf("write syn-cookie config: %w", err)
	}
	return nil
}

// SynCookieConfig reads back the currently active Phase 17 thresholds.
func (f *Firewall) SynCookieConfig() (SynCookieConfig, error) {
	var raw synCookieCfgRaw
	if err := f.synCookieCfg.Lookup(uint32(0), &raw); err != nil {
		if isNotFound(err) {
			return SynCookieConfig{}, nil
		}
		return SynCookieConfig{}, err
	}
	return SynCookieConfig{LowPPS: raw.LowPPS, HighPPS: raw.HighPPS}, nil
}

// SetKnockConfig writes the Phase 18 port-knock sequence into the kernel.
// Passing a KnockConfig with an empty Sequence disables the feature.
func (f *Firewall) SetKnockConfig(cfg KnockConfig) error {
	if len(cfg.Sequence) > maxKnockSteps {
		return fmt.Errorf("knock sequence too long: %d ports (max %d)", len(cfg.Sequence), maxKnockSteps)
	}
	var raw knockCfgRaw
	for i, port := range cfg.Sequence {
		raw.Sequence[i] = port
	}
	raw.SeqLen = uint8(len(cfg.Sequence))
	raw.OpenPort = cfg.OpenPort
	raw.WindowSecond = cfg.WindowSeconds
	if err := f.knockCfg.Put(uint32(0), raw); err != nil {
		return fmt.Errorf("write knock config: %w", err)
	}
	return nil
}

// KnockConfig reads back the currently active Phase 18 knock sequence.
func (f *Firewall) KnockConfig() (KnockConfig, error) {
	var raw knockCfgRaw
	if err := f.knockCfg.Lookup(uint32(0), &raw); err != nil {
		if isNotFound(err) {
			return KnockConfig{}, nil
		}
		return KnockConfig{}, err
	}
	cfg := KnockConfig{
		Sequence:      append([]uint16{}, raw.Sequence[:raw.SeqLen]...),
		OpenPort:      raw.OpenPort,
		WindowSeconds: raw.WindowSecond,
	}
	return cfg, nil
}

// ---- Phase 20: GeoIP blocking -------------------------------------------

// BlockCIDR adds an IPv4 CIDR range to the kernel's LPM-trie geoip
// blocklist under ReasonGeoIP. country is purely descriptive metadata
// (e.g. "CN") — the kernel trie itself has no notion of countries, only
// prefixes, so callers are responsible for grouping ranges sensibly.
func (f *Firewall) BlockCIDR(cidr, country, label string) error {
	key, err := cidrToGeoKey(cidr)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.geoBlocklist.Put(key, uint8(ReasonGeoIP)); err != nil {
		return fmt.Errorf("write geoip blocklist entry: %w", err)
	}
	f.geoRules[cidr] = GeoRule{CIDR: cidr, Country: country, Label: label, CreatedAt: time.Now()}
	return nil
}

// UnblockCIDR removes a previously-blocked CIDR range.
func (f *Firewall) UnblockCIDR(cidr string) error {
	key, err := cidrToGeoKey(cidr)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.geoBlocklist.Delete(key); err != nil && !isNotFound(err) {
		return fmt.Errorf("delete geoip blocklist entry: %w", err)
	}
	delete(f.geoRules, cidr)
	return nil
}

// ListGeoBlocks returns every currently blocked CIDR range.
func (f *Firewall) ListGeoBlocks() []GeoRule {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]GeoRule, 0, len(f.geoRules))
	for _, r := range f.geoRules {
		out = append(out, r)
	}
	return out
}

// cidrToGeoKey converts an IPv4 CIDR string ("203.0.113.0/24") into the
// LPM-trie key format geoip_blocklist expects: prefix length in bits,
// then the network address in the same raw network-byte-order encoding
// ipToKey already uses for the exact-match blocklist.
func cidrToGeoKey(cidr string) (geoipKeyRaw, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return geoipKeyRaw{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return geoipKeyRaw{}, fmt.Errorf("only IPv4 CIDR ranges are supported: %q", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	return geoipKeyRaw{Prefixlen: uint32(ones), IP: ipToKey(v4)}, nil
}

// ---- Phase 21: ARP spoofing detection -----------------------------------

// ArpAlerts iterates the kernel's arp_table/arp_alerts maps and returns
// every source IP currently flagged as having claimed more than one MAC
// address faster than a plausible DHCP lease change would explain. Never
// auto-cleared by a read — an alert stays until the daemon restarts or the
// LRU map evicts it, since "this IP did this at some point recently" stays
// true even after the traffic itself has stopped.
func (f *Firewall) ArpAlerts() ([]ArpAlert, error) {
	var out []ArpAlert

	it := f.arpAlerts.Iterate()
	var key uint32
	var raw arpAlertRaw
	for it.Next(&key, &raw) {
		out = append(out, ArpAlert{
			IP:       keyToIP(key).String(),
			OldMAC:   macString(raw.OldMAC),
			NewMAC:   macString(raw.NewMAC),
			LastSeen: f.bootTimeToWall(raw.TsNs),
			Count:    uint64(raw.Count),
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate arp_alerts: %w", err)
	}
	return out, nil
}

func macString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// ---- Phase 22: packet capture / pcap export -----------------------------

// SetCaptureEnabled flips the kernel-side capture switch. While enabled,
// every packet the XDP program itself drops or flags streams up to
// CaptureSnaplen raw bytes into the capture_events ringbuf; while
// disabled (the default), capture_packet() in the XDP program is a single
// cheap array lookup that returns immediately, same as if Phase 22 didn't
// exist. Safe to toggle at any time, including with a reader already open.
func (f *Firewall) SetCaptureEnabled(enabled bool) error {
	var raw captureCfgRaw
	if enabled {
		raw.Enabled = 1
	}
	if err := f.captureCfg.Put(uint32(0), raw); err != nil {
		return fmt.Errorf("write capture config: %w", err)
	}
	return nil
}

// CaptureEnabled reports whether kernel-side capture is currently on.
func (f *Firewall) CaptureEnabled() (bool, error) {
	var raw captureCfgRaw
	if err := f.captureCfg.Lookup(uint32(0), &raw); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return raw.Enabled != 0, nil
}

// OpenCaptureReader opens a streaming reader on the capture_events
// ringbuf. Callers (internal/capture) own the returned reader's lifecycle
// — Close it when done draining, independently of SetCaptureEnabled;
// closing the reader without disabling capture just means the kernel
// keeps trying to reserve ringbuf space that never gets drained; ringbuf
// entries are then silently dropped rather than blocking any packet.
func (f *Firewall) OpenCaptureReader() (*ringbuf.Reader, error) {
	r, err := ringbuf.NewReader(f.captureEvents)
	if err != nil {
		return nil, fmt.Errorf("open capture_events ringbuf: %w", err)
	}
	return r, nil
}

// BootTimeToWall converts a bpf_ktime_get_ns()-style timestamp (nanoseconds
// since boot, CLOCK_MONOTONIC) into a wall-clock time.Time, the same
// conversion ArpAlerts/DropReason use internally — exported so
// internal/capture can render correct pcap record timestamps from
// capture_event.ts_ns without duplicating the boot-reference logic.
func (f *Firewall) BootTimeToWall(monoNs uint64) time.Time {
	return f.bootTimeToWall(monoNs)
}

// Interface returns the name of the network interface this instance is
// attached to.
func (f *Firewall) Interface() string { return f.iface }

// AttachedAt returns when the XDP program was attached to the interface.
func (f *Firewall) AttachedAt() time.Time { return f.attachedAt }

// ipToKey converts a 4-byte IPv4 address into the __u32 key format the XDP
// program expects (raw network-byte-order bits of ip->saddr).
func ipToKey(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func keyToIP(key uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, key)
	return net.IP(b)
}

// v6Key converts a parsed IPv6 address into the 16-byte array layout that
// mirrors `struct in6_addr` in bpf/xdp_sentryx.c exactly (network byte
// order, no separators). Returns an error for anything that isn't a real
// 16-byte IPv6 address (e.g. an IPv4-mapped address slipping through).
func v6Key(ip net.IP) ([16]byte, error) {
	var key [16]byte
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return key, fmt.Errorf("not a valid IPv6 address: %v", ip)
	}
	copy(key[:], v6)
	return key, nil
}

func isNotFound(err error) bool {
	return err != nil && err == ebpf.ErrKeyNotExist
}

// protoName renders an IP protocol number the way `sxctl connections` and
// the dashboard expect to see it. Falls back to "proto/N" for anything
// that isn't TCP/UDP/ICMP — conn_table is TCP-only today (see the Phase 16
// roadmap note), but this stays generic rather than assuming.
func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("proto/%d", proto)
	}
}

// bePortToHost converts a port value stored raw in network byte order (as
// conn_key's src_port/dst_port fields are, straight from tcp->source /
// tcp->dest) into normal host byte order for JSON/display.
func bePortToHost(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

// computeBootWallRef approximates the wall-clock instant the system's
// monotonic clock (CLOCK_MONOTONIC — the basis for the kernel's own
// bpf_ktime_get_ns(), which is what fills last_seen_ns/last_ts_ns in every
// Phase 16/17 map) hit zero, by reading /proc/uptime once at Load. This is
// inherently a best-effort approximation — a few milliseconds of drift is
// possible — which is fine for a "last seen" display and never worth a
// syscall on every single map read. Falls back to time.Now() (zero offset)
// if /proc/uptime can't be read, which just makes bootTimeToWall() less
// precise, never wrong in a way that panics or misleads structurally.
func computeBootWallRef() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now()
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Now()
	}
	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(uptimeSec * float64(time.Second)))
}

// bootTimeToWall converts a bpf_ktime_get_ns()-style timestamp (nanoseconds
// since boot) into a wall-clock time.Time, using the reference captured at
// Load.
func (f *Firewall) bootTimeToWall(monoNs uint64) time.Time {
	return f.bootWallRef.Add(time.Duration(monoNs))
}

// var _ Backend confirms at compile time that the Linux backend satisfies
// the cross-platform Backend interface declared in types.go, the same
// assertion firewall_windows.go and firewall_darwin.go each make for
// their own platform.
var _ Backend = (*Firewall)(nil)
