// This file holds the parts of package firewall that have nothing to do
// with eBPF/XDP specifically: the Reason vocabulary, the user-facing view
// structs (Rule, Stats, Activity, ...), and the Backend interface. Every
// platform-specific implementation (firewall_linux.go's XDP-backed
// Firewall, firewall_windows.go's netsh-backed one, firewall_darwin.go's
// pfctl-backed one) speaks in these same types, so internal/api,
// internal/anomaly, internal/geoip, internal/dnsresolve,
// internal/threatintel, internal/threatshare, and cmd/sxctl don't need to
// know or care which OS the daemon they're talking to is running on.
//
// This file has no build constraint — it compiles on every GOOS.
package firewall

import "time"

// Reason codes — mirror the REASON_* defines in bpf/xdp_sentryx.c exactly
// on Linux. Non-Linux backends reuse the same vocabulary for consistency
// even though most of these are produced by features (anomaly detection,
// DNS/GeoIP blocking, threat sharing) that work identically everywhere;
// a handful (SynFlood, PortKnock, Bandwidth) only ever originate from the
// Linux/XDP data plane and simply never appear in a Rule on other OSes.
type Reason uint8

const (
	ReasonNone        Reason = 0
	ReasonManual      Reason = 1
	ReasonRateLimit   Reason = 2
	ReasonAnomaly     Reason = 3
	ReasonThreatIntel Reason = 4
	ReasonSynFlood    Reason = 5  // Phase 17: SYN-cookie extreme-tier hard drop (Linux/XDP only)
	ReasonPortKnock   Reason = 6  // Phase 18: knock-port noise / unknocked protected port (Linux/XDP only)
	ReasonDNSBlock    Reason = 7  // Phase 19: resolved IP of a blocked domain
	ReasonGeoIP       Reason = 8  // Phase 20: source IP falls in a blocked country's CIDR range
	ReasonShared      Reason = 9  // Phase 23: relayed here by a peer daemon via threat-share, not decided locally
	ReasonBandwidth   Reason = 10 // Phase 25: dropped for exceeding a per-IP QoS byte-rate cap (Linux/XDP only)
)

func (r Reason) String() string {
	switch r {
	case ReasonManual:
		return "manual"
	case ReasonRateLimit:
		return "rate-limit"
	case ReasonAnomaly:
		return "anomaly"
	case ReasonThreatIntel:
		return "threat-intel"
	case ReasonSynFlood:
		return "syn-flood"
	case ReasonPortKnock:
		return "port-knock"
	case ReasonDNSBlock:
		return "dns-block"
	case ReasonGeoIP:
		return "geoip"
	case ReasonShared:
		return "threat-shared"
	case ReasonBandwidth:
		return "bandwidth-limit"
	default:
		return "none"
	}
}

// ConnState values mirror the CONN_STATE_* defines in bpf/xdp_sentryx.c.
// Phase 16 connection tracking is a Linux/XDP-only feature (see the
// package comment on firewall_linux.go) — ConnState and Connection live
// here rather than there only so a non-Linux Backend can still compile
// against the same method signature and honestly report "not tracked"
// (an empty slice) instead of the caller needing a build-tag switch of
// its own.
type ConnState uint8

const (
	ConnStateNone        ConnState = 0
	ConnStateSynSeen     ConnState = 1
	ConnStateEstablished ConnState = 2
	ConnStateClosing     ConnState = 3
)

func (s ConnState) String() string {
	switch s {
	case ConnStateSynSeen:
		return "syn-seen"
	case ConnStateEstablished:
		return "established"
	case ConnStateClosing:
		return "closing"
	default:
		return "none"
	}
}

// Connection is the user-facing view of one tracked flow (Phase 16,
// Linux/XDP only elsewhere this is always an empty list).
type Connection struct {
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	SrcPort  uint16    `json:"src_port"`
	DstPort  uint16    `json:"dst_port"`
	Proto    string    `json:"proto"`
	State    ConnState `json:"state"`
	StateStr string    `json:"state_str"`
	SynCount uint32    `json:"syn_count"`
	LastSeen time.Time `json:"last_seen"`
}

// SynCookieConfig controls the Phase 17 SYN-cookie tiering thresholds.
// Zero values (the default) mean the feature is disabled. Linux/XDP only.
type SynCookieConfig struct {
	LowPPS  uint32 // below this per-source SYN rate: pass through normally
	HighPPS uint32 // at/above this rate: hard drop, no challenge attempted
}

// KnockConfig controls the Phase 18 port-knock sequence. A zero-value
// (empty Sequence) disables the feature. Linux/XDP only.
type KnockConfig struct {
	Sequence      []uint16 // up to 8 ports, in order
	OpenPort      uint16   // the real port this sequence unlocks
	WindowSeconds uint32   // time allowed between knocks / unlock duration base
}

// CaptureSnaplen mirrors CAPTURE_SNAPLEN in bpf/xdp_sentryx.c — the
// maximum number of raw packet bytes captured per event (Phase 22,
// Linux/XDP only). Exported so internal/capture can size its decode
// buffer without duplicating the magic number.
const CaptureSnaplen = 128

// GeoRule is the user-facing view of one blocked CIDR range, enriched with
// the metadata (which country it came from, when it was added) that
// doesn't live in the kernel trie itself.
type GeoRule struct {
	CIDR      string    `json:"cidr"`
	Country   string    `json:"country"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// ArpAlert is a single "this source IP has claimed more than one MAC
// address, faster than a normal DHCP renewal would explain" detection
// (Phase 21, Linux/XDP only — ARP spoofing detection needs raw Ethernet
// frame visibility that only the XDP data plane has).
type ArpAlert struct {
	IP       string    `json:"ip"`
	OldMAC   string    `json:"old_mac"`
	NewMAC   string    `json:"new_mac"`
	LastSeen time.Time `json:"last_seen"`
	Count    uint64    `json:"count"`
}

// Rule is the user-facing view of a blocked address, enriched with metadata
// that doesn't live in the kernel/OS-native rule itself (label, timestamp,
// reason).
type Rule struct {
	IP        string `json:"ip"`
	Label     string `json:"label,omitempty"`
	Reason    Reason `json:"reason"`
	ReasonStr string `json:"reason_str"`
	RateLimit uint32 `json:"rate_limit_pps,omitempty"`
	// BandwidthLimit is Phase 25's QoS byte-rate cap (kbps), independent
	// of and stackable with RateLimit's packet-rate cap. Linux/XDP only —
	// always 0 on other backends.
	BandwidthLimit uint32    `json:"rate_limit_kbps,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Stats is a snapshot of live packet counters. On the Linux/XDP backend
// these come from the kernel at line rate; other backends can't see
// traffic without eBPF, so they report zero — see each backend's Stats
// doc comment for its honest capability.
type Stats struct {
	Allowed      uint64 `json:"allowed"`
	Dropped      uint64 `json:"dropped"`
	BytesAllowed uint64 `json:"bytes_allowed"`
	BytesDropped uint64 `json:"bytes_dropped"`
}

// Activity is a snapshot of a source IP's rolling packet window (Linux/XDP
// only — this is the raw feed the anomaly detector reads; other backends
// report an empty map, which the detector already treats as "nothing to
// baseline yet").
type Activity struct {
	IP         string  `json:"ip"`
	Packets    uint64  `json:"packets"`
	SynPackets uint64  `json:"syn_packets"`
	Bytes      uint64  `json:"bytes"`
	SynRatio   float64 `json:"syn_ratio"`
}

// DropInfo explains the most recent drop recorded for a source IP.
type DropInfo struct {
	IP        string    `json:"ip"`
	Reason    Reason    `json:"reason"`
	ReasonStr string    `json:"reason_str"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
}

// Backend is the surface every platform's Firewall implementation
// provides. It exists mainly as living documentation and a compile-time
// assertion point (each firewall_<os>.go has a `var _ Backend = (*Firewall)(nil)`)
// rather than as a type callers juggle directly — cmd/sentryxd,
// internal/api, and every feature package (anomaly, dnsresolve, geoip,
// threatintel, threatshare, capture) simply import "firewall" and use
// *firewall.Firewall, and the build tag on each firewall_<os>.go file
// ensures exactly one concrete definition of that type exists per
// compiled binary. See Phase 27.2 in SENTRYX_PHASE2_ROADMAP.md: "control
// plane is cross-platform, XDP data-plane acceleration is Linux-native,
// other platforms fall back to OS-native filtering."
type Backend interface {
	Block(ipStr, label string) error
	BlockWithReason(ipStr, label string, reason Reason) error
	Unblock(ipStr string) error
	RateLimit(ipStr string, limitPPS uint32) error
	BandwidthLimit(ipStr string, limitKbps uint32) error
	List() []Rule
	Stats() (Stats, error)
	DropReason(ipStr string) (DropInfo, bool, error)
	ActivitySnapshot() (map[string]Activity, error)
	ActiveConnections() ([]Connection, error)
	SynCookieConfig() (SynCookieConfig, error)
	SetSynCookieConfig(cfg SynCookieConfig) error
	KnockConfig() (KnockConfig, error)
	SetKnockConfig(cfg KnockConfig) error
	BlockCIDR(cidr, country, label string) error
	UnblockCIDR(cidr string) error
	ListGeoBlocks() []GeoRule
	ArpAlerts() ([]ArpAlert, error)
	SetBlockObserver(fn func(ip, label string, reason Reason))
	AddBlockObserver(fn func(ip, label string, reason Reason))
	Interface() string
	AttachedAt() time.Time
	Close() error
}
