// SENTRYX — kernel-space packet filter
//
// Attaches to a network interface's XDP hook and makes a drop/pass decision
// on every incoming packet before the kernel allocates an sk_buff for it.
// Rules and stats live in eBPF maps, shared live with the user-space daemon —
// nothing here ever needs to be recompiled or reloaded to change behaviour.
//
// Beyond the static blocklist + rate limiter, this program also maintains a
// lightweight per-source-IP activity window (packet count, SYN count, byte
// count) so user space can run behavioral anomaly detection without the
// kernel having to know anything about "normal" — that judgment call stays
// in Go, where it's easy to evolve. Every drop, whatever the cause, is
// recorded with a reason code + timestamp so the control plane can answer
// "why was this dropped" without guessing.
//
// Phase 16/17/18 additions (see SENTRYX_PHASE2_ROADMAP.md):
//
//   Phase 16 — lightweight TCP connection tracking (`conn_table`). This
//   hook only ever sees ingress traffic (the client -> server direction),
//   so "ESTABLISHED" here means "we've seen more than a bare SYN from this
//   client on this 5-tuple", not literal 3-way-handshake confirmation —
//   that's enough to tell a real conversation from a bare flood of SYNs,
//   which is exactly what Phase 17 needs downstream.
//
//   Phase 17 — SYN-cookie style source verification. A full TCP-splicing
//   SYN-cookie implementation (where XDP itself completes the handshake on
//   the backend's behalf) would make SENTRYX a TCP-terminating proxy —
//   out of scope for an XDP filter. What's built here is the honest,
//   achievable subset: under load, a challenged source gets our own
//   keyed-hash SYN-ACK instead of a forwarded SYN; only a source that can
//   complete a real TCP round trip earns a "verified" fast-path window.
//   The specific handshake that triggered the challenge is sacrificed (the
//   backend never sees it) — but the client's own TCP stack retries with a
//   fresh SYN, which now hits the verified fast path and gets through.
//   That's a deliberate, documented tradeoff, not a bug — see the comment
//   block above the cookie helpers below for the full explanation.
//
//   Phase 18 — port knocking / stealth mode. A configured sequence of SYNs
//   to decoy ports temporarily unlocks a real protected port for that
//   source IP; anyone else hitting the protected port without knocking
//   first sees it as closed (silently dropped) rather than filtered —
//   that's the "stealth" part.
//
//   Phase 19 — DNS-based blocking. XDP sees IPs, never domain names, so
//   there is deliberately no kernel-side change for this phase at all —
//   internal/dnsresolve resolves configured domains in user space and
//   pushes the resulting addresses into the exact same `blocklist` map
//   this file already maintains, tagged REASON_DNS_BLOCK so `sxctl why`
//   can still tell a DNS-derived block apart from a manual one.
//
//   Phase 20 — GeoIP blocking. A new `geoip_blocklist` LPM-trie map lets
//   the kernel longest-prefix-match a source IP against CIDR ranges for
//   blocked countries, so a whole country's announced ranges are one
//   trie, not thousands of exact-match host entries. internal/geoip
//   populates it from a public per-country CIDR feed.
//
//   Phase 21 — ARP spoofing detection. Layer 2, so this is handled before
//   any IP parsing at all: a small `arp_table` remembers the last MAC
//   claimed for each source IP seen in an ARP packet, and a MAC change
//   that happens faster than a plausible DHCP lease change gets recorded
//   into `arp_alerts` for user space to pick up. Detection only — ARP
//   spoofing has real false positives on legitimate DHCP renewal/failover,
//   so this never drops a packet, it just feeds the same anomaly/why
//   explainability path everything else here already uses.
//
//   Phase 22 — packet capture / pcap export. Opt-in debug mode, off by
//   default (`capture_cfg_map.enabled == 0`). When on, every packet that
//   this program itself drops or flags (blocklist/geoip/syn-flood/
//   rate-limit/port-knock — anomaly-triggered blocks land here too, since
//   an auto-block just adds a `blocklist` entry the very next packet then
//   hits) gets up to CAPTURE_SNAPLEN raw bytes streamed into the
//   `capture_events` ringbuf. Format conversion to an actual .pcap file
//   happens entirely in user space (internal/capture) — the kernel side's
//   only job is "copy some bytes out cheaply", nothing here understands
//   pcap framing at all.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES     65536
#define MAX_ACTIVITY  65536
#define STAT_SLOTS    4

// stats[] indices
#define STAT_ALLOWED       0
#define STAT_DROPPED       1
#define STAT_BYTES_ALLOWED 2
#define STAT_BYTES_DROPPED 3

// Drop reason codes — mirrored in Go as firewall.Reason*. Also doubles as
// the value stored in `blocklist`, so a lookup there tells you both
// "is this IP blocked" and "why" in one map read.
#define REASON_NONE          0
#define REASON_MANUAL        1
#define REASON_RATE_LIMIT    2
#define REASON_ANOMALY       3
#define REASON_THREAT_INTEL  4
#define REASON_SYN_FLOOD     5  // Phase 17: SYN-cookie extreme-tier hard drop
#define REASON_PORT_KNOCK    6  // Phase 18: knock-port noise / unknocked protected port
#define REASON_DNS_BLOCK     7  // Phase 19: resolved IP of a blocked domain
#define REASON_GEOIP         8  // Phase 20: source IP falls in a blocked country's CIDR range
#define REASON_SHARED        9  // Phase 23: enforced here only because a peer daemon relayed it in
#define REASON_BANDWIDTH     10 // Phase 25: dropped for exceeding a per-IP QoS byte-rate cap

// ---- Phase 16: connection state machine -------------------------------
#define CONN_STATE_NONE        0
#define CONN_STATE_SYN_SEEN    1
#define CONN_STATE_ESTABLISHED 2
#define CONN_STATE_CLOSING     3

// ---- Phase 17: SYN-cookie tuning ---------------------------------------
#define SYN_RATE_WINDOW_NS         (1ULL * 1000000000ULL)   // 1s sliding window per src_ip
#define SYN_SECRET_ROTATE_NS       (60ULL * 1000000000ULL)  // rotate the cookie secret every 60s
#define SYN_COOKIE_TIME_QUANTUM_NS (30ULL * 1000000000ULL)  // one cookie "epoch" is 30s
#define SYN_VERIFIED_TTL_NS        (120ULL * 1000000000ULL) // how long a proven-real src_ip skips the challenge

// handle_port_knock() verdicts
#define KNOCK_NOT_APPLICABLE   0 // not a knock port and not the protected port -> normal handling
#define KNOCK_SEQUENCE_HANDLED 1 // packet was itself a knock attempt -> always dropped (stealth)
#define KNOCK_PROTECTED_ALLOW  2 // dest is the protected port and src_ip is currently unlocked
#define KNOCK_PROTECTED_DENY   3 // dest is the protected port but src_ip hasn't knocked -> dropped (stealth)

#define MAX_KNOCK_STEPS 8

// ---- Phase 22: packet capture tuning -------------------------------------
// Capped small deliberately: this is a debug aid for seeing "what did the
// packet that got flagged actually look like" (headers + a little payload),
// not a full-packet capture tool — keeping it small keeps the ringbuf
// cheap even under a real flood with capture left on by mistake.
#define CAPTURE_SNAPLEN 128

// ---- Maps -------------------------------------------------------------

// Blocklist: key = source IPv4 (network byte order), value = reason code
// (non-zero means blocked; the code itself says who/what blocked it).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

// IPv6 blocklist: key = source IPv6 address (16 bytes, network byte order),
// value = reason code, same encoding as the IPv4 `blocklist` above. Kept as
// a separate map (rather than widening the IPv4 key) so the common IPv4
// hot path stays a cheap 4-byte hash lookup — most deployments are still
// overwhelmingly IPv4, and this avoids paying a 128-bit hash cost on every
// packet just to support the IPv6 minority.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct in6_addr);
    __type(value, __u8);
} blocklist_v6 SEC(".maps");

// Per-IP rate limit: key = source IP, value = token bucket state.
struct rate_bucket {
    __u64 tokens;
    __u64 last_refill_ns;
    __u32 limit_pps;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rate_bucket);
} rate_limits SEC(".maps");

// ---- Phase 25: eBPF bandwidth shaping / QoS ------------------------------
//
// A second, independent token bucket per source IP — this one spends
// *bytes* instead of packets, so it caps throughput (kbps) rather than
// packet rate (pps). Deliberately its own map and its own check (see
// bandwidth_exceeded below) rather than folding into rate_bucket: an
// operator may want either cap alone, or both stacked on the same IP (e.g.
// "at most 200pps AND at most 512kbps"), and keeping them separate means
// neither has to know the other exists. Ingress only, same as every other
// enforcement point in this file — see the file header for why egress
// (TC-based) shaping is out of scope here.
struct bandwidth_bucket {
    __u64 tokens_bytes;
    __u64 last_refill_ns;
    __u32 limit_kbps;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct bandwidth_bucket);
} bandwidth_limits SEC(".maps");

// Per-IP behavioral activity window. User space polls this on a timer,
// derives per-IP rates from the deltas, and resets it — the kernel just
// counts, it never decides what's "anomalous".
struct activity {
    __u64 packets;
    __u64 syn_packets;
    __u64 bytes;
    __u64 window_start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, struct activity);
} activity SEC(".maps");

// Per-IP explanation for the most recent drop. Dashboard hover cards and
// `sxctl` read this to answer "why was this dropped".
struct drop_info {
    __u8  reason;
    __u8  _pad[7];
    __u64 last_ts_ns;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, struct drop_info);
} drop_reasons SEC(".maps");

// Global counters, read by the daemon on every stats poll.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// ---- Phase 16: connection tracking --------------------------------------

// 5-tuple key. Field order/sizes are load-bearing: internal/firewall/firewall.go
// mirrors this exactly so a raw map read on the Go side means the same thing
// on both ends (this bit us once before per the project report — see the
// roadmap's "Gotcha" note for Phase 16).
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  _pad[3];
};

struct conn_state {
    __u8  state;
    __u8  _pad[3];
    __u32 syn_count;
    __u64 last_seen_ns;
};

// LRU, not plain HASH: connections age out under memory pressure on their
// own, so nothing needs to reap this from user space at line rate.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} conn_table SEC(".maps");

// ---- Phase 17: SYN-cookie DDoS mitigation --------------------------------
//
// See the file-header comment for the overall design tradeoff. In short:
// low SYN rate for a src_ip -> tracked normally like before. Medium rate
// -> challenged with a keyed-hash SYN-ACK instead of forwarded (this is
// the "SYN cookie": the sequence number itself IS the proof, so no
// per-source state needs to be held while under load). Only a source that
// answers with a matching ACK gets marked `syn_verified` and fast-tracked
// afterward. Extreme rate -> hard drop, same as pre-Phase-17 behavior.

// Global cookie signing config. Populated by sentryxd from policy.yaml
// (`syn_cookie_low_pps` / `syn_cookie_high_pps`). Left unset (all zero) ==
// feature disabled, in which case every SYN takes the exact pre-Phase-17
// path (blocklist -> rate limit -> allow) with zero behavior change.
struct syn_cookie_cfg {
    __u32 low_pps;  // below this: pass through & track normally
    __u32 high_pps; // at/above this: hard drop, no cookie challenge attempted
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_cookie_cfg);
} syn_cookie_cfg_map SEC(".maps");

// Rotating keyed-hash secret. `prev` is kept alongside `cur` so a cookie
// minted just before a rotation still validates just after it — without
// this, every secret rotation would silently fail every in-flight
// challenge, which is worse than not rotating at all.
struct syn_secret {
    __u32 cur;
    __u32 prev;
    __u64 rotated_at_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_secret);
} syn_secret_map SEC(".maps");

// Per-src_ip SYN counter for the current 1s window — the trigger input for
// the tiering decision above. Deliberately separate from the `activity`
// map's syn_packets (that one is cumulative/never reset, meant for the
// anomaly detector's own EWMA baseline; this one needs a hard, resettable
// per-second rate for a real-time in-kernel gating decision).
struct syn_rate_state {
    __u32 count;
    __u64 window_start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, struct syn_rate_state);
} syn_rate SEC(".maps");

// src_ip -> "trusted until" timestamp. A source that has ever completed a
// cookie challenge lands here and skips straight to the normal path for a
// while, instead of being re-challenged on every subsequent connection.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, __u64);
} syn_verified SEC(".maps");

// ---- Phase 18: port knocking / stealth mode ------------------------------

// Global knock sequence config. Populated from policy.yaml's
// `knock_sequence` / `open_port` / `window_seconds`. seq_len == 0 means
// the feature is off — the protected-port check is skipped entirely and
// behavior is unchanged from pre-Phase-18.
struct knock_cfg {
    __u16 sequence[MAX_KNOCK_STEPS];
    __u8  seq_len;
    __u8  _pad;
    __u16 open_port;
    __u32 window_seconds;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knock_cfg);
} knock_cfg_map SEC(".maps");

// Per-src_ip progress through the configured sequence.
struct knock_progress {
    __u8  seq_index;
    __u8  _pad[7];
    __u64 last_knock_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, struct knock_progress);
} knock_state SEC(".maps");

// src_ip -> unlock expiry (ns since boot). Checked before the protected
// port is allowed through to the rest of the pipeline; anyone not present
// (or expired) here gets a silent drop on that port, same as any other
// closed port would look to a scanner.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, __u64);
} knock_unlocked SEC(".maps");

// ---- Phase 20: GeoIP blocking --------------------------------------------
//
// LPM-trie key: prefixlen (bits) + the IP itself, both matching the raw
// network-byte-order encoding ip->saddr already uses elsewhere in this
// file, so a lookup here is directly comparable with the exact-match
// `blocklist` above. internal/geoip populates this from a public
// per-country CIDR feed — one trie entry per announced range for every
// blocked country, instead of expanding each range into individual host
// entries (which is exactly the "option (a)" tradeoff called out in
// SENTRYX_PHASE2_ROADMAP.md's Phase 20).
struct geoip_key {
    __u32 prefixlen;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_RULES);
    __type(key, struct geoip_key);
    __type(value, __u8);
} geoip_blocklist SEC(".maps");

// ---- Phase 21: ARP spoofing detection ------------------------------------
//
// Layer 2, so this runs before any IP parsing — see handle_arp() below.
// Detection only, never enforcement: ARP spoofing detection has real false
// positives on legitimate DHCP renewal/failover, so a MAC change never
// drops a packet here, it only ever gets surfaced through arp_alerts for
// user space to explain via the existing anomaly/why pipeline.

#define ARP_SPOOF_WINDOW_NS (30ULL * 1000000000ULL) // MAC change faster than this looks suspicious, not like a lease change

// Standard Ethernet/IPv4 ARP packet layout (ar_hln == 6, ar_pln == 4).
// Defined by hand (rather than pulling in <linux/if_arp.h>'s variable-width
// struct arphdr) so the fixed-size fields below are trivially bounds-check
// -able for the verifier.
struct arp_eth_ipv4 {
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8  ar_hln;
    __u8  ar_pln;
    __u16 ar_op;
    __u8  ar_sha[6];
    __u32 ar_sip;
    __u8  ar_tha[6];
    __u32 ar_tip;
} __attribute__((packed));

// Last MAC claimed for a given source IP, and when we last saw it.
struct arp_entry {
    __u8  mac[6];
    __u8  _pad[2];
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32); // sender IP from the ARP payload
    __type(value, struct arp_entry);
} arp_table SEC(".maps");

// One outstanding "possible spoof" explanation per source IP — old MAC vs
// new MAC, when, and how many times it's happened. `sxctl arp` / the
// anomaly detector read and explain this; it is never consulted by the
// drop path itself.
struct arp_alert {
    __u8  old_mac[6];
    __u8  new_mac[6];
    __u64 ts_ns;
    __u32 count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ACTIVITY);
    __type(key, __u32);
    __type(value, struct arp_alert);
} arp_alerts SEC(".maps");

// ---- Phase 22: packet capture / pcap export ------------------------------
//
// One event per captured packet: enough metadata for internal/capture to
// write a standards-compliant pcap record (timestamp + captured length +
// original wire length), plus up to CAPTURE_SNAPLEN raw bytes starting at
// the Ethernet header — a real .pcap file, openable in Wireshark/tcpdump,
// not a bespoke format.
struct capture_event {
    __u64 ts_ns;         // bpf_ktime_get_ns() at capture time (CLOCK_MONOTONIC, since boot)
    __u32 pkt_len;        // original wire length — may exceed captured_len
    __u32 captured_len;   // how many bytes of `data` are actually valid
    __u32 src_ip;
    __u8  reason;          // REASON_* — why this packet was captured
    __u8  _pad[3];
    __u8  data[CAPTURE_SNAPLEN];
};

// Sized for a burst of flagged traffic during a real attack without
// blocking the packet-processing path — bpf_ringbuf_reserve() just returns
// NULL (silently skipping that one sample) if this fills up faster than
// user space drains it, which is the correct failure mode for a debug
// feature: never let capture back-pressure the drop/pass decision itself.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} capture_events SEC(".maps");

// Global on/off switch, written by sentryxd via `sxctl capture start/stop`.
// No entry / enabled == 0 means "off", which is the default and matches
// pre-Phase-22 behavior exactly (zero extra work on the hot path beyond
// one array lookup per would-be-captured packet).
struct capture_cfg {
    __u8 enabled;
    __u8 _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_cfg);
} capture_cfg_map SEC(".maps");

// ---- Helpers ------------------------------------------------------------

static __always_inline void bump(__u32 idx, __u64 amount) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, amount);
}

// Very small token-bucket check. Returns 1 if the packet should be dropped
// for exceeding its configured rate, 0 otherwise. Buckets without an entry
// are treated as unlimited.
static __always_inline int rate_exceeded(__u32 src_ip) {
    struct rate_bucket *b = bpf_map_lookup_elem(&rate_limits, &src_ip);
    if (!b)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - b->last_refill_ns;
    __u64 refill = (elapsed_ns * b->limit_pps) / 1000000000ULL;

    if (refill > 0) {
        b->tokens += refill;
        if (b->tokens > b->limit_pps)
            b->tokens = b->limit_pps;
        b->last_refill_ns = now;
    }

    if (b->tokens == 0)
        return 1;

    b->tokens -= 1;
    return 0;
}

// Phase 25's byte-rate token-bucket check, structurally identical to
// rate_exceeded() above but refilling/spending bytes instead of a flat 1
// token per packet. Returns 1 if pkt_len would overdraw the bucket (packet
// should be dropped), 0 otherwise. IPs without a bandwidth_limits entry
// are unlimited, exactly like rate_exceeded's untracked-IP behavior.
static __always_inline int bandwidth_exceeded(__u32 src_ip, __u64 pkt_len) {
    struct bandwidth_bucket *b = bpf_map_lookup_elem(&bandwidth_limits, &src_ip);
    if (!b)
        return 0;

    // kbps -> bytes/sec: 1 kbps = 1000 bits/sec = 125 bytes/sec.
    __u64 bytes_per_sec = ((__u64)b->limit_kbps * 1000) / 8;
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - b->last_refill_ns;
    __u64 refill = (elapsed_ns * bytes_per_sec) / 1000000000ULL;

    if (refill > 0) {
        b->tokens_bytes += refill;
        if (b->tokens_bytes > bytes_per_sec)
            b->tokens_bytes = bytes_per_sec; // cap burst to 1 second worth of bytes
        b->last_refill_ns = now;
    }

    if (pkt_len > b->tokens_bytes)
        return 1;

    b->tokens_bytes -= pkt_len;
    return 0;
}

// Records/updates the drop explanation for src_ip. Best-effort: a lost race
// on first-insert just means one dropped sample, not a correctness issue.
static __always_inline void record_drop(__u32 src_ip, __u8 reason) {
    __u64 now = bpf_ktime_get_ns();
    struct drop_info *di = bpf_map_lookup_elem(&drop_reasons, &src_ip);
    if (di) {
        di->reason = reason;
        di->last_ts_ns = now;
        __sync_fetch_and_add(&di->count, 1);
        return;
    }
    struct drop_info init = { .reason = reason, .last_ts_ns = now, .count = 1 };
    bpf_map_update_elem(&drop_reasons, &src_ip, &init, BPF_NOEXIST);
}

// Phase 22 — streams up to CAPTURE_SNAPLEN raw bytes of a flagged/dropped
// packet into capture_events for internal/capture to turn into a real
// .pcap file. Only ever called from the drop/challenge paths below, and
// only actually does anything while capture is turned on — see the
// capture_cfg_map doc comment above. Skipped (not just a no-op check, an
// early return before touching the ringbuf at all) when capture is off, so
// this costs exactly one array lookup on the hot path in the common case.
static __always_inline void capture_packet(struct xdp_md *ctx, __u32 src_ip, __u8 reason) {
    __u32 zero = 0;
    struct capture_cfg *cc = bpf_map_lookup_elem(&capture_cfg_map, &zero);
    if (!cc || !cc->enabled)
        return;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = data_end - data;

    struct capture_event *ev = bpf_ringbuf_reserve(&capture_events, sizeof(*ev), 0);
    if (!ev)
        return; // ring buffer momentarily full — drop this one sample, never the packet itself

    ev->ts_ns  = bpf_ktime_get_ns();
    ev->pkt_len = pkt_len;
    ev->src_ip = src_ip;
    ev->reason = reason;

    // Fixed-trip-count, per-byte bounds-checked copy — the verifier needs
    // a statically provable bound on every iteration, so this can't be a
    // variable-length memcpy(min(pkt_len, SNAPLEN)) even though that's
    // conceptually what's happening.
    __u32 n = 0;
    #pragma unroll
    for (__u32 i = 0; i < CAPTURE_SNAPLEN; i++) {
        if (data + i + 1 > data_end)
            break;
        ev->data[i] = ((__u8 *)data)[i];
        n = i + 1;
    }
    ev->captured_len = n;

    bpf_ringbuf_submit(ev, 0);
}

// Updates the rolling per-IP activity window. Called for every packet that
// reaches IP-layer parsing, blocked or not, so the anomaly detector can see
// an attack ramping up even before any rule exists for that IP.
static __always_inline void track_activity(__u32 src_ip, __u64 pkt_len, int is_syn) {
    struct activity *act = bpf_map_lookup_elem(&activity, &src_ip);
    if (act) {
        __sync_fetch_and_add(&act->packets, 1);
        __sync_fetch_and_add(&act->bytes, pkt_len);
        if (is_syn)
            __sync_fetch_and_add(&act->syn_packets, 1);
        return;
    }
    struct activity init = {
        .packets = 1,
        .syn_packets = is_syn ? 1 : 0,
        .bytes = pkt_len,
        .window_start_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&activity, &src_ip, &init, BPF_NOEXIST);
}

// ---- Phase 16 helper: connection tracking --------------------------------

// Applies one packet's worth of state transition to conn_table. Kept
// intentionally small: SYN with no entry -> SYN_SEEN; any non-SYN packet
// on a SYN_SEEN flow -> ESTABLISHED (the closest signal this ingress-only
// hook has to "handshake completed" — see file header); FIN/RST -> CLOSING.
// LRU eviction handles cleanup of stale CLOSING/idle entries, so there's no
// explicit delete path here.
static __always_inline void conn_track(struct conn_key *key, int is_syn, int is_ack, int is_rst, int is_fin, __u64 now) {
    struct conn_state *cs = bpf_map_lookup_elem(&conn_table, key);
    if (cs) {
        if (is_rst || is_fin) {
            cs->state = CONN_STATE_CLOSING;
        } else if (cs->state == CONN_STATE_SYN_SEEN && !is_syn) {
            cs->state = CONN_STATE_ESTABLISHED;
        }
        cs->last_seen_ns = now;
        return;
    }
    if (is_syn && !is_ack) {
        struct conn_state init = {
            .state = CONN_STATE_SYN_SEEN,
            .syn_count = 1,
            .last_seen_ns = now,
        };
        bpf_map_update_elem(&conn_table, key, &init, BPF_NOEXIST);
    }
}

// ---- Phase 17 helpers: SYN-cookie DDoS mitigation ------------------------

// Small, fast, keyed integer mixer (Murmur3-fmix-style finalizer). This is
// not a cryptographic hash — it doesn't need to be. Its only job is to make
// the cookie unpredictable to someone without the rotating secret, exactly
// the same trust model the kernel's own net.ipv4.tcp_syncookies uses.
static __always_inline __u32 mix32(__u32 h) {
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

static __always_inline __u32 syn_cookie_hash(__u32 src_ip, __u32 dst_ip, __u16 sport, __u16 dport, __u32 secret, __u8 time_idx) {
    __u32 h = secret;
    h = mix32(h ^ src_ip);
    h = mix32(h ^ dst_ip);
    h = mix32(h ^ (((__u32)sport << 16) | dport));
    h = mix32(h ^ time_idx);
    return h;
}

// Returns the current signing secret, rotating it (best-effort, racy under
// concurrency but harmless — see record_drop's comment for the same
// reasoning applied here) once SYN_SECRET_ROTATE_NS has elapsed.
static __always_inline __u32 cookie_secret(__u64 now) {
    __u32 zero = 0;
    struct syn_secret *s = bpf_map_lookup_elem(&syn_secret_map, &zero);
    if (!s)
        return 0;
    if (now - s->rotated_at_ns > SYN_SECRET_ROTATE_NS) {
        s->prev = s->cur;
        s->cur = bpf_get_prandom_u32();
        s->rotated_at_ns = now;
    }
    return s->cur;
}

// Encodes a 3-bit time epoch into the low bits of the cookie so a stale
// (replayed) ACK outside the tolerance window in syn_cookie_valid() gets
// rejected even if it somehow had the right hash bits.
static __always_inline __u32 make_syn_cookie(__u32 src_ip, __u32 dst_ip, __u16 sport, __u16 dport, __u32 secret, __u64 now) {
    __u8 idx = (__u8)((now / SYN_COOKIE_TIME_QUANTUM_NS) & 0x7);
    __u32 h = syn_cookie_hash(src_ip, dst_ip, sport, dport, secret, idx);
    return (h & 0xFFFFFFF8u) | idx;
}

static __always_inline int syn_cookie_valid(__u32 src_ip, __u32 dst_ip, __u16 sport, __u16 dport, __u32 cookie, __u32 secret, __u64 now) {
    __u8 idx = cookie & 0x7;
    __u8 cur_idx = (__u8)((now / SYN_COOKIE_TIME_QUANTUM_NS) & 0x7);
    __u8 diff = (cur_idx - idx) & 0x7;
    if (diff > 1) // only accept the current epoch or the one right before it
        return 0;
    __u32 h = syn_cookie_hash(src_ip, dst_ip, sport, dport, secret, idx);
    return ((h & 0xFFFFFFF8u) | idx) == cookie;
}

// Bumps and returns this src_ip's SYN count for the current 1s window.
static __always_inline __u32 syn_rate_bump(__u32 src_ip, __u64 now) {
    struct syn_rate_state *st = bpf_map_lookup_elem(&syn_rate, &src_ip);
    if (st) {
        if (now - st->window_start_ns > SYN_RATE_WINDOW_NS) {
            st->window_start_ns = now;
            st->count = 1;
        } else {
            __sync_fetch_and_add(&st->count, 1);
        }
        return st->count;
    }
    struct syn_rate_state init = { .count = 1, .window_start_ns = now };
    bpf_map_update_elem(&syn_rate, &src_ip, &init, BPF_NOEXIST);
    return 1;
}

// checksum helpers ---------------------------------------------------------

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *buf = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < 10; i++) // sizeof(struct iphdr) == 20 bytes, no options on our reply
        csum += buf[i];
    return csum_fold(csum);
}

static __always_inline __u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    __u32 csum = 0;
    csum += (ip->saddr >> 16) & 0xffff;
    csum += ip->saddr & 0xffff;
    csum += (ip->daddr >> 16) & 0xffff;
    csum += ip->daddr & 0xffff;
    csum += bpf_htons(IPPROTO_TCP);
    csum += bpf_htons(sizeof(struct tcphdr));

    __u16 *buf = (__u16 *)tcp;
    #pragma unroll
    for (int i = 0; i < 10; i++) // sizeof(struct tcphdr) == 20 bytes, no options on our reply
        csum += buf[i];
    return csum_fold(csum);
}

// Rewrites the just-parsed SYN in place into our SYN-ACK cookie challenge
// (swap L2/L3/L4 addressing, strip any TCP options down to a bare 20-byte
// header, set the cookie as our ISN) and bounces it straight back out the
// same interface with XDP_TX. Returns 0 on success, -1 if the packet
// couldn't be safely resized (caller should fail closed and drop).
static __always_inline int craft_syn_ack(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, void *data_end, __u32 cookie, __u32 client_seq) {
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->ihl = 5; // our reply carries no IP options, regardless of the request
    ip->ttl = 64;
    ip->tot_len = bpf_htons(sizeof(*ip) + sizeof(*tcp));
    ip->check = 0;

    __u16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;
    tcp->seq = bpf_htonl(cookie);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->doff = 5; // no TCP options on our reply either
    tcp->res1 = 0;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;
    tcp->window = bpf_htons(64240);
    tcp->urg_ptr = 0;
    tcp->check = 0;

    ip->check = ip_checksum(ip);
    tcp->check = tcp_checksum(ip, tcp);

    long cur_len = data_end - (void *)eth;
    long new_len = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
    if (new_len < cur_len) {
        if (bpf_xdp_adjust_tail(ctx, (int)(new_len - cur_len)))
            return -1;
    }
    return 0;
}

// ---- Phase 18 helper: port knocking / stealth mode -----------------------

// Evaluates one TCP packet against the configured knock sequence / protected
// port. Never touches packet contents — pure map bookkeeping — so it's safe
// to call before we've committed to any particular handling of the packet.
static __always_inline int handle_port_knock(__u32 src_ip, __u16 dst_port_h, int is_syn, __u64 now) {
    __u32 zero = 0;
    struct knock_cfg *cfg = bpf_map_lookup_elem(&knock_cfg_map, &zero);
    if (!cfg || cfg->seq_len == 0)
        return KNOCK_NOT_APPLICABLE; // feature not configured: no behavior change

    if (cfg->open_port != 0 && dst_port_h == cfg->open_port) {
        __u64 *unlocked_until = bpf_map_lookup_elem(&knock_unlocked, &src_ip);
        if (unlocked_until && *unlocked_until > now)
            return KNOCK_PROTECTED_ALLOW;
        return KNOCK_PROTECTED_DENY;
    }

    if (!is_syn)
        return KNOCK_NOT_APPLICABLE; // only SYNs count as knock attempts

    __u8 matched_step = 0xFF;
    #pragma unroll
    for (int i = 0; i < MAX_KNOCK_STEPS; i++) {
        if (i < cfg->seq_len && cfg->sequence[i] == dst_port_h)
            matched_step = (__u8)i;
    }
    if (matched_step == 0xFF)
        return KNOCK_NOT_APPLICABLE; // not part of the configured dance at all

    __u64 window_ns = (__u64)cfg->window_seconds * 1000000000ULL;
    if (window_ns == 0)
        window_ns = 10ULL * 1000000000ULL;

    struct knock_progress *kp = bpf_map_lookup_elem(&knock_state, &src_ip);
    __u8 expect = 0;
    if (kp && (now - kp->last_knock_ns) <= window_ns)
        expect = kp->seq_index;

    if (matched_step == expect) {
        __u8 next = expect + 1;
        if (next >= cfg->seq_len) {
            __u64 expiry = now + window_ns * 3; // unlock outlives a few knock-windows
            bpf_map_update_elem(&knock_unlocked, &src_ip, &expiry, BPF_ANY);
            next = 0;
        }
        struct knock_progress upd = { .seq_index = next, .last_knock_ns = now };
        bpf_map_update_elem(&knock_state, &src_ip, &upd, BPF_ANY);
    } else {
        // Wrong step: treat a step-0 hit as a fresh restart, anything else
        // resets progress to zero.
        struct knock_progress upd = { .seq_index = (matched_step == 0) ? 1 : 0, .last_knock_ns = now };
        bpf_map_update_elem(&knock_state, &src_ip, &upd, BPF_ANY);
    }

    return KNOCK_SEQUENCE_HANDLED; // knock ports themselves are never reachable
}

// ---- Phase 21 helper: ARP spoofing detection -----------------------------
//
// Called for every ARP packet, before any IP-layer parsing exists. Updates
// arp_table with whatever MAC this source IP is currently claiming, and if
// that's a *change* from what we saw last, and it happened suspiciously
// fast, records an explanation into arp_alerts. Never returns a verdict —
// callers always XDP_PASS an ARP packet, this is observation only.
static __always_inline void handle_arp(struct ethhdr *eth, void *data_end) {
    struct arp_eth_ipv4 *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return;

    // Only standard Ethernet/IPv4 ARP is something we can safely interpret
    // with this fixed-size struct — anything else (rare in practice) is
    // left alone rather than risk misreading the payload.
    if (arp->ar_hrd != bpf_htons(1) || arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hln != 6 || arp->ar_pln != 4)
        return;

    __u32 sip = arp->ar_sip;
    __u64 now = bpf_ktime_get_ns();

    struct arp_entry *e = bpf_map_lookup_elem(&arp_table, &sip);
    if (!e) {
        struct arp_entry init = { .last_seen_ns = now };
        __builtin_memcpy(init.mac, arp->ar_sha, 6);
        bpf_map_update_elem(&arp_table, &sip, &init, BPF_NOEXIST);
        return;
    }

    int changed = 0;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (e->mac[i] != arp->ar_sha[i]) {
            changed = 1;
            break;
        }
    }

    if (changed) {
        __u64 elapsed = now - e->last_seen_ns;
        if (elapsed < ARP_SPOOF_WINDOW_NS) {
            struct arp_alert *existing = bpf_map_lookup_elem(&arp_alerts, &sip);
            if (existing) {
                __builtin_memcpy(existing->old_mac, e->mac, 6);
                __builtin_memcpy(existing->new_mac, arp->ar_sha, 6);
                existing->ts_ns = now;
                __sync_fetch_and_add(&existing->count, 1);
            } else {
                struct arp_alert alert = { .ts_ns = now, .count = 1 };
                __builtin_memcpy(alert.old_mac, e->mac, 6);
                __builtin_memcpy(alert.new_mac, arp->ar_sha, 6);
                bpf_map_update_elem(&arp_alerts, &sip, &alert, BPF_NOEXIST);
            }
        }
        __builtin_memcpy(e->mac, arp->ar_sha, 6);
    }
    e->last_seen_ns = now;
}

// ---- Entry point ----------------------------------------------------------

SEC("xdp")
int xdp_sentryx(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 pkt_len  = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Phase 21 — ARP spoofing detection. Layer 2, so this happens before
    // any IP parsing at all. Always XDP_PASS afterward: detection only,
    // see the file-header comment for why this never drops.
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        handle_arp(eth, data_end);
        return XDP_PASS;
    }

    // IPv6: checked against its own blocklist map. This path intentionally
    // doesn't feed the (IPv4-only) rate limiter or activity/anomaly window
    // yet — see the project report's "Future Scope" for extending those to
    // dual-stack; a matched blocklist entry still drops at full XDP speed.
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        __u8 *reason6 = bpf_map_lookup_elem(&blocklist_v6, &ip6->saddr);
        if (reason6 && *reason6 != REASON_NONE) {
            bump(STAT_DROPPED, 1);
            bump(STAT_BYTES_DROPPED, pkt_len);
            return XDP_DROP;
        }
        bump(STAT_ALLOWED, 1);
        bump(STAT_BYTES_ALLOWED, pkt_len);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // not IPv4 or IPv6 (ARP etc.) — pass through untouched

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Bounds-checked TCP header lookup, reused by activity tracking below
    // and by every Phase 16/17/18 feature further down — computed once so
    // every consumer agrees on the same (options-aware) offset.
    struct tcphdr *tcp = NULL;
    int tcp_ok = 0;
    int is_syn = 0, is_ack = 0, is_rst = 0, is_fin = 0;
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            tcp_ok = 1;
            is_syn = tcp->syn && !tcp->ack;
            is_ack = tcp->ack;
            is_rst = tcp->rst;
            is_fin = tcp->fin;
        }
    }
    track_activity(src_ip, pkt_len, is_syn);

    // 1. Static blocklist check (manual / anomaly / threat-intel / DNS —
    //    the stored value tells us which). Cheapest check, stays first.
    __u8 *reason = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (reason && *reason != REASON_NONE) {
        bump(STAT_DROPPED, 1);
        bump(STAT_BYTES_DROPPED, pkt_len);
        record_drop(src_ip, *reason);
        capture_packet(ctx, src_ip, *reason);
        return XDP_DROP;
    }

    // 1b. Phase 20 — GeoIP CIDR blocklist, longest-prefix match. Kept right
    //     after the exact-match blocklist since it's still a single map
    //     lookup and still cheaper than anything stateful below.
    struct geoip_key gk = { .prefixlen = 32, .ip = src_ip };
    __u8 *greason = bpf_map_lookup_elem(&geoip_blocklist, &gk);
    if (greason && *greason != REASON_NONE) {
        bump(STAT_DROPPED, 1);
        bump(STAT_BYTES_DROPPED, pkt_len);
        record_drop(src_ip, *greason);
        capture_packet(ctx, src_ip, *greason);
        return XDP_DROP;
    }

    // 2. Phase 16/17/18 — connection tracking, SYN-cookie tiering, and
    //    port knocking, all gated on this being a bounds-checked TCP
    //    packet. Every one of these features is opt-in via policy.yaml
    //    (unset config == the corresponding map lookup returns nothing or
    //    a zeroed struct == exactly pre-Phase-16 behavior).
    if (tcp_ok) {
        __u16 dst_port_h = bpf_ntohs(tcp->dest);
        __u64 now = bpf_ktime_get_ns();

        // 2a. Port knocking gate (Phase 18) — cheap scalar-only check,
        //     runs before we spend cycles on conn tracking / cookies.
        int knock_verdict = handle_port_knock(src_ip, dst_port_h, is_syn, now);
        if (knock_verdict == KNOCK_SEQUENCE_HANDLED || knock_verdict == KNOCK_PROTECTED_DENY) {
            bump(STAT_DROPPED, 1);
            bump(STAT_BYTES_DROPPED, pkt_len);
            record_drop(src_ip, REASON_PORT_KNOCK);
            capture_packet(ctx, src_ip, REASON_PORT_KNOCK);
            return XDP_DROP;
        }
        // KNOCK_NOT_APPLICABLE / KNOCK_PROTECTED_ALLOW: fall through.

        struct conn_key ck = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
            .proto = ip->protocol,
        };
        struct conn_state *cs = bpf_map_lookup_elem(&conn_table, &ck);

        if (cs) {
            // Known flow: just update state/liveness, no cookie logic —
            // cookies only ever gate the *first* SYN of a new flow.
            if (is_rst || is_fin) {
                cs->state = CONN_STATE_CLOSING;
            } else if (cs->state == CONN_STATE_SYN_SEEN && !is_syn) {
                cs->state = CONN_STATE_ESTABLISHED;
            }
            cs->last_seen_ns = now;
        } else if (is_syn && !is_ack) {
            // Brand-new connection attempt — Phase 17 tiering decides.
            __u64 *verified_until = bpf_map_lookup_elem(&syn_verified, &src_ip);
            int trusted = verified_until && *verified_until > now;

            __u32 zero = 0;
            struct syn_cookie_cfg *cc = bpf_map_lookup_elem(&syn_cookie_cfg_map, &zero);
            __u32 low = cc ? cc->low_pps : 0;
            __u32 high = cc ? cc->high_pps : 0;
            int cookie_enabled = (low > 0 || high > 0);

            if (trusted || !cookie_enabled) {
                conn_track(&ck, is_syn, is_ack, is_rst, is_fin, now);
            } else {
                __u32 rate = syn_rate_bump(src_ip, now);
                if (rate < low) {
                    conn_track(&ck, is_syn, is_ack, is_rst, is_fin, now);
                } else if (rate < high) {
                    // Challenge tier: absorb via SYN cookie, don't create a
                    // conn_table entry yet (that's the whole point — no
                    // state held for an unproven source).
                    __u32 secret = cookie_secret(now);
                    __u32 client_seq = bpf_ntohl(tcp->seq);
                    __u32 cookie = make_syn_cookie(ip->saddr, ip->daddr, tcp->source, tcp->dest, secret, now);
                    if (craft_syn_ack(ctx, eth, ip, tcp, data_end, cookie, client_seq) == 0) {
                        bump(STAT_ALLOWED, 1); // handled, not silently dropped
                        return XDP_TX;
                    }
                    bump(STAT_DROPPED, 1);
                    bump(STAT_BYTES_DROPPED, pkt_len);
                    record_drop(src_ip, REASON_SYN_FLOOD);
                    capture_packet(ctx, src_ip, REASON_SYN_FLOOD);
                    return XDP_DROP;
                } else {
                    // Extreme tier: fall back to a hard drop, same as
                    // pre-Phase-17 behavior for an unconfigured source.
                    bump(STAT_DROPPED, 1);
                    bump(STAT_BYTES_DROPPED, pkt_len);
                    record_drop(src_ip, REASON_SYN_FLOOD);
                    capture_packet(ctx, src_ip, REASON_SYN_FLOOD);
                    return XDP_DROP;
                }
            }
        } else if (is_ack && !is_syn && !is_rst) {
            // No known flow, but this could be the answer to an earlier
            // cookie challenge — validate before treating it as noise.
            __u32 zero = 0;
            struct syn_cookie_cfg *cc = bpf_map_lookup_elem(&syn_cookie_cfg_map, &zero);
            if (cc && (cc->low_pps || cc->high_pps)) {
                struct syn_secret *s = bpf_map_lookup_elem(&syn_secret_map, &zero);
                if (s) {
                    __u32 claimed = bpf_ntohl(tcp->ack_seq) - 1;
                    int valid = syn_cookie_valid(ip->saddr, ip->daddr, tcp->source, tcp->dest, claimed, s->cur, now)
                             || syn_cookie_valid(ip->saddr, ip->daddr, tcp->source, tcp->dest, claimed, s->prev, now);
                    if (valid) {
                        __u64 verified_until = now + SYN_VERIFIED_TTL_NS;
                        bpf_map_update_elem(&syn_verified, &src_ip, &verified_until, BPF_ANY);
                    }
                }
            }
            // Either way this specific bare ACK has nowhere real to go —
            // the backend never saw the original SYN. See the file-header
            // comment for why that's an accepted tradeoff. The *next* SYN
            // from a now-verified source sails through the fast path.
            bump(STAT_DROPPED, 1);
            bump(STAT_BYTES_DROPPED, pkt_len);
            return XDP_DROP;
        }
        // else: stray RST / retransmit of something we already handled /
        // random noise for an unknown flow — fall through to the normal
        // rate-limit/allow path below, same as pre-Phase-16 behavior.
    }

    // 3. Per-IP rate limit check
    if (rate_exceeded(src_ip)) {
        bump(STAT_DROPPED, 1);
        bump(STAT_BYTES_DROPPED, pkt_len);
        record_drop(src_ip, REASON_RATE_LIMIT);
        capture_packet(ctx, src_ip, REASON_RATE_LIMIT);
        return XDP_DROP;
    }

    // 4. Per-IP bandwidth (QoS) check — Phase 25. Independent of and
    // checked after the packet-rate cap above: a source can be well under
    // its pps budget and still be throttled here for exceeding its kbps
    // budget (e.g. fewer, larger packets).
    if (bandwidth_exceeded(src_ip, pkt_len)) {
        bump(STAT_DROPPED, 1);
        bump(STAT_BYTES_DROPPED, pkt_len);
        record_drop(src_ip, REASON_BANDWIDTH);
        capture_packet(ctx, src_ip, REASON_BANDWIDTH);
        return XDP_DROP;
    }

    bump(STAT_ALLOWED, 1);
    bump(STAT_BYTES_ALLOWED, pkt_len);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
