// Package policy implements SENTRYX's policy-as-code layer: a small,
// versioned YAML file that describes what should be blocked (and, as of
// Phase 17/18, how SYN-cookie mitigation and port knocking should be
// configured), so all of that can live in git instead of only existing as
// ad-hoc CLI calls.
//
// A policy.yaml is applied in two places:
//   - by sentryxd itself on boot (-policy policy.yaml), on top of
//     whatever was already restored from the local rule store
//   - by `sxctl policy apply <path>` against a *running* daemon, over the
//     REST API, without a restart
//
// Both paths go through Apply, so the semantics are identical either way.
//
// The parser here handles exactly the fixed shape documented in Example —
// a top-level `version`, a `block` list of {ip, label, rate_limit_pps}, an
// optional `syn_cookie` block of {low_pps, high_pps}, and an optional
// `knock` block of {sequence, open_port, window_seconds} — on purpose,
// rather than pulling in a general-purpose YAML library as a dependency
// for a firewall's rule file. If your policy.yaml needs more than this,
// that's a sign it belongs in Go, not YAML.
package policy

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// Rule is a single blocklist entry as written in policy.yaml.
type Rule struct {
	IP        string `yaml:"ip"`
	Label     string `yaml:"label"`
	RateLimit uint32 `yaml:"rate_limit_pps"`
	// BandwidthLimit is Phase 25's QoS byte-rate cap, independent of and
	// stackable with RateLimit's packet-rate cap.
	BandwidthLimit uint32 `yaml:"rate_limit_kbps"`
}

// SynCookiePolicy is the Phase 17 `syn_cookie:` section. A nil
// *SynCookiePolicy on Policy (the section is simply absent from the file)
// means "disabled" — Apply treats that identically to an explicit
// {low_pps: 0, high_pps: 0}.
type SynCookiePolicy struct {
	LowPPS  uint32 `yaml:"low_pps"`
	HighPPS uint32 `yaml:"high_pps"`
}

// KnockPolicy is the Phase 18 `knock:` section. A nil *KnockPolicy, or one
// with an empty Sequence, means "disabled" — every protected port behaves
// exactly as it did before Phase 18.
type KnockPolicy struct {
	Sequence      []uint16 `yaml:"sequence"`
	OpenPort      uint16   `yaml:"open_port"`
	WindowSeconds uint32   `yaml:"window_seconds"`
}

// DNSPolicy is the Phase 19 `dns:` section. A nil *DNSPolicy, or one with
// an empty BlockedDomains, means "disabled" — internal/dnsresolve simply
// isn't started. RefreshMinutes of 0 falls back to dnsresolve's own
// default (5 minutes).
type DNSPolicy struct {
	BlockedDomains []string `yaml:"blocked_domains"`
	RefreshMinutes uint32   `yaml:"refresh_minutes"`
}

// GeoIPPolicy is the Phase 20 `geoip:` section. A nil *GeoIPPolicy, or one
// with an empty BlockedCountries, means "disabled". RefreshHours of 0
// falls back to internal/geoip's own default (24 hours) — country-level
// allocations change slowly, so this never needs to be minutes.
type GeoIPPolicy struct {
	BlockedCountries []string `yaml:"blocked_countries"`
	RefreshHours     uint32   `yaml:"refresh_hours"`
}

// Policy is the top-level shape of a policy.yaml file.
type Policy struct {
	Version   int              `yaml:"version"`
	Block     []Rule           `yaml:"block"`
	SynCookie *SynCookiePolicy `yaml:"syn_cookie"`
	Knock     *KnockPolicy     `yaml:"knock"`
	DNS       *DNSPolicy       `yaml:"dns"`
	GeoIP     *GeoIPPolicy     `yaml:"geoip"`
}

// Example is written out by `sxctl policy init` as a starting point.
const Example = `# SENTRYX policy-as-code
#
# Commit this file. Apply it with:
#   sentryxd -policy policy.yaml         (on daemon boot)
#   sxctl policy apply policy.yaml        (push to a running daemon now)
version: 1

block:
  - ip: 203.0.113.9
    label: "known scanner"
    rate_limit_pps: 0

  - ip: 198.51.100.23
    label: "noisy bot, rate-limited instead of hard-blocked"
    rate_limit_pps: 20
    rate_limit_kbps: 512   # Phase 25 — also cap this source to 512kbps (QoS),
                           # independent of and stackable with rate_limit_pps

# Phase 17 — SYN-cookie DDoS mitigation. Omit this whole section (or leave
# both fields at 0) to disable it: every SYN then takes the plain
# blocklist -> rate-limit -> allow path with no cookie challenge at all.
#
#   below low_pps     -> passed through and tracked normally
#   low_pps..high_pps  -> challenged with a SYN-cookie instead of forwarded
#   at/above high_pps  -> hard-dropped (no cookie challenge attempted)
syn_cookie:
  low_pps: 200
  high_pps: 2000

# Phase 18 — port knocking / stealth mode. Omit this whole section (or
# leave sequence empty) to disable it. A source must hit every port in
# "sequence", in order, within "window_seconds" of each step, to unlock
# "open_port" for itself for a short while afterward. Anyone else hitting
# open_port without knocking first sees it as silently closed.
knock:
  sequence: [7000, 8000, 9000]
  open_port: 22
  window_seconds: 10

# Phase 19 — DNS-based blocking. Omit this whole section (or leave
# blocked_domains empty) to disable it. Domains are re-resolved on a
# timer and their current IPs are pushed into the same blocklist every
# other feature here uses — this blocks resolved IPs, not domains
# themselves, see internal/dnsresolve's header comment for the honest
# limitations (DoH/DoT, IP-rotating CDNs) that come with that tradeoff.
dns:
  blocked_domains: ["example-malicious-domain.test"]
  refresh_minutes: 5

# Phase 20 — GeoIP blocking. Omit this whole section (or leave
# blocked_countries empty) to disable it. Countries are ISO 3166-1
# alpha-2 codes; ranges refresh far less often than DNS since country-
# level allocations change on the order of months, not minutes.
geoip:
  blocked_countries: []
  refresh_hours: 24
`

// Load reads and validates a policy.yaml file at path.
//
// Only the fixed shape documented in Example is understood: a top-level
// `version:`, a `block:` list of {ip, label, rate_limit_pps} entries, an
// optional `syn_cookie:` block of {low_pps, high_pps}, and an optional
// `knock:` block of {sequence, open_port, window_seconds}. That's a
// deliberately small subset of YAML (2-space list indent, one key per
// line, `[a, b, c]` inline lists for `sequence` only, no flow-style maps,
// no anchors) — enough to keep a policy readable and diffable in git
// without a general YAML parser dependency.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	defer f.Close()

	pol := &Policy{Version: 1}

	type section int
	const (
		sectionNone section = iota
		sectionBlock
		sectionSynCookie
		sectionKnock
		sectionDNS
		sectionGeoIP
	)

	sect := sectionNone
	var curRule *Rule
	var curSynCookie *SynCookiePolicy
	var curKnock *KnockPolicy
	var curDNS *DNSPolicy
	var curGeoIP *GeoIPPolicy
	lineNo := 0

	flush := func() {
		if curRule != nil {
			pol.Block = append(pol.Block, *curRule)
			curRule = nil
		}
		if curSynCookie != nil {
			pol.SynCookie = curSynCookie
			curSynCookie = nil
		}
		if curKnock != nil {
			pol.Knock = curKnock
			curKnock = nil
		}
		if curDNS != nil {
			pol.DNS = curDNS
			curDNS = nil
		}
		if curGeoIP != nil {
			pol.GeoIP = curGeoIP
			curGeoIP = nil
		}
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNo++
		raw := sc.Text()

		// Strip full-line and trailing comments; blank lines are skipped.
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "version:"):
			flush()
			sect = sectionNone
			v := strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("policy %s:%d: invalid version %q", path, lineNo, v)
			}
			pol.Version = n

		case trimmed == "block:":
			flush()
			sect = sectionBlock

		case trimmed == "syn_cookie:":
			flush()
			sect = sectionSynCookie
			curSynCookie = &SynCookiePolicy{}

		case trimmed == "knock:":
			flush()
			sect = sectionKnock
			curKnock = &KnockPolicy{}

		case trimmed == "dns:":
			flush()
			sect = sectionDNS
			curDNS = &DNSPolicy{}

		case trimmed == "geoip:":
			flush()
			sect = sectionGeoIP
			curGeoIP = &GeoIPPolicy{}

		case sect == sectionBlock && strings.HasPrefix(trimmed, "- "):
			// Start of a new block entry: "- ip: 1.2.3.4"
			if curRule != nil {
				pol.Block = append(pol.Block, *curRule)
			}
			curRule = &Rule{}
			if err := setField(curRule, strings.TrimPrefix(trimmed, "- "), path, lineNo); err != nil {
				return nil, err
			}

		case sect == sectionBlock && curRule != nil:
			// Continuation field of the current block entry.
			if err := setField(curRule, trimmed, path, lineNo); err != nil {
				return nil, err
			}

		case sect == sectionSynCookie && curSynCookie != nil:
			if err := setSynCookieField(curSynCookie, trimmed, path, lineNo); err != nil {
				return nil, err
			}

		case sect == sectionKnock && curKnock != nil:
			if err := setKnockField(curKnock, trimmed, path, lineNo); err != nil {
				return nil, err
			}

		case sect == sectionDNS && curDNS != nil:
			if err := setDNSField(curDNS, trimmed, path, lineNo); err != nil {
				return nil, err
			}

		case sect == sectionGeoIP && curGeoIP != nil:
			if err := setGeoIPField(curGeoIP, trimmed, path, lineNo); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("policy %s:%d: unexpected line %q", path, lineNo, raw)
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}

	for i, r := range pol.Block {
		if strings.TrimSpace(r.IP) == "" {
			return nil, fmt.Errorf("policy %s: block[%d] is missing an ip", path, i)
		}
	}
	if pol.Knock != nil && len(pol.Knock.Sequence) > 0 {
		if len(pol.Knock.Sequence) > 8 {
			return nil, fmt.Errorf("policy %s: knock.sequence too long: %d ports (max 8)", path, len(pol.Knock.Sequence))
		}
		if pol.Knock.OpenPort == 0 {
			return nil, fmt.Errorf("policy %s: knock.sequence is set but knock.open_port is missing", path)
		}
	}
	if pol.SynCookie != nil && pol.SynCookie.HighPPS != 0 && pol.SynCookie.HighPPS < pol.SynCookie.LowPPS {
		return nil, fmt.Errorf("policy %s: syn_cookie.high_pps must be >= syn_cookie.low_pps", path)
	}

	return pol, nil
}

// setField applies a single "key: value" pair to a Rule being built.
func setField(r *Rule, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	val = unquote(strings.TrimSpace(val))

	switch key {
	case "ip":
		r.IP = val
	case "label":
		r.Label = val
	case "rate_limit_pps":
		if val == "" {
			return nil
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid rate_limit_pps %q", path, lineNo, val)
		}
		r.RateLimit = uint32(n)
	case "rate_limit_kbps":
		if val == "" {
			return nil
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid rate_limit_kbps %q", path, lineNo, val)
		}
		r.BandwidthLimit = uint32(n)
	default:
		return fmt.Errorf("policy %s:%d: unknown field %q", path, lineNo, key)
	}
	return nil
}

// setSynCookieField applies a single "key: value" pair inside the
// `syn_cookie:` section.
func setSynCookieField(c *SynCookiePolicy, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	val = unquote(strings.TrimSpace(val))

	switch key {
	case "low_pps":
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid low_pps %q", path, lineNo, val)
		}
		c.LowPPS = uint32(n)
	case "high_pps":
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid high_pps %q", path, lineNo, val)
		}
		c.HighPPS = uint32(n)
	default:
		return fmt.Errorf("policy %s:%d: unknown syn_cookie field %q", path, lineNo, key)
	}
	return nil
}

// setKnockField applies a single "key: value" pair inside the `knock:`
// section. "sequence" is the one field that takes an inline list, e.g.
// "sequence: [7000, 8000, 9000]".
func setKnockField(k *KnockPolicy, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)

	switch key {
	case "sequence":
		seq, err := parseUint16List(val)
		if err != nil {
			return fmt.Errorf("policy %s:%d: %w", path, lineNo, err)
		}
		k.Sequence = seq
	case "open_port":
		n, err := strconv.ParseUint(unquote(val), 10, 16)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid open_port %q", path, lineNo, val)
		}
		k.OpenPort = uint16(n)
	case "window_seconds":
		n, err := strconv.ParseUint(unquote(val), 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid window_seconds %q", path, lineNo, val)
		}
		k.WindowSeconds = uint32(n)
	default:
		return fmt.Errorf("policy %s:%d: unknown knock field %q", path, lineNo, key)
	}
	return nil
}

// setDNSField applies a single "key: value" pair inside the `dns:`
// section. "blocked_domains" takes the same inline-list syntax as
// knock.sequence, e.g. blocked_domains: [a.test, b.test].
func setDNSField(d *DNSPolicy, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)

	switch key {
	case "blocked_domains":
		list, err := parseStringList(val)
		if err != nil {
			return fmt.Errorf("policy %s:%d: %w", path, lineNo, err)
		}
		d.BlockedDomains = list
	case "refresh_minutes":
		n, err := strconv.ParseUint(unquote(val), 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid refresh_minutes %q", path, lineNo, val)
		}
		d.RefreshMinutes = uint32(n)
	default:
		return fmt.Errorf("policy %s:%d: unknown dns field %q", path, lineNo, key)
	}
	return nil
}

// setGeoIPField applies a single "key: value" pair inside the `geoip:`
// section. "blocked_countries" takes the same inline-list syntax as
// knock.sequence, e.g. blocked_countries: [CN, RU].
func setGeoIPField(g *GeoIPPolicy, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)

	switch key {
	case "blocked_countries":
		list, err := parseStringList(val)
		if err != nil {
			return fmt.Errorf("policy %s:%d: %w", path, lineNo, err)
		}
		g.BlockedCountries = list
	case "refresh_hours":
		n, err := strconv.ParseUint(unquote(val), 10, 32)
		if err != nil {
			return fmt.Errorf("policy %s:%d: invalid refresh_hours %q", path, lineNo, val)
		}
		g.RefreshHours = uint32(n)
	default:
		return fmt.Errorf("policy %s:%d: unknown geoip field %q", path, lineNo, key)
	}
	return nil
}

// parseUint16List parses the one inline-list value this parser supports —
// "[7000, 8000, 9000]" — into a []uint16. An empty or "[]" value returns a
// nil slice, meaning "no sequence configured".
func parseUint16List(s string) ([]uint16, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("expected a bracketed list like [7000, 8000, 9000], got %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return nil, nil
	}
	parts := strings.Split(inner, ",")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q in sequence", p)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

// parseStringList parses an inline bracketed list of bare or quoted
// strings, e.g. `["a.test", b.test]` or `[CN, RU]` or `[]`, into a
// []string. An empty or "[]" value returns a nil slice, meaning "nothing
// configured" (i.e. the corresponding feature is disabled).
func parseStringList(s string) ([]string, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("expected a bracketed list like [a, b, c], got %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return nil, nil
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = unquote(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// stripComment removes a trailing "# ..." comment, respecting quoted
// strings so a '#' inside a label doesn't truncate it.
func stripComment(line string) string {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Apply pushes every rule in pol directly into a locally-loaded firewall
// (used by sentryxd on boot, where it already holds the firewall handle),
// and also applies (or explicitly clears) the Phase 17 SYN-cookie config
// and Phase 18 knock sequence. It returns how many block rules applied
// cleanly and a slice of any per-rule/per-feature errors, so one bad entry
// in policy.yaml doesn't stop the rest.
//
// A missing `syn_cookie:` or `knock:` section means "disable that feature"
// — the same way `sxctl policy apply` behaves against a running daemon —
// not "leave whatever the daemon currently has configured untouched".
func Apply(fw *firewall.Firewall, pol *Policy) (applied int, errs []error) {
	for _, r := range pol.Block {
		if err := fw.Block(r.IP, r.Label); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.IP, err))
			continue
		}
		if r.RateLimit > 0 {
			if err := fw.RateLimit(r.IP, r.RateLimit); err != nil {
				errs = append(errs, fmt.Errorf("%s: rate limit: %w", r.IP, err))
				continue
			}
		}
		if r.BandwidthLimit > 0 {
			if err := fw.BandwidthLimit(r.IP, r.BandwidthLimit); err != nil {
				errs = append(errs, fmt.Errorf("%s: bandwidth limit: %w", r.IP, err))
				continue
			}
		}
		applied++
	}

	scCfg := firewall.SynCookieConfig{}
	if pol.SynCookie != nil {
		scCfg = firewall.SynCookieConfig{LowPPS: pol.SynCookie.LowPPS, HighPPS: pol.SynCookie.HighPPS}
	}
	if err := fw.SetSynCookieConfig(scCfg); err != nil {
		errs = append(errs, fmt.Errorf("syn_cookie: %w", err))
	}

	knockCfg := firewall.KnockConfig{}
	if pol.Knock != nil {
		knockCfg = firewall.KnockConfig{
			Sequence:      pol.Knock.Sequence,
			OpenPort:      pol.Knock.OpenPort,
			WindowSeconds: pol.Knock.WindowSeconds,
		}
	}
	if err := fw.SetKnockConfig(knockCfg); err != nil {
		errs = append(errs, fmt.Errorf("knock: %w", err))
	}

	return applied, errs
}
