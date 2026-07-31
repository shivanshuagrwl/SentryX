//go:build windows

// Package firewall — Windows backend. There is no XDP on Windows, so this
// file trades kernel-speed packet interdiction for Windows' own native
// firewall, driven through `netsh advfirewall`. That means:
//
//   - Block/Unblock/BlockCIDR/UnblockCIDR are real — they add and remove
//     actual "block inbound" rules enforced by the Windows Filtering
//     Platform, the same engine the GUI Windows Defender Firewall uses.
//   - Everything that depends on seeing individual packets in-kernel at
//     line rate (per-IP rate limiting, SYN-cookie mitigation, port
//     knocking, connection tracking, ARP spoof detection, QoS bandwidth
//     shaping, live packet activity/stats) has no equivalent without a
//     kernel-mode driver this project doesn't ship, so those calls are
//     honest no-ops: setters return ErrUnsupported, getters return the
//     zero value / empty slice. See Phase 27.2 in
//     SENTRYX_PHASE2_ROADMAP.md: "control plane is cross-platform, XDP
//     data-plane acceleration is Linux-native, other platforms fall back
//     to OS-native filtering."
//
// This keeps every caller (cmd/sentryxd, internal/api, internal/anomaly,
// internal/geoip, internal/dnsresolve, internal/threatintel,
// internal/threatshare) working unmodified: they all just import
// "firewall" and use *firewall.Firewall, and the build tag above ensures
// only this definition of that type exists in a Windows build.
package firewall

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported is returned by every method that has no meaningful
// implementation without a kernel-mode packet-filtering driver on this
// platform.
var ErrUnsupported = errors.New("not supported on this platform (Windows control-plane fallback — see firewall_windows.go)")

const rulePrefix = "SENTRYX-block-"

// Firewall is the Windows netsh-backed implementation of Backend.
type Firewall struct {
	mu    sync.RWMutex
	iface string

	rules    map[string]Rule    // keyed by IP
	geoRules map[string]GeoRule // keyed by CIDR

	blockObservers []func(ip, label string, reason Reason)

	attachedAt time.Time
}

// Load "attaches" the Windows backend. objPath and generic are accepted
// (and ignored) purely so cmd/sentryxd's main.go can call
// firewall.Load(objPath, iface, generic) identically on every platform —
// iface is recorded for display purposes only, since netsh rules aren't
// scoped to a single NIC the way an XDP program is.
func Load(objPath, iface string, generic bool) (*Firewall, error) {
	if _, err := exec.LookPath("netsh"); err != nil {
		return nil, fmt.Errorf("netsh not found on PATH — is this really Windows? %w", err)
	}
	return &Firewall{
		iface:      iface,
		rules:      make(map[string]Rule),
		geoRules:   make(map[string]GeoRule),
		attachedAt: time.Now(),
	}, nil
}

// Close removes every rule this daemon added and cleans up.
func (f *Firewall) Close() error {
	f.mu.Lock()
	ips := make([]string, 0, len(f.rules))
	for ip := range f.rules {
		ips = append(ips, ip)
	}
	cidrs := make([]string, 0, len(f.geoRules))
	for cidr := range f.geoRules {
		cidrs = append(cidrs, cidr)
	}
	f.mu.Unlock()

	var firstErr error
	for _, ip := range ips {
		if err := f.Unblock(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, cidr := range cidrs {
		if err := f.UnblockCIDR(cidr); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func ruleName(ipOrCIDR string) string {
	return rulePrefix + strings.NewReplacer("/", "_", ":", "_").Replace(ipOrCIDR)
}

func (f *Firewall) netshAddBlock(remote string) error {
	name := ruleName(remote)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=in", "action=block", "remoteip="+remote, "enable=yes")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh add rule for %s: %w (%s)", remote, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f *Firewall) netshDeleteBlock(remote string) error {
	name := ruleName(remote)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh delete rule for %s: %w (%s)", remote, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Block adds ipStr to the Windows Firewall block list with reason
// ReasonManual.
func (f *Firewall) Block(ipStr, label string) error {
	return f.BlockWithReason(ipStr, label, ReasonManual)
}

// BlockWithReason is like Block but records why, mirroring the Linux
// backend's API exactly so callers don't need a platform switch.
func (f *Firewall) BlockWithReason(ipStr, label string, reason Reason) error {
	if net.ParseIP(ipStr) == nil {
		return fmt.Errorf("invalid IP address: %q", ipStr)
	}
	if reason == ReasonNone {
		reason = ReasonManual
	}
	if err := f.netshAddBlock(ipStr); err != nil {
		return err
	}

	f.mu.Lock()
	f.rules[ipStr] = Rule{IP: ipStr, Label: label, Reason: reason, ReasonStr: reason.String(), CreatedAt: time.Now()}
	observers := append([]func(ip, label string, reason Reason){}, f.blockObservers...)
	f.mu.Unlock()

	if reason != ReasonShared {
		for _, obs := range observers {
			obs(ipStr, label, reason)
		}
	}
	return nil
}

// Unblock removes ipStr's block rule.
func (f *Firewall) Unblock(ipStr string) error {
	if err := f.netshDeleteBlock(ipStr); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.rules, ipStr)
	f.mu.Unlock()
	return nil
}

// RateLimit has no Windows Filtering Platform equivalent reachable from
// user space without a custom driver — see the package doc comment.
func (f *Firewall) RateLimit(ipStr string, limitPPS uint32) error { return ErrUnsupported }

// BandwidthLimit — see RateLimit.
func (f *Firewall) BandwidthLimit(ipStr string, limitKbps uint32) error { return ErrUnsupported }

// List returns every address this daemon currently has blocked.
func (f *Firewall) List() []Rule {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Rule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, r)
	}
	return out
}

// Stats reports zero — Windows gives no cheap, driver-free way to count
// packets matched by a firewall rule. Honest limitation, not a bug.
func (f *Firewall) Stats() (Stats, error) { return Stats{}, nil }

// DropReason has no per-packet drop log without a kernel-mode driver, so
// it reports "not dropped" for anything not currently in the block list,
// and the block metadata for anything that is — a coarser but still
// useful answer to "why is this blocked".
func (f *Firewall) DropReason(ipStr string) (DropInfo, bool, error) {
	f.mu.RLock()
	r, ok := f.rules[ipStr]
	f.mu.RUnlock()
	if !ok {
		return DropInfo{}, false, nil
	}
	return DropInfo{IP: ipStr, Reason: r.Reason, ReasonStr: r.ReasonStr, LastSeen: r.CreatedAt, Count: 0}, true, nil
}

// ActivitySnapshot reports empty — no per-packet visibility on this
// platform. The anomaly detector already treats an empty map as "nothing
// to baseline yet" rather than erroring.
func (f *Firewall) ActivitySnapshot() (map[string]Activity, error) {
	return map[string]Activity{}, nil
}

// ActiveConnections reports empty — Phase 16 connection tracking is
// Linux/XDP only.
func (f *Firewall) ActiveConnections() ([]Connection, error) { return nil, nil }

// SynCookieConfig / SetSynCookieConfig — Phase 17 is Linux/XDP only.
func (f *Firewall) SynCookieConfig() (SynCookieConfig, error) { return SynCookieConfig{}, nil }
func (f *Firewall) SetSynCookieConfig(cfg SynCookieConfig) error {
	if cfg.LowPPS != 0 || cfg.HighPPS != 0 {
		return ErrUnsupported
	}
	return nil
}

// KnockConfig / SetKnockConfig — Phase 18 is Linux/XDP only.
func (f *Firewall) KnockConfig() (KnockConfig, error) { return KnockConfig{}, nil }
func (f *Firewall) SetKnockConfig(cfg KnockConfig) error {
	if len(cfg.Sequence) != 0 {
		return ErrUnsupported
	}
	return nil
}

// BlockCIDR blocks an entire range (Phase 20 GeoIP feeds this) via a
// single netsh rule with remoteip=<CIDR> — Windows Firewall accepts CIDR
// notation natively, so this is a real, enforced block, not a stub.
func (f *Firewall) BlockCIDR(cidr, country, label string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR: %q", cidr)
	}
	if err := f.netshAddBlock(cidr); err != nil {
		return err
	}
	f.mu.Lock()
	f.geoRules[cidr] = GeoRule{CIDR: cidr, Country: country, Label: label, CreatedAt: time.Now()}
	f.mu.Unlock()
	return nil
}

// UnblockCIDR removes a previously-added CIDR block rule.
func (f *Firewall) UnblockCIDR(cidr string) error {
	if err := f.netshDeleteBlock(cidr); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.geoRules, cidr)
	f.mu.Unlock()
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

// ArpAlerts reports empty — Phase 21 needs raw Ethernet frame visibility
// only the XDP data plane has.
func (f *Firewall) ArpAlerts() ([]ArpAlert, error) { return nil, nil }

// SetBlockObserver / AddBlockObserver mirror the Linux backend so Phase 23
// threat-share and Phase 26 topology work identically here.
func (f *Firewall) SetBlockObserver(fn func(ip, label string, reason Reason)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockObservers = []func(ip, label string, reason Reason){fn}
}

func (f *Firewall) AddBlockObserver(fn func(ip, label string, reason Reason)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockObservers = append(f.blockObservers, fn)
}

// Interface returns the network interface this daemon was told to protect
// (informational only — netsh rules aren't scoped to a single NIC).
func (f *Firewall) Interface() string { return f.iface }

// AttachedAt returns when this backend was initialized.
func (f *Firewall) AttachedAt() time.Time { return f.attachedAt }

var _ Backend = (*Firewall)(nil)
