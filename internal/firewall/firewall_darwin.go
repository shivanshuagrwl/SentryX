//go:build darwin

// Package firewall — macOS backend. No XDP on Darwin either, so this file
// drives the BSD packet filter (pf) via `pfctl` instead: SENTRYX gets its
// own named anchor ("sentryx") holding one table ("sentryx_block") and one
// rule ("block in quick from <sentryx_block>"), and Block/Unblock just
// add/remove entries in that table — a real, kernel-enforced block, same
// idea as the Linux blocklist map, just driven through pf's control
// utility instead of a BPF map syscall.
//
// Everything that needs per-packet visibility at line rate (rate
// limiting, SYN-cookie mitigation, port knocking, connection tracking,
// ARP spoof detection, QoS shaping, live activity/stats) has no pfctl
// equivalent, so those are honest no-ops — see Phase 27.2 in
// SENTRYX_PHASE2_ROADMAP.md.
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
// implementation without a kernel extension on this platform.
var ErrUnsupported = errors.New("not supported on this platform (macOS control-plane fallback — see firewall_darwin.go)")

const pfAnchor = "sentryx"
const pfTable = "sentryx_block"

// pfAnchorRules is loaded into the "sentryx" anchor once at startup. It
// defines the table Block/Unblock manipulate and the one rule that
// enforces it; the table itself starts empty.
const pfAnchorRules = "table <" + pfTable + "> persist\nblock in quick from <" + pfTable + "> to any\n"

// Firewall is the macOS pfctl-backed implementation of Backend.
type Firewall struct {
	mu    sync.RWMutex
	iface string

	rules    map[string]Rule
	geoRules map[string]GeoRule

	blockObservers []func(ip, label string, reason Reason)

	attachedAt time.Time
}

// Load "attaches" the macOS backend: loads SENTRYX's pf anchor and makes
// sure pf itself is enabled. objPath and generic are accepted (and
// ignored) so main.go can call firewall.Load(objPath, iface, generic)
// identically on every platform.
func Load(objPath, iface string, generic bool) (*Firewall, error) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return nil, fmt.Errorf("pfctl not found on PATH — is this really macOS? %w", err)
	}

	load := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	load.Stdin = strings.NewReader(pfAnchorRules)
	if out, err := load.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pfctl: load anchor %q: %w (%s)", pfAnchor, err, strings.TrimSpace(string(out)))
	}

	// -e (enable) fails harmlessly if pf is already enabled — that's the
	// common case on a normal macOS box, so its exit status is ignored;
	// what matters is the anchor above loaded without error.
	_ = exec.Command("pfctl", "-e").Run()

	return &Firewall{
		iface:      iface,
		rules:      make(map[string]Rule),
		geoRules:   make(map[string]GeoRule),
		attachedAt: time.Now(),
	}, nil
}

// Close flushes SENTRYX's own anchor table so nothing this daemon added
// outlives the process, without touching any other pf rules on the box.
func (f *Firewall) Close() error {
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "flush")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: flush table %q: %w (%s)", pfTable, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f *Firewall) pfTableAdd(entry string) error {
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "add", entry)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: add %s to table %q: %w (%s)", entry, pfTable, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f *Firewall) pfTableDelete(entry string) error {
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-t", pfTable, "-T", "delete", entry)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: delete %s from table %q: %w (%s)", entry, pfTable, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Block adds ipStr to the pf block table with reason ReasonManual.
func (f *Firewall) Block(ipStr, label string) error {
	return f.BlockWithReason(ipStr, label, ReasonManual)
}

// BlockWithReason is like Block but records why.
func (f *Firewall) BlockWithReason(ipStr, label string, reason Reason) error {
	if net.ParseIP(ipStr) == nil {
		return fmt.Errorf("invalid IP address: %q", ipStr)
	}
	if reason == ReasonNone {
		reason = ReasonManual
	}
	if err := f.pfTableAdd(ipStr); err != nil {
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

// Unblock removes ipStr from the pf block table.
func (f *Firewall) Unblock(ipStr string) error {
	if err := f.pfTableDelete(ipStr); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.rules, ipStr)
	f.mu.Unlock()
	return nil
}

// RateLimit has no pf equivalent reachable without a kernel extension.
func (f *Firewall) RateLimit(ipStr string, limitPPS uint32) error { return ErrUnsupported }

// BandwidthLimit — see RateLimit. (pf does support traffic shaping via
// dummynet/ALTQ on some macOS versions, but it's deprecated/removed on
// recent releases, so this stays an honest no-op rather than a
// version-fragile implementation.)
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

// Stats reports zero — reading pf's own packet/byte counters per table
// entry needs `pfctl -t sentryx_block -T show -v` output parsing, which
// is possible but not wired up yet; tracked as future scope.
func (f *Firewall) Stats() (Stats, error) { return Stats{}, nil }

// DropReason reports the block metadata for anything currently blocked —
// no per-packet drop log without a kernel extension, so this is coarser
// than the Linux backend's, but still answers "why is this blocked".
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
// platform.
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

// BlockCIDR blocks an entire range (Phase 20 GeoIP feeds this) by adding
// the CIDR directly to the pf table — pf tables accept CIDR entries
// natively, so this is a real, enforced block.
func (f *Firewall) BlockCIDR(cidr, country, label string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR: %q", cidr)
	}
	if err := f.pfTableAdd(cidr); err != nil {
		return err
	}
	f.mu.Lock()
	f.geoRules[cidr] = GeoRule{CIDR: cidr, Country: country, Label: label, CreatedAt: time.Now()}
	f.mu.Unlock()
	return nil
}

// UnblockCIDR removes a previously-added CIDR block.
func (f *Firewall) UnblockCIDR(cidr string) error {
	if err := f.pfTableDelete(cidr); err != nil {
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
// (informational only — pf table rules aren't scoped to a single NIC).
func (f *Firewall) Interface() string { return f.iface }

// AttachedAt returns when this backend was initialized.
func (f *Firewall) AttachedAt() time.Time { return f.attachedAt }

var _ Backend = (*Firewall)(nil)
