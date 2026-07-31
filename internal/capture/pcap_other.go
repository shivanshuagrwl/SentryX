//go:build !linux

// Package capture — non-Linux stub. Phase 22's packet capture reads raw
// packet bytes out of a BPF ringbuf that only exists on the Linux/XDP
// data plane (see pcap_linux.go's package comment); Windows/macOS have no
// equivalent kernel-side capture hook in this project, so this file gives
// `sxctl capture` and the dashboard an honest, always-empty implementation
// instead of a build failure — the same "control plane is cross-platform,
// XDP data-plane acceleration is Linux-native" pattern used throughout
// internal/firewall's platform split.
package capture

import (
	"fmt"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// Status mirrors pcap_linux.go's Status exactly (same fields, same JSON
// tags) so internal/api and cmd/sxctl decode it identically regardless of
// which platform's file actually compiled.
type Status struct {
	Running     bool      `json:"running"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	SnapBytes   uint64    `json:"snap_bytes"`
	DurationSec uint32    `json:"duration_seconds,omitempty"`
}

// Recorder is a no-op stand-in on platforms without a kernel-side capture
// hook. Every method returns a clear "not supported here" error rather
// than silently pretending to work.
type Recorder struct{}

// NewRecorder builds a Recorder. fw is accepted (and ignored) purely so
// cmd/sentryxd's main.go can call capture.NewRecorder(fw) identically on
// every platform.
func NewRecorder(fw *firewall.Firewall) *Recorder { return &Recorder{} }

var errUnsupported = fmt.Errorf("packet capture needs the Linux/XDP data plane — not available on this platform")

func (r *Recorder) Start(duration time.Duration) error { return errUnsupported }
func (r *Recorder) Stop() error                        { return nil }
func (r *Recorder) Snapshot() []byte                   { return nil }
func (r *Recorder) Status() Status                     { return Status{} }
func (r *Recorder) Close() error                       { return nil }
