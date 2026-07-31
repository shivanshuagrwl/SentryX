//go:build linux

// Package capture implements SENTRYX's Phase 22 packet capture / pcap
// export.
//
// The kernel side (bpf/xdp_sentryx.c's capture_packet()) already does the
// expensive-feeling part cheaply: copy up to CAPTURE_SNAPLEN raw bytes of
// any packet it drops or flags into a BPF ringbuf, gated behind a single
// on/off switch so this costs nothing when disabled. Everything in this
// package is the user-space other half — drain that ringbuf and write out
// a standard, Wireshark/tcpdump-openable .pcap file. No cgo, no libpcap:
// the classic pcap file format is a 24-byte global header followed by a
// stream of {16-byte record header, raw bytes} entries, simple enough to
// write by hand with encoding/binary.
//
// Deliberately opt-in and time-bounded (see Recorder.Start's duration
// parameter) rather than always-on, per the roadmap's explicit warning:
// capturing everything at line rate during a real attack would drown the
// operator in data instead of helping them.
package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/shivanshuagrwl/SentryX/internal/firewall"
)

// pcap file format constants (RFC-less but universally implemented —
// see https://wiki.wireshark.org/Development/LibpcapFileFormat).
const (
	pcapMagicMicros  = 0xa1b2c3d4 // microsecond-resolution timestamps
	pcapVersionMajor = 2
	pcapVersionMinor = 4
	linktypeEthernet = 1 // capture starts at the Ethernet header, see capture_packet()
)

// eventRaw mirrors struct capture_event in bpf/xdp_sentryx.c exactly —
// field order and sizes are load-bearing, same rule as every other raw
// struct in internal/firewall.
type eventRaw struct {
	TsNs        uint64
	PktLen      uint32
	CapturedLen uint32
	SrcIP       uint32
	Reason      uint8
	_           [3]uint8
	Data        [firewall.CaptureSnaplen]byte
}

// Status reports a capture session's progress for `sxctl capture status` /
// the dashboard. Mirrored exactly (same fields, same JSON tags) by
// pcap_other.go's Status for every non-Linux platform, so internal/api and
// cmd/sxctl decode it identically regardless of which one actually compiled.
type Status struct {
	Running     bool      `json:"running"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	SnapBytes   uint64    `json:"snap_bytes"`
	DurationSec uint32    `json:"duration_seconds,omitempty"` // 0 == runs until explicit Stop
}

// Recorder owns Phase 22's ringbuf reader lifecycle end to end: flips the
// kernel-side switch on Start, drains capture_events into an in-memory
// pcap buffer as records arrive, and can hand back a snapshot of that
// buffer at any time — a pcap file is just a header followed by N
// complete records, so a mid-capture read is always itself a valid,
// independently-openable .pcap, not something that needs Stop first.
type Recorder struct {
	fw *firewall.Firewall

	mu        sync.Mutex
	reader    *ringbuf.Reader
	stopTimer *time.Timer
	buf       bytes.Buffer
	running   bool
	startedAt time.Time
	packets   uint64
	rawBytes  uint64 // sum of original pkt_len, may exceed what was actually captured
	snapBytes uint64 // sum of captured_len, i.e. what's actually in buf
	duration  time.Duration
}

// NewRecorder builds a Recorder bound to a live Firewall. Does not touch
// the kernel or start anything until Start is called.
func NewRecorder(fw *firewall.Firewall) *Recorder {
	return &Recorder{fw: fw}
}

// Start enables kernel-side capture and begins draining events into a
// fresh in-memory buffer, discarding whatever a previous run captured.
// duration of 0 runs until Stop is called explicitly; otherwise the
// Recorder stops itself after duration elapses, so a forgotten `sxctl
// capture start` without a matching stop can't run forever.
func (r *Recorder) Start(duration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("capture already running (started %s ago)", time.Since(r.startedAt).Round(time.Second))
	}

	reader, err := r.fw.OpenCaptureReader()
	if err != nil {
		return err
	}
	if err := r.fw.SetCaptureEnabled(true); err != nil {
		reader.Close()
		return fmt.Errorf("enable capture: %w", err)
	}

	r.buf.Reset()
	writePcapHeader(&r.buf)
	r.packets, r.rawBytes, r.snapBytes = 0, 0, 0
	r.reader = reader
	r.running = true
	r.startedAt = time.Now()
	r.duration = duration

	go r.drain(reader)

	if duration > 0 {
		r.stopTimer = time.AfterFunc(duration, func() {
			if err := r.Stop(); err != nil {
				log.Printf("capture: auto-stop after %s failed: %v", duration, err)
			} else {
				log.Printf("capture: auto-stopped after %s", duration)
			}
		})
	}
	return nil
}

// drain reads events off the ringbuf until it's closed by Stop. Runs in
// its own goroutine for the lifetime of one capture session.
func (r *Recorder) drain(reader *ringbuf.Reader) {
	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return // Stop() closed it — expected, quiet exit
			}
			log.Printf("capture: ringbuf read error: %v", err)
			continue
		}

		var ev eventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("capture: decode event: %v", err)
			continue
		}
		r.appendRecord(ev)
	}
}

// appendRecord writes one decoded event as a pcap record into buf.
func (r *Recorder) appendRecord(ev eventRaw) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		// Stop() already flipped running off and is closing the reader —
		// this is a straggler event that lost that race. Discard it
		// rather than writing into a buffer a concurrent Snapshot() might
		// already be copying out.
		return
	}

	n := ev.CapturedLen
	if n > uint32(len(ev.Data)) {
		n = uint32(len(ev.Data)) // defensive only — the kernel never sets this over CaptureSnaplen
	}

	wall := r.fw.BootTimeToWall(ev.TsNs)
	writeUint32(&r.buf, uint32(wall.Unix()))
	writeUint32(&r.buf, uint32(wall.Nanosecond()/1000))
	writeUint32(&r.buf, n)
	writeUint32(&r.buf, ev.PktLen)
	r.buf.Write(ev.Data[:n])

	r.packets++
	r.rawBytes += uint64(ev.PktLen)
	r.snapBytes += uint64(n)
}

// Stop disables kernel-side capture and closes the ringbuf reader,
// letting the drain goroutine exit. The buffered pcap data is left
// intact and readable via Snapshot — Stop ends the *session*, not the
// data. Calling Stop when nothing is running is a no-op, not an error, so
// both the auto-stop timer and an explicit `sxctl capture stop` can race
// harmlessly.
func (r *Recorder) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = false
	reader := r.reader
	r.reader = nil
	if r.stopTimer != nil {
		r.stopTimer.Stop()
		r.stopTimer = nil
	}
	r.mu.Unlock()

	var firstErr error
	if reader != nil {
		if err := reader.Close(); err != nil {
			firstErr = fmt.Errorf("close capture reader: %w", err)
		}
	}
	if err := r.fw.SetCaptureEnabled(false); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("disable capture: %w", err)
	}
	return firstErr
}

// Snapshot returns the current pcap file bytes — the global header plus
// every record captured so far. Valid whether or not a session is
// currently running, and safe to call repeatedly (e.g. polling progress
// on a long capture without stopping it first).
func (r *Recorder) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.buf.Len())
	copy(out, r.buf.Bytes())
	return out
}

// Status reports the current session's progress for `sxctl capture
// status` / the dashboard.
func (r *Recorder) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{
		Running:   r.running,
		Packets:   r.packets,
		Bytes:     r.rawBytes,
		SnapBytes: r.snapBytes,
	}
	if r.running {
		st.StartedAt = r.startedAt
		st.DurationSec = uint32(r.duration / time.Second)
	}
	return st
}

// Close stops any in-progress session and releases resources. Safe to
// call during daemon shutdown regardless of whether a capture is active.
func (r *Recorder) Close() error {
	return r.Stop()
}

// ---- pcap file format writing -------------------------------------------

func writePcapHeader(buf *bytes.Buffer) {
	writeUint32(buf, pcapMagicMicros)
	writeUint16(buf, pcapVersionMajor)
	writeUint16(buf, pcapVersionMinor)
	writeUint32(buf, 0) // thiszone — always 0 (UTC), per convention
	writeUint32(buf, 0) // sigfigs — always 0, unused by every real reader
	writeUint32(buf, firewall.CaptureSnaplen)
	writeUint32(buf, linktypeEthernet)
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeUint16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}
