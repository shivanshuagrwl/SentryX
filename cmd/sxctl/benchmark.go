package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

var (
	benchTarget   string
	benchDuration time.Duration
	benchRate     int
	benchWorkers  int
	benchPayload  int
	benchReport   string
	benchMode     string
)

// benchResult is what --json / --report emit, and what the bar chart is
// drawn from.
type benchResult struct {
	Target        string    `json:"target"`
	Mode          string    `json:"mode"`
	Duration      string    `json:"duration"`
	RequestedPPS  int       `json:"requested_pps"`
	Sent          uint64    `json:"packets_sent"`
	SendErrors    uint64    `json:"send_errors"`
	AchievedPPS   float64   `json:"achieved_pps"`
	AllowedBefore uint64    `json:"allowed_before"`
	AllowedAfter  uint64    `json:"allowed_after"`
	DroppedBefore uint64    `json:"dropped_before"`
	DroppedAfter  uint64    `json:"dropped_after"`
	AllowedDelta  uint64    `json:"allowed_delta"`
	DroppedDelta  uint64    `json:"dropped_delta"`
	KernelDropPct float64   `json:"kernel_drop_pct"`
	StartedAt     time.Time `json:"started_at"`
}

// benchmarkCmd fires synthetic UDP traffic at a target and reads the
// daemon's own kernel counters (/api/stats) before and after, so the claim
// "line-rate in-kernel filtering" is backed by a number produced in front
// of whoever's watching, not a slide.
//
// This benchmarks the SENTRYX instance currently attached to the daemon
// at --host. To compare against iptables, point --target at a second host
// (or interface) protected by iptables instead and run the same command
// against it — sxctl only measures, it doesn't reconfigure either side.
var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Fire synthetic traffic and report SENTRYX's live drop/allow throughput",
	Long: `Generates synthetic traffic against --target for --duration at
--rate packets/sec using --workers concurrent senders, then diffs
/api/stats (the daemon's live kernel counters) from before to after.

--mode udp (default) sends best-effort UDP datagrams — no handshake, no
privileges required, exercises the same per-packet XDP drop path as any
other protocol.

--mode syn-flood sends bare TCP SYNs at --target (also unprivileged: each
one is a net.DialTimeout given just long enough for the SYN itself to hit
the wire, then abandoned rather than waiting out a handshake that Phase
17's SYN-cookie tiering may not even forward). This is what demonstrates
the "detection + mitigation" story rather than detection alone: at low
rates traffic passes through normally, at medium rates SENTRYX challenges
with a SYN-cookie instead of forwarding (counted as "allowed" in the
kernel stats — the connection is being absorbed, not silently dropped),
and only past --syn-flood-high does it fall back to a hard drop.

This proves throughput and drop behavior with a number produced live,
in front of whoever's watching — not a slide. It measures whatever is
currently attached to the daemon at --host; to compare against
iptables, run the same command a second time with --target pointed at
a host/port protected by iptables instead, and compare the two reports.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if benchTarget == "" {
			return fmt.Errorf("--target is required, e.g. --target 10.0.0.5:9999")
		}
		if benchRate <= 0 || benchWorkers <= 0 {
			return fmt.Errorf("--rate and --workers must be positive")
		}
		if benchMode != "udp" && benchMode != "syn-flood" {
			return fmt.Errorf("--mode must be %q or %q", "udp", "syn-flood")
		}

		var before statsView
		if err := apiRequest("GET", "/api/stats", nil, &before); err != nil {
			return fmt.Errorf("read baseline stats: %w", err)
		}

		res := benchResult{
			Target:        benchTarget,
			Mode:          benchMode,
			Duration:      benchDuration.String(),
			RequestedPPS:  benchRate,
			AllowedBefore: before.Allowed,
			DroppedBefore: before.Dropped,
			StartedAt:     time.Now(),
		}

		verb := "sending"
		if benchMode == "syn-flood" {
			verb = "SYN-flooding"
		}
		stop := spinner(fmt.Sprintf("%s ~%d pps to %s for %s (%d workers)", verb, benchRate, benchTarget, benchDuration, benchWorkers))
		var sent, sendErrs uint64
		if benchMode == "syn-flood" {
			sent, sendErrs = fireSynFlood(benchTarget, benchRate, benchWorkers, benchDuration)
		} else {
			sent, sendErrs = fireLoad(benchTarget, benchRate, benchWorkers, benchPayload, benchDuration)
		}
		stop("load generation complete", true)

		res.Sent = sent
		res.SendErrors = sendErrs
		res.AchievedPPS = float64(sent) / benchDuration.Seconds()

		// Give the kernel counters a moment to catch the last packets and
		// the daemon a moment to poll/expose them before reading again.
		time.Sleep(300 * time.Millisecond)

		var after statsView
		if err := apiRequest("GET", "/api/stats", nil, &after); err != nil {
			return fmt.Errorf("read post-run stats: %w", err)
		}
		res.AllowedAfter = after.Allowed
		res.DroppedAfter = after.Dropped
		res.AllowedDelta = safeSub(after.Allowed, before.Allowed)
		res.DroppedDelta = safeSub(after.Dropped, before.Dropped)
		total := res.AllowedDelta + res.DroppedDelta
		if total > 0 {
			res.KernelDropPct = float64(res.DroppedDelta) / float64(total) * 100
		}

		if benchReport != "" {
			data, _ := json.MarshalIndent(res, "", "  ")
			if err := os.WriteFile(benchReport, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "%s failed to write report: %v\n", amber("warning:"), err)
			} else {
				fmt.Printf("%s wrote %s\n", green("✓"), bold(benchReport))
			}
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		printBenchReport(res)
		return nil
	},
}

// fireLoad sends best-effort UDP datagrams at roughly rate pps split
// across workers goroutines for duration, and returns how many were sent
// successfully vs errored (e.g. target unreachable). UDP is used
// deliberately: no handshake, no privileges required, and it exercises
// the same per-packet XDP drop path as any other protocol.
func fireLoad(target string, rate, workers, payloadSize int, duration time.Duration) (sent, errs uint64) {
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	perWorker := rate / workers
	if perWorker < 1 {
		perWorker = 1
	}
	interval := time.Second / time.Duration(perWorker)

	var sentCt, errCt uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(duration)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", target)
			if err != nil {
				atomic.AddUint64(&errCt, 1)
				return
			}
			defer conn.Close()

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for time.Now().Before(deadline) {
				<-ticker.C
				if _, err := conn.Write(payload); err != nil {
					atomic.AddUint64(&errCt, 1)
					continue
				}
				atomic.AddUint64(&sentCt, 1)
			}
		}()
	}
	wg.Wait()
	return sentCt, errCt
}

// fireSynFlood fires bare TCP SYNs at target at roughly rate pps split
// across workers goroutines, for the Phase 17 SYN-cookie mitigation demo.
// Deliberately doesn't wait out a full handshake: net.DialTimeout with a
// short timeout puts the SYN on the wire immediately, and once SENTRYX's
// tiering kicks in (cookie-challenge or hard-drop), no ordinary reply is
// coming anyway — the timeout itself becomes the expected outcome, not a
// failure, so it's counted toward `sent`, not `errs`. A genuine dial
// error (bad address, local resource exhaustion) is what actually counts
// as an error here.
func fireSynFlood(target string, rate, workers int, duration time.Duration) (sent, errs uint64) {
	const dialTimeout = 75 * time.Millisecond

	perWorker := rate / workers
	if perWorker < 1 {
		perWorker = 1
	}
	interval := time.Second / time.Duration(perWorker)

	var sentCt, errCt uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(duration)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for time.Now().Before(deadline) {
				<-ticker.C
				conn, err := net.DialTimeout("tcp", target, dialTimeout)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						atomic.AddUint64(&sentCt, 1) // SYN went out; no reply is expected once mitigation engages
						continue
					}
					atomic.AddUint64(&errCt, 1)
					continue
				}
				conn.Close()
				atomic.AddUint64(&sentCt, 1)
			}
		}()
	}
	wg.Wait()
	return sentCt, errCt
}

func safeSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// printBenchReport renders the result as a short terminal bar chart —
// enough to hold up on a shared screen without a slide.
func printBenchReport(r benchResult) {
	fmt.Println(bold("SENTRYX benchmark"))
	fmt.Printf("  target:        %s\n", r.Target)
	fmt.Printf("  mode:          %s\n", r.Mode)
	fmt.Printf("  duration:      %s\n", r.Duration)
	fmt.Printf("  sent:          %d packets (%d send errors)\n", r.Sent, r.SendErrors)
	fmt.Printf("  achieved rate: %s\n", bold(fmt.Sprintf("%.0f pps", r.AchievedPPS)))
	fmt.Println()

	fmt.Println(bold("kernel counters (delta over the run)"))
	bar("allowed", r.AllowedDelta, r.AllowedDelta+r.DroppedDelta, green)
	bar("dropped", r.DroppedDelta, r.AllowedDelta+r.DroppedDelta, red)
	fmt.Println()

	dropColor := green
	if r.KernelDropPct > 5 {
		dropColor = amber
	}
	if r.KernelDropPct > 50 {
		dropColor = red
	}
	fmt.Printf("%s %s\n", bold("kernel drop rate:"), dropColor(fmt.Sprintf("%.1f%%", r.KernelDropPct)))
	if r.AllowedDelta+r.DroppedDelta == 0 {
		fmt.Println(dim("no counter movement observed — check that --target actually routes through this interface"))
	}
	if r.Mode == "syn-flood" {
		fmt.Println(dim("note: Phase 17 SYN-cookie challenges count as \"allowed\" (the source is being absorbed,"))
		fmt.Println(dim("not silently dropped) — run `sxctl why <your-source-ip>` to see if you tripped syn-flood"))
		fmt.Println(dim("hard-drop tier instead, and `sxctl connections` to see what conn_table thinks is going on."))
	}
}

const barWidth = 40

func bar(label string, value, max uint64, color func(string) string) {
	frac := 0.0
	if max > 0 {
		frac = float64(value) / float64(max)
	}
	filled := int(frac * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bars := ""
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bars += "█"
		} else {
			bars += "·"
		}
	}
	fmt.Printf("  %-8s %s %s\n", label, color(bars), dim(fmt.Sprintf("%d", value)))
}

func init() {
	benchmarkCmd.Flags().StringVar(&benchTarget, "target", "", "host:port to send synthetic traffic to (required)")
	benchmarkCmd.Flags().StringVar(&benchMode, "mode", "udp", `traffic type: "udp" (default) or "syn-flood" (Phase 17 mitigation demo)`)
	benchmarkCmd.Flags().DurationVar(&benchDuration, "duration", 10*time.Second, "how long to generate load")
	benchmarkCmd.Flags().IntVar(&benchRate, "rate", 2000, "target packets/sec, split across --workers")
	benchmarkCmd.Flags().IntVar(&benchWorkers, "workers", 4, "concurrent sender goroutines")
	benchmarkCmd.Flags().IntVar(&benchPayload, "payload", 64, "UDP payload size in bytes (--mode udp only)")
	benchmarkCmd.Flags().StringVar(&benchReport, "report", "", "also write the result as JSON to this path")
	rootCmd.AddCommand(benchmarkCmd)
}
