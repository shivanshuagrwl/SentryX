package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// captureStatus mirrors capture.Status's JSON shape.
type captureStatus struct {
	Available   bool      `json:"available"`
	Running     bool      `json:"running"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	SnapBytes   uint64    `json:"snap_bytes"`
	DurationSec uint32    `json:"duration_seconds,omitempty"`
}

// captureCmd is the parent for Phase 22's opt-in, time-bounded packet
// capture: every packet the XDP program itself drops or flags streams up
// to CAPTURE_SNAPLEN raw bytes into a ringbuf, and sentryxd assembles a
// real, Wireshark/tcpdump-openable .pcap from it — see internal/capture's
// package comment for why this is off by default and always time-boundable.
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Start, stop, or download a Phase 22 packet capture",
}

var captureDuration time.Duration
var captureOut string

var captureStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Begin capturing dropped/flagged packets",
	Long: `start flips on kernel-side capture and begins draining flagged/dropped
packets into an in-memory pcap buffer. Use --duration to auto-stop after a
bounded window (recommended — capturing everything at line rate during a
real attack would drown you in data instead of helping); omit it to run
until an explicit "sxctl capture stop".`,
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"duration_seconds": uint32(captureDuration.Seconds())}
		var status captureStatus
		if err := apiRequest("POST", "/api/capture/start", body, &status); err != nil {
			return err
		}
		if captureDuration > 0 {
			fmt.Printf("✓ capture started (auto-stops in %s)\n", captureDuration)
		} else {
			fmt.Println("✓ capture started (run \"sxctl capture stop\" when done)")
		}
		return nil
	},
}

var captureStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the current capture session",
	Long: `stop ends the capture session but does not discard what was captured —
the data stays downloadable via "sxctl capture start --out" (er, "sxctl
capture download") until the next "sxctl capture start" begins a fresh one.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var status captureStatus
		if err := apiRequest("POST", "/api/capture/stop", nil, &status); err != nil {
			return err
		}
		fmt.Printf("✓ capture stopped (%d packet(s), %s bytes captured)\n", status.Packets, humanBytes(status.SnapBytes))
		return nil
	},
}

var captureStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether a capture is running and its progress so far",
	RunE: func(cmd *cobra.Command, args []string) error {
		var status captureStatus
		if err := apiRequest("GET", "/api/capture/status", nil, &status); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(status)
		}

		if !status.Running && status.Packets == 0 {
			fmt.Println(dim("no capture running, nothing captured yet"))
			return nil
		}
		if status.Running {
			since := time.Since(status.StartedAt).Round(time.Second)
			fmt.Printf("%s running for %s — %d packet(s), %s captured\n", green("●"), since, status.Packets, humanBytes(status.SnapBytes))
		} else {
			fmt.Printf("%s stopped — %d packet(s), %s captured (still downloadable)\n", dim("○"), status.Packets, humanBytes(status.SnapBytes))
		}
		return nil
	},
}

var captureDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download the current capture as a .pcap file",
	Long: `download streams the pcap file — the global header plus every record
captured so far — to --out. Valid and openable in Wireshark/tcpdump
whether or not a session is still running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if captureOut == "" {
			captureOut = "sentryx-capture.pcap"
		}
		data, err := downloadCapture()
		if err != nil {
			return err
		}
		if err := os.WriteFile(captureOut, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", captureOut, err)
		}
		fmt.Printf("✓ wrote %s (%s)\n", captureOut, humanBytes(uint64(len(data))))
		return nil
	},
}

// downloadCapture is a small direct-HTTP helper rather than going through
// apiRequest, since apiRequest always decodes the response as JSON and a
// pcap file is raw binary.
func downloadCapture() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, daemonHost+"/api/capture/download", nil)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach sentryxd at %s: %w", daemonHost, err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(buf.Bytes(), &e)
		if e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("daemon returned %s", resp.Status)
	}
	return buf.Bytes(), nil
}

func init() {
	captureStartCmd.Flags().DurationVarP(&captureDuration, "duration", "d", 30*time.Second, "auto-stop after this long (0 to run until an explicit stop)")
	captureDownloadCmd.Flags().StringVarP(&captureOut, "out", "o", "", "output .pcap path (default: sentryx-capture.pcap)")

	captureCmd.AddCommand(captureStartCmd)
	captureCmd.AddCommand(captureStopCmd)
	captureCmd.AddCommand(captureStatusCmd)
	captureCmd.AddCommand(captureDownloadCmd)
	rootCmd.AddCommand(captureCmd)
}
