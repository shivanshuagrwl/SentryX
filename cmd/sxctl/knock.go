package main

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
)

var (
	knockDelay    time.Duration
	knockSeqFlag  []int
	knockOpenPort uint16
)

// knockConfigResp mirrors GET /api/knock in server.go.
type knockConfigResp struct {
	Sequence      []uint16 `json:"sequence"`
	OpenPort      uint16   `json:"open_port"`
	WindowSeconds uint32   `json:"window_seconds"`
	Enabled       bool     `json:"enabled"`
}

// knockCmd is the client-side half of Phase 18 port knocking: it sends
// the actual knock sequence to a target so the feature is demonstrable,
// not just claimed. By default it fetches the currently configured
// sequence from the daemon at --host (so a demo never drifts out of sync
// with what the daemon is actually enforcing); --sequence overrides that
// for testing a sequence before it's applied.
//
// Each knock is a bare TCP SYN — sent via a very short-timeout DialTimeout
// so the packet goes out on the wire without this process ever needing
// raw-socket privileges (a knock port is expected to be silently dropped
// by SENTRYX anyway, so no reply is ever expected).
var knockCmd = &cobra.Command{
	Use:   "knock <target-ip>",
	Short: "Send a port-knock sequence to unlock a stealth-mode protected port",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		sequence := uint16Sequence(knockSeqFlag)
		openPort := knockOpenPort
		if len(sequence) == 0 {
			var cfg knockConfigResp
			if err := apiRequest("GET", "/api/knock", nil, &cfg); err != nil {
				return fmt.Errorf("fetch knock config from %s: %w", daemonHost, err)
			}
			if !cfg.Enabled {
				return fmt.Errorf("no knock sequence is configured on the daemon at %s — pass --sequence explicitly, or set one via policy.yaml", daemonHost)
			}
			sequence = cfg.Sequence
			openPort = cfg.OpenPort
		}

		fmt.Printf("knocking %s: %v\n", bold(target), sequence)
		for i, port := range sequence {
			addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
			// Timeout is deliberately short: SENTRYX drops knock-port
			// packets silently (that's the whole point of stealth mode),
			// so there's never a real handshake to wait out — the SYN
			// itself is what matters, not the (never-coming) reply.
			conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
			if err != nil {
				fmt.Printf("  %s step %d/%d → port %d %s\n", dim("•"), i+1, len(sequence), port, dim("(sent, no reply expected)"))
			} else {
				conn.Close()
				fmt.Printf("  %s step %d/%d → port %d %s\n", green("✓"), i+1, len(sequence), port, dim("(unexpectedly open?)"))
			}
			if i < len(sequence)-1 {
				time.Sleep(knockDelay)
			}
		}

		fmt.Println()
		if openPort != 0 {
			fmt.Printf("%s sequence sent — %s should now be unlocked for this source IP for a short window\n", green("✓"), bold(fmt.Sprintf("port %d", openPort)))
		} else {
			fmt.Printf("%s sequence sent\n", green("✓"))
		}
		return nil
	},
}

// uint16Sequence converts a --sequence []int flag (pflag has no uint16
// slice type) into the []uint16 the knock config actually needs.
func uint16Sequence(ports []int) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	out := make([]uint16, len(ports))
	for i, p := range ports {
		out[i] = uint16(p)
	}
	return out
}

func init() {
	knockCmd.Flags().DurationVar(&knockDelay, "delay", 150*time.Millisecond, "pause between knocks")
	knockCmd.Flags().IntSliceVar(&knockSeqFlag, "sequence", nil, "override the knock sequence instead of fetching it from the daemon (e.g. --sequence 7000,8000,9000)")
	knockCmd.Flags().Uint16Var(&knockOpenPort, "open-port", 0, "the port the sequence is expected to unlock (display only, used with --sequence)")
	rootCmd.AddCommand(knockCmd)
}
