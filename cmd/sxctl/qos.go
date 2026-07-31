package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// qosCmd is the parent for Phase 25's QoS byte-rate cap — independent of
// and stackable with `sxctl block --rate-limit`'s packet-rate cap. It's
// its own small command tree (set/clear) rather than another flag on
// `block`, since — unlike a rate limit, which only ever makes sense
// alongside a block — a bandwidth cap is often applied to an address
// that's otherwise fully allowed, just throttled.
var qosCmd = &cobra.Command{
	Use:   "qos",
	Short: "Set or clear a Phase 25 per-IP bandwidth (QoS) cap",
	Long: `qos manages Phase 25's independent byte-rate token bucket per source
IP. It stacks with, but is entirely separate from, the packet-rate cap set
by "sxctl block --rate-limit" / "sxctl rate-limit": an address can be
under its pps budget and still be throttled here for exceeding its kbps
budget, or vice versa.`,
}

var qosSetCmd = &cobra.Command{
	Use:   "set <ip> --kbps N",
	Short: "Cap an address to N kbps",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kbps, _ := cmd.Flags().GetUint32("kbps")
		if kbps == 0 {
			return fmt.Errorf("--kbps must be greater than 0 (use \"sxctl qos clear\" to remove a cap)")
		}
		ip := args[0]
		body := map[string]any{"limit_kbps": kbps}
		if err := apiRequest("POST", "/api/rules/"+ip+"/bandwidth-limit", body, nil); err != nil {
			return err
		}
		fmt.Printf("✓ capped %s to %d kbps\n", ip, kbps)
		return nil
	},
}

var qosClearCmd = &cobra.Command{
	Use:   "clear <ip>",
	Short: "Remove an address's bandwidth cap",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		body := map[string]any{"limit_kbps": uint32(0)}
		if err := apiRequest("POST", "/api/rules/"+ip+"/bandwidth-limit", body, nil); err != nil {
			return err
		}
		fmt.Printf("✓ cleared bandwidth cap on %s\n", ip)
		return nil
	},
}

func init() {
	qosSetCmd.Flags().Uint32P("kbps", "k", 0, "bandwidth cap in kbps (required)")
	qosCmd.AddCommand(qosSetCmd)
	qosCmd.AddCommand(qosClearCmd)
	rootCmd.AddCommand(qosCmd)
}
