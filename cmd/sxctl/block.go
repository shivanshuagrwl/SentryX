package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	blockLabel     string
	blockRateLimit uint32
	blockBandwidth uint32
)

var blockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Block an IPv4 address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		body := map[string]any{
			"ip":              ip,
			"label":           blockLabel,
			"rate_limit_pps":  blockRateLimit,
			"rate_limit_kbps": blockBandwidth,
		}
		if err := apiRequest("POST", "/api/rules", body, nil); err != nil {
			return err
		}
		fmt.Printf("✓ blocked %s\n", ip)
		return nil
	},
}

func init() {
	blockCmd.Flags().StringVarP(&blockLabel, "label", "l", "", "optional label for this rule (e.g. \"known scanner\")")
	blockCmd.Flags().Uint32VarP(&blockRateLimit, "rate-limit", "r", 0, "also cap this IP to N packets/sec instead of a hard block window")
	blockCmd.Flags().Uint32Var(&blockBandwidth, "bandwidth-kbps", 0, "also cap this IP to N kbps (Phase 25 QoS), independent of --rate-limit")
	rootCmd.AddCommand(blockCmd)
}
