package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// whyResp mirrors the JSON shape of GET /api/why/{ip} in server.go.
type whyResp struct {
	IP        string `json:"ip"`
	Dropped   bool   `json:"dropped"`
	Reason    uint8  `json:"reason"`
	ReasonStr string `json:"reason_str"`
	Count     uint64 `json:"count"`
}

// whyCmd answers the single question every firewall operator eventually
// asks in a panic: "why is this IP being dropped?" — one kernel map read,
// surfaced as one human sentence, no log-grepping required.
var whyCmd = &cobra.Command{
	Use:   "why <ip>",
	Short: `Explain why an address is (or isn't) being dropped`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		var resp whyResp
		if err := apiRequest("GET", "/api/why/"+ip, nil, &resp); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(resp)
		}

		if !resp.Dropped {
			fmt.Printf("%s %s has no recorded drops\n", green("✓"), bold(ip))
			return nil
		}

		fmt.Printf("%s %s is being dropped\n", red("✗"), bold(ip))
		fmt.Printf("  reason: %s\n", colorReason(resp.ReasonStr))
		fmt.Printf("  count:  %s packets dropped for this reason\n", bold(fmt.Sprintf("%d", resp.Count)))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whyCmd)
}
