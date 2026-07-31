package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// threatEntry mirrors threatshare.ThreatEntry's JSON shape.
type threatEntry struct {
	IP        string    `json:"ip"`
	Label     string    `json:"label,omitempty"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`
	ExpiresAt time.Time `json:"expires_at"`
}

// threatsResp mirrors GET /api/threats in server.go.
type threatsResp struct {
	Enabled bool          `json:"enabled"`
	Threats []threatEntry `json:"threats"`
}

// threatsCmd shows Phase 23's cross-daemon threat sharing state: every
// block this daemon is currently enforcing only because a peer reported
// it, and when each one is due to automatically expire.
var threatsCmd = &cobra.Command{
	Use:   "threats",
	Short: "List blocks this daemon is enforcing because a peer relayed them (Phase 23)",
	Long: `threats shows every currently-enforced block that originated on a
different daemon and was relayed here via -threat-share-peers, along with
which peer reported it and when this daemon will automatically lift it.

Blocks this daemon discovered itself (manual, anomaly, threat-intel, ...)
don't show up here — see "sxctl list" for the full blocklist. This is
specifically the subset enforced under ReasonShared.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var resp threatsResp
		if err := apiRequest("GET", "/api/threats", nil, &resp); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(resp)
		}

		if !resp.Enabled {
			fmt.Println(dim("threat-share disabled — start sentryxd with -threat-share-peers to enable"))
			return nil
		}

		if len(resp.Threats) == 0 {
			fmt.Println(dim("no blocks currently enforced via threat-share"))
			return nil
		}

		sort.Slice(resp.Threats, func(i, j int) bool {
			return resp.Threats[i].ExpiresAt.Before(resp.Threats[j].ExpiresAt)
		})

		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "IP\tSOURCE\tREASON\tLABEL\tEXPIRES")
		for _, t := range resp.Threats {
			label := t.Label
			if label == "" {
				label = "—"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.IP, t.Source, colorReason(t.Reason), label, t.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
		}
		_ = tw.Flush()
		fmt.Printf("\n%s\n", dim(fmt.Sprintf("%d threat(s) shared in from peers", len(resp.Threats))))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(threatsCmd)
}
