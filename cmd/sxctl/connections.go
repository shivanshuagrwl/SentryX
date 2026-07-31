package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// connectionView mirrors firewall.Connection.
type connectionView struct {
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	SrcPort  uint16    `json:"src_port"`
	DstPort  uint16    `json:"dst_port"`
	Proto    string    `json:"proto"`
	State    uint8     `json:"state"`
	StateStr string    `json:"state_str"`
	SynCount uint32    `json:"syn_count"`
	LastSeen time.Time `json:"last_seen"`
}

var connState string

// connectionsCmd surfaces the kernel's Phase 16 connection-tracking table
// — every flow SENTRYX currently holds state for, regardless of whether
// either side is separately blocked. This is "what does the kernel think
// is currently talking to this box, and how far into a handshake is it",
// as opposed to `sxctl activity`'s raw per-IP packet/byte counters.
var connectionsCmd = &cobra.Command{
	Use:     "connections",
	Aliases: []string{"conns"},
	Short:   "Show actively tracked TCP connections (Phase 16 conn_table)",
	RunE: func(cmd *cobra.Command, args []string) error {
		var conns []connectionView
		if err := apiRequest("GET", "/api/connections", nil, &conns); err != nil {
			return err
		}

		if connState != "" {
			filtered := conns[:0]
			for _, c := range conns {
				if c.StateStr == connState {
					filtered = append(filtered, c)
				}
			}
			conns = filtered
		}

		sort.Slice(conns, func(i, j int) bool { return conns[i].LastSeen.After(conns[j].LastSeen) })

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(conns)
		}

		if len(conns) == 0 {
			fmt.Println(dim("no tracked connections"))
			return nil
		}

		fmt.Println(bold("SRC                     DST                     STATE         SYNS  LAST SEEN"))
		for _, c := range conns {
			stateCol := dim
			switch c.StateStr {
			case "established":
				stateCol = green
			case "syn-seen":
				stateCol = amber
			case "closing":
				stateCol = gray
			}
			src := fmt.Sprintf("%s:%d", c.SrcIP, c.SrcPort)
			dst := fmt.Sprintf("%s:%d/%s", c.DstIP, c.DstPort, c.Proto)
			fmt.Printf("%-23s %-23s %-13s %-5d %s\n",
				src, dst, stateCol(c.StateStr), c.SynCount, humanAgo(c.LastSeen))
		}
		return nil
	},
}

// humanAgo renders a timestamp as a short relative duration, e.g. "4s ago".
func humanAgo(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}

func init() {
	connectionsCmd.Flags().StringVar(&connState, "state", "", "filter by state (syn-seen, established, closing)")
	rootCmd.AddCommand(connectionsCmd)
}
