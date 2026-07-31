package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

// activityView mirrors firewall.Activity.
type activityView struct {
	IP         string  `json:"ip"`
	Packets    uint64  `json:"packets"`
	SynPackets uint64  `json:"syn_packets"`
	Bytes      uint64  `json:"bytes"`
	SynRatio   float64 `json:"syn_ratio"`
}

var activityTop int

// activityCmd exposes the kernel's raw per-IP activity window — the same
// counters the anomaly detector reads — sorted by packet count, so an
// operator can eyeball "what's actually talking to this box right now"
// without waiting for the detector to flag anything.
var activityCmd = &cobra.Command{
	Use:   "activity",
	Short: "Show the live per-source-IP traffic window (top talkers)",
	RunE: func(cmd *cobra.Command, args []string) error {
		var snap map[string]activityView
		if err := apiRequest("GET", "/api/activity", nil, &snap); err != nil {
			return err
		}

		rows := make([]activityView, 0, len(snap))
		for _, a := range snap {
			rows = append(rows, a)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Packets > rows[j].Packets })
		if activityTop > 0 && len(rows) > activityTop {
			rows = rows[:activityTop]
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}

		if len(rows) == 0 {
			fmt.Println(dim("no activity recorded yet"))
			return nil
		}

		fmt.Println(bold("IP                 PACKETS      SYN%    BYTES"))
		for _, a := range rows {
			synCol := dim
			if a.SynRatio >= 0.9 {
				synCol = red
			} else if a.SynRatio >= 0.5 {
				synCol = amber
			}
			fmt.Printf("%-18s %-12d %-8s %s\n",
				a.IP, a.Packets, synCol(fmt.Sprintf("%.0f%%", a.SynRatio*100)), humanBytes(a.Bytes))
		}
		return nil
	},
}

func init() {
	activityCmd.Flags().IntVarP(&activityTop, "top", "n", 15, "show only the top N sources by packet count (0 = all)")
	rootCmd.AddCommand(activityCmd)
}
