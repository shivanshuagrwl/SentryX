package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type statsView struct {
	Allowed      uint64 `json:"allowed"`
	Dropped      uint64 `json:"dropped"`
	BytesAllowed uint64 `json:"bytes_allowed"`
	BytesDropped uint64 `json:"bytes_dropped"`
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show live traffic counters",
	RunE: func(cmd *cobra.Command, args []string) error {
		var s statsView
		if err := apiRequest("GET", "/api/stats", nil, &s); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(s)
		}

		total := s.Allowed + s.Dropped
		var dropPct float64
		if total > 0 {
			dropPct = float64(s.Dropped) / float64(total) * 100
		}

		fmt.Printf("%s  %d packets  (%s)\n", green("Allowed:"), s.Allowed, humanBytes(s.BytesAllowed))
		fmt.Printf("%s  %d packets  (%s)\n", red("Dropped:"), s.Dropped, humanBytes(s.BytesDropped))

		rateColor := green
		if dropPct > 5 {
			rateColor = amber
		}
		if dropPct > 25 {
			rateColor = red
		}
		fmt.Printf("%s %s\n", bold("Drop rate:"), rateColor(fmt.Sprintf("%.2f%%", dropPct)))
		return nil
	},
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
