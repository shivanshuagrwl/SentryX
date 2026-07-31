package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// anomalyEvent mirrors anomaly.Event.
type anomalyEvent struct {
	IP       string    `json:"ip"`
	Detected time.Time `json:"detected"`
	Metric   string    `json:"metric"`
	Rate     float64   `json:"rate"`
	Baseline float64   `json:"baseline"`
	SynRatio float64   `json:"syn_ratio"`
	Blocked  bool      `json:"blocked"`
	Label    string    `json:"label"`
}

var anomaliesCmd = &cobra.Command{
	Use:   "anomalies",
	Short: "Show the behavioral detector's recent detections",
	Long: `Shows what the EWMA-baseline anomaly detector has flagged: every
entry is self-explanatory ("14x baseline packet rate ...") because the
detector is plain statistics, not a black-box model — there's nothing to
decode. Empty output just means the detector hasn't found anything, or is
disabled (see -anomaly-dry-run on the daemon).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var events []anomalyEvent
		if err := apiRequest("GET", "/api/anomalies", nil, &events); err != nil {
			return err
		}
		sort.Slice(events, func(i, j int) bool { return events[i].Detected.After(events[j].Detected) })

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(events)
		}

		if len(events) == 0 {
			fmt.Println(dim("no anomalies detected yet"))
			return nil
		}

		for _, e := range events {
			mark := amber("~")
			verdict := dim("(dry-run, not blocked)")
			if e.Blocked {
				mark = red("✗")
				verdict = red("blocked")
			}
			fmt.Printf("%s %s  %-16s %s  %s\n",
				mark, gray(e.Detected.Local().Format("15:04:05")), bold(e.IP), e.Label, verdict)
		}
		return nil
	},
}

var baselinesCmd = &cobra.Command{
	Use:   "baselines",
	Short: `Show each IP's current "what does normal look like" baseline`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var baselines map[string]float64
		if err := apiRequest("GET", "/api/baselines", nil, &baselines); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(baselines)
		}

		if len(baselines) == 0 {
			fmt.Println(dim("no baselines tracked yet"))
			return nil
		}

		type row struct {
			ip   string
			rate float64
		}
		rows := make([]row, 0, len(baselines))
		for ip, r := range baselines {
			rows = append(rows, row{ip, r})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].rate > rows[j].rate })

		fmt.Println(bold("IP                 BASELINE (pps)"))
		for _, r := range rows {
			fmt.Printf("%-18s %.1f\n", r.ip, r.rate)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(anomaliesCmd)
	rootCmd.AddCommand(baselinesCmd)
}
