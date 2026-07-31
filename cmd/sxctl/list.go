package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type ruleView struct {
	IP        string    `json:"ip"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all active blocklist rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		var rules []ruleView
		if err := apiRequest("GET", "/api/rules", nil, &rules); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rules)
		}

		if len(rules) == 0 {
			fmt.Println("no active rules")
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "IP\tLABEL\tBLOCKED SINCE")
		for _, r := range rules {
			label := r.Label
			if label == "" {
				label = "—"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.IP, label, r.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		}
		return tw.Flush()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
