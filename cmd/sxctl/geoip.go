package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// geoRuleView mirrors firewall.GeoRule.
type geoRuleView struct {
	CIDR      string    `json:"cidr"`
	Country   string    `json:"country"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// geoipCmd is the parent for Phase 20 GeoIP blocking commands. Blocking
// itself is policy-driven (see the `geoip:` section in policy.yaml /
// `sxctl policy init`) rather than a one-off `sxctl geoip block <cc>` —
// country ranges come from a live feed (internal/geoip), so a manually
// added CIDR would just get reconciled away on the next refresh unless
// it's actually in the configured country list.
var geoipCmd = &cobra.Command{
	Use:   "geoip",
	Short: "Inspect Phase 20 GeoIP (country-level CIDR) blocking",
}

var geoipListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every currently blocked GeoIP CIDR range",
	RunE: func(cmd *cobra.Command, args []string) error {
		var rules []geoRuleView
		if err := apiRequest("GET", "/api/geoip", nil, &rules); err != nil {
			return err
		}
		sort.Slice(rules, func(i, j int) bool {
			if rules[i].Country != rules[j].Country {
				return rules[i].Country < rules[j].Country
			}
			return rules[i].CIDR < rules[j].CIDR
		})

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rules)
		}

		if len(rules) == 0 {
			fmt.Println(dim("no GeoIP ranges blocked — configure geoip.blocked_countries in policy.yaml"))
			return nil
		}

		fmt.Println(bold("COUNTRY  CIDR                LABEL"))
		for _, r := range rules {
			fmt.Printf("%-8s %-19s %s\n", r.Country, r.CIDR, r.Label)
		}
		fmt.Printf("\n%s\n", dim(fmt.Sprintf("%d range(s) total", len(rules))))
		return nil
	},
}

func init() {
	geoipCmd.AddCommand(geoipListCmd)
	rootCmd.AddCommand(geoipCmd)
}
