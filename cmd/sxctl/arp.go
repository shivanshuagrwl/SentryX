package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// arpAlertView mirrors firewall.ArpAlert.
type arpAlertView struct {
	IP       string    `json:"ip"`
	OldMAC   string    `json:"old_mac"`
	NewMAC   string    `json:"new_mac"`
	LastSeen time.Time `json:"last_seen"`
	Count    uint64    `json:"count"`
}

// arpCmd shows Phase 21's detection-only ARP spoofing alerts: an IP that
// claimed more than one MAC address faster than a plausible DHCP lease
// change would explain. Never auto-blocked — see bpf/xdp_sentryx.c's
// Phase 21 note — surfaced here so an operator can decide what to do
// about it manually (e.g. `sxctl block <ip>`).
var arpCmd = &cobra.Command{
	Use:   "arp",
	Short: "Show Phase 21 ARP spoof-suspected alerts",
	Long: `Shows source IPs the kernel has flagged as having claimed more than one
MAC address faster than a plausible DHCP lease change would explain.

This is detection only — it's never auto-blocked, since legitimate DHCP
renewal/failover can trigger the same signature. Investigate and block
manually with 'sxctl block <ip>' if it's actually malicious.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var alerts []arpAlertView
		if err := apiRequest("GET", "/api/arp", nil, &alerts); err != nil {
			return err
		}
		sort.Slice(alerts, func(i, j int) bool { return alerts[i].LastSeen.After(alerts[j].LastSeen) })

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(alerts)
		}

		if len(alerts) == 0 {
			fmt.Println(dim("no ARP spoof-suspected alerts"))
			return nil
		}

		fmt.Println(bold("IP                 OLD MAC            NEW MAC            COUNT  LAST SEEN"))
		for _, a := range alerts {
			fmt.Printf("%s %-18s %-18s %-18s %-6d %s\n",
				amber("~"), a.IP, a.OldMAC, a.NewMAC, a.Count, gray(a.LastSeen.Local().Format("2006-01-02 15:04:05")))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(arpCmd)
}
