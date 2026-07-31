package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

// dnsResolution mirrors dnsresolve.Resolution.
type dnsResolution struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

// dnsResp mirrors the JSON shape of GET /api/dns in server.go.
type dnsResp struct {
	Enabled     bool            `json:"enabled"`
	Domains     []string        `json:"domains"`
	Resolutions []dnsResolution `json:"resolutions"`
}

// dnsCmd shows Phase 19's current state: which domains are configured and
// which IPs are presently blocked because they resolved to one of them —
// the same "why is this IP blocked" question `sxctl why` answers, but
// starting from the domain name side instead of the address.
var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Show Phase 19 DNS-based blocking status",
	Long: `Shows the domain list configured via policy.yaml's dns: section and
every IP currently blocked because it resolved to one of them.

Remember the honest limitation: this blocks *resolved IPs*, not domains
themselves. A client using DoH/DoT, or a domain behind an IP-rotating CDN
that rotates faster than -dns-refresh, can evade it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var resp dnsResp
		if err := apiRequest("GET", "/api/dns", nil, &resp); err != nil {
			return err
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(resp)
		}

		if !resp.Enabled {
			fmt.Println(dim("dns-block disabled — configure dns.blocked_domains in policy.yaml"))
			return nil
		}

		fmt.Printf("%s domain(s) configured: %s\n\n", bold(fmt.Sprintf("%d", len(resp.Domains))), gray(fmt.Sprint(resp.Domains)))

		if len(resp.Resolutions) == 0 {
			fmt.Println(dim("no IPs currently blocked via DNS resolution"))
			return nil
		}

		sort.Slice(resp.Resolutions, func(i, j int) bool {
			if resp.Resolutions[i].Domain != resp.Resolutions[j].Domain {
				return resp.Resolutions[i].Domain < resp.Resolutions[j].Domain
			}
			return resp.Resolutions[i].IP < resp.Resolutions[j].IP
		})

		fmt.Println(bold("DOMAIN                          IP"))
		for _, r := range resp.Resolutions {
			fmt.Printf("%-32s %s\n", r.Domain, r.IP)
		}
		fmt.Printf("\n%s\n", dim(fmt.Sprintf("%d IP(s) blocked total", len(resp.Resolutions))))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
}
