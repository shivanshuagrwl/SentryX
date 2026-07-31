package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/shivanshuagrwl/SentryX/internal/policy"
)

// policyCmd is the CLI half of policy-as-code: internal/policy.Apply already
// lets sentryxd itself load a policy.yaml on boot (-policy), and this adds
// the other path described in that package's own doc comment — pushing the
// same file at a *running* daemon over the REST API, without a restart.
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage SENTRYX's policy-as-code (policy.yaml) files",
}

var policyOut string

var policyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a starter policy.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if policyOut == "" || policyOut == "-" {
			fmt.Print(policy.Example)
			return nil
		}
		if _, err := os.Stat(policyOut); err == nil {
			return fmt.Errorf("%s already exists — pass a different --out path, or remove it first", policyOut)
		}
		if err := os.WriteFile(policyOut, []byte(policy.Example), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s wrote %s\n", green("✓"), bold(policyOut))
		return nil
	},
}

var policyApplyCmd = &cobra.Command{
	Use:   "apply <policy.yaml>",
	Short: "Push a policy.yaml's rules to the running daemon at --host, right now",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pol, err := policy.Load(args[0])
		if err != nil {
			return err
		}

		applied, failed := 0, 0
		for _, r := range pol.Block {
			body := map[string]any{
				"ip":             r.IP,
				"label":          r.Label,
				"rate_limit_pps": r.RateLimit,
			}
			if err := apiRequest("POST", "/api/rules", body, nil); err != nil {
				fmt.Printf("  %s %s: %v\n", red("✗"), r.IP, err)
				failed++
				continue
			}
			fmt.Printf("  %s %s\n", green("✓"), r.IP)
			applied++
		}

		// Phase 17/18: apply unconditionally, same as internal/policy.Apply
		// does for the local (sentryxd -policy) path — a missing block in
		// policy.yaml means "disable this feature", not "leave whatever
		// the daemon currently has running untouched".
		scBody := map[string]any{"low_pps": 0, "high_pps": 0}
		if pol.SynCookie != nil {
			scBody = map[string]any{"low_pps": pol.SynCookie.LowPPS, "high_pps": pol.SynCookie.HighPPS}
		}
		if err := apiRequest("PUT", "/api/syn-cookie", scBody, nil); err != nil {
			fmt.Printf("  %s syn_cookie: %v\n", red("✗"), err)
			failed++
		} else {
			fmt.Printf("  %s syn_cookie\n", green("✓"))
		}

		knockBody := map[string]any{"sequence": []uint16{}, "open_port": 0, "window_seconds": 0}
		if pol.Knock != nil {
			knockBody = map[string]any{
				"sequence":       pol.Knock.Sequence,
				"open_port":      pol.Knock.OpenPort,
				"window_seconds": pol.Knock.WindowSeconds,
			}
		}
		if err := apiRequest("PUT", "/api/knock", knockBody, nil); err != nil {
			fmt.Printf("  %s knock: %v\n", red("✗"), err)
			failed++
		} else {
			fmt.Printf("  %s knock\n", green("✓"))
		}

		fmt.Println()
		if failed == 0 {
			fmt.Printf("%s applied %d rule(s) from %s to %s\n", green("✓"), applied, args[0], daemonHost)
		} else {
			fmt.Printf("%s applied %d rule(s), %d failed — see above\n", amber("!"), applied, failed)
		}
		return nil
	},
}

func init() {
	policyInitCmd.Flags().StringVar(&policyOut, "out", "policy.yaml", "where to write the starter file (\"-\" for stdout)")
	policyCmd.AddCommand(policyInitCmd)
	policyCmd.AddCommand(policyApplyCmd)
	rootCmd.AddCommand(policyCmd)
}
