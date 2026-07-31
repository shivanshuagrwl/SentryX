package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/shivanshu-agarwal/sentryx/internal/firewall"
)

// doctorIface lets an operator check a specific NIC's XDP support; empty
// (the default) skips the interface-specific checks rather than failing
// them, since "no interface chosen yet" is a normal state before install.
var doctorIface string

// doctorCmd is deliberately a local, unprivileged, no-daemon-required
// command: it runs entirely against this machine (file reads +
// exec.LookPath/exec.Command, see internal/firewall/doctor.go), not
// against a running sentryxd's REST API — the whole point is answering
// "will sentryxd actually run here" *before* one exists to talk to.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Pre-flight check: will sentryxd actually run on this machine",
	Long: `Runs a battery of local checks — OS/kernel version, build toolchain,
network interface + XDP attach mode, root/capabilities, and container/WSL2
detection — and prints a clear PASS/WARN/FAIL/SKIP per line.

This never loads a BPF program, opens a raw socket, or touches a kernel
map — it's safe to run unprivileged, and safe to run before sentryxd has
ever been installed. Exit code is non-zero if any check FAILs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		checks := firewall.RunDoctor(doctorIface)

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(checks); err != nil {
				return err
			}
		} else {
			printDoctorReport(checks)
		}

		if firewall.AnyFailed(checks) {
			os.Exit(1)
		}
		return nil
	},
}

func printDoctorReport(checks []firewall.Check) {
	fmt.Println(bold("SENTRYX pre-flight check"))
	fmt.Println()
	for _, c := range checks {
		fmt.Printf("%s  %-38s %s\n", doctorBadge(c.Status), c.Name, gray(c.Detail))
	}
	fmt.Println()

	if firewall.AnyFailed(checks) {
		fmt.Println(red("✗ one or more checks failed — sentryxd is unlikely to run until these are fixed"))
		return
	}
	warned := false
	for _, c := range checks {
		if c.Status == firewall.StatusWarn {
			warned = true
			break
		}
	}
	if warned {
		fmt.Println(amber("~ no failures, but some checks warrant a look before you install"))
		return
	}
	fmt.Println(green("✓ looks good — sentryxd should run cleanly on this machine"))
}

func doctorBadge(s firewall.Status) string {
	switch s {
	case firewall.StatusPass:
		return green("[ PASS ]")
	case firewall.StatusWarn:
		return amber("[ WARN ]")
	case firewall.StatusFail:
		return red("[ FAIL ]")
	default:
		return gray("[ SKIP ]")
	}
}

func init() {
	doctorCmd.Flags().StringVar(&doctorIface, "iface", "", "network interface to check XDP support for (optional)")
	rootCmd.AddCommand(doctorCmd)
}
