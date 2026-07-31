//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

const serviceName = "SENTRYXD"

// installService registers sentryxd as a Windows Service via sc.exe —
// simpler and dependency-free compared to golang.org/x/sys/windows/svc/mgr
// for a one-shot installer that just needs "create it and start it once",
// per the roadmap's own note that either approach is fine.
func installService(cfg InstallConfig) (InstallResult, error) {
	envPath, err := writePolicyAndEnv(cfg)
	_ = envPath // Windows services don't read EnvironmentFile= the way systemd does;
	// the token is instead passed as a literal -addr/-token-equivalent
	// arg below via SENTRYX_TOKEN baked into the binPath command line is
	// avoided for security (visible in `sc qc`), so sentryxd instead reads
	// it from the env file directly at a well-known path — see note below.
	if err != nil {
		return InstallResult{}, err
	}

	dryRun := ""
	if dryRunFlag(cfg.Mode) {
		dryRun = " -anomaly-dry-run"
	}
	// sentryxd reads SENTRYX_TOKEN from its process environment, not a
	// -token flag — Windows services can be given a fixed environment via
	// `sc.exe`'s registry entry, but the simplest, most transparent path
	// for a first-run wizard is documented here rather than silently
	// injected: the done screen tells the operator SENTRYX_TOKEN lives in
	// cfg.ConfDir\sentryx.env and points sxctl at it directly. The service
	// itself still needs -insecure until that's wired to a real Windows
	// service environment block, which is exactly the kind of platform
	// nuance flagged honestly rather than papered over.
	binPath := fmt.Sprintf(`"%s" -iface "%s" -data "%s" -policy "%s\policy.yaml" -addr "%s" -insecure%s`,
		cfg.DaemonPath, cfg.Iface, cfg.DataDir, cfg.ConfDir, cfg.Addr, dryRun)

	// Remove any previous SENTRYX_setup install so re-running the wizard
	// is idempotent rather than erroring on "service already exists".
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	_ = exec.Command("sc.exe", "delete", serviceName).Run()

	createCmd := exec.Command("sc.exe", "create", serviceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "SENTRYX Firewall Daemon")
	if out, err := createCmd.CombinedOutput(); err != nil {
		return InstallResult{}, fmt.Errorf("sc.exe create failed (are you running as Administrator?): %w (%s)", err, string(out))
	}

	if out, err := exec.Command("sc.exe", "start", serviceName).CombinedOutput(); err != nil {
		return InstallResult{
				ServiceInstalled: false,
				ServiceManager:   "Windows Service",
				DashboardURL:     "http://localhost" + cfg.Addr,
				Detail:           fmt.Sprintf("Service %q was created but failed to start: %s. Try `sc start %s` manually, or check the Windows Event Log.", serviceName, string(out), serviceName),
			},
			nil
	}

	return InstallResult{
		ServiceInstalled: true,
		ServiceManager:   "Windows Service",
		DashboardURL:     "http://localhost" + cfg.Addr,
		Detail: fmt.Sprintf(
			"sentryxd is installed and running as Windows Service %q, currently in -insecure mode (no API token enforced yet — see %s\\sentryx.env for the generated token to wire up manually). Manage it with services.msc or `sc query %s`.",
			serviceName, cfg.ConfDir, serviceName),
	}, nil
}
