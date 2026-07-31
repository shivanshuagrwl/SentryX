//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const systemdUnitTemplate = `[Unit]
Description=SENTRYX — kernel-speed XDP packet interdiction daemon
Documentation=https://github.com/shivanshuagrwl/SentryX
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%s
ExecStart=%s -iface %s -data %s -policy %s/policy.yaml -addr %s%s

AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN
NoNewPrivileges=true

Restart=on-failure
RestartSec=2s
TimeoutStopSec=10s

[Install]
WantedBy=multi-user.target
`

// installService writes /etc/systemd/system/sentryxd.service and enables
// it. If the process isn't root (a very likely case for a double-clicked
// GUI installer), this still writes every file it can — policy.yaml,
// sentryx.env — and returns a clear, actionable error instead of a
// permission-denied stack trace, so the wizard's done screen can tell the
// operator exactly what to run manually to finish.
func installService(cfg InstallConfig) (InstallResult, error) {
	envPath, err := writePolicyAndEnv(cfg)
	if err != nil {
		return InstallResult{}, err
	}

	dryRun := ""
	if dryRunFlag(cfg.Mode) {
		dryRun = " -anomaly-dry-run"
	}
	unit := fmt.Sprintf(systemdUnitTemplate, envPath, cfg.DaemonPath, cfg.Iface, cfg.DataDir, cfg.ConfDir, cfg.Addr, dryRun)

	unitPath := "/etc/systemd/system/sentryxd.service"
	if os.Geteuid() != 0 {
		// Best-effort: still hand back a fully-formed unit file next to
		// the config so `sudo cp` is the only remaining step, rather than
		// silently doing nothing.
		fallback := filepath.Join(cfg.ConfDir, "sentryxd.service")
		_ = os.WriteFile(fallback, []byte(unit), 0o644)
		return InstallResult{
			ServiceInstalled: false,
			ServiceManager:   "systemd",
			DashboardURL:     "http://localhost" + cfg.Addr,
			Detail: fmt.Sprintf(
				"Not running as root, so systemd wasn't touched. A ready-to-install unit file was written to %s — finish with:\n"+
					"  sudo cp %s %s && sudo systemctl daemon-reload && sudo systemctl enable --now sentryxd",
				fallback, fallback, unitPath),
		}, nil
	}

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return InstallResult{}, fmt.Errorf("writing %s: %w", unitPath, err)
	}

	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", "sentryxd"},
	} {
		cmd := exec.Command("systemctl", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return InstallResult{}, fmt.Errorf("systemctl %v: %w (%s)", args, err, string(out))
		}
	}

	return InstallResult{
		ServiceInstalled: true,
		ServiceManager:   "systemd",
		DashboardURL:     "http://localhost" + cfg.Addr,
		Detail:           "sentryxd is installed and running as a systemd service (sentryxd.service). Check status with: systemctl status sentryxd",
	}, nil
}
