//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

const launchdLabel = "com.sentryx.sentryxd"

const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>-iface</string>
    <string>%s</string>
    <string>-data</string>
    <string>%s</string>
    <string>-policy</string>
    <string>%s/policy.yaml</string>
    <string>-addr</string>
    <string>%s</string>%s
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SENTRYX_TOKEN</key>
    <string>%s</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/sentryxd.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/sentryxd.err.log</string>
</dict>
</plist>
`

// installService writes a launchd plist to ~/Library/LaunchAgents and
// loads it. Deliberately a *user* LaunchAgent rather than a system-level
// LaunchDaemon in /Library/LaunchDaemons — pfctl still needs elevated
// privileges per packet-filter call (see firewall_darwin.go), which the
// wizard doesn't attempt to work around here; running `sentryx-setup`
// itself via sudo is the documented path for a fully unattended service,
// same as scripts/install.sh's Linux equivalent needing sudo.
func installService(cfg InstallConfig) (InstallResult, error) {
	envPath, err := writePolicyAndEnv(cfg)
	_ = envPath // launchd gets the token via <EnvironmentVariables> in the plist itself, not an env file
	if err != nil {
		return InstallResult{}, err
	}

	usr, err := user.Current()
	if err != nil {
		return InstallResult{}, fmt.Errorf("resolving home directory: %w", err)
	}
	agentsDir := filepath.Join(usr.HomeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		return InstallResult{}, fmt.Errorf("creating %s: %w", agentsDir, err)
	}

	dryRun := ""
	if dryRunFlag(cfg.Mode) {
		dryRun = "\n    <string>-anomaly-dry-run</string>"
	}
	plist := fmt.Sprintf(launchdPlistTemplate, launchdLabel, cfg.DaemonPath, cfg.Iface, cfg.DataDir, cfg.ConfDir, cfg.Addr, dryRun, cfg.Token)

	plistPath := filepath.Join(agentsDir, launchdLabel+".plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return InstallResult{}, fmt.Errorf("writing %s: %w", plistPath, err)
	}

	// Unload any previous run first so re-running the wizard is
	// idempotent instead of erroring on "already loaded".
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	if out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput(); err != nil {
		return InstallResult{
			ServiceInstalled: false,
			ServiceManager:   "launchd",
			DashboardURL:     "http://localhost" + cfg.Addr,
			Detail:           fmt.Sprintf("Wrote %s but `launchctl load` failed: %s. Load it manually once fixed: launchctl load %s", plistPath, string(out), plistPath),
		}, nil
	}

	return InstallResult{
		ServiceInstalled: true,
		ServiceManager:   "launchd",
		DashboardURL:     "http://localhost" + cfg.Addr,
		Detail: fmt.Sprintf(
			"sentryxd is installed and running as a launchd agent (%s). Note: pf rule changes still need root — run sentryxd under sudo if Block/Unblock calls fail with a permissions error. Manage it with: launchctl list | grep sentryx",
			launchdLabel),
	}, nil
}
