package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
)

// interfaceInfo is one entry in Step 2's picker.
type interfaceInfo struct {
	Name     string `json:"name"`
	Up       bool   `json:"up"`
	Note     string `json:"note"`           // e.g. XDP mode hint on Linux, or a loopback/virtual warning
	Warn     bool   `json:"warn,omitempty"` // true if Note is a caution rather than pure info
	Loopback bool   `json:"loopback,omitempty"`
}

// handleInterfaces backs Step 2. Uses net.Interfaces() (works identically
// on every OS sxctl/sentryxd support) rather than shelling out, so this
// never fails just because `ip`/`ifconfig` isn't on PATH — good detail is
// added on top where available (best-effort XDP-mode hint on Linux via
// bpftool, when present).
func (cfg wizardConfig) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "listing interfaces: "+err.Error())
		return
	}

	out := make([]interfaceInfo, 0, len(ifaces))
	for _, ifi := range ifaces {
		info := interfaceInfo{
			Name:     ifi.Name,
			Up:       ifi.Flags&net.FlagUp != 0,
			Loopback: ifi.Flags&net.FlagLoopback != 0,
		}
		if info.Loopback {
			info.Note = "loopback — not a real network path, skip this one"
			info.Warn = true
		} else if !info.Up {
			info.Note = "currently down"
			info.Warn = true
		} else if runtime.GOOS == "linux" {
			info.Note = linuxXDPHint(ifi.Name)
		} else {
			info.Note = "control-plane only on " + runtime.GOOS + " — see the daemon's package docs"
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

// linuxXDPHint gives a best-effort native-vs-generic XDP note using
// bpftool if it's on PATH, same idea as internal/firewall/doctor.go's
// checkInterface but condensed to a single string for the picker's inline
// hint. Never fails the request — an empty/generic hint is fine, the
// wizard doesn't block on this.
func linuxXDPHint(iface string) string {
	if _, err := exec.LookPath("bpftool"); err != nil {
		return "ready"
	}
	out, err := exec.Command("bpftool", "net", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return "ready"
	}
	text := string(out)
	switch {
	case strings.Contains(text, "xdpdrv") || strings.Contains(text, "xdp/id"):
		return "native XDP driver support detected — fastest mode"
	case strings.Contains(text, "xdpgeneric"):
		return "generic/SKB mode only — works, but not line-rate"
	default:
		return "ready, no XDP program currently attached"
	}
}

// installRequest is Step 2+3's picks, posted together to Step 4.
type installRequest struct {
	Iface string `json:"iface"`
	Mode  string `json:"mode"` // "strict" | "learning"
}

// handleInstall backs Step 4 — resolves the right binaries for this
// OS/arch (locally bundled, on PATH, or downloaded from GitHub Releases),
// writes policy.yaml + sentryx.env, and installs the OS-native service via
// installService (one implementation per OS — see install_linux.go /
// install_windows.go / install_darwin.go).
func (cfg wizardConfig) handleInstall(w http.ResponseWriter, r *http.Request) {
	var req installRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Iface == "" {
		writeErr(w, http.StatusBadRequest, "iface is required")
		return
	}
	if req.Mode != "strict" && req.Mode != "learning" {
		req.Mode = "strict"
	}

	daemonPath, cliPath, resolveNote, err := resolveBinaries(cfg.releaseBase)
	if err != nil {
		writeErr(w, http.StatusFailedDependency, "couldn't find or download sentryxd/sxctl: "+err.Error())
		return
	}

	token, err := generateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	ic := InstallConfig{
		Iface:      req.Iface,
		Mode:       req.Mode,
		DaemonPath: daemonPath,
		CLIPath:    cliPath,
		ConfDir:    defaultConfDir(),
		DataDir:    defaultDataDir(),
		Addr:       cfg.daemonAddr,
		Token:      token,
	}

	result, err := installService(ic)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	result.Detail = resolveNote + " " + result.Detail

	writeJSON(w, http.StatusOK, map[string]any{
		"result":   result,
		"token":    token,
		"conf_dir": ic.ConfDir,
		"cli_path": ic.CLIPath,
	})
}
