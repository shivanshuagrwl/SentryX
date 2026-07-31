// Phase 27.1 — `sxctl doctor`. A pre-flight command that answers "will
// sentryxd actually run here" *before* an operator hits a cryptic BPF-load
// error three steps into setup. Every check below is pure stdlib (file
// reads + exec.LookPath/exec.Command) — no cgo, no eBPF library calls, so
// this file has no build tag and is safe to run (and gives an honest,
// mostly-Skip result) on every platform sxctl itself compiles for.
//
// This is diagnostic-only: nothing here loads a BPF program, opens a raw
// socket, or touches a kernel map. It's safe to run unprivileged, and
// safe to run before sentryxd has ever been installed.
package firewall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Status is the outcome of a single doctor check.
type Status int

const (
	StatusPass Status = iota
	StatusWarn        // not fatal, but worth the operator's attention
	StatusFail        // sentryxd is unlikely to work until this is fixed
	StatusSkip        // not applicable on this platform/configuration
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "SKIP"
	}
}

// Check is one line of `sxctl doctor` output.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"-"`
	// StatusStr mirrors Status as text so this survives a JSON round-trip
	// (sxctl's --json output, or a future GUI-installer preflight call)
	// without the caller needing to know the int encoding.
	StatusStr string `json:"status"`
	Detail    string `json:"detail"`
}

func check(name string, status Status, detail string) Check {
	return Check{Name: name, Status: status, StatusStr: status.String(), Detail: detail}
}

// RunDoctor runs every Phase 27.1 pre-flight check in order and returns
// the full report. iface may be empty — the interface-specific checks
// then report StatusSkip rather than failing, since "no interface chosen
// yet" is a normal state (e.g. running `sxctl doctor` before deciding
// which NIC to protect).
func RunDoctor(iface string) []Check {
	var out []Check
	out = append(out, checkOS())
	out = append(out, checkKernelVersion())
	out = append(out, checkBuildToolchain()...)
	out = append(out, checkInterface(iface)...)
	out = append(out, checkCapabilities())
	out = append(out, checkContainer()...)
	return out
}

// AnyFailed reports whether the report contains a StatusFail — the exit
// code `sxctl doctor` should return.
func AnyFailed(checks []Check) bool {
	for _, c := range checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// ---- 1. OS + kernel version -----------------------------------------

func checkOS() Check {
	return check("Operating system", StatusPass, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}

// checkKernelVersion requires Linux >=5.x for XDP support (BPF_LINK,
// XDP_FLAGS_UPDATE_IF_NOEXIST, and several helpers sentryx relies on all
// need a reasonably modern kernel). On non-Linux this is StatusSkip, not
// StatusFail — the control plane runs fine there, it just falls back to
// firewall_windows.go/firewall_darwin.go's OS-native filtering instead of
// XDP (see those files' package comments).
func checkKernelVersion() Check {
	if runtime.GOOS != "linux" {
		return check("Linux kernel version", StatusSkip,
			fmt.Sprintf("not applicable on %s — control plane is cross-platform, XDP data-plane acceleration is Linux-native", runtime.GOOS))
	}

	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return check("Linux kernel version", StatusWarn, "couldn't run `uname -r`: "+err.Error())
	}
	release := strings.TrimSpace(string(out))
	major, minor := parseKernelVersion(release)
	if major == 0 {
		return check("Linux kernel version", StatusWarn, fmt.Sprintf("couldn't parse kernel release %q", release))
	}
	if major >= 5 {
		return check("Linux kernel version", StatusPass, release+fmt.Sprintf(" (XDP-capable, %d.%d)", major, minor))
	}
	return check("Linux kernel version", StatusFail, release+" — XDP needs Linux 5.x or newer")
}

// parseKernelVersion pulls the leading "MAJOR.MINOR" off a `uname -r`
// string like "6.8.0-45-generic" or "5.15.0-1053-aws", ignoring
// everything after the second dot (distro build numbers, -generic
// suffixes, etc.) since only major.minor matters for the XDP feature
// checks above.
func parseKernelVersion(release string) (major, minor int) {
	fields := strings.SplitN(release, ".", 3)
	if len(fields) < 2 {
		return 0, 0
	}
	major, err1 := strconv.Atoi(fields[0])
	// fields[1] can have trailing non-digit runs on some distros
	// ("15-1053"); take the leading digit run only.
	minorStr := fields[1]
	for i, r := range minorStr {
		if r < '0' || r > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err2 := strconv.Atoi(minorStr)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return major, minor
}

// ---- 2. Build toolchain (only matters building from source) ----------

// checkBuildToolchain looks for clang/llvm/libbpf — only relevant if
// compiling bpf/xdp_sentryx.c yourself rather than running a pre-built
// release binary (Phase 27.3), so a miss here is StatusWarn, never
// StatusFail: `sxctl doctor` shouldn't tell someone running a downloaded
// binary that their machine is broken over a dependency they don't need.
func checkBuildToolchain() []Check {
	if runtime.GOOS != "linux" {
		return []Check{check("Build toolchain (clang/llvm/libbpf)", StatusSkip,
			"not applicable on "+runtime.GOOS+" — the XDP object is only compiled on Linux")}
	}

	var out []Check
	for _, tool := range []struct{ bin, purpose string }{
		{"clang", "compiles bpf/xdp_sentryx.c to BPF bytecode"},
		{"llvm-strip", "strips debug info from the compiled BPF object (optional)"},
		{"bpftool", "used by doctor's interface-mode check below, and handy for manual map inspection"},
	} {
		path, err := exec.LookPath(tool.bin)
		if err != nil {
			out = append(out, check("Build toolchain: "+tool.bin, StatusWarn,
				"not found on PATH — only needed if building from source ("+tool.purpose+")"))
			continue
		}
		out = append(out, check("Build toolchain: "+tool.bin, StatusPass, path))
	}
	return out
}

// ---- 3. Network interface + XDP mode ----------------------------------

// checkInterface confirms the chosen interface actually exists (using
// net.Interfaces() indirectly via `ip link show`, which also gives us the
// operstate for free) and, on Linux, whether it currently has an XDP
// program attached in native or generic (SKB) mode via `bpftool net`.
// Native XDP runs in the NIC driver itself (fastest); generic/SKB is the
// kernel-wide fallback every driver supports but at a real throughput
// cost — both work, but an operator debugging "why is this slower than I
// expected" wants to know which one they're getting.
func checkInterface(iface string) []Check {
	if iface == "" {
		return []Check{check("Network interface", StatusSkip, "no -iface given — pass one to check a specific NIC")}
	}
	if runtime.GOOS != "linux" {
		// firewall_windows.go/firewall_darwin.go don't scope rules to a
		// single NIC the way XDP does (see their Interface() doc
		// comments) — the concept of "does this iface support XDP"
		// simply doesn't apply, so this reports informational only.
		return []Check{check("Network interface", StatusSkip,
			fmt.Sprintf("%q is only used informationally on %s — netsh/pfctl rules aren't scoped to one NIC", iface, runtime.GOOS))}
	}

	var out []Check

	if _, err := exec.LookPath("ip"); err != nil {
		out = append(out, check("Network interface", StatusWarn, "`ip` command not found — can't verify interface "+iface))
		return out
	}

	linkOut, err := exec.Command("ip", "link", "show", iface).CombinedOutput()
	if err != nil {
		out = append(out, check("Network interface", StatusFail,
			fmt.Sprintf("interface %q not found (%s)", iface, strings.TrimSpace(string(linkOut)))))
		return out
	}
	state := "unknown"
	if strings.Contains(string(linkOut), "state UP") {
		state = "UP"
	} else if strings.Contains(string(linkOut), "state DOWN") {
		state = "DOWN"
	}
	out = append(out, check("Network interface", StatusPass, fmt.Sprintf("%s exists, link state %s", iface, state)))

	if _, err := exec.LookPath("bpftool"); err != nil {
		out = append(out, check("XDP attach mode", StatusWarn, "bpftool not found — install it to see native vs generic/SKB mode before attaching"))
		return out
	}
	netOut, err := exec.Command("bpftool", "net", "show", "dev", iface).CombinedOutput()
	if err != nil {
		out = append(out, check("XDP attach mode", StatusWarn, "bpftool net show failed: "+strings.TrimSpace(string(netOut))))
		return out
	}
	text := string(netOut)
	switch {
	case strings.Contains(text, "xdp/id") || strings.Contains(text, "xdpdrv"):
		out = append(out, check("XDP attach mode", StatusPass, "native driver-mode XDP support detected"))
	case strings.Contains(text, "xdpgeneric"):
		out = append(out, check("XDP attach mode", StatusWarn, "no XDP program currently attached in native mode — generic/SKB fallback will be used (pass -generic explicitly to acknowledge), which is correct but slower"))
	default:
		out = append(out, check("XDP attach mode", StatusPass, "no XDP program currently attached (clean slate)"))
	}
	return out
}

// ---- 4. Root / CAP_NET_ADMIN + CAP_BPF ---------------------------------

// checkCapabilities is root-or-bust on every platform sentryxd runs on —
// loading an XDP program, opening raw sockets, or writing native firewall
// rules all need elevated privileges one way or another. On Linux this
// also accepts a non-root process that specifically holds CAP_NET_ADMIN +
// CAP_BPF (read from /proc/self/status's CapEff line — no golang.org/x/sys
// dependency needed for two capability bits), since that's how a
// production deployment would run this under systemd's
// AmbientCapabilities instead of full root.
func checkCapabilities() Check {
	if runtime.GOOS != "linux" {
		if os.Geteuid() == 0 {
			return check("Privileges", StatusPass, "running as root")
		}
		return check("Privileges", StatusWarn, "not running elevated — sentryxd needs Administrator (Windows) or root (macOS) to install firewall rules")
	}

	if os.Geteuid() == 0 {
		return check("Root / CAP_NET_ADMIN+CAP_BPF", StatusPass, "running as root (uid 0)")
	}

	capEff, err := readCapEff()
	if err != nil {
		return check("Root / CAP_NET_ADMIN+CAP_BPF", StatusWarn, "not root, and couldn't read /proc/self/status to check capabilities: "+err.Error())
	}
	const (
		capNetAdmin = 12
		capBPF      = 39
	)
	hasNetAdmin := capEff&(1<<capNetAdmin) != 0
	hasBPF := capEff&(1<<capBPF) != 0
	if hasNetAdmin && hasBPF {
		return check("Root / CAP_NET_ADMIN+CAP_BPF", StatusPass, "not root, but holds CAP_NET_ADMIN + CAP_BPF")
	}
	missing := []string{}
	if !hasNetAdmin {
		missing = append(missing, "CAP_NET_ADMIN")
	}
	if !hasBPF {
		missing = append(missing, "CAP_BPF")
	}
	return check("Root / CAP_NET_ADMIN+CAP_BPF", StatusFail,
		"not root and missing "+strings.Join(missing, ", ")+" — run as root, or `setcap cap_net_admin,cap_bpf+ep` on the binary")
}

// readCapEff reads the current process's effective-capabilities bitmask
// from /proc/self/status. Pure text parsing — no cgo, no
// golang.org/x/sys/unix dependency for what's otherwise a one-line
// syscall wrapper.
func readCapEff() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "CapEff:") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			v, err := strconv.ParseUint(hex, 16, 64)
			if err != nil {
				return 0, err
			}
			return v, nil
		}
	}
	return 0, fmt.Errorf("CapEff line not found in /proc/self/status")
}

// ---- 5. Container / WSL2 detection -------------------------------------

// checkContainer fails early with a clear message instead of letting the
// operator hit a cryptic BPF-load error deep inside sentryxd — a
// container or WSL2 guest usually doesn't have real NIC access, which is
// exactly what XDP needs. This is the specific pain point Phase 27.1's
// roadmap entry calls out by name.
func checkContainer() []Check {
	if runtime.GOOS != "linux" {
		return []Check{check("Container / WSL2 environment", StatusSkip, "not applicable on "+runtime.GOOS)}
	}

	var notes []string

	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if strings.Contains(strings.ToLower(string(release)), "microsoft") {
			notes = append(notes, "WSL2 detected (/proc/sys/kernel/osrelease mentions Microsoft) — WSL2's virtualized NIC usually has no native XDP driver support; expect generic/SKB mode at best, and some WSL2 kernels lack XDP entirely")
		}
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		notes = append(notes, "Docker container detected (/.dockerenv present) — needs --privileged or explicit --cap-add=NET_ADMIN,BPF plus --network host to see the real NIC; the default bridge network namespace won't have XDP-capable access to it")
	}

	if cgroup, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		text := string(cgroup)
		if strings.Contains(text, "docker") || strings.Contains(text, "kubepods") || strings.Contains(text, "containerd") {
			notes = append(notes, "container runtime detected via /proc/1/cgroup — same host-networking caveat as above applies")
		}
	}

	if len(notes) == 0 {
		return []Check{check("Container / WSL2 environment", StatusPass, "running on bare metal or a full VM — no container/WSL2 signals detected")}
	}
	out := make([]Check, 0, len(notes))
	for _, n := range notes {
		out = append(out, check("Container / WSL2 environment", StatusWarn, n))
	}
	return out
}
