package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// resolveBinaries finds a usable sentryxd + sxctl for this OS/arch,
// trying three places in order, cheapest/most-offline-friendly first:
//
//  1. Right next to sentryx-setup itself — the "download one archive
//     containing all three binaries, double-click sentryx-setup" flow,
//     which needs no network access at all once that archive is on disk.
//  2. Already on PATH — covers an operator who built from source with
//     `make all` and has bin/ on PATH, or a previous install.
//  3. Downloaded fresh from releaseBase (Phase 27.3's cross-compiled
//     release binaries) — the true "download one *file*" flow from the
//     roadmap, for whichever OS/arch this wizard itself is running on.
//
// Returns the resolved paths plus a human-readable note about which path
// was used, so the wizard can be transparent about it on the done screen
// instead of it being invisible magic.
func resolveBinaries(releaseBase string) (daemonPath, cliPath, note string, err error) {
	daemonName, cliName := binaryNames()

	// "Bundled next to sentryx-setup" is always trusted without a version
	// check: it's exactly the pair the installer package (the .exe/.pkg/
	// .deb built from this same tag) shipped sentryx-setup with, so it's
	// current by construction — re-downloading it would just be a wasted
	// round trip to fetch the file already sitting on disk.
	if d, c, ok := findBeside(daemonName, cliName); ok {
		return d, c, "Found sentryxd/sxctl bundled next to sentryx-setup.", nil
	}

	// A copy already on PATH is a different story — it could be a
	// previous install from months ago. Blindly reusing it is exactly
	// how re-running the wizard used to leave an operator on an old
	// version with no indication anything was stale. Check its
	// reported version against this wizard's own build version before
	// trusting it.
	if d, c, ok := findOnPath(daemonName, cliName); ok {
		if isCurrent(d, c) {
			return d, c, "Found an existing sentryxd/sxctl on PATH, already up to date.", nil
		}
		note = fmt.Sprintf("Found sentryxd/sxctl on PATH, but at an older version than this installer (%s) — fetching the current release instead. ", version)
	}

	d, c, dlErr := downloadRelease(releaseBase, daemonName, cliName)
	if dlErr != nil {
		if daemonPath, cliPath, ok := findOnPath(daemonName, cliName); ok {
			// Couldn't confirm/fetch the latest release (offline, proxy,
			// GitHub unreachable) — fall back to the stale-but-working
			// PATH copy rather than leaving the operator with nothing,
			// but say so plainly instead of pretending it's current.
			return daemonPath, cliPath, note + fmt.Sprintf("Could not check for a newer release (%v); continuing with the existing install.", dlErr), nil
		}
		return "", "", "", fmt.Errorf("not bundled locally, not on PATH, and download failed: %w", dlErr)
	}
	return d, c, note + "Downloaded the latest sentryxd/sxctl from " + releaseBase + ".", nil
}

// isCurrent shells out to `sentryxd -version` / `sxctl version` and
// compares the result against sentryx-setup's own build version. Any
// failure to determine the installed version (binary predates the
// -version/version flag, unreadable output, etc.) is treated as "not
// current" — erring toward re-fetching a known-good release rather than
// silently trusting a binary sentryx-setup can't identify.
func isCurrent(daemonPath, cliPath string) bool {
	if version == "" || version == "dev" {
		// sentryx-setup itself wasn't built with a real version (a local
		// `go run`/`make all` build) — there's nothing meaningful to
		// compare against, so don't churn re-downloading on every run.
		return true
	}
	dv, err := exec.Command(daemonPath, "-version").Output()
	if err != nil {
		return false
	}
	cv, err := exec.Command(cliPath, "version").Output()
	if err != nil {
		return false
	}
	return normalizeVersion(dv) == normalizeVersion(version) && normalizeVersion(cv) == normalizeVersion(version)
}

func normalizeVersion(v any) string {
	var s string
	switch t := v.(type) {
	case []byte:
		s = string(t)
	case string:
		s = t
	}
	s = strings.TrimSpace(s)
	return strings.TrimPrefix(s, "v")
}

// binaryNames returns the Makefile dist-target filenames for this
// OS/arch — see the `dist` target in the Makefile for the exact naming
// convention these need to match.
func binaryNames() (daemon, cli string) {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	daemon = fmt.Sprintf("sentryxd-%s-%s%s", runtime.GOOS, runtime.GOARCH, suffix)
	cli = fmt.Sprintf("sxctl-%s-%s%s", runtime.GOOS, runtime.GOARCH, suffix)
	return
}

func findBeside(daemonName, cliName string) (daemonPath, cliPath string, ok bool) {
	self, err := os.Executable()
	if err != nil {
		return "", "", false
	}
	dir := filepath.Dir(self)
	// Accept both the exact release-asset filename ("sentryxd-linux-amd64")
	// and a plain generic name ("sentryxd"/"sentryxd.exe") sitting next to
	// sentryx-setup, since a hand-built `make all` produces the latter.
	genericDaemon, genericCLI := "sentryxd", "sxctl"
	if runtime.GOOS == "windows" {
		genericDaemon, genericCLI = "sentryxd.exe", "sxctl.exe"
	}
	for _, cand := range [][2]string{{daemonName, cliName}, {genericDaemon, genericCLI}} {
		d := filepath.Join(dir, cand[0])
		c := filepath.Join(dir, cand[1])
		if fileExists(d) && fileExists(c) {
			return d, c, true
		}
	}
	return "", "", false
}

func findOnPath(daemonName, cliName string) (daemonPath, cliPath string, ok bool) {
	genericDaemon, genericCLI := "sentryxd", "sxctl"
	d, errD := exec.LookPath(genericDaemon)
	c, errC := exec.LookPath(genericCLI)
	_ = daemonName
	_ = cliName
	if errD == nil && errC == nil {
		return d, c, true
	}
	return "", "", false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// downloadRelease fetches both binaries from releaseBase/<name> into a
// per-user cache directory and marks them executable. releaseBase follows
// GitHub's "latest release" download convention, e.g.
// https://github.com/<owner>/<repo>/releases/latest/download — the same
// URL shape scripts/install.sh (Phase 27.4) uses.
func downloadRelease(releaseBase, daemonName, cliName string) (daemonPath, cliPath string, err error) {
	cacheDir := filepath.Join(os.TempDir(), "sentryx-setup-download")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", "", fmt.Errorf("creating cache dir %s: %w", cacheDir, err)
	}

	daemonPath = filepath.Join(cacheDir, daemonName)
	cliPath = filepath.Join(cacheDir, cliName)

	if err := downloadFile(releaseBase+"/"+daemonName, daemonPath); err != nil {
		return "", "", fmt.Errorf("downloading %s: %w", daemonName, err)
	}
	if err := downloadFile(releaseBase+"/"+cliName, cliPath); err != nil {
		return "", "", fmt.Errorf("downloading %s: %w", cliName, err)
	}
	return daemonPath, cliPath, nil
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s fetching %s", resp.Status, url)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Chmod(0o755) // no-op on Windows, needed for the binary to run at all on Linux/macOS
}
