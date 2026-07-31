package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	if d, c, ok := findBeside(daemonName, cliName); ok {
		return d, c, "Found sentryxd/sxctl bundled next to sentryx-setup.", nil
	}

	if d, c, ok := findOnPath(daemonName, cliName); ok {
		return d, c, "Found an existing sentryxd/sxctl already on PATH.", nil
	}

	d, c, err := downloadRelease(releaseBase, daemonName, cliName)
	if err != nil {
		return "", "", "", fmt.Errorf("not bundled locally, not on PATH, and download failed: %w", err)
	}
	return d, c, "Downloaded sentryxd/sxctl from " + releaseBase + ".", nil
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
