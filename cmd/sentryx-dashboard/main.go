// Command sentryx-dashboard is the icon the operator double-clicks *after*
// setup — from the Start Menu, /Applications, or the Linux Applications
// menu, exactly like Blender or any other installed app. It does not open
// "localhost:9090 in whatever browser tab happens to be around": it opens
// the dashboard in its own chromeless window (Chrome/Edge/Chromium/Brave
// "app mode" — no address bar, no tabs, its own icon in the
// Dock/Taskbar/Alt-Tab switcher), which is the same trick most
// non-Electron desktop wrappers use to avoid "it's just a website" feel.
//
// If no Chromium-family browser is installed, it falls back to opening the
// dashboard URL in the operator's normal default browser rather than doing
// nothing — a real window beats an error message.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

func main() {
	addr := flag.String("addr", ":9090", "sentryxd control API / dashboard address (must match what setup installed)")
	flag.Parse()

	url := fmt.Sprintf("http://127.0.0.1%s/", normalizeAddr(*addr))

	if err := waitForDaemon(url, 3*time.Second); err != nil {
		// sentryxd isn't up yet (not started, or setup was never finished).
		// Still open the window — the dashboard's own page handles a
		// "can't reach the API yet" state — but log why, since a
		// double-clicked GUI app has no other way to tell the operator.
		log.Printf("sentryx-dashboard: %s isn't responding yet (%v) — opening the window anyway", url, err)
	}

	if err := openAsApp(url); err != nil {
		log.Printf("sentryx-dashboard: couldn't open an app-style window (%v), falling back to your default browser", err)
		if err := openInDefaultBrowser(url); err != nil {
			log.Fatalf("sentryx-dashboard: couldn't open %s at all: %v", url, err)
		}
	}
}

func normalizeAddr(addr string) string {
	if addr == "" {
		return ":9090"
	}
	return addr
}

// waitForDaemon does one quick, short-timeout probe rather than a real
// retry loop — this binary's job is "open the window fast", not "babysit
// the daemon's startup".
func waitForDaemon(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// openAsApp tries every Chromium-family browser it can find, in order of
// how likely it is to already be installed, and launches it with --app=
// so it opens as its own undecorated window instead of a normal tab.
func openAsApp(url string) error {
	candidates := appModeCandidates()
	flagArg := "--app=" + url

	var lastErr error
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, flagArg)
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no Chromium-family browser found on PATH (tried %v)", candidates)
	}
	return lastErr
}

// appModeCandidates lists binary names to try, per OS, most-likely-present
// first. macOS/Windows browsers usually aren't on PATH by binary name the
// way Linux's are, so those two also get a couple of well-known
// absolute-path fallbacks appended in openAsApp's caller — see
// browserPaths() below.
func appModeCandidates() []string {
	names := []string{"microsoft-edge", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser"}
	switch runtime.GOOS {
	case "windows":
		names = append(names, browserPaths()...)
	case "darwin":
		names = append(names, browserPaths()...)
	}
	return names
}

// openInDefaultBrowser is the same three-line OS switch sentryx-setup's
// main.go already uses — kept here too so this binary has zero dependency
// on that one and can be shipped/upgraded independently.
func openInDefaultBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
