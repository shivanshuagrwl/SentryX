// Command sentryx-setup is SENTRYX's Phase 28 GUI installer: a small,
// standalone binary whose only job is "download one file → double-click →
// clicky-clicky → running", no terminal required. On launch it starts a
// tiny local HTTP server, opens the operator's default browser to it, and
// serves a single-page wizard (plain HTML/CSS/JS — no framework, styled to
// match web/dashboard/index.html) that walks through picking an
// interface and a mode, then installs sentryxd as a proper OS service.
//
// This binary is deliberately separate from sentryxd and sxctl — it's a
// bootstrapper, not a long-running app, and exits once install completes.
// The dashboard the operator lands on afterward is sentryxd's own
// web/dashboard, not a second UI this package has to maintain.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var version = "dev" // overridden via -ldflags "-X main.version=..." by `make dist`

//go:embed wizard/index.html wizard/favicon.png wizard/brand-mark.png
var wizardFS embed.FS

func main() {
	var (
		port        = flag.Int("port", 0, "port to serve the wizard on (0 = pick a free port automatically)")
		openBrowser = flag.Bool("open", true, "open the default browser automatically")
		releaseBase = flag.String("release-base", "https://github.com/shivanshu-agarwal/sentryx/releases/latest/download", "base URL release binaries are downloaded from if not found locally")
		addr        = flag.String("api-addr", ":9090", "address sentryxd's control API will listen on once installed")
	)
	flag.Parse()

	listener, actualPort, err := listen(*port)
	if err != nil {
		log.Fatalf("sentryx-setup: couldn't bind a local port: %v", err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", actualPort)

	mux := http.NewServeMux()
	registerRoutes(mux, wizardConfig{releaseBase: *releaseBase, daemonAddr: *addr})

	srv := &http.Server{Handler: mux}

	fmt.Printf("\nSENTRYX setup wizard (%s) — %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Serving the installer at %s\n", url)
	fmt.Println("Leave this window open until setup finishes.")
	fmt.Println()

	if *openBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond) // give the listener a beat before the browser hits it
			if err := openInBrowser(url); err != nil {
				log.Printf("couldn't auto-open a browser (%v) — open %s manually", err, url)
			}
		}()
	}

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("sentryx-setup: server error: %v", err)
	}
}

// listen binds the requested port, or a random free one if port == 0 —
// this is what makes "download → double-click" work without ever asking
// the operator to pick a port themselves.
func listen(port int) (net.Listener, int, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, 0, err
	}
	return l, l.Addr().(*net.TCPAddr).Port, nil
}

// openInBrowser is the three-line OS switch the roadmap calls for —
// nothing fancier is needed.
func openInBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default: // linux and anything else with an XDG-compliant desktop
		return exec.Command("xdg-open", url).Start()
	}
}

// registerRoutes wires the wizard's static page and its step-by-step API.
func registerRoutes(mux *http.ServeMux, cfg wizardConfig) {
	sub, err := fs.Sub(wizardFS, "wizard")
	if err != nil {
		log.Fatalf("sentryx-setup: embedded wizard assets missing: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/info", cfg.handleInfo)
	mux.HandleFunc("GET /api/interfaces", cfg.handleInterfaces)
	mux.HandleFunc("POST /api/install", cfg.handleInstall)
}

type wizardConfig struct {
	releaseBase string
	daemonAddr  string
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleInfo backs Step 1 — Welcome + OS/arch auto-detect. The wizard
// doesn't ask the operator to choose anything here; the server already
// knows runtime.GOOS/GOARCH, which is also exactly what picks the right
// release asset in handleInstall below.
func (cfg wizardConfig) handleInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      version,
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"hostname":     hostname,
		"conf_dir":     defaultConfDir(),
		"data_dir":     defaultDataDir(),
		"daemon_addr":  cfg.daemonAddr,
		"service_kind": serviceKindLabel(),
	})
}

func serviceKindLabel() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows Service"
	case "darwin":
		return "launchd agent"
	default:
		return "systemd service"
	}
}
