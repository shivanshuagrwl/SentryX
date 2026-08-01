// Command sxctl is the operator CLI for SENTRYX. It's a thin HTTP client
// over the daemon's REST API — it never touches eBPF maps directly, so it
// works exactly the same whether the daemon is on localhost or a remote box.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	daemonHost string
	authToken  string
	jsonOutput bool
)

// version is overridden via -ldflags "-X main.version=..." by `make dist` /
// the release workflow — same pattern as cmd/sentryxd. sentryx-setup's
// resolveBinaries shells out to `sxctl version` when it finds a copy
// already on PATH, so it can tell a current install from a stale one
// instead of silently reusing whatever happens to be there.
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print sxctl's version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var rootCmd = &cobra.Command{
	Use:   "sxctl",
	Short: "SENTRYX control CLI — manage a running sentryxd instance",
	Long: `sxctl talks to a running sentryxd daemon over its REST API to
block/unblock addresses, set rate limits, and read live traffic stats.`,
}

func main() {
	rootCmd.PersistentFlags().StringVar(&daemonHost, "host", envOr("SENTRYX_HOST", "http://localhost:9090"), "sentryxd API address")
	rootCmd.PersistentFlags().StringVar(&authToken, "token", defaultToken(), "API auth token")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output raw JSON instead of a formatted table")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// defaultToken picks the token sxctl uses when --token isn't passed
// explicitly. $SENTRYX_TOKEN wins if set; otherwise, since sxctl is most
// often run on the same box the daemon is installed on, fall back to
// reading it straight out of the sentryx.env file scripts/install.sh and
// sentryx-setup already generate — same idea as the shell snippet the
// README/install.sh output tells people to run by hand
// (`export SENTRYX_TOKEN=$(grep ... | cut -d= -f2)`), just done for them.
//
// This is deliberately best-effort: sentryx.env is chmod 0600 and
// typically root-owned, so a non-root invocation simply won't be able to
// read it and authToken stays empty — no different than today, just one
// less manual step for the common "I'm root/sudo on this box" case.
func defaultToken() string {
	if v := os.Getenv("SENTRYX_TOKEN"); v != "" {
		return v
	}
	for _, path := range candidateEnvFiles() {
		if tok := readTokenFromEnvFile(path); tok != "" {
			return tok
		}
	}
	return ""
}

// candidateEnvFiles mirrors defaultConfDir() in cmd/sentryx-setup/install.go
// so sxctl looks in the exact same place install.sh / sentryx-setup wrote
// sentryx.env, per OS.
func candidateEnvFiles() []string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return []string{base + `\SENTRYX\sentryx.env`}
	case "darwin":
		return []string{"/usr/local/etc/sentryx/sentryx.env"}
	default:
		return []string{"/etc/sentryx/sentryx.env"}
	}
}

// readTokenFromEnvFile parses a single SENTRYX_TOKEN=... line out of a
// sentryx.env-shaped file. Returns "" (never an error) on any problem —
// missing file, permission denied, no such key — since this is only ever
// a convenience fallback, not something that should ever block sxctl from
// starting.
func readTokenFromEnvFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "SENTRYX_TOKEN=") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "SENTRYX_TOKEN="))
	}
	return ""
}

// apiRequest performs an HTTP call against the daemon and decodes the JSON
// response into out (pass nil to discard the body).
func apiRequest(method, path string, body any, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyBytes = b
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// A fresh request is built on every attempt (the body reader is
	// re-created from bodyBytes each time) so a transient failure — the
	// daemon mid-restart, a momentary network blip — gets three tries
	// with a short exponential backoff before sxctl gives up. A real 4xx
	// from the daemon still surfaces immediately below; only the
	// "couldn't even reach it" case gets retried here.
	var resp *http.Response
	doErr := retryBackoff(3, func() error {
		var reader io.Reader
		if bodyBytes != nil {
			reader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, daemonHost+path, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if authToken != "" {
			req.Header.Set("Authorization", "Bearer "+authToken)
		}
		resp, err = client.Do(req)
		return err
	})
	if doErr != nil {
		return fmt.Errorf("could not reach sentryxd at %s: %w", daemonHost, doErr)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if authToken == "" {
			return fmt.Errorf(
				"%s at %s (no token set) — sxctl looks for one in $SENTRYX_TOKEN or %s automatically; "+
					"if that file isn't readable here, pass one explicitly with --token or `export SENTRYX_TOKEN=...`",
				resp.Status, daemonHost, strings.Join(candidateEnvFiles(), " / "))
		}
		return fmt.Errorf("%s at %s — the token in use was rejected; check it matches SENTRYX_TOKEN in %s on the machine running sentryxd",
			resp.Status, daemonHost, strings.Join(candidateEnvFiles(), " / "))
	}

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}

	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
