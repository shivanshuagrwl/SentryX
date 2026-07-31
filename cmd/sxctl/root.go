// Command sxctl is the operator CLI for SENTRYX. It's a thin HTTP client
// over the daemon's REST API — it never touches eBPF maps directly, so it
// works exactly the same whether the daemon is on localhost or a remote box.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	rootCmd.PersistentFlags().StringVar(&authToken, "token", os.Getenv("SENTRYX_TOKEN"), "API auth token")
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
