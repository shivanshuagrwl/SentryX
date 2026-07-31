package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/shivanshuagrwl/SentryX/internal/policy"
)

// node is one daemon a controller run talks to. It's intentionally the same
// shape whether it comes from a local box or one three continents away —
// sxctl only ever talks to sentryxd over its REST API, never anything
// lower-level, so "distributed" here just means "more than one host".
type node struct {
	Name  string
	Host  string
	Token string
}

// loadNodes parses a nodes.yaml file. It deliberately reuses the same tiny,
// dependency-free subset of YAML as policy.go (2-space list indent, one
// key per line, no flow style) rather than pulling in a real YAML library
// for a file this simple:
//
//	nodes:
//	  - name: edge-1
//	    host: http://10.0.0.11:9090
//	    token: env:SENTRYX_TOKEN_EDGE1
//	  - name: edge-2
//	    host: http://10.0.0.12:9090
//
// A token value of "env:NAME" is resolved from that environment variable at
// load time, so real tokens never have to live in the file itself. An empty
// or missing token means that node is running -insecure.
func loadNodes(path string) ([]node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read nodes file: %w", err)
	}
	defer f.Close()

	var nodes []node
	var cur *node

	flush := func() {
		if cur != nil {
			nodes = append(nodes, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if trimmed == "" {
			continue
		}

		switch {
		case trimmed == "nodes:":
			flush()
		case strings.HasPrefix(trimmed, "- "):
			flush()
			cur = &node{}
			if err := setNodeField(cur, strings.TrimPrefix(trimmed, "- "), path, lineNo); err != nil {
				return nil, err
			}
		case cur != nil:
			if err := setNodeField(cur, trimmed, path, lineNo); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("nodes %s:%d: unexpected line %q", path, lineNo, raw)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}

	for i, n := range nodes {
		if n.Host == "" {
			return nil, fmt.Errorf("nodes %s: entry %d is missing a host", path, i)
		}
		if n.Name == "" {
			nodes[i].Name = n.Host
		}
	}
	return nodes, nil
}

func setNodeField(n *node, kv, path string, lineNo int) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("nodes %s:%d: expected key: value, got %q", path, lineNo, kv)
	}
	key = strings.TrimSpace(key)
	// strings.Cut only splits on the *first* ':', so a value like
	// "http://10.0.0.11:9090" survives intact in val.
	val = strings.TrimSpace(val)

	switch key {
	case "name":
		n.Name = val
	case "host":
		n.Host = strings.TrimSuffix(val, "/")
	case "token":
		if strings.HasPrefix(val, "env:") {
			n.Token = os.Getenv(strings.TrimPrefix(val, "env:"))
		} else {
			n.Token = val
		}
	default:
		return fmt.Errorf("nodes %s:%d: unknown field %q", path, lineNo, key)
	}
	return nil
}

// nodeResult is one node's outcome from a controller push or status check.
type nodeResult struct {
	Node    node
	Applied int
	Errs    []error
	Up      bool
	Iface   string
}

func pushToNode(n node, pol *policy.Policy, timeout time.Duration) nodeResult {
	res := nodeResult{Node: n}
	client := buildHTTPClient(timeout)

	for _, r := range pol.Block {
		body := map[string]any{
			"ip":              r.IP,
			"label":           r.Label,
			"rate_limit_pps":  r.RateLimit,
			"rate_limit_kbps": r.BandwidthLimit,
		}
		err := retryBackoff(3, func() error {
			return nodeRequest(client, n, "POST", "/api/rules", body)
		})
		if err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("%s: %w", r.IP, err))
			continue
		}
		res.Applied++
	}
	return res
}

func checkNode(n node, timeout time.Duration) nodeResult {
	res := nodeResult{Node: n}
	client := buildHTTPClient(timeout)

	var health struct {
		Interface string `json:"interface"`
	}
	err := retryBackoff(3, func() error {
		return nodeGet(client, n, "/api/health", &health)
	})
	if err != nil {
		res.Errs = append(res.Errs, err)
		return res
	}
	res.Up = true
	res.Iface = health.Interface
	return res
}

// buildHTTPClient returns a plain http.Client, or — when Phase 24 mTLS
// flags are set (--client-cert/--client-key, and optionally --ca to trust
// a private CA instead of the system pool) — one configured to present a
// client certificate and verify the peer against that CA. Every
// controller request (push, status) goes through this, so mTLS coverage
// is uniform across the whole `sxctl controller` surface rather than
// per-route.
func buildHTTPClient(timeout time.Duration) *http.Client {
	if ctrlClientCert == "" && ctrlClientKey == "" && ctrlCA == "" {
		return &http.Client{Timeout: timeout}
	}

	tlsCfg := &tls.Config{}
	if ctrlClientCert != "" || ctrlClientKey != "" {
		cert, err := tls.LoadX509KeyPair(ctrlClientCert, ctrlClientKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load --client-cert/--client-key: %v (continuing without a client certificate)\n", err)
		} else {
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}
	if ctrlCA != "" {
		caPEM, err := os.ReadFile(ctrlCA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to read --ca %s: %v (falling back to the system trust store)\n", ctrlCA, err)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caPEM) {
				tlsCfg.RootCAs = pool
			}
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// retryBackoff runs fn up to maxAttempts times, waiting an exponentially
// increasing delay between attempts (250ms, 500ms, 1s, 2s, ...) so a node
// that's mid-restart or behind a momentarily flaky link doesn't get marked
// failed by a single unlucky request. Only transient errors are worth
// retrying here — nodeRequest/nodeGet already return a plain error for both
// "unreachable" and "4xx", so retrying is safe: a persistent 4xx just fails
// the same way maxAttempts times over, at a small, bounded extra cost.
func retryBackoff(maxAttempts int, fn func() error) error {
	var lastErr error
	delay := 250 * time.Millisecond
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if lastErr = fn(); lastErr == nil {
			return nil
		}
		if attempt < maxAttempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func nodeRequest(client *http.Client, n node, method, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, n.Host+path, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s returned %s", n.Host, resp.Status)
	}
	return nil
}

func nodeGet(client *http.Client, n node, path string, out any) error {
	req, err := http.NewRequest("GET", n.Host+path, nil)
	if err != nil {
		return err
	}
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s returned %s", n.Host, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var (
	ctrlNodesPath  string
	ctrlPolicyPath string
	ctrlParallel   int
	ctrlTimeout    time.Duration

	// Phase 24 mTLS: presented to every node contacted by `sxctl
	// controller`, so a fleet using -mtls-ca on sentryxd can still be
	// pushed to / health-checked from the operator's workstation.
	ctrlClientCert string
	ctrlClientKey  string
	ctrlCA         string
)

// controllerCmd is the parent for SENTRYX's "controller" mode: pushing one
// policy.yaml to many independently-running sentryxd daemons from a single
// place, and checking that they're all actually up. It does not run as its
// own daemon or hold any state between invocations — every run reads
// nodes.yaml and policy.yaml fresh and reports what happened, the same way
// `sxctl policy apply` does for a single daemon. That keeps a "fleet" of
// SENTRYX instances centrally controllable without inventing a second
// control plane: every node is still just a sentryxd with its own REST API.
var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Push policy to (or check the health of) a fleet of sentryxd daemons",
	Long: `controller lets one operator manage many independent sentryxd
instances from a single nodes.yaml, without standing up any new
infrastructure — it just fans the same requests sxctl always makes
(POST /api/rules, GET /api/health) out to every node in the list,
concurrently, and reports a per-node result.

nodes.yaml:
  nodes:
    - name: edge-1
      host: http://10.0.0.11:9090
      token: env:SENTRYX_TOKEN_EDGE1
    - name: edge-2
      host: http://10.0.0.12:9090`,
}

var controllerPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Apply a policy.yaml's rules to every node in nodes.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ctrlNodesPath == "" || ctrlPolicyPath == "" {
			return fmt.Errorf("--nodes and --policy are both required")
		}
		nodes, err := loadNodes(ctrlNodesPath)
		if err != nil {
			return err
		}
		pol, err := policy.Load(ctrlPolicyPath)
		if err != nil {
			return err
		}

		results := fanOut(nodes, ctrlParallel, func(n node) nodeResult {
			return pushToNode(n, pol, ctrlTimeout)
		})

		printControllerReport(results, fmt.Sprintf("pushed %d rule(s) from %s", len(pol.Block), ctrlPolicyPath))
		return nil
	},
}

var controllerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check /api/health on every node in nodes.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ctrlNodesPath == "" {
			return fmt.Errorf("--nodes is required")
		}
		nodes, err := loadNodes(ctrlNodesPath)
		if err != nil {
			return err
		}

		results := fanOut(nodes, ctrlParallel, func(n node) nodeResult {
			return checkNode(n, ctrlTimeout)
		})

		printControllerReport(results, "health check")
		return nil
	},
}

// fanOut runs fn against every node with at most `parallel` in flight at
// once, and returns results in the same order as nodes so reports read
// top-to-bottom the same way nodes.yaml does.
func fanOut(nodes []node, parallel int, fn func(node) nodeResult) []nodeResult {
	if parallel <= 0 {
		parallel = 8
	}
	results := make([]nodeResult, len(nodes))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	for i, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n node) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = fn(n)
		}(i, n)
	}
	wg.Wait()
	return results
}

func printControllerReport(results []nodeResult, action string) {
	fmt.Printf("%s across %d node(s)\n\n", bold(action), len(results))

	okCount := 0
	for _, r := range results {
		mark := green("✓")
		detail := ""
		switch {
		case len(r.Errs) > 0:
			mark = red("✗")
		case r.Iface != "":
			detail = dim("(" + r.Iface + ")")
		}
		if len(r.Errs) == 0 {
			okCount++
		}

		if r.Applied > 0 {
			detail = dim(fmt.Sprintf("%d rule(s) applied", r.Applied))
		}

		fmt.Printf("  %s %-14s %-28s %s\n", mark, bold(r.Node.Name), r.Node.Host, detail)
		for _, e := range r.Errs {
			fmt.Printf("      %s %v\n", amber("↳"), e)
		}
	}

	fmt.Println()
	if okCount == len(results) {
		fmt.Printf("%s all %d node(s) succeeded\n", green("✓"), len(results))
	} else {
		fmt.Printf("%s %d/%d node(s) failed — see above\n", amber("!"), len(results)-okCount, len(results))
	}
}

func init() {
	controllerCmd.PersistentFlags().StringVar(&ctrlNodesPath, "nodes", "nodes.yaml", "path to nodes.yaml listing the daemon fleet")
	controllerCmd.PersistentFlags().IntVar(&ctrlParallel, "parallel", 8, "max concurrent nodes in flight")
	controllerCmd.PersistentFlags().DurationVar(&ctrlTimeout, "timeout", 8*time.Second, "per-node request timeout")
	controllerCmd.PersistentFlags().StringVar(&ctrlClientCert, "client-cert", "", "path to a client certificate (PEM) to present to every node (Phase 24 mTLS)")
	controllerCmd.PersistentFlags().StringVar(&ctrlClientKey, "client-key", "", "path to the client private key (PEM) matching --client-cert")
	controllerCmd.PersistentFlags().StringVar(&ctrlCA, "ca", "", "path to a CA certificate (PEM) to verify nodes against, instead of the system trust store")
	controllerPushCmd.Flags().StringVar(&ctrlPolicyPath, "policy", "policy.yaml", "path to the policy.yaml to push to every node")

	controllerCmd.AddCommand(controllerPushCmd)
	controllerCmd.AddCommand(controllerStatusCmd)
	rootCmd.AddCommand(controllerCmd)
}
