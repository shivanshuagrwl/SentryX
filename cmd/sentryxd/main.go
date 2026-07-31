// Command sentryxd is the SENTRYX control daemon. It loads the compiled
// XDP program onto a network interface, keeps the eBPF maps it needs open
// for its entire lifetime, and exposes them safely over a REST + SSE API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shivanshuagrwl/SentryX/internal/anomaly"
	"github.com/shivanshuagrwl/SentryX/internal/api"
	"github.com/shivanshuagrwl/SentryX/internal/capture"
	"github.com/shivanshuagrwl/SentryX/internal/dnsresolve"
	"github.com/shivanshuagrwl/SentryX/internal/firewall"
	"github.com/shivanshuagrwl/SentryX/internal/geoip"
	"github.com/shivanshuagrwl/SentryX/internal/policy"
	"github.com/shivanshuagrwl/SentryX/internal/store"
	"github.com/shivanshuagrwl/SentryX/internal/threatintel"
	"github.com/shivanshuagrwl/SentryX/internal/threatshare"
	"github.com/shivanshuagrwl/SentryX/internal/topology"
)

// version is overridden via -ldflags "-X main.version=..." by `make dist` /
// the release workflow. Without this var the ldflags -X target doesn't
// exist and the linker silently drops the flag, which is exactly how
// sentryxd ended up unable to report its own version — see -version below
// and sentryx-setup's resolveBinaries, which relies on this to decide
// whether an already-installed daemon needs upgrading.
var version = "dev"

const banner = `
 __      __   ______   ______   _______   __     __   ______   __       __
/  \    /  | /      \ /      \ /       \ /  |   /  | /      \ /  |     /  |
$$  \  /$$ |/$$$$$$  |/$$$$$$  |$$$$$$$  |$$ |   $$ |/$$$$$$  |$$ |     $$ |
$$$  \/$$$ |$$ |  $$ |$$ |  $$/ $$ |  $$ |$$ |   $$ |$$ |__$$ |$$ |     $$ |
$$$$  $$$$ |$$ |  $$ |$$ |      $$ |  $$ |$$  \ /$$/ $$    $$ |$$ |     $$ |
$$ $$ $$/$$ |$$ |  $$ |$$ |   __ $$ |  $$ | $$  /$$/  $$$$$$$$ |$$ |     $$ |
$$ |$$$/ $$ |$$ \__$$ |$$ \__/  |$$ |__$$ |  $$ $$/   $$ |  $$ |$$ |_____$$ |
$$ | $/  $$ |$$    $$/ $$    $$/ $$    $$/    $$$/    $$ |  $$ |$$       |
$$/      $$/  $$$$$$/   $$$$$$/  $$$$$$$/      $/     $$/   $$/ $$$$$$$$/

  kernel-speed packet interdiction · github.com/shivanshuagrwl/SentryX
`

// run holds sentryxd's entire lifecycle: parse flags, attach the
// firewall backend, wire up every optional feature, serve the control
// API, and block until ctx is cancelled — at which point it shuts
// everything down gracefully and returns. Split out from main() so it can
// be driven two different ways: directly by an OS signal (normal
// terminal/systemd/launchd launch, see main() below), or by the Windows
// Service Control Manager's stop/shutdown handshake (see
// service_windows.go) — SCM needs a real Go context it can cancel, not a
// signal, since it never actually sends this process a Ctrl+C.
func run(ctx context.Context) {
	var (
		iface    = flag.String("iface", "eth0", "network interface to attach the XDP program to")
		objPath  = flag.String("obj", "bpf/xdp_sentryx.o", "path to the compiled XDP object file")
		addr     = flag.String("addr", ":9090", "address for the control API to listen on")
		dataDir  = flag.String("data", "/var/lib/sentryx", "directory for persisted rule state")
		generic  = flag.Bool("generic", false, "attach in generic (SKB) XDP mode instead of native — use for testing on interfaces without native XDP support")
		insecure = flag.Bool("insecure", false, "disable API token authentication (local development only)")

		tlsCert = flag.String("tls-cert", "", "path to a TLS certificate (PEM) for the control API — enables HTTPS when set together with -tls-key")
		tlsKey  = flag.String("tls-key", "", "path to the TLS private key (PEM) matching -tls-cert")

		mtlsCA         = flag.String("mtls-ca", "", "path to a CA certificate (PEM) — when set (with -tls-cert/-tls-key), the control API requires and verifies a client certificate signed by this CA on every connection (Phase 24 mTLS)")
		mtlsAllowedCNs = flag.String("mtls-allowed-cns", "", "comma-separated list of client-certificate Common Names to accept; empty means any CA-signed cert is accepted (only meaningful with -mtls-ca)")

		anomalyEnabled  = flag.Bool("anomaly", true, "enable the behavioral anomaly detector (EWMA baseline + threshold)")
		anomalyDryRun   = flag.Bool("anomaly-dry-run", false, "detect and log anomalies but never auto-block (tune thresholds safely against real traffic)")
		anomalyRateMult = flag.Float64("anomaly-rate-multiplier", anomaly.DefaultConfig().RateMultiplier, "flag an IP when its rate exceeds this multiple of its own baseline")

		threatIntel     = flag.Bool("threat-intel", false, "auto-block IPs from the public Feodo Tracker C2 feed on boot and every -threat-intel-interval")
		threatIntelURL  = flag.String("threat-intel-url", "", "override the threat-intel feed URL (default: abuse.ch Feodo Tracker)")
		threatIntelFreq = flag.Duration("threat-intel-interval", 30*time.Minute, "how often to re-sync the threat-intel feed")

		threatSharePeers = flag.String("threat-share-peers", "", "comma-separated list of peer sentryxd base URLs (e.g. http://10.0.0.12:9090) to relay auto-blocks to and accept reports from (Phase 23)")
		threatShareToken = flag.String("threat-share-token", "", "bearer token to use when reporting to peers listed in -threat-share-peers; defaults to this daemon's own SENTRYX_TOKEN, which only works if every peer shares the same token")
		threatShareTTL   = flag.Duration("threat-share-ttl", threatshare.DefaultTTL, "how long a block relayed from a peer is enforced before it's automatically lifted")
		threatShareName  = flag.String("threat-share-name", "", "this daemon's name as reported to peers (defaults to -iface); purely informational")

		policyPath = flag.String("policy", "", "path to a policy.yaml to apply on boot (policy-as-code; see `sxctl policy init`)")

		showVersion = flag.Bool("version", false, "print sentryxd's version and exit")
	)
	flag.Parse()

	// Handled before anything else touches an interface, a map, or a
	// port — `sentryxd -version` needs to work unprivileged, offline,
	// and even against a broken install, since sentryx-setup's upgrade
	// check (see resolveBinaries in cmd/sentryx-setup/fetch.go) shells
	// out to exactly this to decide whether an already-installed daemon
	// is stale.
	if *showVersion {
		fmt.Println(version)
		return
	}

	fmt.Fprint(os.Stderr, banner)

	token := os.Getenv("SENTRYX_TOKEN")
	if token == "" && !*insecure {
		log.Fatal("SENTRYX_TOKEN is not set. Set it, or start with -insecure for local dev only.")
	}
	if *insecure {
		log.Println("⚠  running in -insecure mode: the control API has NO authentication")
		token = ""
	}

	useTLS := *tlsCert != "" || *tlsKey != ""
	if useTLS && (*tlsCert == "" || *tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must both be set to enable HTTPS")
	}
	if !useTLS {
		log.Println("⚠  control API is running over plain HTTP — pass -tls-cert/-tls-key (or put a TLS-terminating proxy in front) before exposing it beyond localhost")
	}

	// Phase 24 — mTLS. -mtls-ca layers client-certificate verification on
	// top of the server TLS above: the standard library enforces the
	// CA-signature check itself via tls.Config.ClientAuth, so what we build
	// here is that config plus (if -mtls-allowed-cns is set) a narrower
	// allowlist the API middleware checks per-request — a cert can be
	// perfectly CA-signed and still not belong to a name we've decided to
	// trust for write access.
	var tlsConfig *tls.Config
	var allowedCNs []string
	if *mtlsCA != "" {
		if !useTLS {
			log.Fatal("-mtls-ca requires -tls-cert/-tls-key to also be set — mTLS layers on top of server TLS, it doesn't replace it")
		}
		caPEM, err := os.ReadFile(*mtlsCA)
		if err != nil {
			log.Fatalf("failed to read -mtls-ca %s: %v", *mtlsCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			log.Fatalf("no certificates found in -mtls-ca %s", *mtlsCA)
		}
		tlsConfig = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
		if *mtlsAllowedCNs != "" {
			for _, cn := range strings.Split(*mtlsAllowedCNs, ",") {
				if cn = strings.TrimSpace(cn); cn != "" {
					allowedCNs = append(allowedCNs, cn)
				}
			}
		}
		log.Printf("⚠  mTLS enabled: the control API now requires a client certificate signed by %s%s", *mtlsCA,
			func() string {
				if len(allowedCNs) > 0 {
					return fmt.Sprintf(" (restricted to CN in %v)", allowedCNs)
				}
				return ""
			}())
	}

	fw, err := firewall.Load(*objPath, *iface, *generic)
	if err != nil {
		log.Fatalf("failed to load XDP program: %v", err)
	}
	defer fw.Close()
	log.Printf("attached to interface %q (object: %s)", *iface, *objPath)

	st, err := store.New(*dataDir + "/rules.json")
	if err != nil {
		log.Fatalf("failed to open rule store: %v", err)
	}

	if entries, err := st.Load(); err != nil {
		log.Printf("warning: failed to load persisted rules: %v", err)
	} else {
		for _, e := range entries {
			if err := fw.BlockWithReason(e.IP, e.Label, firewall.Reason(e.Reason)); err != nil {
				log.Printf("warning: failed to restore rule for %s: %v", e.IP, err)
				continue
			}
			if e.RateLimit > 0 {
				_ = fw.RateLimit(e.IP, e.RateLimit)
			}
			if e.BandwidthLimit > 0 {
				_ = fw.BandwidthLimit(e.IP, e.BandwidthLimit)
			}
		}
		log.Printf("restored %d rule(s) from %s", len(entries), *dataDir+"/rules.json")
	}

	// Policy-as-code: apply a versionable policy.yaml on top of whatever
	// was restored from the local store. Safe to re-apply on every boot.
	var dnsResolver *dnsresolve.Resolver
	stopDNS := make(chan struct{})
	var geoFeed *geoip.Feed
	stopGeoIP := make(chan struct{})
	if *policyPath != "" {
		pol, err := policy.Load(*policyPath)
		if err != nil {
			log.Fatalf("failed to load policy %s: %v", *policyPath, err)
		}
		applied, errs := policy.Apply(fw, pol)
		for _, e := range errs {
			log.Printf("policy: %v", e)
		}
		log.Printf("policy: applied %d rule(s) from %s", applied, *policyPath)

		// Phase 19: DNS-based blocking. XDP never sees domain names, so
		// this is a pure user-space resolve-and-block loop that pushes
		// into the exact same blocklist map everything else here uses.
		if pol.DNS != nil && len(pol.DNS.BlockedDomains) > 0 {
			interval := time.Duration(pol.DNS.RefreshMinutes) * time.Minute
			dnsResolver = dnsresolve.New(fw, interval)
			dnsResolver.SetDomains(pol.DNS.BlockedDomains)
			if err := dnsResolver.Refresh(context.Background()); err != nil {
				log.Printf("dnsresolve: initial resolve failed: %v", err)
			}
			go dnsResolver.Run(stopDNS)
			log.Printf("dns-block enabled (%d domain(s): %v)", len(pol.DNS.BlockedDomains), dnsResolver.Domains())
		}

		// Phase 20: GeoIP blocking. Populates the kernel's LPM-trie
		// geoip_blocklist from a public per-country CIDR feed.
		if pol.GeoIP != nil && len(pol.GeoIP.BlockedCountries) > 0 {
			interval := time.Duration(pol.GeoIP.RefreshHours) * time.Hour
			geoFeed = geoip.New(fw, interval)
			geoFeed.SetCountries(pol.GeoIP.BlockedCountries)
			if err := geoFeed.Refresh(context.Background()); err != nil {
				log.Printf("geoip: initial sync failed: %v", err)
			}
			go geoFeed.Run(stopGeoIP)
			log.Printf("geoip-block enabled (countries: %v)", geoFeed.Countries())
		}
	}

	// Behavioral anomaly detector: EWMA baseline per source IP, no ML,
	// no training phase — every auto-block is explainable in one sentence.
	var det *anomaly.Detector
	stopDetector := make(chan struct{})
	if *anomalyEnabled {
		cfg := anomaly.DefaultConfig()
		cfg.RateMultiplier = *anomalyRateMult
		cfg.AutoBlock = !*anomalyDryRun
		det = anomaly.New(fw, cfg)
		go det.Run(stopDetector)
		mode := "auto-block"
		if *anomalyDryRun {
			mode = "dry-run (detect only)"
		}
		log.Printf("anomaly detector enabled (%s, %.0fx baseline threshold)", mode, cfg.RateMultiplier)
	}

	// Threat-intel auto-feed: seeds + keeps the blocklist current against
	// a public, named source of known-malicious IPs.
	stopFeed := make(chan struct{})
	if *threatIntel {
		feed := threatintel.New(fw, *threatIntelURL, *threatIntelFreq)
		if err := feed.Refresh(context.Background()); err != nil {
			log.Printf("threatintel: initial sync failed: %v", err)
		}
		go feed.Run(stopFeed)
		log.Printf("threat-intel feed enabled (refresh every %s)", *threatIntelFreq)
	}

	// Phase 26: live topology / war-room map. Always constructed (cheap —
	// it's just an in-memory ring buffer until something calls Observe) so
	// the dashboard's map has something to query even on a daemon with no
	// GeoIP feed configured; geoResolver is left nil in that case, and
	// Recorder.Observe already treats a nil resolver as "record the event
	// unresolved" rather than failing. Only assign the interface when
	// geoFeed is a real, non-nil *geoip.Feed — passing a merely
	// typed-but-nil pointer through the interface would make
	// topo.resolver != nil true while still panicking on first use.
	var geoResolver topology.CountryResolver
	if geoFeed != nil {
		geoResolver = geoFeed
	}
	topo := topology.New(geoResolver)
	fw.AddBlockObserver(topo.Observe)

	// Phase 22: packet capture / pcap export. Always constructed (cheap —
	// touches no kernel state until an operator runs `sxctl capture
	// start`) so the feature is available on every daemon without a
	// separate opt-in flag, the same way `sxctl why` is always available.
	capRecorder := capture.NewRecorder(fw)

	// Phase 23: cross-daemon threat sharing. Peer-to-peer rather than a
	// star topology through a separate "controller" service — see
	// internal/threatshare's package comment for why. Both halves (Sharer:
	// outbound, Registry: inbound) only exist if -threat-share-peers names
	// at least one peer; an empty Registry (share == nil) makes
	// /api/threats/report answer 503 rather than silently accepting
	// reports nobody configured this daemon to expect.
	var shareRegistry *threatshare.Registry
	stopShare := make(chan struct{})
	if *threatSharePeers != "" {
		var peers []threatshare.Peer
		shareToken := *threatShareToken
		if shareToken == "" {
			shareToken = token
		}
		for _, u := range strings.Split(*threatSharePeers, ",") {
			if u = strings.TrimSpace(u); u != "" {
				peers = append(peers, threatshare.Peer{URL: strings.TrimSuffix(u, "/"), Token: shareToken})
			}
		}
		selfName := *threatShareName
		if selfName == "" {
			selfName = *iface
		}
		sharer := threatshare.New(peers, selfName, *threatShareTTL)
		fw.AddBlockObserver(sharer.Report)

		shareRegistry = threatshare.NewRegistry(fw)
		go shareRegistry.Run(stopShare)
		log.Printf("threat-share enabled (%d peer(s), ttl %s)", len(peers), *threatShareTTL)
	}

	srv := api.New(fw, st, det, dnsResolver, capRecorder, shareRegistry, topo, token, allowedCNs)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
	}

	go func() {
		var err error
		if useTLS {
			log.Printf("control API listening on %s (HTTPS)", *addr)
			err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			log.Printf("control API listening on %s (HTTP)", *addr)
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("api server error: %v", err)
		}
	}()

	<-ctx.Done()

	log.Println("shutting down…")
	close(stopDetector)
	close(stopFeed)
	close(stopDNS)
	close(stopGeoIP)
	close(stopShare)
	if err := capRecorder.Close(); err != nil {
		log.Printf("capture: shutdown cleanup: %v", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	log.Println("XDP program detached, daemon stopped")
}

// main dispatches to whichever way this process was actually launched.
// On Windows, `sc start sentryxd` (what cmd/sentryx-setup's
// install_windows.go registers) launches this exe under the Service
// Control Manager, which expects a service-protocol handshake within a
// few seconds or it kills the process with "did not respond in a timely
// fashion" (error 1053) — runAsWindowsService performs that handshake and
// only returns true if SCM is actually who launched us; every other
// launch method (terminal, systemd, launchd, a plain double-click) falls
// through to the ordinary OS-signal-driven path unchanged.
func main() {
	if runAsWindowsService(run) {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	run(ctx)
}
