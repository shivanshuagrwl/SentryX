// Package api exposes SENTRYX's control daemon over HTTP: a small REST
// surface for rule management, a JSON stats endpoint, and a Server-Sent
// Events stream that the dashboard uses for live updates.
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/shivanshu-agarwal/sentryx/internal/anomaly"
	"github.com/shivanshu-agarwal/sentryx/internal/capture"
	"github.com/shivanshu-agarwal/sentryx/internal/dnsresolve"
	"github.com/shivanshu-agarwal/sentryx/internal/firewall"
	"github.com/shivanshu-agarwal/sentryx/internal/store"
	"github.com/shivanshu-agarwal/sentryx/internal/threatshare"
	"github.com/shivanshu-agarwal/sentryx/internal/topology"
)

// dashboardFS embeds the control-room UI directly into the sentryxd binary
// (rather than serving it from a relative "web/dashboard" path on disk).
// That matters once sentryxd ships inside the native installers
// (installers/{macos,linux,windows}) — those only place the compiled
// binary on the target machine, never the source tree, so a disk-relative
// path would 404 there. Embedding makes the UI part of the binary itself,
// same as cmd/sentryx-setup's wizard already does for its own page.
//
//go:embed webui/index.html webui/favicon.png webui/brand-mark.png
var dashboardFS embed.FS

type Server struct {
	fw         *firewall.Firewall
	st         *store.Store
	det        *anomaly.Detector     // nil if the anomaly detector is disabled
	dns        *dnsresolve.Resolver  // nil if Phase 19 DNS blocking is disabled
	cap        *capture.Recorder     // nil if Phase 22 capture support wasn't wired up by main.go
	share      *threatshare.Registry // nil if Phase 23 cross-daemon threat sharing is disabled
	topo       *topology.Recorder    // Phase 26 live topology feed; never nil (main.go always constructs one)
	token      string
	allowedCNs []string // Phase 24: non-empty means only these mTLS client-cert CNs may write
	mux        *http.ServeMux
	startedAt  time.Time
}

// New builds a ready-to-serve API. Pass an empty token to run in -insecure
// mode (local development only — the daemon logs a loud warning if so).
// det may be nil if the daemon was started with the anomaly detector
// disabled — the /api/anomalies and /api/baselines routes then report
// an empty result set instead of failing. dns may be nil if Phase 19 DNS
// blocking isn't configured — /api/dns then reports an empty result set.
// cap may be nil, in which case every /api/capture/* route reports the
// feature as unavailable rather than panicking. share may be nil if Phase
// 23 threat sharing has no peers configured — /api/threats/report then
// rejects with 503 instead of silently accepting reports nobody asked for.
// topo is Phase 26's live topology recorder — main.go always constructs
// one (it's a cheap passive listener, same reasoning as cap), so this is
// never nil in practice, but handlers still nil-check it defensively.
// allowedCNs is Phase 24's optional mTLS client-cert CN allowlist — nil or
// empty means "any cert this connection's tls.Config already accepted",
// i.e. no additional restriction beyond CA-signature verification.
func New(fw *firewall.Firewall, st *store.Store, det *anomaly.Detector, dns *dnsresolve.Resolver, cap *capture.Recorder, share *threatshare.Registry, topo *topology.Recorder, token string, allowedCNs []string) *Server {
	s := &Server{fw: fw, st: st, det: det, dns: dns, cap: cap, share: share, topo: topo, token: token, allowedCNs: allowedCNs, mux: http.NewServeMux(), startedAt: time.Now()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	mw := []func(http.HandlerFunc) http.HandlerFunc{withLogging, withCORS}
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return chain(h, append(mw,
			func(next http.HandlerFunc) http.HandlerFunc {
				return withAuth(s.token, next)
			},
			func(next http.HandlerFunc) http.HandlerFunc {
				return withClientCN(s.allowedCNs, next)
			},
		)...)
	}

	s.mux.HandleFunc("GET /api/health", chain(s.handleHealth, mw...))
	s.mux.HandleFunc("GET /api/rules", authed(s.handleListRules))
	s.mux.HandleFunc("POST /api/rules", authed(s.handleCreateRule))
	s.mux.HandleFunc("DELETE /api/rules/{ip}", authed(s.handleDeleteRule))
	s.mux.HandleFunc("POST /api/rules/{ip}/rate-limit", authed(s.handleRateLimit))
	s.mux.HandleFunc("POST /api/rules/{ip}/bandwidth-limit", authed(s.handleBandwidthLimit))
	s.mux.HandleFunc("GET /api/stats", authed(s.handleStats))
	s.mux.HandleFunc("GET /api/stream", authed(s.handleStream))
	s.mux.HandleFunc("GET /api/why/{ip}", authed(s.handleWhy))
	s.mux.HandleFunc("GET /api/activity", authed(s.handleActivity))
	s.mux.HandleFunc("GET /api/anomalies", authed(s.handleAnomalies))
	s.mux.HandleFunc("GET /api/baselines", authed(s.handleBaselines))
	s.mux.HandleFunc("GET /api/connections", authed(s.handleConnections))
	s.mux.HandleFunc("GET /api/syn-cookie", authed(s.handleGetSynCookie))
	s.mux.HandleFunc("PUT /api/syn-cookie", authed(s.handleSetSynCookie))
	s.mux.HandleFunc("GET /api/knock", authed(s.handleGetKnock))
	s.mux.HandleFunc("PUT /api/knock", authed(s.handleSetKnock))
	s.mux.HandleFunc("GET /api/geoip", authed(s.handleGeoIP))
	s.mux.HandleFunc("GET /api/arp", authed(s.handleArp))
	s.mux.HandleFunc("GET /api/dns", authed(s.handleDNS))
	s.mux.HandleFunc("POST /api/capture/start", authed(s.handleCaptureStart))
	s.mux.HandleFunc("POST /api/capture/stop", authed(s.handleCaptureStop))
	s.mux.HandleFunc("GET /api/capture/status", authed(s.handleCaptureStatus))
	s.mux.HandleFunc("GET /api/capture/download", authed(s.handleCaptureDownload))
	s.mux.HandleFunc("POST /api/threats/report", authed(s.handleThreatReport))
	s.mux.HandleFunc("GET /api/threats", authed(s.handleThreatList))
	s.mux.HandleFunc("GET /api/topology", authed(s.handleTopology))
	s.mux.HandleFunc("GET /api/topology/stream", authed(s.handleTopologyStream))
	s.mux.HandleFunc("GET /metrics", authed(s.handleMetrics))

	// Serve the dashboard as static files at / — from the embedded FS
	// above, not disk, so it works no matter where sentryxd is installed.
	uiRoot, err := fs.Sub(dashboardFS, "webui")
	if err != nil {
		log.Fatalf("sentryxd: embedded dashboard assets missing: %v", err)
	}
	s.mux.Handle("/", http.FileServer(http.FS(uiRoot)))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "up",
		"interface": s.fw.Interface(),
		"time":      time.Now().UTC(),
	})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.fw.List())
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP             string `json:"ip"`
		Label          string `json:"label"`
		RateLimit      uint32 `json:"rate_limit_pps"`
		BandwidthLimit uint32 `json:"rate_limit_kbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := s.fw.Block(body.IP, body.Label); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if body.RateLimit > 0 {
		if err := s.fw.RateLimit(body.IP, body.RateLimit); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if body.BandwidthLimit > 0 {
		if err := s.fw.BandwidthLimit(body.IP, body.BandwidthLimit); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.persist()
	writeJSON(w, http.StatusCreated, map[string]string{"status": "blocked", "ip": body.IP})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if err := s.fw.Unblock(ip); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persist()
	writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked", "ip": ip})
}

func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	var body struct {
		LimitPPS uint32 `json:"limit_pps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.fw.RateLimit(ip, body.LimitPPS); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "limit_pps": body.LimitPPS})
}

// handleBandwidthLimit sets/clears a Phase 25 QoS byte-rate cap for ip,
// independent of the packet-rate cap handleRateLimit sets. Backs `sxctl
// qos set <ip> --kbps N`.
func (s *Server) handleBandwidthLimit(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	var body struct {
		LimitKbps uint32 `json:"limit_kbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.fw.BandwidthLimit(ip, body.LimitKbps); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "limit_kbps": body.LimitKbps})
}

// handleWhy answers "why was this IP dropped" — the single-map read that
// backs both the dashboard's hover cards and `sxctl why <ip>`.
func (s *Server) handleWhy(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	info, ok, err := s.fw.DropReason(ip)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "dropped": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":         ip,
		"dropped":    true,
		"reason":     info.Reason,
		"reason_str": info.ReasonStr,
		"count":      info.Count,
	})
}

// handleActivity exposes the kernel's live per-IP activity window — packet
// rate, byte count, SYN ratio — regardless of whether an IP has a rule
// against it yet. This is the raw feed the anomaly detector itself reads.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	snap, err := s.fw.ActivitySnapshot()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleAnomalies returns the detector's recent detection log — each entry
// is a self-contained, human-readable explanation ("14x baseline packet
// rate, sustained for 2 samples"), not just a bare flag.
func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if s.det == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.det.RecentEvents(100))
}

// handleBaselines exposes the detector's current "what does normal look
// like" view — one EWMA packet-rate baseline per tracked source IP.
func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	if s.det == nil {
		writeJSON(w, http.StatusOK, map[string]float64{})
		return
	}
	writeJSON(w, http.StatusOK, s.det.Baselines())
}

// handleConnections exposes the kernel's Phase 16 connection-tracking
// table — every flow SENTRYX currently has state for, regardless of
// whether either endpoint is otherwise blocked. Backs `sxctl connections`.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := s.fw.ActiveConnections()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

// handleGetSynCookie / handleSetSynCookie read and write the Phase 17
// SYN-cookie DDoS-mitigation tiering thresholds. PUT with both fields at
// zero (or omitted) disables the feature.
func (s *Server) handleGetSynCookie(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.fw.SynCookieConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"low_pps":  cfg.LowPPS,
		"high_pps": cfg.HighPPS,
		"enabled":  cfg.LowPPS > 0 || cfg.HighPPS > 0,
	})
}

func (s *Server) handleSetSynCookie(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LowPPS  uint32 `json:"low_pps"`
		HighPPS uint32 `json:"high_pps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.HighPPS != 0 && body.HighPPS < body.LowPPS {
		writeErr(w, http.StatusBadRequest, "high_pps must be >= low_pps")
		return
	}
	if err := s.fw.SetSynCookieConfig(firewall.SynCookieConfig{LowPPS: body.LowPPS, HighPPS: body.HighPPS}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"low_pps": body.LowPPS, "high_pps": body.HighPPS})
}

// handleGetKnock / handleSetKnock read and write the Phase 18 port-knock
// sequence. PUT with an empty sequence disables the feature.
func (s *Server) handleGetKnock(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.fw.KnockConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sequence":       cfg.Sequence,
		"open_port":      cfg.OpenPort,
		"window_seconds": cfg.WindowSeconds,
		"enabled":        len(cfg.Sequence) > 0,
	})
}

func (s *Server) handleSetKnock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sequence      []uint16 `json:"sequence"`
		OpenPort      uint16   `json:"open_port"`
		WindowSeconds uint32   `json:"window_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfg := firewall.KnockConfig{Sequence: body.Sequence, OpenPort: body.OpenPort, WindowSeconds: body.WindowSeconds}
	if err := s.fw.SetKnockConfig(cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sequence": body.Sequence, "open_port": body.OpenPort, "window_seconds": body.WindowSeconds,
	})
}

// handleDNS returns the Phase 19 DNS-blocking resolver's current
// domain->IP resolutions (i.e. what's currently blocked and why, in terms
// of a domain name). Backs `sxctl dns`.
func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "domains": []string{}, "resolutions": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     true,
		"domains":     s.dns.Domains(),
		"resolutions": s.dns.Resolutions(),
	})
}

// handleCaptureStart begins a Phase 22 packet-capture session: flips the
// kernel-side switch and starts draining the ringbuf into an in-memory
// pcap buffer. An optional JSON body {"duration_seconds": N} auto-stops
// the session after N seconds so an operator can't forget a running
// capture; omit or send 0 to run until an explicit stop.
func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		writeErr(w, http.StatusServiceUnavailable, "packet capture isn't available on this daemon")
		return
	}
	var body struct {
		DurationSeconds uint32 `json:"duration_seconds"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if err := s.cap.Start(time.Duration(body.DurationSeconds) * time.Second); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.cap.Status())
}

// handleCaptureStop ends the current capture session. The captured data
// stays available at /api/capture/download afterward — stopping doesn't
// discard it, only the next /api/capture/start does.
func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		writeErr(w, http.StatusServiceUnavailable, "packet capture isn't available on this daemon")
		return
	}
	if err := s.cap.Stop(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.cap.Status())
}

// handleCaptureStatus reports whether a capture is running and how much
// it's captured so far — backs `sxctl capture status` and lets a client
// poll progress on a long-running capture without stopping it.
func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, s.cap.Status())
}

// handleCaptureDownload streams the current pcap file — the global header
// plus every record captured so far, valid and Wireshark-openable whether
// or not a session is still running. Backs `sxctl capture start --out`.
func (s *Server) handleCaptureDownload(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		writeErr(w, http.StatusServiceUnavailable, "packet capture isn't available on this daemon")
		return
	}
	data := s.cap.Snapshot()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="sentryx-capture.pcap"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleThreatReport receives a Phase 23 threat report from a peer daemon
// and enforces it locally under ReasonShared, with a TTL so one node's
// false positive can't permanently poison the whole fleet. Returns 503 if
// this daemon wasn't started with any threat-share peers configured — see
// -threat-share-peers in cmd/sentryxd, since a Registry with nowhere to
// expire entries via Run still needs to exist for this to be safe to call.
func (s *Server) handleThreatReport(w http.ResponseWriter, r *http.Request) {
	if s.share == nil {
		writeErr(w, http.StatusServiceUnavailable, "cross-daemon threat sharing isn't enabled on this daemon")
		return
	}
	var rep threatshare.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if rep.IP == "" {
		writeErr(w, http.StatusBadRequest, "ip is required")
		return
	}
	if err := s.share.Apply(rep); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied", "ip": rep.IP})
}

// handleThreatList returns every block this daemon is currently enforcing
// because a peer reported it (Phase 23). Backs `sxctl threats list`.
func (s *Server) handleThreatList(w http.ResponseWriter, r *http.Request) {
	if s.share == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "threats": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "threats": s.share.List()})
}

// handleGeoIP returns every currently blocked GeoIP CIDR range (Phase 20).
// Backs `sxctl geoip list`.
func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.fw.ListGeoBlocks())
}

// handleArp returns the kernel's Phase 21 ARP spoof-suspected alerts —
// detection only, never enforced, see bpf/xdp_sentryx.c's Phase 21 note.
// Backs `sxctl arp`.
func (s *Server) handleArp(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.fw.ArpAlerts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// handleTopology returns a backfill snapshot of recent geo-tagged block
// events for Phase 26's live topology map — used on initial dashboard
// load before the SSE stream below takes over. An optional ?limit=N query
// param caps how many are returned (default: everything currently
// buffered, up to topology.Recorder's own cap).
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	if s.topo == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "latest_seq": 0})
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":     s.topo.Snapshot(limit),
		"latest_seq": s.topo.LatestSeq(),
	})
}

// handleTopologyStream pushes newly-recorded geo-tagged block events over
// Server-Sent Events as they happen — the war-room map's pulsing dots are
// driven by this endpoint. Same ticker-based approach as handleStream
// above rather than a pub/sub fan-out, since a 1-second latency on a
// block-to-dot animation is imperceptible and this keeps the
// implementation consistent with the rest of the codebase.
func (s *Server) handleTopologyStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	if s.topo == nil {
		writeErr(w, http.StatusServiceUnavailable, "topology feed isn't available on this daemon")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Start from "now" — a client that wants history first calls
	// GET /api/topology, then opens this stream for anything after.
	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			since = n
		}
	} else {
		since = s.topo.LatestSeq()
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			events := s.topo.Since(since)
			if len(events) == 0 {
				continue
			}
			since = events[len(events)-1].Seq
			data, _ := json.Marshal(events)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// handleMetrics exposes the same live counters as /api/stats, in Prometheus
// text exposition format, so SENTRYX can be scraped by an existing
// Prometheus setup instead of needing a bespoke exporter. Point a scrape
// config at this path with bearer_token (or bearer_token_file) set to the
// daemon's SENTRYX_TOKEN if the API isn't running -insecure.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	stats, err := s.fw.Stats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rules := s.fw.List()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP sentryx_packets_allowed_total Packets passed by the XDP program.\n")
	fmt.Fprintf(w, "# TYPE sentryx_packets_allowed_total counter\n")
	fmt.Fprintf(w, "sentryx_packets_allowed_total %d\n", stats.Allowed)

	fmt.Fprintf(w, "# HELP sentryx_packets_dropped_total Packets dropped by the XDP program.\n")
	fmt.Fprintf(w, "# TYPE sentryx_packets_dropped_total counter\n")
	fmt.Fprintf(w, "sentryx_packets_dropped_total %d\n", stats.Dropped)

	fmt.Fprintf(w, "# HELP sentryx_bytes_allowed_total Bytes passed by the XDP program.\n")
	fmt.Fprintf(w, "# TYPE sentryx_bytes_allowed_total counter\n")
	fmt.Fprintf(w, "sentryx_bytes_allowed_total %d\n", stats.BytesAllowed)

	fmt.Fprintf(w, "# HELP sentryx_bytes_dropped_total Bytes dropped by the XDP program.\n")
	fmt.Fprintf(w, "# TYPE sentryx_bytes_dropped_total counter\n")
	fmt.Fprintf(w, "sentryx_bytes_dropped_total %d\n", stats.BytesDropped)

	fmt.Fprintf(w, "# HELP sentryx_rules_total Number of active blocklist rules.\n")
	fmt.Fprintf(w, "# TYPE sentryx_rules_total gauge\n")
	fmt.Fprintf(w, "sentryx_rules_total %d\n", len(rules))

	fmt.Fprintf(w, "# HELP sentryx_uptime_seconds Seconds since the control daemon started.\n")
	fmt.Fprintf(w, "# TYPE sentryx_uptime_seconds gauge\n")
	fmt.Fprintf(w, "sentryx_uptime_seconds %.0f\n", time.Since(s.startedAt).Seconds())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.fw.Stats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleStream pushes a stats snapshot to the client every second over
// Server-Sent Events — the dashboard's live counters and traffic graph are
// driven by this endpoint.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			stats, err := s.fw.Stats()
			if err != nil {
				continue
			}
			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// persist writes the current rule set to disk so it survives a restart.
func (s *Server) persist() {
	rules := s.fw.List()
	entries := make([]store.Entry, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, store.Entry{
			IP:             r.IP,
			Label:          r.Label,
			RateLimit:      r.RateLimit,
			BandwidthLimit: r.BandwidthLimit,
			Reason:         uint8(r.Reason),
			CreatedAt:      r.CreatedAt,
		})
	}
	_ = s.st.Save(entries) // best-effort; a failed persist doesn't affect live filtering
}
