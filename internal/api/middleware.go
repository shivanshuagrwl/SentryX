package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"time"
)

// withAuth rejects any request whose Authorization: Bearer <token> header
// doesn't match the daemon's configured token. SENTRYX controls live
// network access, so this is not optional in production — the daemon
// refuses to start without a token unless -insecure is explicitly passed.
//
// As a fallback it also accepts ?token=<token> in the query string. That's
// solely for the dashboard's /api/stream connection: browsers' EventSource
// API can't set custom headers, so the token has nowhere else to ride. Every
// other route (rules, stats, why, ...) is called via fetch() and always uses
// the Authorization header instead.
func withAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next(w, r) // -insecure mode, local dev only
			return
		}

		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			next(w, r)
			return
		}

		if qt := r.URL.Query().Get("token"); qt != "" && subtle.ConstantTimeCompare([]byte(qt), []byte(token)) == 1 {
			next(w, r)
			return
		}

		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}
}

// withClientCN is Phase 24's optional extra layer on top of mTLS: even
// though tls.Config.ClientAuth already refuses any connection whose client
// certificate isn't signed by the configured CA before a request ever
// reaches here, a CA can legitimately sign certs for more than one
// identity (e.g. every node in the fleet plus a handful of operator
// laptops). allowedCNs, when non-empty, narrows that down to specific
// Common Names — a CA-valid cert that isn't one of them still gets
// rejected. An empty allowedCNs is a no-op: any cert the TLS handshake
// itself already accepted is allowed through unchanged, which is also the
// correct behavior when mTLS isn't enabled at all (r.TLS is nil for plain
// HTTP, or has no PeerCertificates without ClientAuth requiring one).
func withClientCN(allowedCNs []string, next http.HandlerFunc) http.HandlerFunc {
	if len(allowedCNs) == 0 {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"error":"client certificate required"}`, http.StatusUnauthorized)
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		for _, allowed := range allowedCNs {
			if subtle.ConstantTimeCompare([]byte(cn), []byte(allowed)) == 1 {
				next(w, r)
				return
			}
		}
		log.Printf("mtls: rejected client cert CN %q (not in allowlist)", cn)
		http.Error(w, `{"error":"client certificate not authorized"}`, http.StatusForbidden)
	}
}

// withLogging writes a one-line access log per request in a format that's
// easy to grep or ship to a log aggregator.
func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start))
	}
}

// withCORS allows the dashboard to be served from a different origin/port
// than the API during local development (e.g. a Vite dev server).
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func chain(h http.HandlerFunc, mw ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
