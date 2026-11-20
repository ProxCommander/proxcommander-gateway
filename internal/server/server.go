// Package server implements the gateway's HTTP front end: routing, the Host
// and Origin checks, CORS, the audit log and the filtered API proxy.
package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/policy"
	"github.com/ProxCommander/proxcommander-gateway/internal/upstream"
	"github.com/ProxCommander/proxcommander-gateway/internal/version"
)

// Config configures the handler.
type Config struct {
	Name         string
	Pool         *upstream.Pool
	Policy       *policy.Policy
	Authorizer   Authorizer // nil: every API call gets 503
	CORSOrigins  []string
	AllowedHosts []string // in addition to localhost, 127.0.0.1 and ::1
	Logger       *slog.Logger
}

type server struct {
	cfg     Config
	origins map[string]bool
	hosts   map[string]bool
	log     *slog.Logger
}

// New returns the gateway's root handler.
func New(cfg Config) http.Handler {
	s := &server{
		cfg:     cfg,
		origins: map[string]bool{},
		hosts:   map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true},
		log:     cfg.Logger,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	for _, o := range cfg.CORSOrigins {
		s.origins[strings.TrimSuffix(o, "/")] = true
	}
	for _, h := range cfg.AllowedHosts {
		s.hosts[strings.ToLower(strings.Trim(h, "[]"))] = true
	}
	var h http.Handler = http.HandlerFunc(s.route)
	h = s.withCORS(h)
	h = s.withHostCheck(h)
	return s.withAudit(h)
}

// route dispatches on the raw escaped path. http.ServeMux is avoided on
// purpose: it redirects unclean paths instead of rejecting them.
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	switch {
	case p == "/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	case p == "/gateway/v1/info":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"name":    s.cfg.Name,
			"version": version.Version,
			"pairing": "not-yet-supported",
		})
	case strings.HasPrefix(p, "/api2/"):
		s.proxy(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// withHostCheck rejects requests whose Host header is not an allowed name,
// which blocks DNS rebinding. /healthz is exempt so probes can use any address.
func (s *server) withHostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !s.hosts[hostOnly(r.Host)] {
			writeError(w, http.StatusMisdirectedRequest, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

// withCORS allows only configured origins, rejects requests from any other
// origin, and answers every OPTIONS request itself (pveproxy answers 501).
func (s *server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.origins[origin] {
				writeError(w, http.StatusForbidden, "origin not allowed")
				return
			}
			h.Set("Access-Control-Allow-Origin", origin)
		}
		if r.Method == http.MethodOptions {
			if origin != "" && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withAudit writes one JSON line per request.
func (s *server) withAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		tr := &upstream.Trace{}
		next.ServeHTTP(rec, r.WithContext(upstream.WithTrace(r.Context(), tr)))
		path := r.URL.EscapedPath()
		if len(path) > policy.MaxPathLen {
			path = path[:policy.MaxPathLen]
		}
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("remote", r.RemoteAddr),
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", rec.status),
			slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
			slog.String("node", tr.Node),
		)
	})
}

type recorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush (and later Hijack).
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// writeError writes a Proxmox-style JSON error body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"data": nil, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
