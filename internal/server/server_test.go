package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
	"github.com/ProxCommander/proxcommander-gateway/internal/policy"
	"github.com/ProxCommander/proxcommander-gateway/internal/testpki"
	"github.com/ProxCommander/proxcommander-gateway/internal/upstream"
)

const token = "root@pam!gw=00000000-1111-2222-3333-444444444444"

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (s *seen) last() (*http.Request, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil, ""
	}
	return s.reqs[len(s.reqs)-1], s.body[len(s.body)-1]
}

func setup(t *testing.T, auth Authorizer, profile string) (http.Handler, *seen, *bytes.Buffer) {
	t.Helper()
	ca := testpki.CA(t, "CA")
	leaf := testpki.Leaf(t, "pve1", ca)
	got := &seen{}
	be := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.reqs = append(got.reqs, r)
		got.body = append(got.body, string(b))
		got.mu.Unlock()
		w.Header().Set("Set-Cookie", "PVEAuthCookie=secret")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"version":"9.0"}}`)
	}))
	be.TLS = &tls.Config{Certificates: []tls.Certificate{testpki.TLSCert(leaf, ca)}}
	be.StartTLS()
	t.Cleanup(be.Close)

	pool, err := upstream.New([]upstream.Node{{Name: "pve1", URL: be.URL, Fingerprints: []string{pin.Fingerprint(ca.Cert.Raw)}}}, upstream.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.ForProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	h := New(Config{
		Name:         "test-gw",
		Pool:         pool,
		Policy:       pol,
		Authorizer:   auth,
		CORSOrigins:  []string{"http://localhost:8081", "https://proxcommander.app"},
		AllowedHosts: []string{"gw.example.com"},
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
	})
	return h, got, logs
}

func serve(h http.Handler, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	req.Host = "localhost:8080"
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestProxyForwardsWithGatewayToken(t *testing.T) {
	h, got, logs := setup(t, NewAPITokenAuth(token), "operator")
	w := serve(h, "POST", "/api2/json/nodes/pve1/qemu/100/status/start?timeout=5", map[string]string{
		"Authorization":       "PVEAuthCookie=client",
		"Cookie":              "PVEAuthCookie=client",
		"CSRFPreventionToken": "client",
		"Referer":             "http://evil",
		"X-Forwarded-For":     "1.2.3.4",
		"Content-Type":        "application/x-www-form-urlencoded",
		"Origin":              "https://proxcommander.app",
	}, "skiplock=0")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	r, body := got.last()
	if r == nil {
		t.Fatal("request not forwarded")
	}
	if a := r.Header.Get("Authorization"); a != "PVEAPIToken="+token {
		t.Errorf("Authorization = %q", a)
	}
	for _, k := range []string{"Cookie", "CSRFPreventionToken", "Referer", "Origin", "X-Forwarded-For"} {
		if v := r.Header.Get(k); v != "" {
			t.Errorf("%s forwarded: %q", k, v)
		}
	}
	if r.URL.Path != "/api2/json/nodes/pve1/qemu/100/status/start" || r.URL.RawQuery != "timeout=5" || body != "skiplock=0" {
		t.Errorf("forwarded %s?%s body %q", r.URL.Path, r.URL.RawQuery, body)
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type not forwarded")
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("upstream Set-Cookie leaked to client")
	}
	if got := w.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "https://proxcommander.app" {
		t.Errorf("Access-Control-Allow-Origin = %v", got)
	}

	var rec map[string]any
	line := strings.TrimSpace(logs.String())
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("audit line %q: %v", line, err)
	}
	for _, k := range []string{"time", "remote", "method", "path", "status", "duration_ms", "node"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("audit record missing %q: %s", k, line)
		}
	}
	if rec["node"] != "pve1" || rec["status"] != float64(200) || rec["path"] != "/api2/json/nodes/pve1/qemu/100/status/start" {
		t.Errorf("audit record: %s", line)
	}
	for _, secret := range []string{token, "00000000-1111", "client", "skiplock", "timeout=5"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
}

func TestProxyRefusals(t *testing.T) {
	h, got, _ := setup(t, NewAPITokenAuth(token), "read-only")
	unconfigured, _, _ := setup(t, NewAPITokenAuth(""), "operator")
	nilAuth, _, _ := setup(t, nil, "operator")

	tests := []struct {
		name   string
		h      http.Handler
		method string
		target string
		hdr    map[string]string
		body   string
		want   int
	}{
		{"no token", unconfigured, "GET", "/api2/json/version", nil, "", 503},
		{"nil authorizer", nilAuth, "GET", "/api2/json/version", nil, "", 503},
		{"policy deny", h, "POST", "/api2/json/nodes/pve1/qemu/100/status/start", nil, "", 403},
		{"root endpoint", h, "POST", "/api2/json/nodes/pve1/termproxy", nil, "", 403},
		{"dot segments", h, "GET", "/api2/json/nodes/%2e%2e/access/users", nil, "", 400},
		{"double slash", h, "GET", "/api2/json//version", nil, "", 400},
		{"outside prefix", h, "GET", "/api2/extjs/version", nil, "", 400},
		{"unknown route", h, "GET", "/api/json/version", nil, "", 404},
		{"bad host", h, "GET", "/api2/json/version", map[string]string{"Host": "evil.example:8080"}, "", 421},
		{"bad origin", h, "GET", "/api2/json/version", map[string]string{"Origin": "https://evil.example"}, "", 403},
		{"null origin", h, "GET", "/api2/json/version", map[string]string{"Origin": "null"}, "", 403},
		{"body too large", operatorHandler(t), "POST", "/api2/json/nodes/pve1/qemu/100/status/start", nil, strings.Repeat("a", upstream.MaxBody+1), 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := got.count()
			w := serve(tt.h, tt.method, tt.target, tt.hdr, tt.body)
			if w.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.want, w.Body)
			}
			if got.count() != before {
				t.Fatal("refused request reached Proxmox")
			}
		})
	}
}

// operatorHandler returns an operator handler with a token, for body tests.
func operatorHandler(t *testing.T) http.Handler {
	h, _, _ := setup(t, NewAPITokenAuth(token), "operator")
	return h
}

func TestAllowedHosts(t *testing.T) {
	h, _, _ := setup(t, NewAPITokenAuth(token), "read-only")
	for _, host := range []string{"localhost", "localhost:8080", "127.0.0.1:8080", "[::1]:8080", "[::1]", "GW.example.com", "gw.example.com:443"} {
		if w := serve(h, "GET", "/api2/json/version", map[string]string{"Host": host}, ""); w.Code != 200 {
			t.Errorf("Host %q: status %d", host, w.Code)
		}
	}
	for _, host := range []string{"", "evil.example", "localhost.evil.example", "127.0.0.2:8080", "gw.example.com.evil"} {
		if w := serve(h, "GET", "/gateway/v1/info", map[string]string{"Host": host}, ""); w.Code != 421 {
			t.Errorf("Host %q: status %d, want 421", host, w.Code)
		}
	}
	if w := serve(h, "GET", "/healthz", map[string]string{"Host": "10.1.2.3:8080"}, ""); w.Code != 200 {
		t.Errorf("/healthz with IP host: %d", w.Code)
	}
}

func TestPreflight(t *testing.T) {
	h, got, _ := setup(t, NewAPITokenAuth(token), "read-only")
	w := serve(h, "OPTIONS", "/api2/json/nodes/pve1/qemu/100/status/start", map[string]string{
		"Origin":                         "http://localhost:8081",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization",
	}, "")
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	hd := w.Header()
	if hd.Get("Access-Control-Allow-Origin") != "http://localhost:8081" ||
		!strings.Contains(hd.Get("Access-Control-Allow-Headers"), "Authorization") ||
		!strings.Contains(hd.Get("Access-Control-Allow-Methods"), "POST") ||
		hd.Get("Vary") != "Origin" {
		t.Fatalf("headers %v", hd)
	}
	if got.count() != 0 {
		t.Fatal("preflight forwarded to Proxmox")
	}
	w = serve(h, "OPTIONS", "/api2/json/version", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}, "")
	if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight: %d %v", w.Code, w.Header())
	}
}

func TestVaryOnEveryResponse(t *testing.T) {
	h, _, _ := setup(t, nil, "read-only")
	for _, p := range []string{"/healthz", "/gateway/v1/info", "/api2/json/version", "/nope"} {
		if w := serve(h, "GET", p, nil, ""); w.Header().Get("Vary") != "Origin" {
			t.Errorf("%s: Vary = %q", p, w.Header().Get("Vary"))
		}
	}
}

func TestInfoAndHealth(t *testing.T) {
	h, _, _ := setup(t, nil, "read-only")
	w := serve(h, "GET", "/gateway/v1/info", nil, "")
	var info map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if info["name"] != "test-gw" || info["pairing"] != "not-yet-supported" || info["version"] == "" {
		t.Fatalf("info = %v", info)
	}
	if w := serve(h, "GET", "/healthz", nil, ""); w.Code != 200 || w.Body.String() != "ok\n" {
		t.Fatalf("healthz %d %q", w.Code, w.Body)
	}
	if w := serve(h, "POST", "/healthz", nil, ""); w.Code != 405 {
		t.Fatalf("POST healthz %d", w.Code)
	}
}

func TestNewAPITokenAuth(t *testing.T) {
	for _, in := range []string{token, "PVEAPIToken=" + token, " " + token + "\n"} {
		set, err := NewAPITokenAuth(in).Authorize(nil)
		if err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		set(h)
		if h.Get("Authorization") != "PVEAPIToken="+token {
			t.Errorf("%q -> %q", in, h.Get("Authorization"))
		}
	}
	if _, err := NewAPITokenAuth("  ").Authorize(nil); err != ErrNotConfigured {
		t.Errorf("empty token: %v", err)
	}
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}
