package upstream

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
	"github.com/ProxCommander/proxcommander-gateway/internal/testpki"
)

type backend struct {
	srv  *httptest.Server
	hits atomic.Int64
	node Node
}

func newBackend(t *testing.T, name string, delay time.Duration) *backend {
	t.Helper()
	ca := testpki.CA(t, name+" CA")
	leaf := testpki.Leaf(t, name, ca)
	b := &backend{}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Node", name)
		io.WriteString(w, name+":"+r.Method+":"+r.URL.Path+":"+string(body))
	}))
	b.srv.TLS = &tls.Config{Certificates: []tls.Certificate{testpki.TLSCert(leaf, ca)}}
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	b.node = Node{Name: name, URL: b.srv.URL, Fingerprints: []string{pin.Fingerprint(ca.Cert.Raw)}}
	return b
}

// deadNode returns a node whose address refuses connections.
func deadNode(t *testing.T, name string) Node {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return Node{Name: name, URL: "https://" + addr, Fingerprints: []string{pin.Fingerprint([]byte(name))}}
}

func do(t *testing.T, p *Pool, method, body string) (*http.Response, string, error) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://placeholder/api2/json/version", rd)
	req.RequestURI = ""
	if ok, err := BufferBody(req); !ok || err != nil {
		t.Fatalf("BufferBody: %v %v", ok, err)
	}
	tr := &Trace{}
	req = req.WithContext(WithTrace(req.Context(), tr))
	resp, err := p.RoundTrip(req)
	if err != nil {
		return nil, tr.Node, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(b)))
	return resp, tr.Node, nil
}

func body(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestNewRequiresPins(t *testing.T) {
	if _, err := New([]Node{{Name: "a", URL: "https://127.0.0.1:1"}}, Options{}); err == nil {
		t.Fatal("expected error for node without pins")
	}
	if _, err := New([]Node{{Name: "a", URL: "http://127.0.0.1:1", Fingerprints: []string{pin.Fingerprint(nil)}}}, Options{}); err == nil {
		t.Fatal("expected error for non-https node")
	}
}

func TestPinnedSuccess(t *testing.T) {
	b := newBackend(t, "n1", 0)
	p, err := New([]Node{b.node}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	resp, node, err := do(t, p, "POST", "x=1")
	if err != nil {
		t.Fatal(err)
	}
	if got := body(resp); got != "n1:POST:/api2/json/version:x=1" || node != "n1" {
		t.Fatalf("got %q via %q", got, node)
	}
}

func TestWrongPinFailsAndFailsOver(t *testing.T) {
	bad := newBackend(t, "bad", 0)
	bad.node.Fingerprints = []string{pin.Fingerprint([]byte("other"))}
	good := newBackend(t, "good", 0)

	p, _ := New([]Node{bad.node}, Options{})
	_, _, err := do(t, p, "GET", "")
	var ce *ConnectError
	if err == nil || !errors.As(err, &ce) {
		t.Fatalf("wrong pin: err = %v, want ConnectError", err)
	}
	if bad.hits.Load() != 0 {
		t.Fatal("request reached a node with a wrong pin")
	}

	// A pin mismatch means nothing was sent, so even a POST may move on.
	p, _ = New([]Node{bad.node, good.node}, Options{})
	resp, node, err := do(t, p, "POST", "a")
	if err != nil || node != "good" || body(resp) != "good:POST:/api2/json/version:a" {
		t.Fatalf("failover: %v via %q", err, node)
	}
	if bad.hits.Load() != 0 {
		t.Fatal("request reached a node with a wrong pin")
	}
}

func TestDeadNodeFailoverForAnyMethod(t *testing.T) {
	good := newBackend(t, "good", 0)
	p, _ := New([]Node{deadNode(t, "dead"), good.node}, Options{})
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		resp, node, err := do(t, p, m, "")
		if err != nil || node != "good" || resp.StatusCode != 200 {
			t.Fatalf("%s: %v via %q", m, err, node)
		}
	}
}

func TestPreferredNodeIsSticky(t *testing.T) {
	a := newBackend(t, "a", 0)
	b := newBackend(t, "b", 0)
	dead := deadNode(t, "dead")
	p, _ := New([]Node{dead, a.node, b.node}, Options{})
	for range 3 {
		if _, node, err := do(t, p, "GET", ""); err != nil || node != "a" {
			t.Fatalf("%v via %q", err, node)
		}
	}
	if int(p.preferred.Load()) != 1 {
		t.Fatalf("preferred = %d, want 1", p.preferred.Load())
	}
}

func TestTimeoutRetriesOnlyReads(t *testing.T) {
	slow := newBackend(t, "slow", 2*time.Second)
	fast := newBackend(t, "fast", 0)
	p, _ := New([]Node{slow.node, fast.node}, Options{ResponseTimeout: 200 * time.Millisecond})

	for _, m := range []string{"GET", "HEAD"} {
		p.preferred.Store(0)
		resp, node, err := do(t, p, m, "")
		if err != nil || node != "fast" || resp.StatusCode != 200 {
			t.Fatalf("%s after timeout: %v via %q", m, err, node)
		}
	}

	for _, m := range []string{"POST", "PUT", "DELETE"} {
		p.preferred.Store(0)
		before := fast.hits.Load()
		_, _, err := do(t, p, m, "x")
		var ne net.Error
		if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("%s: err = %v, want timeout", m, err)
		}
		if fast.hits.Load() != before {
			t.Fatalf("%s was retried on another node after a timeout", m)
		}
	}
}

func TestBufferBodyLimit(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", MaxBody+1)))
	ok, err := BufferBody(req)
	if err != nil || ok {
		t.Fatalf("oversized body accepted: %v %v", ok, err)
	}
	req = httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", MaxBody)))
	if ok, err := BufferBody(req); !ok || err != nil {
		t.Fatalf("max body rejected: %v %v", ok, err)
	}
}

func TestNoNodes(t *testing.T) {
	p, _ := New(nil, Options{})
	if _, _, err := do(t, p, "GET", ""); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("err = %v", err)
	}
}
