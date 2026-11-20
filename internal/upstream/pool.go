// Package upstream sends requests to the configured Proxmox nodes over TLS
// verified only by pinned fingerprints, failing over between nodes.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
)

// Node is one upstream target.
type Node struct {
	Name         string
	URL          string // https://host:port
	Fingerprints []string
}

// Options tunes the pool. Zero values select the defaults.
type Options struct {
	DialTimeout      time.Duration // default 5s
	HandshakeTimeout time.Duration // default 10s
	ResponseTimeout  time.Duration // time to response headers, default 30s
}

// Pool is an http.RoundTripper that sends each request to the first
// reachable node, starting with the one that last answered.
//
// Failover rules: a request is tried on the next node when the connection
// or TLS handshake to a node fails, since nothing was sent. GET and HEAD are
// also retried after any later error, including a timeout. Other methods are
// never retried once they may have reached a node.
type Pool struct {
	nodes     []*poolNode
	preferred atomic.Int64
}

type poolNode struct {
	Node
	host      string
	transport *http.Transport
}

// ConnectError reports that a node could not be reached, so the request was
// never sent to it.
type ConnectError struct {
	Node string
	Err  error
}

func (e *ConnectError) Error() string { return fmt.Sprintf("connect to node %s: %v", e.Node, e.Err) }
func (e *ConnectError) Unwrap() error { return e.Err }

// ErrNoNodes is returned when the pool has no nodes.
var ErrNoNodes = errors.New("upstream: no nodes configured")

// New builds a pool. Every node must have at least one pinned fingerprint.
func New(nodes []Node, opt Options) (*Pool, error) {
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 5 * time.Second
	}
	if opt.HandshakeTimeout == 0 {
		opt.HandshakeTimeout = 10 * time.Second
	}
	if opt.ResponseTimeout == 0 {
		opt.ResponseTimeout = 30 * time.Second
	}
	p := &Pool{}
	for _, n := range nodes {
		u, err := url.Parse(n.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("upstream: node %s: invalid URL %q", n.Name, n.URL)
		}
		cfg, err := pin.TLSConfig(n.Fingerprints, u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("upstream: node %s: %w", n.Name, err)
		}
		pn := &poolNode{Node: n, host: u.Host}
		pn.transport = &http.Transport{
			Proxy:                 nil, // never route upstream traffic via HTTP(S)_PROXY
			DialTLSContext:        dialPinned(n.Name, cfg, opt),
			ResponseHeaderTimeout: opt.ResponseTimeout,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     false,
		}
		p.nodes = append(p.nodes, pn)
	}
	return p, nil
}

func dialPinned(name string, cfg *tls.Config, opt Options) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: opt.DialTimeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, &ConnectError{Node: name, Err: err}
		}
		conn := tls.Client(raw, cfg.Clone())
		hctx, cancel := context.WithTimeout(ctx, opt.HandshakeTimeout)
		defer cancel()
		if err := conn.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, &ConnectError{Node: name, Err: err}
		}
		return conn, nil
	}
}

// Len returns the number of nodes.
func (p *Pool) Len() int { return len(p.nodes) }

// Trace records which node answered a request.
type Trace struct{ Node string }

type traceKey struct{}

// WithTrace returns a context that makes the pool record the node it used in t.
func WithTrace(ctx context.Context, t *Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

// MaxBody is the largest request body the pool will buffer for replay.
const MaxBody = 1 << 20

// RoundTrip implements http.RoundTripper. req.URL's scheme and host are
// ignored; each attempt targets a node's address with req.URL's path and query.
// The request body, if any, must be replayable via req.GetBody.
func (p *Pool) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(p.nodes) == 0 {
		return nil, ErrNoNodes
	}
	trace, _ := req.Context().Value(traceKey{}).(*Trace)
	idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead
	start := int(p.preferred.Load())
	var lastErr error
	for i := range p.nodes {
		idx := (start + i) % len(p.nodes)
		n := p.nodes[idx]
		out := req.Clone(req.Context())
		out.URL.Scheme = "https"
		out.URL.Host = n.host
		out.Host = ""
		if req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return nil, errors.New("upstream: request body is not replayable")
			}
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			out.Body = body
		}
		if trace != nil {
			trace.Node = n.Name
		}
		resp, err := n.transport.RoundTrip(out)
		if err == nil {
			p.preferred.Store(int64(idx))
			return resp, nil
		}
		lastErr = err
		if req.Context().Err() != nil {
			return nil, err
		}
		var ce *ConnectError
		if errors.As(err, &ce) || idempotent {
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

// BufferBody reads r's body (up to MaxBody) so it can be replayed on another
// node. It reports false if the body is too large.
func BufferBody(r *http.Request) (bool, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return true, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	r.Body.Close()
	if err != nil {
		return false, err
	}
	if len(b) > MaxBody {
		return false, nil
	}
	r.ContentLength = int64(len(b))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	r.Body, _ = r.GetBody()
	if len(b) == 0 {
		r.Body, r.GetBody = http.NoBody, nil
	}
	return true, nil
}

// CloseIdle closes idle upstream connections.
func (p *Pool) CloseIdle() {
	for _, n := range p.nodes {
		n.transport.CloseIdleConnections()
	}
}
