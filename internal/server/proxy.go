package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/ProxCommander/proxcommander-gateway/internal/policy"
	"github.com/ProxCommander/proxcommander-gateway/internal/upstream"
)

// Authorizer authenticates a client API request and returns a function that
// sets the credentials presented to Proxmox. It returns a *StatusError to
// refuse the request.
type Authorizer interface {
	Authorize(r *http.Request) (setAuth func(http.Header), err error)
}

// StatusError is an HTTP status and message returned to the client.
type StatusError struct {
	Status int
	Msg    string
}

func (e *StatusError) Error() string { return e.Msg }

// ErrNotConfigured is returned while the gateway has no way to authenticate
// to Proxmox.
var ErrNotConfigured = &StatusError{Status: http.StatusServiceUnavailable, Msg: "gateway not configured"}

// APITokenAuth is a TEMPORARY step-1 mode: every allowed API call is sent to
// Proxmox with one PVE API token configured on the gateway. Clients are not
// authenticated. It goes away when pairing and gateway sessions land.
type APITokenAuth struct {
	header string
}

// NewAPITokenAuth accepts USER@REALM!TOKENID=SECRET, with or without the
// "PVEAPIToken=" prefix. An empty token yields an authorizer that refuses
// every request with ErrNotConfigured.
func NewAPITokenAuth(token string) *APITokenAuth {
	token = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(token), "PVEAPIToken="))
	if token == "" {
		return &APITokenAuth{}
	}
	return &APITokenAuth{header: "PVEAPIToken=" + token}
}

// Authorize implements Authorizer.
func (a *APITokenAuth) Authorize(*http.Request) (func(http.Header), error) {
	if a == nil || a.header == "" {
		return nil, ErrNotConfigured
	}
	return func(h http.Header) { h.Set("Authorization", a.header) }, nil
}

// forwardedRequestHeaders is the allow-list of client headers sent upstream.
// Everything else, notably Authorization, Cookie, CSRFPreventionToken,
// Origin and Referer, is dropped.
var forwardedRequestHeaders = []string{"Accept", "Accept-Encoding", "Accept-Language", "Content-Type", "User-Agent"}

func (s *server) proxy(w http.ResponseWriter, r *http.Request) {
	path, err := policy.Normalize(r.URL.EscapedPath())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid API path")
		return
	}
	var setAuth func(http.Header)
	if s.cfg.Authorizer == nil {
		err = ErrNotConfigured
	} else {
		setAuth, err = s.cfg.Authorizer.Authorize(r)
	}
	if err != nil {
		var se *StatusError
		if !errors.As(err, &se) {
			se = &StatusError{Status: http.StatusUnauthorized, Msg: "unauthorized"}
		}
		writeError(w, se.Status, se.Msg)
		return
	}
	if s.cfg.Policy == nil || !s.cfg.Policy.Allow(r.Method, path) {
		writeError(w, http.StatusForbidden, "not allowed by gateway policy")
		return
	}
	if s.cfg.Pool == nil || s.cfg.Pool.Len() == 0 {
		writeError(w, http.StatusServiceUnavailable, "no Proxmox nodes configured")
		return
	}
	ok, err := upstream.BufferBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	if !ok {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	rp := &httputil.ReverseProxy{
		Transport: s.cfg.Pool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			out.URL.Scheme = "https"
			out.URL.Host = "upstream.invalid" // replaced per node by the pool
			out.URL.Path = path.String()
			out.URL.RawPath = ""
			out.Host = ""
			h := http.Header{}
			for _, k := range forwardedRequestHeaders {
				if v := pr.In.Header.Values(k); len(v) > 0 {
					h[k] = v
				}
			}
			if _, ok := h["User-Agent"]; !ok {
				h["User-Agent"] = nil // stop net/http adding its own
			}
			setAuth(h)
			out.Header = h
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			for k := range resp.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					resp.Header.Del(k)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status, msg := http.StatusBadGateway, "no Proxmox node reachable"
			var ne net.Error
			switch {
			case errors.Is(err, context.Canceled):
				w.WriteHeader(499) // client went away; recorded in the audit log only
				return
			case errors.Is(err, upstream.ErrNoNodes):
				status, msg = http.StatusServiceUnavailable, "no Proxmox nodes configured"
			case errors.As(err, &ne) && ne.Timeout():
				status, msg = http.StatusGatewayTimeout, "Proxmox node timed out"
			}
			s.log.Warn("upstream error", "method", r.Method, "path", path.String(), "error", err.Error())
			writeError(w, status, msg)
		},
	}
	rp.ServeHTTP(w, r)
}
