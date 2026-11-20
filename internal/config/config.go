// Package config reads runtime settings from flags, falling back to PCG_*
// environment variables and then to defaults. Secrets come from the
// environment only, so they never appear in the process list.
package config

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Defaults.
const (
	DefaultListen   = "127.0.0.1:8080"
	DefaultStateDir = "/var/lib/proxcommander-gateway"
	DefaultName     = "proxcommander-gateway"
	DefaultTimeout  = 30 * time.Second
)

// Common holds settings shared by every subcommand.
type Common struct {
	StateDir string
}

// Serve holds the settings for the serve subcommand.
type Serve struct {
	Common
	Listen          string
	Name            string
	AuditLog        string
	AllowedHosts    []string
	CORSOrigins     []string // overrides the state file when set
	Profile         string   // overrides the state file when set
	UpstreamTimeout time.Duration

	// PVEAPIToken is the temporary step-1 upstream credential. Environment
	// only (PCG_PVE_API_TOKEN); never logged.
	PVEAPIToken string
	// AllowRemoteTokenMode permits the token mode on a non-loopback listen
	// address (needed in a container, or behind a tunnel or reverse proxy).
	AllowRemoteTokenMode bool

	envTimeoutErr error
}

// Getenv looks up an environment variable.
type Getenv func(string) string

// CommonFlags registers the shared flags on fs.
func CommonFlags(fs *flag.FlagSet, env Getenv, c *Common) {
	fs.StringVar(&c.StateDir, "state-dir", or(env("PCG_STATE_DIR"), DefaultStateDir), "state directory (env PCG_STATE_DIR)")
}

// ServeFlags registers the serve flags on fs. Call Finish after fs.Parse.
func ServeFlags(fs *flag.FlagSet, env Getenv) *Serve {
	s := &Serve{PVEAPIToken: env("PCG_PVE_API_TOKEN")}
	CommonFlags(fs, env, &s.Common)
	fs.StringVar(&s.Listen, "listen", or(env("PCG_LISTEN"), DefaultListen), "listen address (env PCG_LISTEN)")
	fs.StringVar(&s.Name, "name", or(env("PCG_NAME"), DefaultName), "gateway name shown to apps (env PCG_NAME)")
	fs.StringVar(&s.AuditLog, "audit-log", env("PCG_AUDIT_LOG"), "also append the JSON log to this file (env PCG_AUDIT_LOG)")
	fs.Func("allowed-hosts", "comma-separated public host names accepted in the Host header, besides localhost (env PCG_ALLOWED_HOSTS)", func(v string) error {
		s.AllowedHosts = splitList(v)
		return nil
	})
	fs.Func("cors-origins", "comma-separated allowed web origins; overrides the state file (env PCG_CORS_ORIGINS)", func(v string) error {
		s.CORSOrigins = splitList(v)
		return nil
	})
	fs.StringVar(&s.Profile, "profile", env("PCG_PROFILE"), "policy profile, read-only or operator; overrides the state file (env PCG_PROFILE)")
	fs.BoolVar(&s.AllowRemoteTokenMode, "token-mode-allow-remote", isTrue(env("PCG_TOKEN_MODE_ALLOW_REMOTE")),
		"allow PCG_PVE_API_TOKEN on a non-loopback listen address; clients are not authenticated in that mode (env PCG_TOKEN_MODE_ALLOW_REMOTE)")
	s.AllowedHosts = splitList(env("PCG_ALLOWED_HOSTS"))
	s.CORSOrigins = splitList(env("PCG_CORS_ORIGINS"))
	s.UpstreamTimeout = DefaultTimeout
	fs.Func("upstream-timeout", "time to wait for a node's response headers (env PCG_UPSTREAM_TIMEOUT, default 30s)", func(v string) error {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid duration %q", v)
		}
		s.UpstreamTimeout = d
		return nil
	})
	if v := env("PCG_UPSTREAM_TIMEOUT"); v != "" {
		if f := fs.Lookup("upstream-timeout"); f != nil {
			// Parsed again by fs.Parse if the flag is also given.
			s.envTimeoutErr = f.Value.Set(v)
		}
	}
	return s
}

// Validate reports configuration errors found while reading the environment.
func (s *Serve) Validate() error {
	if s.envTimeoutErr != nil {
		return fmt.Errorf("PCG_UPSTREAM_TIMEOUT: %w", s.envTimeoutErr)
	}
	if s.Listen == "" {
		return fmt.Errorf("listen address is empty")
	}
	if s.PVEAPIToken != "" && !s.AllowRemoteTokenMode && !LoopbackListen(s.Listen) {
		return fmt.Errorf("PCG_PVE_API_TOKEN is set but the gateway listens on %s, beyond this machine. "+
			"The temporary token mode does not authenticate clients, so anyone who can reach it gets the token's permissions. "+
			"Listen on 127.0.0.1, or set PCG_TOKEN_MODE_ALLOW_REMOTE=true if a container port bound to 127.0.0.1, a tunnel or an authenticating proxy is the only way in", s.Listen)
	}
	return nil
}

// LoopbackListen reports whether addr (host:port) only accepts connections
// from this machine.
func LoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isTrue(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
