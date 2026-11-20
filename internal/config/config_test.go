package config

import (
	"flag"
	"io"
	"reflect"
	"testing"
	"time"
)

func parse(t *testing.T, env map[string]string, args ...string) *Serve {
	t.Helper()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	s := ServeFlags(fs, func(k string) string { return env[k] })
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaults(t *testing.T) {
	s := parse(t, nil)
	if s.Listen != DefaultListen || s.StateDir != DefaultStateDir || s.Name != DefaultName ||
		s.UpstreamTimeout != DefaultTimeout || s.Profile != "" || s.CORSOrigins != nil || s.PVEAPIToken != "" {
		t.Fatalf("defaults: %+v", s)
	}
}

func TestEnvThenFlags(t *testing.T) {
	env := map[string]string{
		"PCG_LISTEN":                  ":9000",
		"PCG_STATE_DIR":               "/tmp/s",
		"PCG_ALLOWED_HOSTS":           "a.example, b.example",
		"PCG_CORS_ORIGINS":            "https://x.example",
		"PCG_PROFILE":                 "operator",
		"PCG_UPSTREAM_TIMEOUT":        "5s",
		"PCG_PVE_API_TOKEN":           "u@pam!t=s",
		"PCG_TOKEN_MODE_ALLOW_REMOTE": "true",
	}
	s := parse(t, env)
	if s.Listen != ":9000" || s.StateDir != "/tmp/s" || s.Profile != "operator" ||
		s.UpstreamTimeout != 5*time.Second || s.PVEAPIToken != "u@pam!t=s" ||
		!reflect.DeepEqual(s.AllowedHosts, []string{"a.example", "b.example"}) ||
		!reflect.DeepEqual(s.CORSOrigins, []string{"https://x.example"}) {
		t.Fatalf("env: %+v", s)
	}
	s = parse(t, env, "-listen", ":7000", "-allowed-hosts", "c.example", "-upstream-timeout", "1m")
	if s.Listen != ":7000" || !reflect.DeepEqual(s.AllowedHosts, []string{"c.example"}) || s.UpstreamTimeout != time.Minute {
		t.Fatalf("flags: %+v", s)
	}
}

func TestBadEnvTimeout(t *testing.T) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	s := ServeFlags(fs, func(k string) string {
		if k == "PCG_UPSTREAM_TIMEOUT" {
			return "soon"
		}
		return ""
	})
	if err := s.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenModeNeedsLoopbackOrOptIn(t *testing.T) {
	check := func(env map[string]string, args ...string) error {
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		s := ServeFlags(fs, func(k string) string { return env[k] })
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return s.Validate()
	}
	tok := map[string]string{"PCG_PVE_API_TOKEN": "u@pam!t=s"}
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.2:8080"} {
		if err := check(tok, "-listen", addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.168.1.5:8080", "gw.example.com:8080"} {
		if err := check(tok, "-listen", addr); err == nil {
			t.Errorf("%s: token mode allowed without opt-in", addr)
		}
		if err := check(tok, "-listen", addr, "-token-mode-allow-remote"); err != nil {
			t.Errorf("%s with flag: %v", addr, err)
		}
		if err := check(map[string]string{"PCG_PVE_API_TOKEN": "x", "PCG_TOKEN_MODE_ALLOW_REMOTE": "1"}, "-listen", addr); err != nil {
			t.Errorf("%s with env: %v", addr, err)
		}
		if err := check(nil, "-listen", addr); err != nil {
			t.Errorf("%s without token: %v", addr, err)
		}
	}
}
