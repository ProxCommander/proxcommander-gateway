package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/audit"
	"github.com/ProxCommander/proxcommander-gateway/internal/config"
	"github.com/ProxCommander/proxcommander-gateway/internal/policy"
	"github.com/ProxCommander/proxcommander-gateway/internal/server"
	"github.com/ProxCommander/proxcommander-gateway/internal/state"
	"github.com/ProxCommander/proxcommander-gateway/internal/upstream"
	"github.com/ProxCommander/proxcommander-gateway/internal/version"
)

func (c *cli) serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	cfg := config.ServeFlags(fs, c.getenv)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.Validate(); err != nil {
		return c.fail(err)
	}

	log, closeLog, err := audit.Open(c.stdout, cfg.AuditLog)
	if err != nil {
		return c.fail(err)
	}
	defer closeLog()

	st, err := state.Load(cfg.StateDir)
	if err != nil {
		return c.fail(err)
	}
	profile := st.Profile
	if cfg.Profile != "" {
		profile = cfg.Profile
	}
	pol, err := policy.ForProfile(profile)
	if err != nil {
		return c.fail(err)
	}
	origins := st.CORSOrigins
	if len(cfg.CORSOrigins) > 0 {
		origins = cfg.CORSOrigins
	}
	nodes := make([]upstream.Node, 0, len(st.Nodes))
	for _, n := range st.Nodes {
		nodes = append(nodes, upstream.Node{Name: n.Name, URL: n.URL, Fingerprints: n.Fingerprints})
	}
	pool, err := upstream.New(nodes, upstream.Options{ResponseTimeout: cfg.UpstreamTimeout})
	if err != nil {
		return c.fail(err)
	}
	defer pool.CloseIdle()

	if len(nodes) == 0 {
		log.Warn("no Proxmox nodes configured; add one with: proxcommander-gateway nodes add https://host:8006")
	}
	if cfg.PVEAPIToken == "" {
		log.Warn("PCG_PVE_API_TOKEN is not set; API calls return 503 until pairing is available")
	} else {
		log.Warn("temporary API token mode: API calls are not authenticated and run with the token's permissions; keep the gateway on a trusted network")
	}

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: server.New(server.Config{
			Name:         cfg.Name,
			Pool:         pool,
			Policy:       pol,
			Authorizer:   server.NewAPITokenAuth(cfg.PVEAPIToken),
			CORSOrigins:  origins,
			AllowedHosts: cfg.AllowedHosts,
			Logger:       log,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("gateway started", "version", version.Version, "listen", cfg.Listen,
		"profile", pol.Name(), "nodes", len(nodes), "cors_origins", origins)

	select {
	case err := <-errc:
		return c.fail(err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return c.fail(err)
	}
	log.Info("stopped")
	return 0
}
