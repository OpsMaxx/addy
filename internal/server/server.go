// Package server wires addy's parts together and owns the process lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/opsmaxx/addy/internal/api"
	"github.com/opsmaxx/addy/internal/frontdoor"
	"github.com/opsmaxx/addy/internal/portal"
	"github.com/opsmaxx/addy/internal/store"
)

// Config is what `addy serve` was asked to do.
type Config struct {
	DataDir  string
	Addr     string
	HTTPAddr string
	Dev      bool
	UI       bool
	Email    string
	Domain   string
	Version  string
	BuildSha string
}

// DefaultDataDir is resolved at first use rather than being a constant, because
// it differs per platform and because a relative default would put the database
// wherever the process happened to be started from.
var DefaultDataDir = defaultDataDir()

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "addy")
		}
		return "addy-data"
	}
	// The normal case is a container or a systemd unit, where /var/lib is
	// where durable service state belongs. An unprivileged run falls back to
	// the user's own directory rather than failing, so `addy serve -dev` works
	// with no setup at all -- which is the entire point of dev mode.
	if os.Geteuid() == 0 {
		return "/var/lib/addy"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "addy")
	}
	return "addy-data"
}

// Addr resolves the bind address, which differs in dev mode for a reason worth
// stating: dev binds LOOPBACK, not :8443. A development instance with a
// self-signed certificate and no pairing yet should not be reachable from the
// network by accident.
func (c Config) resolvedAddr() string {
	if c.Addr != "" {
		return c.Addr
	}
	if c.Dev {
		return "127.0.0.1:8443"
	}
	return ":443"
}

// The plain-HTTP port is not optional in production: certmagic obtains
// certificates with an ACME HTTP-01 challenge, and that challenge arrives on
// port 80 or not at all.
func (c Config) resolvedHTTPAddr() string {
	if c.HTTPAddr != "" {
		return c.HTTPAddr
	}
	if c.Dev {
		return "127.0.0.1:8080"
	}
	return ":80"
}

// Run starts the relay and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	log := slog.Default()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("creating data directory %s: %w", cfg.DataDir, err)
	}
	// 0700 whether or not MkdirAll created it. An existing directory keeps its
	// own mode, and this one holds the roster chain and every device's public
	// key -- metadata the threat model is explicit about minimising, which
	// would be undermined by leaving it world-readable because it happened to
	// pre-exist.
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("securing data directory %s: %w", cfg.DataDir, err)
	}

	db, err := store.Open(filepath.Join(cfg.DataDir, "addy.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	routes, err := loadRoutes(ctx, db, cfg)
	if err != nil {
		return err
	}

	// No consumers yet: the services that need certificates as files arrive
	// with the service wizards. The exporter is wired now because dev mode
	// drives it through the same entry point the ACME hook uses, so the path
	// is exercised from the first commit rather than first exercised in
	// production sixty days after an install.
	export := frontdoor.NewExporter(nil)

	tlsConf, challenge, magic, err := frontdoor.NewACME(frontdoor.ACMEConfig{
		Dev:     cfg.Dev,
		Email:   cfg.Email,
		DataDir: cfg.DataDir,
		Routes:  routes,
		Export:  export,
	})
	if err != nil {
		return err
	}

	if cfg.Dev {
		if err := frontdoor.DevCertificate(ctx, magic, export, routes.Hosts()); err != nil {
			return err
		}
	} else if hosts := routes.Hosts(); len(hosts) > 0 {
		// Asynchronously, so a CA that is slow or unreachable delays
		// certificates rather than the whole process starting.
		if err := magic.ManageAsync(ctx, hosts); err != nil {
			return fmt.Errorf("managing certificates: %w", err)
		}
	}

	// The API is always served. The PORTAL is headless by default -- it is a
	// web surface on a box whose whole pitch is that it holds nothing worth
	// attacking, so an operator who does not want one should not be running
	// one. Turning the portal off does not turn addy off.
	mux := http.NewServeMux()
	mux.Handle("/v1/", api.New(db, log).Handler())

	var pages http.Handler = http.NotFoundHandler()
	if cfg.UI {
		p, err := portal.Handler(portal.Config{Version: cfg.Version, BuildSha: cfg.BuildSha})
		if err != nil {
			return fmt.Errorf("building the portal: %w", err)
		}
		pages = portal.NoServiceWorker(p)
	}
	// Longest pattern wins, so this beats "/v1/" for exactly this path. /v1/meta
	// is the portal's, because it is what an unauthenticated page reads to show
	// its own build, and it is tested to expose nothing else.
	mux.Handle("/v1/meta", pages)
	mux.Handle("/", pages)

	var terminated http.Handler = mux

	door := &frontdoor.Door{
		Routes:           routes,
		Handler:          terminated,
		TLSConfig:        tlsConf,
		ChallengeHandler: challenge,
		HTTPSAddr:        cfg.resolvedAddr(),
		HTTPAddr:         cfg.resolvedHTTPAddr(),
		Log:              log,
	}

	log.Info("addy starting",
		"version", cfg.Version,
		"build", cfg.BuildSha,
		"data_dir", cfg.DataDir,
		"https", cfg.resolvedAddr(),
		"http", cfg.resolvedHTTPAddr(),
		"hosts", routes.Hosts(),
		"portal", cfg.UI,
		"dev", cfg.Dev,
	)

	err = door.Run(ctx)
	log.Info("addy stopping")
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// loadRoutes builds the routing table from the database.
//
// In dev the table is seeded with localhost rather than read from disk, so a
// fresh `addy serve -dev` serves something immediately. It is still a real
// route through the real table, which means Table.Decide -- including its
// refusal of everything else -- runs in dev exactly as it does in production.
func loadRoutes(ctx context.Context, db *store.DB, cfg Config) (*frontdoor.Table, error) {
	routes := frontdoor.NewTable()

	stored, err := db.Domains(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range stored {
		if err := routes.Set(frontdoor.Route{
			Host:    d.Hostname,
			Mode:    frontdoor.Mode(d.Mode),
			Backend: d.Backend,
			HTTP80:  d.HTTP80,
		}); err != nil {
			return nil, fmt.Errorf("loading the stored route for %s: %w", d.Hostname, err)
		}
	}

	// A fresh install has nothing in the database, so the domain the installer
	// was given is what gets it its first route -- and therefore its first
	// certificate. Without this an operator would install addy, start it, and
	// find that it refuses every hostname including its own.
	if cfg.Domain != "" {
		if _, ok := routes.Lookup(cfg.Domain); !ok {
			if err := routes.Set(frontdoor.Route{Host: cfg.Domain, Mode: frontdoor.Terminate}); err != nil {
				return nil, fmt.Errorf("seeding the route for %s: %w", cfg.Domain, err)
			}
			if err := db.PutDomain(ctx, store.Domain{Hostname: cfg.Domain, Mode: string(frontdoor.Terminate)}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Dev {
		for _, host := range []string{"localhost", "addy.localhost"} {
			if _, ok := routes.Lookup(host); ok {
				continue
			}
			if err := routes.Set(frontdoor.Route{Host: host, Mode: frontdoor.Terminate}); err != nil {
				return nil, fmt.Errorf("seeding the development route for %s: %w", host, err)
			}
		}
	}
	return routes, nil
}
