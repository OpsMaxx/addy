// Package server wires addy's parts together and owns the process lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/opsmaxx/addy/internal/store"
)

// Config is what `addy serve` was asked to do.
type Config struct {
	DataDir  string
	Addr     string
	Dev      bool
	UI       bool
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

	log.Info("addy starting",
		"version", cfg.Version,
		"build", cfg.BuildSha,
		"data_dir", cfg.DataDir,
		"addr", cfg.resolvedAddr(),
		"dev", cfg.Dev,
	)

	<-ctx.Done()
	log.Info("addy stopping")
	return nil
}

// Selftest proves a running instance actually works, rather than that its
// process started. The distinction is the whole point: a relay that is up and
// cannot relay is the worst first impression the product can make.
func Selftest(ctx context.Context, target string) error {
	return errors.New("selftest needs a running instance to test; not implemented until the relay serves traffic")
}
