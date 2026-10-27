// Package server wires addy's parts together and owns the process lifecycle.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/opsmaxx/addy/internal/api"
	"github.com/opsmaxx/addy/internal/frontdoor"
	"github.com/opsmaxx/addy/internal/operator"
	"github.com/opsmaxx/addy/internal/overlay"
	"github.com/opsmaxx/addy/internal/portal"
	"github.com/opsmaxx/addy/internal/protocol"
	"github.com/opsmaxx/addy/internal/relay"
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

	// TURN. Off unless a public IP is given, because a relay that guesses its
	// own address allocates addresses nobody can reach and fails only under
	// the NAT conditions it exists for.
	//
	// `TurnExternal` points devices at somebody else's relay (coturn, or a
	// hosted one) instead of running one here. Worth having as a first-class
	// option rather than a deployment note: an embedded relay sees the timing
	// and size of every packet two devices exchange, and an operator who would
	// rather that were a different box's problem should not have to fork the
	// server to arrange it.
	TurnPublicIP string
	TurnPort     int
	TurnSecret   string
	TurnExternal string

	// The operator portal's identity provider. OFF unless all three are set,
	// and absent rather than open when it is off — see internal/operator.
	//
	// Google is not special here: it is `https://accounts.google.com` in
	// OIDCIssuer. Any provider with OIDC discovery works, which is the point:
	// a relay somebody runs for their own team should sit behind whatever that
	// team already signs in to.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// Who may sign in besides the operator: open, invite or closed. See
	// operator.SignupPolicy; anything unrecognised becomes `invite`.
	Signup string

	// The overlay control plane. Off unless HeadscaleURL is set; the API key
	// is powerful -- it can create and delete nodes, users and keys across the
	// whole coordination server -- which is why nothing here has a default.
	// ACMECA overrides the certificate authority. Empty means Let's Encrypt
	// production; `-acme-staging` sets it to their staging directory, which is
	// what a test on a hoster's shared default hostname must use.
	ACMECA string

	HeadscaleURL    string
	HeadscaleAPIKey string
	HeadscaleUser   string
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

	acmeStatus := &frontdoor.ACMEStatus{}
	tlsConf, challenge, magic, err := frontdoor.NewACME(frontdoor.ACMEConfig{
		CA:      cfg.ACMECA,
		Status:  acmeStatus,
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
	apiServer := api.New(db, log)

	// The relay. Off unless an operator gave it a public address, and skipped
	// entirely when they pointed devices at somebody else's -- an embedded
	// relay sees the timing and size of every packet two devices exchange, so
	// "not on this box" is a legitimate answer and not a degraded one.
	if cfg.TurnExternal != "" {
		apiServer.TurnExternal = cfg.TurnExternal
		log.Info("relay: using an external TURN server", "url", cfg.TurnExternal)
	} else if cfg.TurnPublicIP != "" {
		secret, err := turnSecret(ctx, db, cfg.TurnSecret)
		if err != nil {
			return fmt.Errorf("relay secret: %w", err)
		}
		r, err := relay.Start(relay.Config{
			PublicIP: cfg.TurnPublicIP,
			Realm:    cfg.Domain,
			Port:     cfg.TurnPort,
			Secret:   secret,
			Log:      log,
		})
		if err != nil {
			return fmt.Errorf("starting the relay: %w", err)
		}
		defer r.Close()
		apiServer.Turn = minter{r}
	} else {
		log.Info("relay: none configured; devices on networks that need one will not connect",
			"hint", "pass -turn-public-ip to run one, or -turn to use an external server")
	}

	// The overlay. Off unless an operator pointed addy at a headscale, which
	// the M5a wizard is what deploys.
	if cfg.HeadscaleURL != "" {
		m, err := overlay.New(overlay.Config{
			BaseURL: cfg.HeadscaleURL,
			APIKey:  cfg.HeadscaleAPIKey,
			User:    cfg.HeadscaleUser,
		})
		if err != nil {
			return fmt.Errorf("overlay: %w", err)
		}
		apiServer.Overlay = overlayAdapter{m}
		// The control URL devices point at is addy's own hostname: headscale
		// sits on loopback behind the front door, so its own base URL is
		// unreachable from anywhere a device is.
		apiServer.OverlayControlURL = "https://" + cfg.Domain
		log.Info("overlay: devices can join through headscale", "control_url", apiServer.OverlayControlURL)
	}

	mux.Handle("/v1/", apiServer.Handler())

	var pages http.Handler = http.NotFoundHandler()
	if cfg.UI {
		p, err := portal.Handler(portal.Config{Version: cfg.Version, BuildSha: cfg.BuildSha})
		if err != nil {
			return fmt.Errorf("building the portal: %w", err)
		}
		pages = portal.NoServiceWorker(p)
	}

	// The operator portal. Mounted on the SAME mux as /v1/ rather than inside
	// `pages`, because it must work whether or not -ui is on: an operator who
	// wants to mint an invite from a browser should not have to also serve the
	// public portal to do it.
	operatorBase := "https://" + cfg.Domain
	if cfg.Dev {
		// LOCALHOST, NOT THE BIND ADDRESS. `-dev` binds 127.0.0.1 by default,
		// and the front door gates on SNI — which an IP literal has none of,
		// so a redirect URI built from the bind address is one this relay
		// refuses to answer. The dev hosts are `localhost` and
		// `addy.localhost`; only the port carries over.
		operatorBase = "https://localhost"
		if _, port, err := net.SplitHostPort(cfg.Addr); err == nil && port != "" {
			operatorBase += ":" + port
		}
	}
	opCfg := operator.Config{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		BaseURL:      operatorBase,
		Signup:       operator.SignupPolicy(cfg.Signup),
	}
	if opCfg.Enabled() {
		admin := adminFor(db)
		operator.New(opCfg, admin.(operator.Store)).Routes(mux, admin)
		log.Info("operator portal: sign-in is configured",
			"issuer", cfg.OIDCIssuer, "redirect", operatorBase+"/admin/callback")
	} else if cfg.UI {
		// Said once at startup rather than discovered as a 404. The portal
		// renders a sign-in button off /admin/v1/me, and an operator who
		// configured two of the three flags should be told which one is
		// missing rather than left pressing a button that does nothing.
		log.Info("operator portal: not configured; administer with the addy command over SSH",
			"needs", "-oidc-issuer, -oidc-client-id and -oidc-client-secret")
	}
	// /v1/meta is served WHETHER OR NOT THE PORTAL IS ON, and that is a fix
	// rather than a preference.
	//
	// It used to be mounted on `pages`, which is a 404 handler when -ui is
	// off -- and the portal is headless by default. So on a default install
	// the one endpoint `addy selftest` and the container healthcheck both
	// fetch answered 404, which means the healthcheck failed forever and the
	// selftest reported "something is listening and it is not addy" about addy.
	// Found by running the selftest against a real instance rather than by
	// reading it.
	//
	// Longest pattern wins, so this beats "/v1/" for exactly this path.
	mux.Handle("/v1/meta", metaHandler(cfg))
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

	// Says WHY TLS is not working, on a timer, in words an operator can act on.
	//
	// Not once at startup: issuance can be fine for a month and then fail, and
	// the moment it does is the moment somebody is looking at the log. Not on
	// every failure either -- certmagic retries on its own schedule and a line
	// per attempt is the noise that buried the cause in the first place. Once
	// a minute while there is something wrong, and silence when there is not.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var said string
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				report := acmeStatus.Report()
				if report == "" || report == said {
					continue
				}
				said = report
				log.Warn("TLS is not being served yet\n" + report)
			}
		}
	}()

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

// minter adapts the relay to the API's interface, which is deliberately
// `any`-shaped so that internal/api does not import a TURN implementation to
// describe one.
type minter struct{ r *relay.Server }

func (m minter) Mint(device string) any { return m.r.Mint(device) }

// turnSecret returns the long-term key TURN credentials are derived from,
// generating and storing one on first run.
//
// Stored rather than regenerated per start, because every credential already
// issued would otherwise stop verifying on restart -- which would mean an
// ordinary upgrade silently breaking relaying for every device mid-connection,
// intermittently, in a way nobody would connect to the upgrade.
//
// `addy panic` clears it along with everything else, which is the one time
// invalidating every outstanding credential is the point.
func turnSecret(ctx context.Context, db *store.DB, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	existing, err := db.TurnSecret(ctx)
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(raw)
	if err := db.SetTurnSecret(ctx, secret); err != nil {
		return "", err
	}
	return secret, nil
}

// metaHandler answers /v1/meta.
//
// A named function rather than a closure in Run so that a test can exercise
// the real one without binding a port -- which is how the bug above went
// unnoticed: every unit test built a portal, so the configuration that broke
// was the only one nothing covered.
func metaHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// A version string and a build hash, and deliberately nothing else.
		// The endpoint is unauthenticated, so anything that identified the
		// instance, counted its devices or named its users would hand a
		// stranger the metadata the threat model spends its length promising
		// to minimise.
		//
		// The protocol version is the one addition, and it says nothing about
		// the instance: every relay of this build answers the same string, and
		// it is what lets a client say "update one end" instead of failing on
		// whatever it first tries to open.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version":  cfg.Version,
			"build":    cfg.BuildSha,
			"protocol": protocol.ProtocolVersion,
		})
	})
}

// overlayAdapter widens the minter's typed result to the `any` the API takes,
// for the same reason `minter` exists next to it: internal/api should not
// import a package for a service most instances never configure.
type overlayAdapter struct{ m *overlay.Minter }

func (a overlayAdapter) Mint(ctx context.Context, device []byte, controlURL string) (any, error) {
	return a.m.Mint(ctx, device, controlURL)
}

// adminFor adapts the store to what the operator portal needs.
//
// An ADAPTER rather than the store implementing the interface directly,
// because the two have different jobs: the store's `Accounts` returns
// `time.Time` and the portal serves JSON, and a store that started formatting
// timestamps for a web page would be a store with a view layer in it.
type storeAdmin struct{ db *store.DB }

func adminFor(db *store.DB) operator.Admin { return storeAdmin{db} }

// UpsertUser crosses the same seam as the rest of this adapter: the store's
// User carries more than the sign-in needs, and the operator package should
// not have to import the store to describe a person.
func (s storeAdmin) UpsertUser(ctx context.Context, issuer, subject, email, name string) (*operator.User, error) {
	u, err := s.db.UpsertUser(ctx, issuer, subject, email, name)
	if err != nil {
		return nil, err
	}
	return &operator.User{UserID: u.UserID, Email: u.Email, Name: u.Name, Blocked: u.Blocked}, nil
}

func (s storeAdmin) InstanceValue(ctx context.Context, key string) (string, time.Time, error) {
	return s.db.InstanceValue(ctx, key)
}

func (s storeAdmin) SetInstanceValue(ctx context.Context, key, value string) error {
	return s.db.SetInstanceValue(ctx, key, value)
}

// translate turns a store sentinel into the operator one that carries a status
// code. THE SEAM IS THE RIGHT PLACE FOR IT: the operator package deliberately
// does not import the store, so it cannot compare against the store's errors,
// and without this every anticipated refusal reached the browser as a 500 with
// the store's internal layering in the body.
//
// Errors that match neither are returned unchanged and become a 500, which is
// what an unanticipated failure should be.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNoAccount), errors.Is(err, store.ErrNoUser):
		return fmt.Errorf("%w: %w", operator.ErrNotFound, err)
	case errors.Is(err, store.ErrBlocked):
		return fmt.Errorf("%w: %w", operator.ErrBlocked, err)
	case errors.Is(err, store.ErrHasAccount):
		return fmt.Errorf("%w: %w", operator.ErrHasAccount, err)
	default:
		return err
	}
}

func (s storeAdmin) NewInviteFor(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	token, err := s.db.NewInviteFor(ctx, userID, ttl)
	return token, translate(err)
}

func (s storeAdmin) SetUserBlocked(ctx context.Context, userID string, blocked bool) error {
	return translate(s.db.SetUserBlocked(ctx, userID, blocked))
}

func (s storeAdmin) AccountsOf(ctx context.Context, userID string) ([]operator.AccountView, error) {
	rows, err := s.db.AccountsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	return accountViews(rows), nil
}

func (s storeAdmin) Users(ctx context.Context) ([]operator.UserView, error) {
	rows, err := s.db.Users(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]operator.UserView, 0, len(rows))
	for _, u := range rows {
		v := operator.UserView{
			UserID:    u.UserID,
			Email:     u.Email,
			Name:      u.Name,
			CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
			Accounts:  u.Accounts,
			UsedBytes: u.UsedBytes,
			QuotaByte: u.QuotaByte,
			Blocked:   u.Blocked,
		}
		if !u.LastSeen.IsZero() {
			v.LastSeen = u.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out, nil
}

func (s storeAdmin) SetQuota(ctx context.Context, accountID string, bytes int64) error {
	return translate(s.db.SetQuota(ctx, accountID, bytes))
}

func (s storeAdmin) DeleteAccount(ctx context.Context, accountID string) error {
	return translate(s.db.DeleteAccount(ctx, accountID))
}

func (s storeAdmin) Accounts(ctx context.Context) ([]operator.AccountView, error) {
	rows, err := s.db.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	return accountViews(rows), nil
}

func accountViews(rows []store.AccountSummary) []operator.AccountView {
	out := make([]operator.AccountView, 0, len(rows))
	for _, r := range rows {
		v := operator.AccountView{
			AccountID:     r.AccountID,
			Owner:         r.OwnerEmail,
			CreatedAt:     r.CreatedAt.UTC().Format(time.RFC3339),
			RosterEntries: r.Devices,
			UsedBytes:     r.UsedBytes,
			QuotaByte:     r.QuotaByte,
		}
		// Omitted rather than sent as the zero time. A device that has never
		// checked in is a real state, and 1970 is not what it looks like.
		if !r.LastSeen.IsZero() {
			v.LastSeen = r.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out
}
