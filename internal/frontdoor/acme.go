package frontdoor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"

	"github.com/caddyserver/certmagic"
)

// ACMEConfig is what the front door needs in order to get certificates.
// LetsEncryptStaging is the CA to point at when testing issuance. Named rather
// than left as a URL in a script, because a URL in a script is a URL somebody
// copies into production.
const LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

type ACMEConfig struct {
	// CA overrides the ACME directory. Empty means Let's Encrypt production.
	CA      string
	Dev     bool
	Email   string
	DataDir string
	Routes  *Table
	Export  *Exporter
}

// NewACME wires certmagic and returns the pieces the Door needs.
//
// DESIGN.md says to use certmagic.HTTPS() and specifically NOT Listen() or
// TLS(), because those disable the HTTP-01 challenge. Reading certmagic
// v0.25.4, HTTPS() does four things: agrees to the terms, calls ManageSync,
// BINDS :80 AND :443 ITSELF, and puts the ACME challenge handler in front of
// the :80 handler. The third is fatal to an SNI router -- certmagic's own doc
// comment says to build your own servers and use Config.TLSConfig() if you need
// to -- and the fourth is the part that actually mattered.
//
// So: Config.TLSConfig() plus our own listeners, plus the challenge handler
// mounted first on our own :80. That is not a deviation from the requirement,
// it is the requirement's substance with the listener ownership dropped.
//
// THE HAZARD THE DESIGN WAS POINTING AT IS SHARPER THAN "these functions
// disable HTTP-01", and it is worth writing down in its real form, because it
// fails silently:
//
//	certmagic's httpSolver.Present calls robustTryListen(":80"). If the bind
//	fails BUT THE PORT CAN BE DIALLED, robustTryListen returns (nil, nil) --
//	it assumes whatever already holds :80 will answer the challenge, and gives
//	up its own server. addy always holds :80. So without the challenge handler
//	mounted, certmagic does not error, does not warn and does not fall back:
//	every ACME validation simply 404s, forever.
//
// Verified in solvers.go at v0.25.4. The identical shape is in
// tlsALPNSolver.Present for :443.
func NewACME(c ACMEConfig) (*tls.Config, func(http.Handler) http.Handler, *certmagic.Config, error) {
	if c.Routes == nil {
		return nil, nil, nil, fmt.Errorf("frontdoor: NewACME needs a routing table")
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: filepath.Join(c.DataDir, "certs")}
	if c.Export != nil {
		certmagic.Default.OnEvent = c.Export.OnEvent
	}

	// The routing table IS the allowlist. A DecisionFunc that returns nil
	// unconditionally turns this box into an open certificate-issuance relay
	// for anyone who points a DNS record at its address, until the CA's rate
	// limit trips and issuance stops for the names that are real.
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: c.Routes.Decide,
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = c.Email

	// The CA, overridable, and the reason is not developer convenience.
	//
	// Let's Encrypt rate-limits per REGISTERED DOMAIN: 50 certificates a week
	// for everything under one. A hoster's default hostname --
	// `vmi1234.example-host.net` -- is shared by every customer of that
	// hoster, so testing against production there spends a limit that is not
	// yours and breaks issuance for strangers. Staging exists for exactly this
	// and issues from an untrusted root, which is the right trade for a test:
	// it proves the whole HTTP-01 path, the order, the challenge and the
	// installation, and the only thing it does not prove is that a browser
	// trusts the result.
	//
	// Empty means production, so the default is unchanged and an operator has
	// to ask for anything else.
	if c.CA != "" {
		certmagic.DefaultACME.CA = c.CA
	}
	// Both challenges stay enabled. addy owns :80 and :443, so certmagic's own
	// solvers decline to bind and defer to the handlers wired here; disabling
	// either would remove the only fallback the other has.
	certmagic.DefaultACME.DisableHTTPChallenge = false
	certmagic.DefaultACME.DisableTLSALPNChallenge = false

	if c.Dev {
		// Unprivileged ports, so `addy serve -dev` runs as a normal user.
		certmagic.HTTPPort = 8080
		certmagic.HTTPSPort = 8443
	}

	// NewDefault and not New(cache, cfg): the latter panics unless the cache
	// already has GetConfigForCert set, which is not a documented constructor
	// requirement so much as a way to find out at runtime.
	magic := certmagic.NewDefault()

	tlsConf := magic.TLSConfig()

	// In dev there is no issuer and no ACME, so there is nothing to mount.
	var challenge func(http.Handler) http.Handler
	if !c.Dev {
		issuer, ok := magic.Issuers[0].(*certmagic.ACMEIssuer)
		if !ok {
			return nil, nil, nil, fmt.Errorf("frontdoor: the default issuer is %T, not an ACME issuer", magic.Issuers[0])
		}
		challenge = issuer.HTTPChallengeHandler
	}

	return tlsConf, challenge, magic, nil
}

// DevCertificate puts a self-signed certificate in certmagic's cache as an
// UNMANAGED one, so it is served from the same code path as a real certificate
// and never queued for renewal.
//
// This is what keeps dev mode honest. The alternative -- a separate tls.Config
// with Certificates set -- would mean the handshake path people develop against
// is not the handshake path that ships, and the difference shows up the first
// time somebody deploys.
//
// Everything else still runs in dev: the SNI peek, the routing table,
// Table.Decide including its refusal path, the fake listener, the reverse
// proxies, the passthrough splice, and the exporter -- files, permissions and
// reload included. Only the issuer and the three challenge types are bypassed.
func DevCertificate(ctx context.Context, magic *certmagic.Config, export *Exporter, names []string) error {
	cert, certPEM, keyPEM, err := selfSigned(names, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	if err != nil {
		return err
	}
	if _, err := magic.CacheUnmanagedTLSCertificate(ctx, cert, nil); err != nil {
		return fmt.Errorf("caching the development certificate: %w", err)
	}
	if export != nil {
		// cert_obtained never fires in dev, so the exporter is driven through
		// its one public entry point instead. That is what keeps "dev
		// exercises the real path" true for the part most likely to be wrong.
		for _, name := range names {
			export.Export(ctx, name, certPEM, keyPEM)
		}
	}
	return nil
}
