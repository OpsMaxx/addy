package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A configuration that would start and then serve nothing is refused, by name.
func TestConfigCheckRefusesWhatWouldServeNothing(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr []string // substrings; nil means accepted
	}{
		{"no domain outside dev", Config{}, []string{"ADDY_DOMAIN"}},
		{"dev needs no domain", Config{Dev: true}, nil},
		{"domain and no sign-in", Config{Domain: "relay.example"}, nil},
		{"all three sign-in settings", Config{Domain: "relay.example",
			OIDCIssuer: "https://issuer.example", OIDCClientID: "id", OIDCClientSecret: "secret"}, nil},
		{"issuer alone", Config{Domain: "relay.example", OIDCIssuer: "https://issuer.example"},
			[]string{"ADDY_OIDC_CLIENT_ID", "ADDY_OIDC_CLIENT_SECRET"}},
		{"secret missing", Config{Domain: "relay.example",
			OIDCIssuer: "https://issuer.example", OIDCClientID: "id"},
			[]string{"ADDY_OIDC_CLIENT_SECRET missing"}},
	}
	for _, c := range cases {
		err := c.cfg.check()
		if c.wantErr == nil {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted; it would start and serve nothing", c.name)
			continue
		}
		for _, want := range c.wantErr {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q does not name %s", c.name, err, want)
			}
		}
	}
}

// A data directory this process does not own -- a Kubernetes volume root,
// owned by root and group-writable through fsGroup -- is a warning, not a
// crash on first boot.
func TestADataDirectoryNotOwnedIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns everything; the case needs an unprivileged process")
	}
	// The filesystem root is owned by root on every Unix, and chmod on it as
	// anybody else is EPERM -- the same error the chart's volume produced.
	if err := secureDataDir("/", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("a directory owned by somebody else stopped the relay: %v", err)
	}
	// Whereas a directory it does own is still tightened.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := secureDataDir(dir, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("an owned data directory was left %v", fi.Mode().Perm())
	}
}

// The probe names the domain and dials loopback.
//
// The Helm probes used to run `selftest -target localhost:443`, and the front
// door drops every name it has no route for -- so the pod was never Ready. The
// probe now dials 127.0.0.1 and says the configured domain in the handshake,
// which is the only name the front door answers for.
func TestSelftestConnectDialsOneAddressAndNamesAnother(t *testing.T) {
	var sni, host string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni, host = r.TLS.ServerName, r.Host
		_ = json.NewEncoder(w).Encode(meta{Version: "1.2.3", Build: "abc"})
	}))
	defer srv.Close()

	// relay.invalid cannot resolve (RFC 6761), so only -connect can reach it.
	m, err := fetchMeta(context.Background(), "relay.invalid", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("the probe could not reach the instance: %v", err)
	}
	if m.Version != "1.2.3" {
		t.Fatalf("meta is %+v", m)
	}
	if sni != "relay.invalid" || host != "relay.invalid" {
		t.Fatalf("the probe named %q in SNI and %q in Host; both must be the configured domain", sni, host)
	}
}
