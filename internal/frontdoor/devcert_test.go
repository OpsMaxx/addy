package frontdoor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
)

// Two starts of a -dev relay serve the same key.
//
// Devices pin the SPKI and refuse a change for a relay they reach with
// insecure TLS. A key minted per start locked every paired device out of a
// development relay at its first restart.
func TestADevRelayKeepsItsKeyAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	spki := func() []byte {
		// A cache of its own per start, as a restarted process has. The
		// default cache is process-wide and would hand back the first start's
		// certificate whatever the second one did.
		var magic *certmagic.Config
		cache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		})
		defer cache.Stop()
		magic = certmagic.New(cache, certmagic.Config{})
		if err := DevCertificate(context.Background(), magic, nil, dir, []string{"localhost"}); err != nil {
			t.Fatal(err)
		}
		cert, err := magic.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.RawSubjectPublicKeyInfo
	}

	first, second := spki(), spki()
	if !bytes.Equal(first, second) {
		t.Fatal("a restart changed the dev certificate's key, and every pinned device is locked out")
	}
	fi, err := os.Stat(filepath.Join(dir, CertDir, "dev-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the dev key is %v", fi.Mode().Perm())
	}

	// An unreadable key is replaced rather than fatal.
	if err := os.WriteFile(filepath.Join(dir, CertDir, "dev-key.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spki(), first) {
		t.Error("a garbage key file was somehow read back as the old key")
	}
}
