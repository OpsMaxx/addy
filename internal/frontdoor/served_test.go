package frontdoor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/caddyserver/certmagic"
)

// A key counts as served once a handshake has been handed it, for that name
// and no other -- through the dev certificate path, which is the same
// certmagic lookup production uses.
func TestServedKeysRecordsWhatHandshakesWereGiven(t *testing.T) {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	defer cache.Stop()
	magic = certmagic.New(cache, certmagic.Config{})
	if err := DevCertificate(context.Background(), magic, nil, t.TempDir(), []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	conf := magic.TLSConfig()
	var served ServedKeys
	served.Wrap(conf)

	cert, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	right := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)

	if !served.Serves("localhost", right[:]) {
		t.Fatal("the key a handshake was given is not recognised")
	}
	if served.Serves("elsewhere.example", right[:]) {
		t.Error("a key served for one name was accepted for another")
	}
	wrong := sha256.Sum256([]byte("somebody else's key"))
	if served.Serves("localhost", wrong[:]) {
		t.Error("a key this relay never served was accepted")
	}

	// A TLS-ALPN-01 challenge certificate is nobody's key to log in against.
	var alpn ServedKeys
	alpnConf := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }}
	alpn.Wrap(alpnConf)
	if _, err := alpnConf.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost", SupportedProtos: []string{"acme-tls/1"}}); err != nil {
		t.Fatal(err)
	}
	if alpn.Serves("localhost", right[:]) {
		t.Error("a certificate handed to an ACME challenge handshake was recorded")
	}
}
