package server

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/frontdoor"
)

// The pin must change when the key changes, and must not change when anything
// else does. That is the entire content of the claim the join string makes.
func TestThePinFollowsTheKeyAndNothingElse(t *testing.T) {
	a := certFor(t, "a.example")
	b := certFor(t, "a.example")

	pinA, err := spkiPin(a)
	if err != nil {
		t.Fatalf("spkiPin: %v", err)
	}
	pinB, err := spkiPin(b)
	if err != nil {
		t.Fatalf("spkiPin: %v", err)
	}

	if pinA == pinB {
		t.Error("two independently generated keys produced the same pin")
	}
	if !strings.HasPrefix(pinA, "sha256:") {
		t.Errorf("pin = %q, want a sha256: prefix so the algorithm can change later", pinA)
	}
	// base64url, unpadded: this ends up in a URL, in a QR code and sometimes in
	// a chat message, and '+', '/' and '=' survive none of those reliably.
	body := strings.TrimPrefix(pinA, "sha256:")
	if strings.ContainsAny(body, "+/=") {
		t.Errorf("pin %q uses characters that do not survive a URL or a QR code", pinA)
	}

	// Same key, second read: identical.
	again, err := spkiPin(a)
	if err != nil {
		t.Fatalf("spkiPin: %v", err)
	}
	if again != pinA {
		t.Error("the same certificate produced two different pins")
	}
}

// The string is copied by hand, read aloud and scanned out of a QR code, so it
// has to survive being a URL without turning into percent-escapes.
func TestTheJoinStringStaysReadableAndParses(t *testing.T) {
	cert := certFor(t, "addy.example")
	pin, err := spkiPin(cert)
	if err != nil {
		t.Fatalf("spkiPin: %v", err)
	}
	raw := (&url.URL{Scheme: "addy", Host: "addy.example:443", RawQuery: "pin=" + pin}).String()

	if strings.Contains(raw, "%3A") || strings.Contains(raw, "%3a") {
		t.Errorf("the join string percent-encodes its colon: %s", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the join string does not parse as a URL: %v", err)
	}
	if u.Scheme != "addy" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	if u.Host != "addy.example:443" {
		t.Errorf("host = %q", u.Host)
	}
	if got := u.Query().Get("pin"); got != pin {
		t.Errorf("pin round-tripped as %q, want %q", got, pin)
	}
}

func certFor(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	_, certPEM, _, err := frontdoor.SelfSignedForTest([]string{name})
	if err != nil {
		t.Fatalf("generating a certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("the generated certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}
