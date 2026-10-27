package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"time"
)

// The join string carries the instance URL and a pin of its certificate.
//
// Nothing in the design carried the instance URL from the server to the first
// laptop, which left the first step of the entire product as "type your domain
// correctly and hope you are talking to your own server". This closes that.
//
// WHAT THE PIN IS AND IS NOT, stated because a pin that is believed to do more
// than it does is worse than none:
//
//   - It is trust-on-first-use for the FIRST connection. It says the box you
//     are adding is the box whose portal printed this string -- which matters,
//     because the alternative is trusting whatever answers a hostname a human
//     typed.
//   - It outlives a renewal. The front door sets certmagic's ReusePrivateKeys,
//     so a renewed certificate carries the same key and the same pin -- which
//     matters because devices keep this pin and sign over it at every login.
//     It changes when the key does: `addy panic` without -keep-certs, or a
//     lost data volume. A string printed before either is refused, and the
//     operator prints a new one.
//   - It is NOT what secures the account. After pairing, the roster and the
//     account key are what identify anything, and the TLS layer is transport.
//
// The pin is over the SubjectPublicKeyInfo rather than the whole certificate,
// which is the same choice HPKP made for the same reason: it survives a
// re-issue that reuses the key, and it is what every other implementation
// means by "certificate pin".
func JoinString(ctx context.Context, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
		// The point is to read the certificate this instance is actually
		// serving, so an untrusted one must not stop us: a self-signed
		// development certificate is exactly the case where a join string is
		// most useful.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", target, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("%s presented no certificate", target)
	}

	pin, err := spkiPin(certs[0])
	if err != nil {
		return "", err
	}

	// RawQuery rather than url.Values.Encode(), which percent-encodes the
	// colon in "sha256:" to %3A. That is legal, and a colon is also legal
	// unescaped in a query per RFC 3986, and this string gets copied by hand,
	// read aloud and scanned out of a QR code -- so it stays readable.
	u := url.URL{
		Scheme:   "addy",
		Host:     target,
		RawQuery: "pin=" + pin,
	}
	return u.String(), nil
}

func spkiPin(cert *x509.Certificate) (string, error) {
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", fmt.Errorf("the certificate carries no public key information")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	// base64url without padding: this ends up in a URL, in a QR code, and
	// occasionally in a chat message, and '+' '/' '=' survive none of those
	// reliably.
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
