package frontdoor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// selfSigned mints a throwaway leaf certificate for dev mode.
//
// Thirty lines of crypto/x509 and no dependency. The alternative -- an embedded
// development CA -- means shipping a private key in the binary and telling
// people to trust it, which is a worse idea than the browser warning it was
// meant to avoid.
//
// The returned PEM is fed through the SAME exporter the ACME path uses, so dev
// mode exercises the export's permissions, atomicity and reload for real rather
// than skipping the part most likely to be wrong.
func selfSigned(names []string, ips []net.IP) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generating dev key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "addy development"},
		// Deliberately short. A development certificate that is valid for a
		// decade ends up trusted somewhere it should not be; one that expires
		// in a month cannot become load-bearing by accident.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Not a CA. It signs nothing, so it cannot be turned into one by
		// someone who finds it on a laptop.
		IsCA:        false,
		DNSNames:    names,
		IPAddresses: ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("creating dev certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshalling dev key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("loading dev certificate: %w", err)
	}
	return pair, certPEM, keyPEM, nil
}

// SelfSignedForTest exposes the development certificate generator to other
// packages' tests.
//
// Exported rather than duplicated: a second implementation of "make a
// certificate" in a test is a second thing that can drift from the one that
// ships, and the point of a test is to exercise what ships.
func SelfSignedForTest(names []string) (tls.Certificate, []byte, []byte, error) {
	return selfSigned(names, nil)
}
