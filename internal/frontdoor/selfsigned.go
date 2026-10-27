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
	"os"
	"path/filepath"
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
	return selfSignedWith(key, names, ips)
}

// selfSignedWith signs a fresh certificate over an existing key.
func selfSignedWith(key *ecdsa.PrivateKey, names []string, ips []net.IP) (tls.Certificate, []byte, []byte, error) {
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

// devKey returns the development certificate's key, created once and kept.
//
// THE KEY, NOT THE CERTIFICATE, IS WHAT A CLIENT PINS. A -dev relay used to
// mint a new key on every start, so restarting it changed its SPKI and every
// device that had paired with it -- which pins, and refuses a change for a
// relay it reaches with insecure TLS -- was locked out. Keeping the key and
// signing a fresh certificate over it at each start is the dev twin of
// certmagic's ReusePrivateKeys: the names and expiry stay current, the pin
// does not move.
//
// Kept in the certificate store, so `addy panic` deletes it with the real
// ones -- the one time a new key is the point. Regenerated only when missing
// or unreadable.
func devKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, "dev-key.pem")
	if b, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if ec, ok := k.(*ecdsa.PrivateKey); ok {
					return ec, nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating dev key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling dev key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	// Written aside and renamed, 0600 from the moment it exists, so a crash
	// mid-write leaves the old key or none -- never half of one.
	tmp, err := os.CreateTemp(dir, "dev-key-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("saving dev key: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("saving dev key: %w", err)
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("saving dev key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("saving dev key: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("saving dev key: %w", err)
	}
	return key, nil
}
