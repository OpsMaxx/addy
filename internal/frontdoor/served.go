package frontdoor

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"slices"
	"sync"
	"time"
)

// ServedKeys remembers which TLS keys this relay has actually presented, per
// server name, so a login can check that the key its signature binds is one of
// them.
//
// WITHOUT THIS THE BINDING BOUND NOTHING. A login signs SHA-256 of the
// SubjectPublicKeyInfo the device saw, which is what stops somebody who
// terminates TLS for this hostname -- with any certificate a device would
// accept -- from forwarding the login and walking off with the session. The
// relay verified the signature over whatever value the device sent and never
// compared it with its own key, so a relayed login verified perfectly.
//
// Recorded where certificates are handed out rather than looked up at login,
// because that is the only place that knows what was really served: the same
// lookup certmagic does for a handshake, for every name, in dev and in
// production, with a key mid-renewal and without.
type ServedKeys struct {
	mu   sync.Mutex
	seen map[string]map[[32]byte]time.Time
}

// servedFor is how long a key stays acceptable after it was last presented
// for a name. A resumed TLS session presents no certificate at all, and Go's
// session tickets live seven days, so a login on one is bound to the key of
// the handshake that issued it.
const servedFor = 7 * 24 * time.Hour

// Wrap records every certificate conf's GetCertificate hands out. It must run
// before conf is cloned into the Door, which copies the function.
func (k *ServedKeys) Wrap(conf *tls.Config) {
	inner := conf.GetCertificate
	conf.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := inner(hello)
		// TLS-ALPN-01 answers with a throwaway challenge certificate, which
		// is nobody's key to log in against.
		if err == nil && cert != nil && !slices.Contains(hello.SupportedProtos, "acme-tls/1") {
			k.record(hello.ServerName, cert)
		}
		return cert, err
	}
}

func (k *ServedKeys) record(name string, cert *tls.Certificate) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return
		}
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.seen == nil {
		k.seen = map[string]map[[32]byte]time.Time{}
	}
	if k.seen[name] == nil {
		k.seen[name] = map[[32]byte]time.Time{}
	}
	k.seen[name][sum] = time.Now()
}

// Serves reports whether spki -- SHA-256 of a SubjectPublicKeyInfo, as a login
// carries it -- is a key this relay has presented for name recently.
func (k *ServedKeys) Serves(name string, spki []byte) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for sum, at := range k.seen[name] {
		if time.Since(at) > servedFor {
			delete(k.seen[name], sum)
			continue
		}
		if bytes.Equal(sum[:], spki) {
			return true
		}
	}
	return false
}
