package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/opsmaxx/addy/internal/protocol"
)

// Who is on a roster, as far as the relay acts on it.
//
// THE RELAY USED TO ACT ON NOTHING. It stored the chain and served it, and
// gave a session to any key that could sign a login -- so a revoked laptop,
// or anybody holding a key and an account id, could write objects, fill the
// quota, append to the roster (which bricks verification on every device) and
// mint itself an overlay key. The clients' own verification kept anything
// from being SEALED to such a device; nothing kept it from acting.
//
// Now: a login is checked against the device set the stored chain names
// (protocol.Members), an append is accepted only from a device in that set,
// and a revoke ends what the revoked device's sessions can do on the spot. A
// key off the roster reads it -- to learn it was revoked, or to recover -- and
// a stranger's may add itself with the root key; that is all.

type standing int

const (
	strangerKey standing = iota // never on this roster: a stranger, or a recovery
	memberKey                   // on it now
	removedKey                  // was on it, and a revoke took it off
)

// standing reads the stored chain and says where a key stands on it.
//
// A chain the relay cannot read names nobody, so every key is a stranger to
// it: failing closed, and failing the same way for an account that does not
// exist, which keeps the login from answering whether one does.
func (s *Server) standing(ctx context.Context, account string, acct protocol.AccountID, device []byte) (standing, error) {
	chain, err := s.DB.Roster(ctx, account, 0)
	if err != nil {
		return strangerKey, err
	}
	present, removed, err := protocol.Members(chain, acct)
	if err != nil {
		s.Log.Warn("a stored roster does not read; no device on it can log in", "account", account, "err", err)
		return strangerKey, nil
	}
	for _, d := range present {
		if bytes.Equal(d.PubSign, device) {
			return memberKey, nil
		}
	}
	for _, k := range removed {
		if bytes.Equal(k, device) {
			return removedKey, nil
		}
	}
	return strangerKey, nil
}

// recoveryRoute is everything a limited session reaches: exactly the calls a
// device recovering from the phrase makes before it is on the roster (OpsMaxx
// session.ts recoverFromPhrase) -- read the escrow at any epoch, read the
// chain, append ONE entry, which appendEntry then holds to a root-signed add
// of the caller itself.
//
// What that hands a stranger who knows an account id: the escrow, sealed to
// the root key the phrase derives, and the chain, which is public keys and
// sealed labels. Both were readable to the same stranger before any of this,
// along with everything else.
func recoveryRoute(r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/roster",
		r.Method == http.MethodPost && r.URL.Path == "/v1/roster",
		r.Method == http.MethodGet && r.URL.Path == "/v1/obj/escrow":
		return true
	}
	return false
}

// refusal is why a live session may not make this request, or nil.
//
// NEITHER MESSAGE IS "unknown or expired session". A client re-logs in on that
// one, and neither of these is cured by logging in: either device would get
// the same session back.
func (sess sessionRecord) refusal(r *http.Request) error {
	switch {
	case sess.removed && !(r.Method == http.MethodGet && r.URL.Path == "/v1/roster"):
		return errors.New("this device has been removed from its sync group")
	case sess.limited && !recoveryRoute(r):
		return errors.New("this device is not on its sync group's roster")
	}
	return nil
}

// appendEntry checks one roster entry against the stored chain, stores it, and
// applies it to the live sessions.
//
// THE STRUCTURE IS CHECKED HERE NOW, not only by the clients afterwards. An
// entry that does not extend the chain -- wrong account, broken link, a revoke
// of somebody absent -- is one every verifier refuses, and once stored it
// leaves every device on a head nobody accepts. Refusing it costs the relay
// nothing it did not already hold.
func (s *Server) appendEntry(ctx context.Context, a authedRequest, seq uint64, wire []byte) (int, error) {
	e, rest, err := protocol.DecodeEntry(wire)
	if err != nil || len(rest) != 0 {
		return http.StatusBadRequest, errors.New("a roster append is exactly one entry")
	}
	var acct protocol.AccountID
	raw, err := hex.DecodeString(a.Account)
	if err != nil || len(raw) != protocol.AccountIDLen {
		return http.StatusUnauthorized, errors.New("malformed session")
	}
	copy(acct[:], raw)

	s.auth.roster.Lock()
	defer s.auth.roster.Unlock()

	chain, err := s.DB.Roster(ctx, a.Account, 0)
	if err != nil {
		return statusFor(err), err
	}
	before, _, err := protocol.Members(chain, acct)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("the stored roster does not read: %w", err)
	}
	if _, _, err := protocol.Members(append(chain[:len(chain):len(chain)], wire...), acct); err != nil {
		// A sequence number already taken is somebody else appending first,
		// and stays the 409 a client re-reads the chain on -- not a 400 that
		// tells it the entry it built was nonsense.
		if errors.Is(err, protocol.ErrBadSequence) {
			return http.StatusConflict, err
		}
		return http.StatusBadRequest, fmt.Errorf("that entry does not extend this roster: %w", err)
	}

	member := false
	for _, d := range before {
		member = member || bytes.Equal(d.PubSign, a.Device)
	}
	if !member {
		// THE ONE APPEND FROM OFF THE ROSTER: a recovering device adding
		// itself, signed by the root key the phrase derives. The relay holds
		// that key's public half from registration, so this is the one entry
		// whose signature it CAN check -- and must, since nothing else about
		// the caller is vouched for.
		root, err := s.DB.RootSignPub(ctx, a.Account)
		if err != nil {
			return statusFor(err), err
		}
		body, err := e.Encode()
		if err != nil || e.Op != protocol.OpAdd || e.Signer != protocol.SignerRK ||
			!bytes.Equal(e.PubSign, a.Device) || !ed25519.Verify(root, body, e.Sig) {
			return http.StatusForbidden, errors.New("a device not on the roster may only add itself, signed with the recovery phrase")
		}
	}

	if err := s.DB.AppendRoster(ctx, a.Account, seq, wire); err != nil {
		return statusFor(err), err
	}
	s.auth.settle(a.Account, e)
	return 0, nil
}

// settle applies a stored entry to the live sessions of the device it names.
//
// A REVOKE ENDS THEM, which is what PROTOCOL.md §9.5 means by "the server stops
// serving it": a session lasts twelve hours, and a laptop revoked for being
// lost should not keep syncing until the token happens to expire. They keep
// reading the roster, which is how the laptop finds out and wipes itself. An add
// lifts the limit from a session the device opened before it was added, which
// is a recovering device after its own append, and a newly paired one that
// logged in before its pairer's append arrived.
func (a *authState) settle(account string, e protocol.Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.sessions {
		if v.account != account || !bytes.Equal(v.device, e.PubSign) {
			continue
		}
		switch e.Op {
		case protocol.OpAdd:
			v.limited, v.removed = false, false
		case protocol.OpRevoke:
			v.removed = true
		}
		a.sessions[k] = v
	}
}
