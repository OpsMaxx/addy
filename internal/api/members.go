package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/opsmaxx/addy/internal/protocol"
	"github.com/opsmaxx/addy/internal/store"
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
// revoked key's login is refused with the chain attached; a never-seen key
// reads the chain and may add itself with the root key, and that is all.

// revokedResponse is the 403 a revoked key's login gets: the reason, and the
// chain exactly as GET /v1/roster serves it, for the client to verify before
// it believes the reason.
type revokedResponse struct {
	Error  string         `json:"error"`
	Roster rosterResponse `json:"roster"`
}

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
	if err == nil {
		err = s.checkSigned(ctx, account, acct, chain)
	}
	if err != nil {
		s.Log.Warn("a stored roster does not verify; no device on it can log in", "account", account, "err", err)
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
	next := append(chain[:len(chain):len(chain)], wire...)
	if _, _, err := protocol.Members(next, acct); err != nil {
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
		// that key's public half from registration, so this entry is one it
		// can check even without the epoch-1 key -- and must, since nothing about
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

	// AND ITS SIGNATURE, when the relay can check one. Structure alone let a
	// member append an add with a junk signature: the relay stored it, gave
	// the named key a full session, and every client's verification failed
	// on that entry for ever -- an append-only chain, bricked, with a relay
	// side door that outlived any revocation.
	if err := s.checkSigned(ctx, a.Account, acct, next); err != nil {
		return http.StatusBadRequest, fmt.Errorf("that entry does not verify: %w", err)
	}

	if err := s.DB.AppendRoster(ctx, a.Account, seq, wire); err != nil {
		return statusFor(err), err
	}
	s.auth.settle(a.Account, e)

	// A REVOCATION RE-KEY, so every conflict copy sealed under an older epoch
	// goes (store.DropConflictsBefore says why): one may be the removed
	// device's, posted while it was still a member. Only a revocation. A
	// routine (hygiene) rotation removes nobody, and its copies are unresolved
	// work that may exist nowhere else; dropping them on every epoch change
	// deleted that work without a word. After the append, not before: a
	// transition that was refused moved nothing. Not a failure of the append
	// either -- the entry is stored and the device needs to hear so; the age
	// sweep reclaims anything left.
	if e.Op == protocol.OpEpoch && e.Flags&protocol.FlagRevocationRotation != 0 {
		if n, err := s.DB.DropConflictsBefore(ctx, a.Account, e.Epoch); err != nil {
			s.Log.Warn("could not drop conflict copies from before an epoch transition",
				"account", a.Account, "epoch", e.Epoch, "err", err)
		} else if n > 0 {
			s.Log.Info("dropped conflict copies from before an epoch transition",
				"account", a.Account, "epoch", e.Epoch, "dropped", n)
		}
	}
	return 0, nil
}

// checkSigned runs the client's own VerifyChain over a chain, when the relay
// holds the account's epoch-1 key -- which is the one key it was missing: the
// root key it has had since registration, and every later epoch's key is
// established inside the chain itself.
//
// An account whose devices have not supplied that key is checked by structure
// alone (Members), as before; nil here says only that nothing more was
// possible.
func (s *Server) checkSigned(ctx context.Context, account string, acct protocol.AccountID, chain []byte) error {
	root, epoch1, err := s.DB.SignKeys(ctx, account)
	if errors.Is(err, store.ErrNoAccount) || (err == nil && epoch1 == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = protocol.VerifyChain(chain, acct, root, epoch1, nil)
	return err
}

type epoch1Request struct {
	Epoch1SignPub string `json:"epoch1_sign_pub"` // hex
}

// setEpoch1 records the account's epoch-1 signing key, for an account that
// registered before the relay asked for it.
//
// SELF-VALIDATING, so it does not matter who sends it: it is accepted only if
// the whole stored chain verifies under it, from the genesis entry it signed
// onward. A wrong key fails that, and so does a chain already holding an
// entry no client accepts -- in which case the account is bricked whatever
// the relay does, and it says so rather than taking the key.
func (s *Server) setEpoch1(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req epoch1Request
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	key, err := hex.DecodeString(req.Epoch1SignPub)
	if err != nil || len(key) != ed25519.PublicKeySize {
		s.fail(w, http.StatusBadRequest, errors.New("an epoch 1 key is 32 bytes of hex"))
		return
	}
	var acct protocol.AccountID
	copy(acct[:], mustDecode(a.Account))

	s.auth.roster.Lock()
	defer s.auth.roster.Unlock()
	chain, err := s.DB.Roster(r.Context(), a.Account, 0)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	root, _, err := s.DB.SignKeys(r.Context(), a.Account)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	if _, err := protocol.VerifyChain(chain, acct, root, key, nil); err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("the stored roster does not verify under that key: %w", err))
		return
	}
	if err := s.DB.SetEpoch1SignPub(r.Context(), a.Account, key); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// stillServing re-checks, at the moment a long poll wakes, that the session it
// was parked on has not been cut by a revoke since authed() let it in.
// ponytail: a scan of every session; index by device if the map grows large.
func (a *authState) stillServing(r authedRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.sessions {
		if v.removed && v.account == r.Account && bytes.Equal(v.device, r.Device) {
			return errors.New("this device has been removed from its sync group")
		}
	}
	return nil
}

// settle applies a stored entry to the live sessions of the device it names.
//
// EndAccount ends every session of an account the operator has deleted.
//
// Deleting the rows is not enough on its own: a session lives here, in memory,
// for twelve hours, and one opened before the deletion would otherwise keep
// answering as a member of a sync group that no longer exists.
func (s *Server) EndAccount(account string) {
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	for k, v := range s.auth.sessions {
		if strings.EqualFold(v.account, account) {
			delete(s.auth.sessions, k)
		}
	}
}

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
