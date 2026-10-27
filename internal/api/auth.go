package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/opsmaxx/addy/internal/protocol"
)

// Device authentication.
//
// A device proves it holds a DK_sign whose public half is an un-revoked entry in
// the account's own roster. The server cannot verify the roster's signatures --
// it holds no epoch key -- but it can read who the chain names, and it accepts
// an append only from somebody the chain already names, so the set it reads is
// one only the account's own devices wrote. See members.go.

const (
	challengeTTL  = 2 * time.Minute
	sessionTTL    = 12 * time.Hour
	maxBody       = 8 << 20
	authHeader    = "Authorization"
	sigHeader     = "X-Addy-Signature"
	nonceHeader   = "X-Addy-Nonce"
	accountHeader = "X-Addy-Account"
	deviceHeader  = "X-Addy-Device"
)

type authState struct {
	mu         sync.Mutex
	challenges map[string]challengeRecord
	sessions   map[string]sessionRecord
	// spent holds request nonces that have already been used.
	//
	// WITHOUT IT AN AUTHORIZATION IS REPLAYABLE. The M1 review measured it
	// against a live instance: the same nonce was accepted four times, and
	// under a second session token. A signature that can be replayed is a
	// signature that authorises every future identical request, and "identical"
	// includes the DELETE somebody captured once.
	//
	// The fix is a spent set, not a timestamp. The protocol is explicit that
	// ts is display-only and that nothing load-bearing may depend on a clock an
	// attacker controls, so an expiry window would be validating against
	// exactly what it must not trust. The set is bounded by the session
	// lifetime instead: entries are swept with their session.
	spent map[string]spentRecord

	// roster serialises "who is on this roster" with acting on the answer: a
	// login reading the chain and storing its session, against an append
	// changing the chain and ending the sessions it removed. Without it a
	// revoke landing between a login's read and its store leaves the revoked
	// device holding a full session nothing will ever end.
	//
	// ponytail: one lock for every account; per-account locks if logins and
	// appends ever queue behind each other.
	roster sync.Mutex
}

type spentRecord struct {
	expires time.Time
}

type challengeRecord struct {
	account string
	device  string
	expires time.Time
}

type sessionRecord struct {
	account string
	device  []byte
	expires time.Time
	// limited is a key the roster does not name, which is either a stranger or
	// a device mid-recovery -- and the relay cannot tell them apart, because
	// a recovering device has freshly minted keys and must read the roster
	// before it can add itself. It reaches only recoveryRoute; an add naming
	// it lifts the limit (members.go).
	limited bool
	// removed is a session whose device a revoke took off the roster while it
	// was live. It reads the roster, which is how it learns to wipe itself, and
	// nothing else. Marked rather than deleted, so its next request is told why
	// instead of "unknown or expired session", which a client answers by
	// logging in again.
	removed bool
}

func newAuthState() *authState {
	return &authState{
		challenges: map[string]challengeRecord{},
		sessions:   map[string]sessionRecord{},
		spent:      map[string]spentRecord{},
	}
}

// sweep drops expired entries. Called on every use rather than on a timer,
// because a timer is one more goroutine to shut down and the maps are small.
func (a *authState) sweep(now time.Time) {
	for k, v := range a.challenges {
		if now.After(v.expires) {
			delete(a.challenges, k)
		}
	}
	for k, v := range a.sessions {
		if now.After(v.expires) {
			delete(a.sessions, k)
		}
	}
	for k, v := range a.spent {
		if now.After(v.expires) {
			delete(a.spent, k)
		}
	}
}

type challengeRequest struct {
	Account string `json:"account"`
	Device  string `json:"device"` // hex DK_sign public half
}

type challengeResponse struct {
	Nonce string `json:"nonce"` // hex
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := readJSON(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}

	nonce := make([]byte, protocol.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}

	now := time.Now()
	s.auth.mu.Lock()
	s.auth.sweep(now)
	s.auth.challenges[hex.EncodeToString(nonce)] = challengeRecord{
		account: req.Account, device: req.Device, expires: now.Add(challengeTTL),
	}
	s.auth.mu.Unlock()

	s.ok(w, challengeResponse{Nonce: hex.EncodeToString(nonce)})
}

type loginRequest struct {
	Account     string `json:"account"`
	Device      string `json:"device"`
	DeviceNonce string `json:"device_nonce"`
	ServerNonce string `json:"server_nonce"`
	ServerSPKI  string `json:"server_spki"`
	TS          uint64 `json:"ts"`
	Signature   string `json:"signature"`
}

type loginResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

// login verifies a signature over the login structure.
//
// THE SERVER NONCE IS SPENT ON USE, whether the login succeeds or fails. A nonce
// that survives a failed attempt is a nonce an attacker can grind against.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}

	now := time.Now()
	s.auth.mu.Lock()
	s.auth.sweep(now)
	rec, ok := s.auth.challenges[req.ServerNonce]
	delete(s.auth.challenges, req.ServerNonce)
	s.auth.mu.Unlock()

	if !ok {
		s.fail(w, http.StatusUnauthorized, errors.New("unknown or spent challenge"))
		return
	}
	if rec.account != req.Account || rec.device != req.Device {
		s.fail(w, http.StatusUnauthorized, errors.New("that challenge was issued to another device"))
		return
	}

	devicePub, err := hex.DecodeString(req.Device)
	if err != nil || len(devicePub) != ed25519.PublicKeySize {
		s.fail(w, http.StatusBadRequest, errors.New("a device key is 32 bytes of hex"))
		return
	}

	var acct protocol.AccountID
	raw, err := hex.DecodeString(req.Account)
	if err != nil || len(raw) != protocol.AccountIDLen {
		s.fail(w, http.StatusBadRequest, errors.New("an account id is 16 bytes of hex"))
		return
	}
	copy(acct[:], raw)

	login := protocol.Login{
		AccountID:   acct,
		DeviceNonce: mustDecode(req.DeviceNonce),
		ServerNonce: mustDecode(req.ServerNonce),
		ServerSPKI:  mustDecode(req.ServerSPKI),
		TS:          req.TS,
	}
	sig := mustDecode(req.Signature)
	if err := protocol.Verify(ed25519.PublicKey(devicePub), login, sig); err != nil {
		// 401 and nothing more specific. Distinguishing "no such account" from
		// "wrong signature" would make this an oracle for which account ids
		// exist.
		s.fail(w, http.StatusUnauthorized, errors.New("that signature does not verify"))
		return
	}

	// AND THE KEY HAS TO BE ON THE ROSTER, which nothing checked: any key that
	// signed got a session, a revoked device's included, and that session could
	// write objects, append to the roster and join the overlay. PROTOCOL.md
	// says the server MUST reject a login whose account the key does not
	// belong to.
	//
	// A key the roster never named still gets a LIMITED session, because of
	// RECOVERY: a device restoring from the phrase mints fresh keys and must
	// read the escrow and the roster before it can append the root-signed
	// entry that adds it, and OpsMaxx 0.58 does exactly that with the session
	// this hands out. It reaches only recoveryRoute (members.go).
	s.auth.roster.Lock()
	defer s.auth.roster.Unlock()
	st, err := s.standing(r.Context(), req.Account, acct, devicePub)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	if st == removedKey {
		// A KEY THE ROSTER REVOKED gets no session, and is told so WITH THE
		// CHAIN. Revocation reaches a device by its reading the roster and
		// finding itself absent, and the wipe that follows must not happen on
		// the relay's word -- a relay that could say "you were removed" and be
		// believed could wipe any device. So the chain comes along, for the
		// client to verify with the keys it holds. Not an oracle: only the
		// holder of this private key got past the signature above.
		chain, err := s.DB.Roster(r.Context(), req.Account, 0)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		s.okStatus(w, http.StatusForbidden, revokedResponse{
			Error:  "this device was removed from the account",
			Roster: rosterResponse{Chain: base64.StdEncoding.EncodeToString(chain)},
		})
		return
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	encoded := base64.RawURLEncoding.EncodeToString(token)

	s.auth.mu.Lock()
	s.auth.sessions[sessionKey(encoded)] = sessionRecord{
		account: req.Account, device: devicePub, expires: now.Add(sessionTTL),
		limited: st == strangerKey,
	}
	s.auth.mu.Unlock()

	s.ok(w, loginResponse{Token: encoded, Expires: now.Add(sessionTTL).Unix()})
}

// sessionKey hashes the bearer token before it is used as a map key, so a heap
// dump does not hand out live sessions.
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte("addy-session-v1\x00" + token))
	return string(sum[:])
}

type authedRequest struct {
	Account string
	Device  []byte
	Body    []byte
}

type authedHandler func(http.ResponseWriter, *http.Request, authedRequest)

// authed checks the bearer token AND a per-request authorization signature.
//
// The token alone is not enough, deliberately. A bearer token is replayable by
// anything that captures it; the signature binds the request to its method,
// path and body, so an authorization for a GET cannot be replayed as a DELETE.
func (s *Server) authed(next authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			s.fail(w, http.StatusUnauthorized, errors.New("no bearer token"))
			return
		}

		now := time.Now()
		s.auth.mu.Lock()
		s.auth.sweep(now)
		sess, live := s.auth.sessions[sessionKey(token)]
		s.auth.mu.Unlock()
		if !live {
			s.fail(w, http.StatusUnauthorized, errors.New("unknown or expired session"))
			return
		}
		if err := sess.refusal(r); err != nil {
			s.fail(w, http.StatusUnauthorized, err)
			return
		}

		// One byte past the limit, so an oversized body is SEEN rather than
		// cut. Truncating it silently used to hash the first 8 MiB, fail the
		// signature over the whole, and answer 401 -- which the client read as
		// "this device is no longer paired" for what was only a large file.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			s.fail(w, http.StatusBadRequest, err)
			return
		}
		if len(body) > maxBody {
			s.fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("a request body is at most %d bytes", maxBody))
			return
		}

		var acct protocol.AccountID
		raw, err := hex.DecodeString(sess.account)
		if err != nil || len(raw) != protocol.AccountIDLen {
			s.fail(w, http.StatusUnauthorized, errors.New("malformed session"))
			return
		}
		copy(acct[:], raw)

		nonce := mustDecode(r.Header.Get(nonceHeader))
		if len(nonce) != protocol.NonceLen {
			s.fail(w, http.StatusUnauthorized, errors.New("a request nonce is 32 bytes of hex"))
			return
		}

		authz := protocol.Authz{
			AccountID:   acct,
			DeviceNonce: nonce,
			Method:      r.Method,
			Path:        r.URL.Path,
			BodyHash:    protocol.HashBody(body),
			TS:          0,
		}
		if err := protocol.Verify(ed25519.PublicKey(sess.device), authz, mustDecode(r.Header.Get(sigHeader))); err != nil {
			s.fail(w, http.StatusUnauthorized, fmt.Errorf("request authorization: %w", err))
			return
		}

		// A nonce is spent once, PER DEVICE. Keyed on the device rather than
		// globally, so one account's traffic cannot deny another's by colliding
		// -- and checked after the signature, so an unauthenticated caller
		// cannot fill the set by guessing nonces.
		key := string(sess.device) + "\x00" + string(nonce)
		s.auth.mu.Lock()
		_, replayed := s.auth.spent[key]
		if !replayed {
			s.auth.spent[key] = spentRecord{expires: sess.expires}
		}
		s.auth.mu.Unlock()
		if replayed {
			s.fail(w, http.StatusUnauthorized, errors.New("that request authorization has already been used"))
			return
		}

		// Last, after the signature and the nonce: an instance in
		// reonboard-required state still refuses forged requests as forgeries
		// rather than blaming the panic, so a log from a box somebody just
		// panicked still says which of the two happened.
		//
		// Checked per request against the database rather than cached at
		// startup. `addy panic` is a separate process writing to the same
		// file, and a cached flag would mean a running server kept serving
		// until someone remembered to restart it -- which is precisely the
		// moment nobody is thinking about restarts.
		if blocked, at, err := s.DB.Reonboard(r.Context()); err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		} else if blocked {
			// 503, not 401: nothing is wrong with this device's credentials
			// and a client that treated it as an auth failure would re-login
			// in a loop. `Retry-After` is deliberately absent -- there is no
			// time at which this clears by itself.
			w.Header().Set("X-Addy-Reonboard", at.UTC().Format(time.RFC3339))
			s.fail(w, http.StatusServiceUnavailable, fmt.Errorf(
				"this instance was reset or panicked at %s and is not serving until an operator has re-checked its devices",
				at.UTC().Format(time.RFC3339)))
			return
		}

		next(w, r, authedRequest{Account: sess.account, Device: sess.device, Body: body})
	})
}

func bearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	v := r.Header.Get(authHeader)
	if len(v) <= len(prefix) || v[:len(prefix)] != prefix {
		return "", false
	}
	return v[len(prefix):], true
}

func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// mustDecode returns nil for anything that is not hex, and the callers treat a
// nil field as a failed verification rather than as an absent one. A signature
// over a field the server silently replaced with zeroes would verify against
// nothing useful.
func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
