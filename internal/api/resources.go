package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/opsmaxx/addy/internal/protocol"
	"github.com/opsmaxx/addy/internal/store"
)

type createAccountRequest struct {
	Account     string `json:"account"`       // hex account id
	RootSignPub string `json:"root_sign_pub"` // hex
	Invite      string `json:"invite"`
	Genesis     string `json:"genesis"` // base64 roster entry, body || sig
	Escrow      string `json:"escrow"`  // base64
	// Epoch1SignPub is AK_1.sign's public half, hex. Optional, so a client
	// that predates it still registers; with it, the relay can verify every
	// roster entry the account ever appends. See checkSigned.
	Epoch1SignPub string `json:"epoch1_sign_pub,omitempty"`
}

// createAccount registers a client-asserted identity.
//
// The server validates NOTHING about who you are -- it stores a public key it
// has never seen and cannot vouch for. Two things it does check, because both
// are about itself rather than about you: that the invite is real and unspent,
// which is the quota slot an admin actually controls; and that the account id
// is the one this root key derives, because storing a self-inconsistent record
// helps nobody and would make the account unreachable.
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if !s.readJSON(w, r, &req) {
		return
	}

	rootPub, err := hex.DecodeString(req.RootSignPub)
	if err != nil || len(rootPub) != 32 {
		s.fail(w, http.StatusBadRequest, errors.New("a root signing key is 32 bytes of hex"))
		return
	}
	if protocol.DeriveAccountID(rootPub).String() != req.Account {
		s.fail(w, http.StatusBadRequest, errors.New("that account id is not the one this root key derives"))
		return
	}

	genesis, err := base64.StdEncoding.DecodeString(req.Genesis)
	if err != nil || len(genesis) == 0 {
		s.fail(w, http.StatusBadRequest, errors.New("a genesis entry is required"))
		return
	}

	// The epoch-1 key, when sent, is checked against the genesis signature
	// before anything is written: a key that does not verify the account's
	// own first entry is a client bug, and storing it would refuse every
	// append the account ever makes.
	var epoch1 []byte
	if req.Epoch1SignPub != "" {
		epoch1, err = hex.DecodeString(req.Epoch1SignPub)
		if err != nil || len(epoch1) != ed25519.PublicKeySize {
			s.fail(w, http.StatusBadRequest, errors.New("an epoch 1 key is 32 bytes of hex"))
			return
		}
		if _, err := protocol.VerifyChain(genesis, protocol.DeriveAccountID(rootPub), rootPub, epoch1, nil); err != nil {
			s.fail(w, http.StatusBadRequest, fmt.Errorf("the genesis entry does not verify under that epoch 1 key: %w", err))
			return
		}
	}

	// Decoded BEFORE anything is written, and the three writes are one
	// transaction: a failure part-way used to leave a spent invite and an
	// account no device could log in to. See store.RegisterAccount.
	var escrow []byte
	if req.Escrow != "" {
		if escrow, err = base64.StdEncoding.DecodeString(req.Escrow); err != nil {
			s.fail(w, http.StatusBadRequest, errors.New("the escrow is not base64"))
			return
		}
	}
	if err := s.DB.RegisterAccount(r.Context(), req.Account, rootPub, req.Invite, genesis, escrow); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	if epoch1 != nil {
		// Not fatal: the account exists and the invite is spent, so failing
		// here would leave the device nothing to retry. Without the key the
		// relay checks appends by structure, and POST /v1/roster/epoch1
		// supplies it later.
		if err := s.DB.SetEpoch1SignPub(r.Context(), req.Account, epoch1); err != nil {
			s.Log.Warn("could not record the epoch 1 key", "account", req.Account, "err", err)
		}
	}

	s.Log.Info("account created", "account", req.Account)
	// okStatus, not WriteHeader-then-ok: `ok` writes its own header now, so
	// the two together produced a superfluous second write that Go logs and
	// nobody reads. Caught because the log line appeared next to an unrelated
	// test's output.
	s.okStatus(w, http.StatusCreated, map[string]string{"account": req.Account})
}

type rosterResponse struct {
	Chain string `json:"chain"` // base64, concatenated entries
}

func (s *Server) getRoster(w http.ResponseWriter, r *http.Request, a authedRequest) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	chain, err := s.DB.Roster(r.Context(), a.Account, from)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	s.ok(w, rosterResponse{Chain: base64.StdEncoding.EncodeToString(chain)})
}

type appendRosterRequest struct {
	Seq   uint64 `json:"seq"`
	Entry string `json:"entry"` // base64, body || sig
}

// appendRoster stores one entry.
//
// The server checks that the entry extends the chain and that the caller is on
// it (members.go). It cannot verify an epoch key's signature -- it holds none
// -- and does not pretend to: the client verifies the chain from genesis before
// trusting any of it, so an appended forgery is caught there rather than here.
func (s *Server) appendRoster(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req appendRosterRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	entry, err := base64.StdEncoding.DecodeString(req.Entry)
	if err != nil || len(entry) == 0 {
		s.fail(w, http.StatusBadRequest, errors.New("an entry is required"))
		return
	}
	if status, err := s.appendEntry(r.Context(), a, req.Seq, entry); err != nil {
		s.fail(w, status, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type objectResponse struct {
	Body    string `json:"body"` // base64
	Counter uint64 `json:"counter"`
	ETag    string `json:"etag"`
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request, a authedRequest) {
	epoch, _ := strconv.ParseUint(r.URL.Query().Get("epoch"), 10, 64)
	o, err := s.DB.GetObject(r.Context(), a.Account, r.PathValue("name"), epoch)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.Header().Set("ETag", o.ETag)
	s.ok(w, objectResponse{
		Body:    base64.StdEncoding.EncodeToString(o.Body),
		Counter: o.Counter,
		ETag:    o.ETag,
	})
}

type putObjectRequest struct {
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
	Body    string `json:"body"` // base64
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req putObjectRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	body, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil {
		s.fail(w, http.StatusBadRequest, errors.New("the body is not base64"))
		return
	}

	etag, err := s.DB.PutObject(r.Context(), a.Account, store.Object{
		Name: r.PathValue("name"), Epoch: req.Epoch, Counter: req.Counter, Body: body,
	}, r.Header.Get("If-Match"))
	if err != nil {
		// 409 rather than 500, so a client can tell "somebody else wrote first"
		// from "you sent nonsense" -- and show a conflict chooser for the one
		// and a bug report for the other.
		s.fail(w, statusFor(err), err)
		return
	}
	// The notification carries the ACTOR, so the writing device drops its own
	// echo without any bookkeeping on either side.
	s.notify.publish(a.Account, Notification{
		Collection: r.PathValue("name"),
		Epoch:      req.Epoch,
		Revision:   req.Counter,
		Actor:      hex.EncodeToString(a.Device),
	})

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusNoContent)
}

// deleteObject removes an object and so frees the quota it held.
//
// `?epoch=N` deletes that epoch's copy, the same addressing GET uses. Without
// it every epoch of the name goes: the caller asked for the object gone, and an
// old epoch's copy left behind would still be charged against the quota this
// call exists to free.
func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, a authedRequest) {
	// NEVER THE ESCROW, at any epoch. It is what a recovery opens when every
	// device is gone, so deleting it is deleting the recovery phrase's only
	// use -- and recovery's own rollback check reads the epoch past the
	// current one, so an old epoch's copy is load-bearing too.
	if r.PathValue("name") == "escrow" {
		s.fail(w, http.StatusForbidden, errors.New("the escrow is what recovery opens, and it is never deleted"))
		return
	}
	var epoch *uint64
	if raw := r.URL.Query().Get("epoch"); raw != "" {
		e, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			s.fail(w, http.StatusBadRequest, errors.New("an epoch is a number"))
			return
		}
		epoch = &e
	}
	if err := s.DB.DeleteObject(r.Context(), a.Account, r.PathValue("name"), epoch); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
