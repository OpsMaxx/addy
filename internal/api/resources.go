package api

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	if err := readJSON(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
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

	ctx := r.Context()
	if err := s.DB.CreateAccount(ctx, req.Account, rootPub, req.Invite); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	if err := s.DB.AppendRoster(ctx, req.Account, 0, genesis); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	if req.Escrow != "" {
		escrow, err := base64.StdEncoding.DecodeString(req.Escrow)
		if err != nil {
			s.fail(w, http.StatusBadRequest, errors.New("the escrow is not base64"))
			return
		}
		if _, err := s.DB.PutObject(ctx, req.Account,
			store.Object{Name: "escrow", Epoch: 1, Counter: 1, Body: escrow}, ""); err != nil {
			s.fail(w, statusFor(err), err)
			return
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
// The server checks contiguity and nothing else. It cannot verify the signature
// -- it holds no key -- and does not pretend to: the client verifies the chain
// from genesis before trusting any of it, so an appended forgery is caught
// there rather than here.
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
	if err := s.DB.AppendRoster(r.Context(), a.Account, req.Seq, entry); err != nil {
		s.fail(w, statusFor(err), err)
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
