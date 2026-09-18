// Package api is addy's HTTP surface: accounts, rosters, objects and the
// signalling relay.
//
// WHAT THE SERVER CAN AND CANNOT DO, which is the whole shape of this package:
// it stores signed entries it cannot forge and opaque bytes it cannot read, and
// it relays frames it learns nothing from. It authenticates devices, because it
// has to know whose quota to charge and whose objects to serve, and it does that
// against public keys the roster already contains.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// Server is the API.
type Server struct {
	DB  *store.DB
	Log *slog.Logger

	// PollWait is how long a signalling read blocks before answering "nothing
	// arrived". Long, because a short one turns every idle device into a
	// request loop; configurable, because a test that waits it out is a test
	// somebody deletes.
	PollWait time.Duration

	auth   *authState
	hub    *hub
	notify *notifier
}

// New builds the API's handler.
func New(db *store.DB, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		DB: db, Log: log, PollWait: defaultPollWait,
		auth: newAuthState(), hub: newHub(), notify: newNotifier(),
	}
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: minting an account is how a client comes to have a key
	// to authenticate WITH, so it cannot itself require one. What it requires
	// instead is an invite, which is the only thing an admin actually controls.
	mux.HandleFunc("POST /v1/account", s.createAccount)
	mux.HandleFunc("POST /v1/auth/challenge", s.challenge)
	mux.HandleFunc("POST /v1/auth/login", s.login)

	// The pairing rendezvous is unauthenticated because a joining device is not
	// in the roster yet and does not know the account id. See signal.go for
	// what that costs and how it is bounded.
	mux.HandleFunc("GET /v1/pair/{pairing}", s.pairRendezvous)
	mux.HandleFunc("POST /v1/pair/{pairing}", s.pairRendezvous)

	// Authenticated. Every one of these carries a request-authorization
	// signature over its method, path and body, so an authorization for a GET
	// cannot be replayed as the DELETE the server would rather have had.
	mux.Handle("GET /v1/roster", s.authed(s.getRoster))
	mux.Handle("POST /v1/roster", s.authed(s.appendRoster))
	mux.Handle("GET /v1/obj/{name}", s.authed(s.getObject))
	mux.Handle("PUT /v1/obj/{name}", s.authed(s.putObject))
	mux.Handle("GET /v1/signal", s.authed(s.signal))
	mux.Handle("GET /v1/changes", s.authed(s.changes))

	// Pastes. Creating needs an account; READING deliberately does not -- the
	// recipient of a link has none, and cannot be made to get one.
	mux.Handle("POST /v1/paste", s.authed(s.createPaste))
	mux.Handle("GET /v1/pastes", s.authed(s.listPastes))
	mux.Handle("DELETE /v1/paste/{id}", s.authed(s.deletePaste))
	// GET reports; POST consumes. A prefetching chat client, mail scanner or
	// link previewer issues the first and never the second, which is what
	// stops a link burning before the human opens it.
	mux.HandleFunc("GET /v1/paste/{id}", s.getPaste)
	mux.HandleFunc("POST /v1/paste/{id}/burn", s.burnPaste)

	// Store-and-forward. The sender and the recipient are both taken from the
	// session, never from the request: a `from` a client could set would let
	// one device leave mail appearing to come from another, and a `for` would
	// let it read another device's.
	mux.Handle("POST /v1/mail", s.authed(s.leaveMail))
	mux.Handle("GET /v1/mail", s.authed(s.collectMail))
	mux.Handle("POST /v1/mail/ack", s.authed(s.ackMail))

	return mux
}

type errorBody struct {
	Error string `json:"error"`
}

// fail writes an error the client can act on without telling an anonymous
// caller anything about the account.
//
// The message is the developer's; the STATUS is the contract. In particular a
// missing account and a wrong signature both answer 401, because distinguishing
// them would turn this endpoint into an oracle for which account ids exist.
func (s *Server) fail(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: err.Error()})
}

func (s *Server) ok(w http.ResponseWriter, v any) {
	s.okStatus(w, http.StatusOK, v)
}

// okStatus is ok with a status other than 200, for the cases where the body is
// still meaningful -- 410 on a burned paste being the one that matters, since
// the page has to tell the reader it WAS a paste and is gone, which a bare
// error body cannot.
//
// Split out rather than letting callers write the header themselves: a
// WriteHeader after Encode is silently ignored and logs a warning nobody
// reads, so the 410 would have gone out as a 200 with a body saying "gone".
func (s *Server) okStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusFor maps a store error to a status. Conflicts are 409 so a client can
// tell "somebody else wrote first" from "you sent nonsense".
func statusFor(err error) int {
	switch {
	case errors.Is(err, store.ErrETagMismatch), errors.Is(err, store.ErrObjectExists),
		errors.Is(err, store.ErrSeqTaken), errors.Is(err, store.ErrSeqGap),
		errors.Is(err, store.ErrAccountExists):
		return http.StatusConflict
	case errors.Is(err, store.ErrNoAccount):
		return http.StatusNotFound
	case errors.Is(err, store.ErrMailboxFull):
		// 507 like a quota, because it is the same shape of problem from the
		// sender's point of view -- the far end has no room -- and a client
		// that already handles "out of space" handles this without a second
		// branch.
		return http.StatusInsufficientStorage
	case errors.Is(err, store.ErrMessageTooLarge), errors.Is(err, store.ErrPasteTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, store.ErrOverQuota):
		// 507, so a client can distinguish "you are out of room" from every
		// other refusal and say so with what to delete -- rather than showing a
		// generic error and quietly stopping, which is the worst version of
		// this feature.
		return http.StatusInsufficientStorage
	case errors.Is(err, store.ErrInviteUnknown), errors.Is(err, store.ErrInviteSpent),
		errors.Is(err, store.ErrInviteExpired):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func unmarshal(body []byte, v any) error { return json.Unmarshal(body, v) }
