package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// One-time pastes.
//
// CREATING one needs an account on this box; READING one does not, and cannot
// -- the whole point is to send a link to somebody who has no account here.
// That asymmetry is the design: an open create endpoint on a self-hosted box
// is a free anonymous file drop for whoever finds it, and the operator ends up
// hosting other people's content under their own domain.
//
// The server never sees a key. The 128-bit key lives in the URL fragment,
// which browsers do not send, so every blob here is opaque to the process
// serving it. A password, where one is used, is stretched with Argon2id IN THE
// BROWSER and mixed into the HKDF input -- it is never a flag the server
// checks, because a server-gated password is a password the server can turn
// off.

const (
	// The longest a paste may be readable. A "one-time" link that is still
	// live a year later is a credential somebody forgot about.
	maxPasteTTL = 30 * 24 * time.Hour
	// How long the row lingers after it stops being readable, so a reader gets
	// "already used" rather than "no such paste". See the schema comment.
	pasteLinger = 7 * 24 * time.Hour
)

type createPasteRequest struct {
	// Base64 of the client-sealed blob: body AND metadata together. The server
	// has no schema for what is inside and must not acquire one.
	Sealed string `json:"sealed"`
	// Seconds. Clamped to maxPasteTTL.
	TTLSeconds int64 `json:"ttlSeconds"`
	// 0 means unlimited. The portal's default is 1; a caller asking for more
	// is making a link, not a one-time paste, and is allowed to.
	MaxViews int `json:"maxViews"`
}

type createPasteResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
	MaxViews  int    `json:"maxViews"`
}

func (s *Server) createPaste(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req createPasteRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(req.Sealed)
	if err != nil || len(sealed) == 0 {
		s.fail(w, http.StatusBadRequest, errors.New("a sealed body is required, base64 encoded"))
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > maxPasteTTL {
		ttl = maxPasteTTL
	}

	p, err := s.DB.CreatePaste(r.Context(), a.Account, sealed, ttl, pasteLinger, req.MaxViews)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	s.ok(w, createPasteResponse{
		ID:        p.ID,
		ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
		MaxViews:  p.MaxViews,
	})
}

// publicPaste is what an anonymous reader is told, and it is a SEPARATE TYPE
// from store.Paste rather than the same struct with fields omitted.
//
// A shared struct with `json:"-"` on the private fields is one forgotten tag
// away from serving the owner's account id, and the forgotten tag is on the
// field somebody adds next year. Two types means adding a field to the owner's
// view cannot leak it into the anonymous one: it has to be written twice,
// deliberately, and the second time is where the thinking happens.
//
// What is deliberately NOT here: the owner, the exact creation time, the
// ciphertext length, and the view count. A reader needs to know whether they
// can read it, not who sent it or how many other people have looked.
type publicPaste struct {
	ID string `json:"id"`
	// "ready", "gone". Never a count.
	State string `json:"state"`
	// Whether reading it will consume it, so the page can warn BEFORE the
	// reader clicks rather than after.
	Burns bool `json:"burns"`
}

// getPaste answers whether a paste may be read. IT NEVER CONSUMES ONE.
//
// Every one-time paste service dies the same way: the link is posted in a chat
// app, the app prefetches the URL to build a preview, the paste burns, and the
// human gets an empty page. Headers and robots.txt help with the crawlers that
// read them; this is the part that works against the ones that do not, because
// none of them issue a POST.
func (s *Server) getPaste(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if s.refusedWhileReonboarding(w, r) {
		return
	}
	id := r.PathValue("id")
	p, err := s.DB.PasteStatus(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrPasteNotFound):
		s.fail(w, http.StatusNotFound, err)
		return
	case errors.Is(err, store.ErrPasteGone):
		// 410, not 404: the distinction is the reason `deleted_at` is a
		// separate column. The sender can tell "they read it" from "I sent the
		// wrong link", and without it both people guess.
		s.okStatus(w, http.StatusGone, publicPaste{ID: id, State: "gone", Burns: false})
		return
	case err != nil:
		s.fail(w, statusFor(err), err)
		return
	}
	s.ok(w, publicPaste{ID: p.ID, State: "ready", Burns: p.MaxViews > 0})
}

type burnResponse struct {
	Sealed string `json:"sealed"`
	// How many reads are left after this one. -1 means unlimited. Told to the
	// person who just consumed one, which is the only party it does not help
	// an attacker to tell.
	Remaining int `json:"remaining"`
}

// burnPaste consumes one view and hands back the sealed bytes.
func (s *Server) burnPaste(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if s.refusedWhileReonboarding(w, r) {
		return
	}
	p, err := s.DB.Burn(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrPasteNotFound):
		s.fail(w, http.StatusNotFound, err)
		return
	case errors.Is(err, store.ErrPasteGone):
		s.fail(w, http.StatusGone, err)
		return
	case err != nil:
		s.fail(w, statusFor(err), err)
		return
	}
	remaining := -1
	if p.MaxViews > 0 {
		remaining = p.MaxViews - p.Views
	}
	s.ok(w, burnResponse{
		Sealed:    base64.StdEncoding.EncodeToString(p.Sealed),
		Remaining: remaining,
	})
}

type ownPaste struct {
	ID        string `json:"id"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	MaxViews  int    `json:"maxViews"`
	Views     int    `json:"views"`
}

// listPastes is the owner's view: what they sent, and whether it has been
// read. No ciphertexts -- their device has the plaintext already, and a
// listing that carried every blob would be a way to bulk-collect them without
// burning any.
func (s *Server) listPastes(w http.ResponseWriter, r *http.Request, a authedRequest) {
	rows, err := s.DB.PastesFor(r.Context(), a.Account)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	out := make([]ownPaste, 0, len(rows))
	for _, p := range rows {
		out = append(out, ownPaste{
			ID:        p.ID,
			CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
			MaxViews:  p.MaxViews,
			Views:     p.Views,
		})
	}
	s.ok(w, map[string]any{"pastes": out})
}

func (s *Server) deletePaste(w http.ResponseWriter, r *http.Request, a authedRequest) {
	err := s.DB.DeletePaste(r.Context(), a.Account, r.PathValue("id"))
	if errors.Is(err, store.ErrPasteNotFound) {
		// 404 for somebody else's paste as well as for a missing one: telling
		// a caller that an id exists but is not theirs is a way to enumerate.
		s.fail(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// noStore keeps a paste out of every cache between here and the reader.
//
// A shared proxy or a browser back button holding the response is a copy of
// the ciphertext that outlives the burn -- and the key is in the URL the same
// cache is keyed on, so it is a copy of the plaintext to anyone who can read
// the cache.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
}

// refusedWhileReonboarding stops the ANONYMOUS paste routes on a box somebody
// has panicked or reset.
//
// The authenticated routes get this inside `authed`. These two do not go
// through it -- a paste recipient holds no account, which is the point -- so
// without this an operator who ran `addy panic` would have stopped their
// devices syncing and left the box still handing out pastes. Pastes are user
// content on a machine its owner has just disowned.
func (s *Server) refusedWhileReonboarding(w http.ResponseWriter, r *http.Request) bool {
	blocked, at, err := s.DB.Reonboard(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return true
	}
	if !blocked {
		return false
	}
	w.Header().Set("X-Addy-Reonboard", at.UTC().Format(time.RFC3339))
	s.fail(w, http.StatusServiceUnavailable,
		errors.New("this instance was reset or panicked and is not serving"))
	return true
}
