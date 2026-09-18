package api

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// Conflict copies, over HTTP.
//
// Concurrency is last-writer-wins per collection WITH THE LOSER KEPT, and
// these are the three calls that make the second half real. A bare LWW
// silently destroys one device's work and tells nobody -- for a `servers` list
// that means a machine somebody added on the laptop is simply gone from the
// desktop, with no error and no symptom.
//
// The server cannot read any of it. It stores the losing ciphertext, says
// which device wrote it and when, and hands it back; deciding which copy wins
// is the client's, because only the client can see what is in them.

type keepConflictRequest struct {
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
	Body    string `json:"body"` // base64, still sealed
}

// keepConflict stores a copy whose conditional PUT lost.
//
// Called by the loser itself, immediately after its 409. That is the only
// moment the bytes exist anywhere but in the losing device's memory, and a
// client that gave up at the 409 would have thrown them away -- which is the
// silent data loss this whole mechanism exists to prevent.
func (s *Server) keepConflict(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req keepConflictRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	body, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil || len(body) == 0 {
		s.fail(w, http.StatusBadRequest, errors.New("a sealed body is required, base64 encoded"))
		return
	}

	if err := s.DB.KeepConflict(r.Context(), a.Account, store.Conflict{
		Name:    r.PathValue("name"),
		Epoch:   req.Epoch,
		Counter: req.Counter,
		Body:    body,
		Device:  a.Device,
	}); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type conflictView struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
	// Who wrote the losing copy. The chooser needs it: "the copy from your
	// laptop" is a question somebody can answer and "copy B" is not.
	Device string `json:"device"`
	// Still sealed. The client opens it to show what is inside; that is the
	// only way a person can choose, and it is why the decision cannot be the
	// server's.
	Body      string `json:"body"`
	CreatedAt string `json:"createdAt"`
}

func (s *Server) listConflicts(w http.ResponseWriter, r *http.Request, a authedRequest) {
	rows, err := s.DB.Conflicts(r.Context(), a.Account)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	out := make([]conflictView, 0, len(rows))
	for _, c := range rows {
		out = append(out, conflictView{
			ID:        c.ID,
			Name:      c.Name,
			Epoch:     c.Epoch,
			Counter:   c.Counter,
			Device:    hex.EncodeToString(c.Device),
			Body:      base64.StdEncoding.EncodeToString(c.Body),
			CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.ok(w, map[string]any{"conflicts": out})
}

// resolveConflict drops a copy the user has finished with.
//
// Called after the client has either merged the losing copy in -- by writing a
// new winning version -- or decided against it. Either way the copy has served
// its purpose, and leaving it would mean the chooser offering the same
// decision forever.
func (s *Server) resolveConflict(w http.ResponseWriter, r *http.Request, a authedRequest) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusBadRequest, errors.New("a conflict id is a number"))
		return
	}
	if err := s.DB.ResolveConflict(r.Context(), a.Account, id); err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
