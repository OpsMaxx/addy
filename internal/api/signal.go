package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

// The signalling relay.
//
// THE SERVER IS A TRANSPORT FOR SIGNALLING, NOT AN AUTHORITY ON IT. It carries
// frames between two devices of one account and learns nothing from any of
// them: the pairing frames carry PAKE material that is useless without the
// code, and later WebRTC offers carry signatures the receiving peer verifies
// against its own roster.
//
// Rooms are keyed on the ACCOUNT, so a device may only address a peer of the
// same account. An offer cannot be relayed to a stranger because there is no
// room in which a stranger and a device of this account both sit.
//
// This is long-polling rather than a WebSocket, deliberately and for now. The
// three pairing frames are the only traffic M1 has, a poll is a handler and a
// channel rather than a protocol upgrade and a ping loop, and the continuity
// work that genuinely needs a socket arrives with the milestone that builds it.
// Swapping it later changes this file and nothing that uses it.

const (
	signalTTL  = 5 * time.Minute
	pollWait   = 25 * time.Second
	maxPending = 16
)

type hub struct {
	mu    sync.Mutex
	rooms map[string]*room
}

type room struct {
	waiting []chan []byte
	pending [][]byte
	touched time.Time
}

func newHub() *hub { return &hub{rooms: map[string]*room{}} }

func (h *hub) get(account string) *room {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep()
	r := h.rooms[account]
	if r == nil {
		r = &room{}
		h.rooms[account] = r
	}
	r.touched = time.Now()
	return r
}

// sweep drops rooms nobody has touched. Called under the hub's lock on every
// use, because an unbounded map of rooms is a memory leak an anonymous caller
// can drive.
func (h *hub) sweep() {
	cutoff := time.Now().Add(-signalTTL)
	for k, r := range h.rooms {
		if r.touched.Before(cutoff) && len(r.waiting) == 0 {
			delete(h.rooms, k)
		}
	}
}

func (h *hub) publish(account string, frame []byte) error {
	r := h.get(account)
	h.mu.Lock()
	defer h.mu.Unlock()

	// Hand it to a waiter if there is one.
	if len(r.waiting) > 0 {
		ch := r.waiting[0]
		r.waiting = r.waiting[1:]
		ch <- frame
		return nil
	}

	// Otherwise queue it, bounded. An unbounded queue is a place for an
	// authenticated device to park memory.
	if len(r.pending) >= maxPending {
		return errors.New("too many undelivered frames")
	}
	r.pending = append(r.pending, frame)
	return nil
}

func (h *hub) subscribe(account string) (<-chan []byte, func()) {
	r := h.get(account)
	ch := make(chan []byte, 1)

	h.mu.Lock()
	if len(r.pending) > 0 {
		frame := r.pending[0]
		r.pending = r.pending[1:]
		h.mu.Unlock()
		ch <- frame
		return ch, func() {}
	}
	r.waiting = append(r.waiting, ch)
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for i, w := range r.waiting {
			if w == ch {
				r.waiting = append(r.waiting[:i], r.waiting[i+1:]...)
				return
			}
		}
	}
}

type signalFrame struct {
	Frame string `json:"frame"` // base64, opaque to the server
}

// signal is both halves: a GET waits for a frame, and a GET with a body
// publishes one. Split by whether the request carried anything, because the
// authorization signature already covers the body and a second method would
// need its own.
func (s *Server) signal(w http.ResponseWriter, r *http.Request, a authedRequest) {
	if len(a.Body) > 0 {
		var in signalFrame
		if err := unmarshal(a.Body, &in); err != nil {
			s.fail(w, http.StatusBadRequest, err)
			return
		}
		frame, err := base64.StdEncoding.DecodeString(in.Frame)
		if err != nil {
			s.fail(w, http.StatusBadRequest, errors.New("the frame is not base64"))
			return
		}
		if err := s.hub.publish(a.Account, frame); err != nil {
			s.fail(w, http.StatusTooManyRequests, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ch, cancel := s.hub.subscribe(a.Account)
	defer cancel()

	select {
	case frame := <-ch:
		s.ok(w, signalFrame{Frame: base64.StdEncoding.EncodeToString(frame)})
	case <-time.After(pollWait):
		// An empty 204 rather than an error: nothing arrived, which is not a
		// failure, and a client that treats a timeout as an error will give up
		// on a pairing the user is still typing.
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		w.WriteHeader(http.StatusNoContent)
	}
}
