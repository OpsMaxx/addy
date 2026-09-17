package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
// EVERY MAILBOX IS DIRECTED. A first draft gave each room one queue, and the
// first end-to-end test found the consequence immediately: a device that
// published and then polled received its own frame back. So a room is a set of
// mailboxes and a sender names the one it is writing to, while a reader only
// ever reads its own. That is not a refinement, it is the difference between a
// relay and an echo.
//
// This is long-polling rather than a WebSocket, deliberately and for now. The
// three pairing frames are the only traffic M1 has, a poll is a handler and a
// channel rather than a protocol upgrade and a ping loop, and the continuity
// work that genuinely needs a socket arrives with the milestone that builds it.
// Swapping it later changes this file and nothing that uses it.

const (
	signalTTL = 5 * time.Minute
	// A long poll, because a short one turns every idle device into a request
	// loop. Overridable on the Server so a test does not have to wait it out.
	defaultPollWait = 25 * time.Second
	maxPending      = 16
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
	// A reader takes its own mailbox, named by its device key; a writer names
	// the peer it is writing to. There is no way to express "read the peer's
	// mailbox", which is what stops a device draining another's frames.
	self := "acct:" + a.Account + ":" + hex.EncodeToString(a.Device)

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
		to := r.URL.Query().Get("to")
		if to == "" {
			s.fail(w, http.StatusBadRequest, errors.New("a frame must name the device it is for"))
			return
		}
		if err := s.hub.publish("acct:"+a.Account+":"+to, frame); err != nil {
			s.fail(w, http.StatusTooManyRequests, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ch, cancel := s.hub.subscribe(self)
	defer cancel()

	select {
	case frame := <-ch:
		s.ok(w, signalFrame{Frame: base64.StdEncoding.EncodeToString(frame)})
	case <-time.After(s.pollWait()):
		// An empty 204 rather than an error: nothing arrived, which is not a
		// failure, and a client that treats a timeout as an error will give up
		// on a pairing the user is still typing.
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		w.WriteHeader(http.StatusNoContent)
	}
}

// The pairing rendezvous, and why it is UNAUTHENTICATED.
//
// A joining device is not in the roster yet, so it cannot authenticate -- and
// it does not know the account id either, which §8.2 of the protocol is
// explicit about: binding the PAKE password to a value one side cannot compute
// is not a binding, it is a bug. So the two devices meet in a room named by the
// pairing id alone.
//
// That is a room an anonymous caller can create, which is a real cost and is
// bounded rather than argued away:
//
//   - The room name is 16 CSPRNG bytes chosen by the initiating device, so it
//     cannot be enumerated or guessed into.
//   - Rooms expire, and the sweep runs on every use rather than on a timer.
//   - The pending queue is small and fixed.
//   - The frames are opaque and useless without the code. The relay carrying
//     them learns nothing, which is the property SPAKE2 is here to provide.
//
// What an anonymous caller CAN do is occupy memory and waste a poll. What it
// cannot do is learn anything, reach an account, or brute-force a code -- the
// attempt limiter that governs that runs on the initiating device, not here.

const pairingIDHexLen = 32

func (s *Server) pairRendezvous(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("pairing")
	if len(id) != pairingIDHexLen {
		s.fail(w, http.StatusBadRequest, errors.New("a pairing id is 16 bytes of hex"))
		return
	}
	// Two mailboxes, one per role. The initiator writes to the joiner's and
	// reads its own, and vice versa -- without that a device that published
	// and then polled would receive its own frame back, which the first
	// end-to-end test found immediately.
	//
	// Namespaced away from account rooms, so a pairing id can never collide
	// with -- or be used to address -- an account's own signalling room.
	role := r.URL.Query().Get("as")
	if role != "initiator" && role != "joiner" {
		s.fail(w, http.StatusBadRequest, errors.New("a pairing request must say which role it is"))
		return
	}
	peer := "joiner"
	if role == "joiner" {
		peer = "initiator"
	}
	mine := "pair:" + id + ":" + role
	theirs := "pair:" + id + ":" + peer

	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}

	if len(body) > 0 {
		var in signalFrame
		if err := json.Unmarshal(body, &in); err != nil {
			s.fail(w, http.StatusBadRequest, err)
			return
		}
		frame, err := base64.StdEncoding.DecodeString(in.Frame)
		if err != nil {
			s.fail(w, http.StatusBadRequest, errors.New("the frame is not base64"))
			return
		}
		if err := s.hub.publish(theirs, frame); err != nil {
			s.fail(w, http.StatusTooManyRequests, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ch, cancel := s.hub.subscribe(mine)
	defer cancel()

	select {
	case frame := <-ch:
		s.ok(w, signalFrame{Frame: base64.StdEncoding.EncodeToString(frame)})
	case <-time.After(s.pollWait()):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) pollWait() time.Duration {
	if s.PollWait > 0 {
		return s.PollWait
	}
	return defaultPollWait
}
