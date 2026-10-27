package api

import (
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Change notifications.
//
// NOTIFICATIONS ARE POINTERS, NEVER PAYLOADS. A message says "this object
// changed, it is now at revision R" and nothing else; no ciphertext rides the
// notification channel. Three things follow, and they are the reason to do it
// this way:
//
//   - The push path stays cheap, because a notification is a few dozen bytes
//     regardless of whether the object is a nickname or a vault.
//   - A DROPPED NOTIFICATION IS NEVER A CORRECTNESS PROBLEM. The client
//     compares its local revision and either skips or fetches; missing the
//     message only delays it until the next catch-up.
//   - The server cannot leak content through a channel it was never given
//     content for.
//
// Borrowed wholesale from a design that has run in production for years. The
// transport is not borrowed -- theirs is SignalR over MessagePack and we already
// have a channel.

// Notification is what a device receives.
type Notification struct {
	Collection string `json:"collection"`
	Epoch      uint64 `json:"epoch"`
	Revision   uint64 `json:"revision"`
	// Actor is the device that made the change, so a client can DROP ITS OWN.
	// Free echo suppression: one field, no bookkeeping, and without it every
	// write a device makes comes back to it as a change to fetch.
	Actor string `json:"actor"`
	// Resync is the escape hatch: "stop reasoning about revisions and refetch
	// everything." It costs nothing to carry and it is the only thing that
	// saves you when the incremental path has a bug in the field.
	Resync bool `json:"resync,omitempty"`
}

// notifier fans changes out to an account's devices.
type notifier struct {
	mu      sync.Mutex
	streams map[string]map[int64]chan Notification
	next    int64
}

func newNotifier() *notifier {
	return &notifier{streams: map[string]map[int64]chan Notification{}}
}

func (n *notifier) subscribe(account string) (<-chan Notification, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.streams[account] == nil {
		n.streams[account] = map[int64]chan Notification{}
	}
	n.next++
	id := n.next
	// Buffered, and dropped rather than blocked on if full. A notification is
	// a pointer, so losing one costs a delay until the next catch-up -- whereas
	// blocking the publisher on a slow reader costs everybody.
	ch := make(chan Notification, 16)
	n.streams[account][id] = ch

	return ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if m := n.streams[account]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(n.streams, account)
			}
		}
	}
}

func (n *notifier) publish(account string, note Notification) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.streams[account] {
		select {
		case ch <- note:
		default:
			// Full. See the buffer comment: a dropped pointer is a delay, not
			// a correctness problem, which is exactly why pointers were chosen
			// over payloads.
		}
	}
}

type changesResponse struct {
	Notifications []Notification `json:"notifications"`
}

// changes is a long poll that returns as soon as anything is waiting.
//
// ON EVERY RECONNECT A CLIENT DOES A FULL CATCH-UP rather than trusting that
// nothing was missed while it was away. This endpoint does not try to replay
// history for it -- the roster and the object counters are the durable record,
// and a notification stream that pretended to be reliable would invite clients
// to rely on it.
func (s *Server) changes(w http.ResponseWriter, r *http.Request, a authedRequest) {
	ch, cancel := s.notify.subscribe(a.Account)
	defer cancel()

	var batch []Notification
	self := hex.EncodeToString(a.Device)

	// Take everything already queued without waiting.
	for drained := false; !drained; {
		select {
		case note := <-ch:
			if note.Actor != self {
				batch = append(batch, note)
			}
		default:
			drained = true
		}
	}
	if len(batch) > 0 {
		s.ok(w, changesResponse{Notifications: batch})
		return
	}

	select {
	case note := <-ch:
		// Re-checked on waking, as signal does: a revoke can land while
		// this poll is parked.
		if err := s.auth.stillServing(a); err != nil {
			s.fail(w, http.StatusUnauthorized, err)
			return
		}
		if note.Actor != self {
			batch = append(batch, note)
		}
		s.ok(w, changesResponse{Notifications: batch})
	case <-time.After(s.pollWait()):
		// Nothing arrived, which is not a failure. A client that treats a
		// timeout as an error will back off from an account that is simply
		// quiet.
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		w.WriteHeader(http.StatusNoContent)
	}
}
