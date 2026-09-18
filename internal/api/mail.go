package api

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// Store-and-forward, over HTTP.
//
// The live path between two devices is a direct connection. This is what a
// sender does when there is no live path, and what a recipient does when it
// wakes up: WebRTC needs both ends awake, and a clipboard that only works when
// the other laptop is on is not a clipboard.
//
// THE SENDER IS THE AUTHENTICATED DEVICE, always, taken from the session and
// never from the body. A `from` field a client could set would let one device
// leave mail that appears to come from another -- and since the recipient
// decides whether to trust a payload partly by who sent it, that is a
// confused-deputy attack inside the user's own account.

type leaveRequest struct {
	// Hex of the recipient's 32-byte signing key, as it appears in the roster.
	ToDevice string `json:"toDevice"`
	// What sort of payload this is, so the recipient can decide whether to
	// fetch it before fetching it. Opaque to the server; it routes and counts,
	// it does not interpret.
	Kind string `json:"kind"`
	// Base64 of the sealed payload. Sealed to the RECIPIENT's key, not to the
	// account's: mail is the one thing here addressed to a device.
	Sealed string `json:"sealed"`
}

type leaveResponse struct {
	ID        int64  `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

func (s *Server) leaveMail(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req leaveRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	to, err := hex.DecodeString(req.ToDevice)
	if err != nil || len(to) != 32 {
		s.fail(w, http.StatusBadRequest, errors.New("toDevice is 32 bytes of hex"))
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(req.Sealed)
	if err != nil || len(sealed) == 0 {
		s.fail(w, http.StatusBadRequest, errors.New("a sealed body is required, base64 encoded"))
		return
	}
	if req.Kind == "" {
		s.fail(w, http.StatusBadRequest, errors.New("a message needs a kind"))
		return
	}

	id, err := s.DB.Leave(r.Context(), a.Account, store.Message{
		ToDevice:   to,
		FromDevice: a.Device,
		Kind:       req.Kind,
		Sealed:     sealed,
	})
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}

	// The recipient may be connected after all -- it just was not when the
	// sender tried. A pointer, never the payload, same as every other
	// notification: a device that is listening picks it up now instead of on
	// its next poll.
	s.notify.publish(a.Account, Notification{
		Collection: "mail",
		Actor:      hex.EncodeToString(a.Device),
	})

	s.ok(w, leaveResponse{
		ID:        id,
		ExpiresAt: time.Now().Add(store.MailboxTTL).UTC().Format(time.RFC3339),
	})
}

type mailItem struct {
	ID         int64  `json:"id"`
	FromDevice string `json:"fromDevice"`
	Kind       string `json:"kind"`
	Sealed     string `json:"sealed"`
	CreatedAt  string `json:"createdAt"`
}

// collectMail returns what is waiting for THE AUTHENTICATED DEVICE.
//
// The recipient is the session's device and is not a parameter. A `for` query
// parameter would be a way to read another device's mail with your own
// credentials -- inside your own account, which is exactly where nothing else
// is scoped per-device and where the habit of not checking would come from.
//
// It does NOT delete. See store.Collect: a collect that deleted would lose
// everything to one dropped connection, and neither end could tell that from a
// successful delivery.
func (s *Server) collectMail(w http.ResponseWriter, r *http.Request, a authedRequest) {
	msgs, err := s.DB.Collect(r.Context(), a.Account, a.Device, 0)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	out := make([]mailItem, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, mailItem{
			ID:         m.ID,
			FromDevice: hex.EncodeToString(m.FromDevice),
			Kind:       m.Kind,
			Sealed:     base64.StdEncoding.EncodeToString(m.Sealed),
			CreatedAt:  m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.ok(w, map[string]any{"messages": out})
}

type ackRequest struct {
	IDs []int64 `json:"ids"`
}

// ackMail deletes messages the recipient has on disk.
//
// This is the only thing that deletes mail, and the recipient is the only one
// who can say when. It is also scoped by device in the statement below the
// API, because ids are a global autoincrement and therefore guessable.
func (s *Server) ackMail(w http.ResponseWriter, r *http.Request, a authedRequest) {
	var req ackRequest
	if err := unmarshal(a.Body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	n, err := s.DB.Ack(r.Context(), a.Account, a.Device, req.IDs)
	if err != nil {
		s.fail(w, statusFor(err), err)
		return
	}
	s.ok(w, map[string]any{"deleted": n})
}
