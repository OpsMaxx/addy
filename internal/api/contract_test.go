package api_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
)

// The statuses the OpsMaxx client acts on, each pinned at the HTTP layer
// rather than through the Go client, because the client that has to agree with
// them is not this one.

func loggedIn(t *testing.T, srv *httptest.Server, invite string) *client.Client {
	t.Helper()
	c := client.New(srv.URL, true)
	if _, err := c.Register("quiet-otter-41", invite); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	return c
}

// status is the response's code, or -1 when there was no response, which no
// assertion below accepts.
func status(resp *http.Response, err error) int {
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// A GET with a body is the old publish, which Node's fetch would not send at
// all. Publishing is POST; a GET that carries a frame is refused rather than
// parked in a long poll for a frame its sender thinks it delivered.
func TestASignalFrameIsPublishedWithPostNotGet(t *testing.T) {
	srv, db := instance(t)
	c := loggedIn(t, srv, invite(t, db))
	frame := map[string]string{"frame": "aGVsbG8="}

	if got := status(c.RawRequest("POST", "/v1/signal?to=00", frame)); got != http.StatusNoContent {
		t.Fatalf("POST /v1/signal = %d, want 204", got)
	}
	if got := status(c.RawRequest("GET", "/v1/signal?to=00", frame)); got != http.StatusBadRequest {
		t.Fatalf("GET /v1/signal with a body = %d, want 400", got)
	}
}

// DELETE frees an object's quota; 404 when there is nothing to delete, and
// another account's object is not there to delete.
func TestDeletingAnObjectOverHTTP(t *testing.T) {
	srv, db := instance(t)
	a := loggedIn(t, srv, invite(t, db))
	b := loggedIn(t, srv, invite(t, db))

	if _, err := a.PutObject("transfer:x", 1, 1, []byte("sealed"), ""); err != nil {
		t.Fatal(err)
	}
	if got := status(b.RawRequest("DELETE", "/v1/obj/transfer:x", nil)); got != http.StatusNotFound {
		t.Fatalf("another account's DELETE = %d, want 404", got)
	}
	if got := status(a.RawRequest("DELETE", "/v1/obj/transfer:x?epoch=2", nil)); got != http.StatusNotFound {
		t.Fatalf("DELETE at an epoch with nothing = %d, want 404", got)
	}
	if got := status(a.RawRequest("DELETE", "/v1/obj/transfer:x", nil)); got != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", got)
	}
	if _, err := a.GetObject("transfer:x", 1); err == nil {
		t.Fatal("the object is still there")
	}
	if got := status(a.RawRequest("DELETE", "/v1/obj/transfer:x", nil)); got != http.StatusNotFound {
		t.Fatalf("a second DELETE = %d, want 404", got)
	}
}

// An oversized body is 413, not truncated. Truncating it failed the signature
// and answered 401, which the client reads as "no longer paired".
func TestAnOversizedBodyIsRefusedAsTooLarge(t *testing.T) {
	srv, db := instance(t)
	c := loggedIn(t, srv, invite(t, db))

	// A JSON string of 8 MiB is 8 MiB plus its quotes: one past the limit is
	// all it takes.
	got := status(c.RawRequest("PUT", "/v1/obj/big", strings.Repeat("a", 8<<20)))
	if got != http.StatusRequestEntityTooLarge {
		t.Fatalf("an 8 MiB + 2 body = %d, want 413", got)
	}
}

// A client that names a different protocol is told so with 426; one that
// names none -- OpsMaxx 0.58 -- is let through.
func TestAClientOnAnotherProtocolIsRefused(t *testing.T) {
	srv, _ := instance(t)
	post := func(header string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/auth/challenge", strings.NewReader(`{}`))
		if header != "" {
			req.Header.Set("X-Addy-Protocol", header)
		}
		resp, err := srv.Client().Do(req)
		return status(resp, err)
	}
	if got := post("addy-protocol-v0"); got != http.StatusUpgradeRequired {
		t.Fatalf("another protocol = %d, want 426", got)
	}
	if got := post(protocol.ProtocolVersion); got != http.StatusOK {
		t.Fatalf("this protocol = %d, want 200", got)
	}
	if got := post(""); got != http.StatusOK {
		t.Fatalf("no header = %d, want 200", got)
	}
}

// The rendezvous lives in memory. A pairing the relay has no record of --
// finished, expired, or lost to a restart -- is answered 404 so the device can
// say "start again" instead of polling an empty room for three minutes.
func TestAPairingTheRelayDoesNotKnowIsGone(t *testing.T) {
	srv, _ := instance(t)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	url := srv.URL + "/v1/pair/" + hex.EncodeToString(id)
	frame := []byte(`{"frame":"aGVsbG8="}`)

	get := func(role string) int {
		resp, err := srv.Client().Get(url + "?as=" + role)
		return status(resp, err)
	}
	post := func(role string) int {
		resp, err := srv.Client().Post(url+"?as="+role, "application/json", bytes.NewReader(frame))
		return status(resp, err)
	}

	if got := get("joiner"); got != http.StatusNotFound {
		t.Fatalf("joiner poll on an unknown pairing = %d, want 404", got)
	}
	if got := post("joiner"); got != http.StatusNotFound {
		t.Fatalf("joiner frame into an unknown pairing = %d, want 404", got)
	}
	if got := get("initiator"); got != http.StatusNotFound {
		t.Fatalf("initiator poll on an unknown pairing = %d, want 404", got)
	}

	// Once the initiator has begun, the same requests are ordinary.
	if got := post("initiator"); got != http.StatusNoContent {
		t.Fatalf("initiator's first frame = %d, want 204", got)
	}
	if got := get("joiner"); got != http.StatusOK {
		t.Fatalf("joiner poll = %d, want 200", got)
	}
	if got := get("joiner"); got != http.StatusNoContent {
		t.Fatalf("an empty poll on a live pairing = %d, want 204", got)
	}
}
