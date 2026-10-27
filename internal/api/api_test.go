package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/api"
	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
	"github.com/opsmaxx/addy/internal/store"
)

func instance(t *testing.T) (*httptest.Server, *store.DB) {
	srv, db, _ := instanceWithAPI(t)
	return srv, db
}

// instanceWithAPI also hands back the *api.Server, for the tests that need to
// configure it -- relaying, chiefly, where the interesting cases are the three
// operator configurations rather than anything a request can reach.
func instanceWithAPI(t *testing.T) (*httptest.Server, *store.DB, *api.Server) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "addy.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// A TLS server, not a plain one: every login signature binds the instance's
	// TLS key, so a client cannot log in to something that presents no
	// certificate. That is the point of the binding -- a login captured from
	// one instance must not replay against another.
	a := api.New(db, nil)
	// A short poll, so a test that legitimately reads an empty mailbox does not
	// wait out the production timeout. A test that takes twenty-five seconds is
	// a test somebody deletes.
	a.PollWait = 250 * time.Millisecond
	srv := httptest.NewTLSServer(a.Handler())
	t.Cleanup(srv.Close)
	// The test server's own key is the one key a login may bind.
	own := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	a.ServesKey = func(_ string, spki []byte) bool { return bytes.Equal(spki, own[:]) }
	return srv, db, a
}

func invite(t *testing.T, db *store.DB) string {
	t.Helper()
	token, err := db.NewInvite(t.Context(), time.Hour)
	if err != nil {
		t.Fatalf("NewInvite: %v", err)
	}
	return token
}

// M1'S GATE, FIRST HALF: a device mints an account from nothing and the server
// accepts it without validating anything about who it is.
func TestADeviceMintsAnAccountFromNothing(t *testing.T) {
	srv, db := instance(t)

	c := client.New(srv.URL, true)
	a, err := c.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := c.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The roster the server serves must be the one the client verifies against
	// keys it already held -- never against anything the server said.
	v, err := c.Roster(
		a.Root.Sign.Public().(ed25519.PublicKey),
		a.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("Roster: %v", err)
	}
	if len(v.Devices) != 1 {
		t.Fatalf("roster has %d devices, want 1", len(v.Devices))
	}
	if v.Epoch != 1 || v.HeadSeq != 0 {
		t.Errorf("epoch=%d head=%d", v.Epoch, v.HeadSeq)
	}
}

// THE INVITE IS THE ONLY THING AN ADMIN CONTROLS, and it is spent once.
func TestRegistrationNeedsAnUnspentInvite(t *testing.T) {
	srv, db := instance(t)
	token := invite(t, db)

	if _, err := client.New(srv.URL, true).Register("one", token); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if _, err := client.New(srv.URL, true).Register("two", token); err == nil {
		t.Fatal("the same invite registered two accounts")
	}
	if _, err := client.New(srv.URL, true).Register("three", "not-a-token"); err == nil {
		t.Fatal("an unknown invite registered an account")
	}
}

// A bearer token is replayable by anything that captures it. The per-request
// signature is what binds a request to its method, path and body.
func TestAnUnsignedRequestIsRefused(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("quiet-otter-41", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	// A request with no authorization signature at all.
	resp, err := srv.Client().Get(srv.URL + "/v1/roster")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("an unauthenticated request returned %d, want 401", resp.StatusCode)
	}
}

// A device of one account must not reach another's roster. Rooms and objects
// are keyed on the account, so there is no path from one to the other.
func TestOneAccountCannotReadAnothers(t *testing.T) {
	srv, db := instance(t)

	a := client.New(srv.URL, true)
	accA, err := a.Register("one", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}

	b := client.New(srv.URL, true)
	accB, err := b.Register("two", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Login(); err != nil {
		t.Fatal(err)
	}

	// B's session must serve B's roster, whatever A's keys say about it.
	v, err := b.Roster(
		accB.Root.Sign.Public().(ed25519.PublicKey),
		accB.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("B's roster: %v", err)
	}
	if v.Devices[0].PubSign == nil {
		t.Fatal("B's roster is empty")
	}
	// And A's keys must not verify B's chain.
	if _, err := b.Roster(
		accA.Root.Sign.Public().(ed25519.PublicKey),
		accA.Epoch.Sign.Public().(ed25519.PublicKey), nil); err == nil {
		t.Fatal("B's chain verified under A's keys")
	}
}

// The relay carries opaque frames between devices of ONE account and learns
// nothing from any of them.
func TestTheSignallingRelayCarriesFramesWithinAnAccount(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("quiet-otter-41", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	// Every mailbox is DIRECTED, so a device cannot receive its own frame. A
	// first draft of the relay had one queue per room and this test passed by
	// echoing -- which is the difference between a relay and a loopback, and
	// the end-to-end pairing test found it immediately.
	self := c.Device.Sign.Public().(ed25519.PublicKey)

	want := []byte("an opaque signalling frame")
	if err := c.SendFrame(self, want); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	got, err := c.NextFrame()
	if err != nil {
		t.Fatalf("NextFrame: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("frame = %q, want %q", got, want)
	}

	// A frame addressed to somebody else must not arrive here.
	other, err := protocol.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SendFrame(other.Sign.Public().(ed25519.PublicKey), []byte("not for you")); err != nil {
		t.Fatalf("SendFrame to a peer: %v", err)
	}
	stray, err := c.NextFrame()
	if err != nil {
		t.Fatalf("NextFrame: %v", err)
	}
	if stray != nil {
		t.Errorf("a frame addressed to another device arrived here: %q", stray)
	}
}

// The server's only structural check on the roster.
func TestTheServerRefusesARosterGap(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	a, err := c.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	gap := a.Genesis
	gap.Seq = 5
	if err := c.AppendRoster(gap); err == nil {
		t.Fatal("the server accepted a roster entry that leaves a gap")
	}
}

// M1 REVIEW, MEDIUM: a request authorization was replayable.
//
// The review measured it against a live instance: the same nonce accepted four
// times, and under a second session token. A signature that can be replayed
// authorises every future identical request, and "identical" includes the
// DELETE somebody captured once.
//
// The fix is a spent set rather than a timestamp window, because the protocol
// is explicit that ts is display-only and that nothing load-bearing may depend
// on a clock an attacker controls.
func TestARequestAuthorizationCannotBeReplayed(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("quiet-otter-41", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	// Capture one authorised request exactly as it went out.
	captured, err := c.CapturedRequestForTest("GET", "/v1/roster")
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}

	first, err := srv.Client().Do(cloneRequest(t, captured))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	if first.StatusCode != 200 {
		t.Fatalf("the first request returned %d, want 200", first.StatusCode)
	}

	replay, err := srv.Client().Do(cloneRequest(t, captured))
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Body.Close()
	if replay.StatusCode != 401 {
		t.Fatalf("the replayed request returned %d, want 401", replay.StatusCode)
	}
}

func cloneRequest(t *testing.T, r *http.Request) *http.Request {
	t.Helper()
	out := r.Clone(context.Background())
	out.Body = io.NopCloser(bytes.NewReader(nil))
	return out
}

func mustDevice(t *testing.T) *protocol.DeviceKeys {
	t.Helper()
	d, err := protocol.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// No handler writes a response header twice.
//
// Go logs "superfluous response.WriteHeader call" and carries on, so the
// symptom is a line in a log nobody reads and a status code that is not the
// one the handler meant. It appeared the moment `ok` started writing its own
// header -- `createAccount` was doing `WriteHeader(201)` and then calling
// `ok`, so the 201 stood and the 200 was dropped, silently, in the one
// direction where a client might reasonably branch on the code.
//
// A source check rather than a runtime one: the runtime version would have to
// exercise every handler, and the shape is what is wrong.
func TestNoHandlerWritesAHeaderTwice(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(src), "\n")
		for i := 0; i+1 < len(lines); i++ {
			if !strings.Contains(lines[i], "w.WriteHeader(") {
				continue
			}
			// The next non-blank, non-comment line.
			for j := i + 1; j < len(lines) && j < i+4; j++ {
				next := strings.TrimSpace(lines[j])
				if next == "" || strings.HasPrefix(next, "//") {
					continue
				}
				if strings.HasPrefix(next, "s.ok(") || strings.HasPrefix(next, "s.okStatus(") {
					t.Errorf("%s:%d writes a header and then calls %s; use okStatus instead",
						e.Name(), i+1, strings.SplitN(next, "(", 2)[0])
				}
				break
			}
		}
	}
}
