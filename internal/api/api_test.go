package api_test

import (
	"crypto/ed25519"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/api"
	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/store"
)

func instance(t *testing.T) (*httptest.Server, *store.DB) {
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
	srv := httptest.NewTLSServer(api.New(db, nil).Handler())
	t.Cleanup(srv.Close)
	return srv, db
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

	want := []byte("an opaque pairing frame")
	if err := c.SendFrame(want); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	got, err := c.NextFrame()
	if err != nil {
		t.Fatalf("NextFrame: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("frame = %q, want %q", got, want)
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
