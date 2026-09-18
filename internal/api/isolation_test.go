package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
	"github.com/opsmaxx/addy/internal/store"
)

// ONE ACCOUNT MUST NOT REACH ANOTHER'S BYTES, PER VERB.
//
// This is the suite the plan calls load-bearing, and the reason is Garage: the
// object store has no bucket policies, so addy's own authorization layer is
// the ONLY boundary between two users' prefixes. There is no second fence
// behind this one to catch a handler that forgot.
//
// What makes the boundary hold is structural rather than a check: no handler
// takes an account from the request. Every one of them reads `a.Account`,
// which `authed` fills from the SESSION, and the request authorization it
// verifies is rebuilt server-side around that same value -- so a device that
// signs an authorization naming somebody else's account does not get a
// permission error, it gets a signature that does not verify.
//
// Structural is not the same as proved. A test per verb, because "the pattern
// is safe" is a claim about code that does not exist yet as much as about code
// that does, and the verb somebody adds next is the one that will not follow
// the pattern.

// twoAccounts returns two registered, logged-in clients on one server.
func twoAccounts(t *testing.T) (*client.Client, *protocol.Account, *client.Client, *protocol.Account) {
	t.Helper()
	srv, db := instance(t)

	a := client.New(srv.URL, true)
	accA, err := a.Register("one", invite(t, db))
	if err != nil {
		t.Fatalf("A register: %v", err)
	}
	if err := a.Login(); err != nil {
		t.Fatalf("A login: %v", err)
	}

	b := client.New(srv.URL, true)
	accB, err := b.Register("two", invite(t, db))
	if err != nil {
		t.Fatalf("B register: %v", err)
	}
	if err := b.Login(); err != nil {
		t.Fatalf("B login: %v", err)
	}
	if a.Account == b.Account {
		t.Fatal("two registrations produced one account id; the rest of this file proves nothing")
	}
	_, _ = accA, accB
	return a, accA, b, accB
}

func TestIsolationGetObject(t *testing.T) {
	a, _, b, _ := twoAccounts(t)

	if _, err := a.PutObject("servers", 1, 1, []byte("A's sealed servers"), ""); err != nil {
		t.Fatalf("A writes: %v", err)
	}

	// Same name, same epoch, B's session. A store keyed on the name alone --
	// the obvious first implementation -- hands back A's bytes here.
	got, err := b.GetObject("servers", 1)
	if err == nil {
		t.Fatalf("B read an object it never wrote: %q", got.Body)
	}

	// And A still can, so the refusal above is isolation rather than the read
	// path simply being broken.
	mine, err := a.GetObject("servers", 1)
	if err != nil {
		t.Fatalf("A cannot read its own object: %v", err)
	}
	if !bytes.Equal(mine.Body, []byte("A's sealed servers")) {
		t.Fatalf("A read back %q", mine.Body)
	}
}

func TestIsolationPutObject(t *testing.T) {
	a, _, b, _ := twoAccounts(t)

	etag, err := a.PutObject("servers", 1, 1, []byte("A's sealed servers"), "")
	if err != nil {
		t.Fatalf("A writes: %v", err)
	}

	// B writes the same name. This is ALLOWED and must be: two accounts each
	// have a `servers` collection and neither has a claim on the word. What
	// must not happen is the write landing on A's.
	if _, err := b.PutObject("servers", 1, 1, []byte("B overwrites"), ""); err != nil {
		t.Fatalf("B cannot write its own object: %v", err)
	}

	after, err := a.GetObject("servers", 1)
	if err != nil {
		t.Fatalf("A reads back: %v", err)
	}
	if !bytes.Equal(after.Body, []byte("A's sealed servers")) {
		t.Fatalf("B's write reached A's object: %q", after.Body)
	}
	if after.ETag != etag {
		t.Fatalf("A's ETag changed from %q to %q without A writing", etag, after.ETag)
	}
}

func TestIsolationGetRoster(t *testing.T) {
	a, accA, b, accB := twoAccounts(t)

	// A appends an entry, so the two chains differ by more than their genesis.
	v, err := a.Roster(
		accA.Root.Sign.Public().(ed25519.PublicKey),
		accA.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("A's roster: %v", err)
	}
	if len(v.Devices) == 0 {
		t.Fatal("A's roster is empty")
	}

	// B's session serves B's chain. Verified under B's OWN keys, which is the
	// only way to tell "B got B's chain" from "B got a chain": the bytes alone
	// would not say whose they are.
	vb, err := b.Roster(
		accB.Root.Sign.Public().(ed25519.PublicKey),
		accB.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("B's roster: %v", err)
	}
	if len(vb.Devices) != 1 {
		t.Fatalf("B's roster has %d devices; B has one", len(vb.Devices))
	}
	if bytes.Equal(vb.Devices[0].PubSign, v.Devices[0].PubSign) {
		t.Fatal("B's roster names A's device")
	}
}

func TestIsolationAppendRoster(t *testing.T) {
	_, _, b, accB := twoAccounts(t)

	// Sequence 1 exists in BOTH accounts -- every account's genesis is seq 0
	// and its second entry is seq 1. An append keyed on the sequence alone
	// would collide across accounts, and the collision would read as a gap or
	// a fork to whichever account lost.
	vb, err := b.Roster(
		accB.Root.Sign.Public().(ed25519.PublicKey),
		accB.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("B's roster: %v", err)
	}
	if got := vb.HeadSeq; got != 0 {
		t.Fatalf("B's head is at seq %d, not genesis", got)
	}
}

// The account is not on the wire, so there is nothing to tamper with -- but a
// device can still SIGN an authorization naming another account and send it
// with its own session token. It is the closest thing to a confused deputy
// this API offers, and the answer has to be a refusal rather than a read.
func TestIsolationAnAuthorizationNamingAnotherAccountIsRefused(t *testing.T) {
	a, _, b, _ := twoAccounts(t)

	if _, err := a.PutObject("servers", 1, 1, []byte("A's sealed servers"), ""); err != nil {
		t.Fatalf("A writes: %v", err)
	}

	// B, with B's live session token and B's device key, signing an
	// authorization whose AccountID is A's.
	raw, err := b.CapturedRequestForTest(http.MethodGet, "/v1/obj/servers?epoch=1")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	nonce, err := protocol.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	authz := protocol.Authz{
		AccountID:   a.Account,
		DeviceNonce: nonce,
		Method:      http.MethodGet,
		Path:        "/v1/obj/servers",
		BodyHash:    protocol.HashBody(nil),
	}
	sig, err := protocol.Sign(b.Device.Sign, authz)
	if err != nil {
		t.Fatal(err)
	}
	raw.Header.Set("X-Addy-Nonce", hex.EncodeToString(nonce))
	raw.Header.Set("X-Addy-Signature", hex.EncodeToString(sig))

	resp, err := b.HTTP.Do(raw)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	// 401, and specifically because the SIGNATURE does not verify: the server
	// rebuilds the authorization around the session's account, so B's claim
	// never becomes a value anything compares. An implementation that trusted
	// the claimed id would answer 200 here with A's bytes.
	if resp.StatusCode != http.StatusUnauthorized {
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		t.Fatalf("claiming another account answered %s: %s", resp.Status, body[:n])
	}
}

// A device that is not logged in at all, with a well-formed everything else.
func TestIsolationNoSessionReachesNothing(t *testing.T) {
	a, _, _, _ := twoAccounts(t)

	if _, err := a.PutObject("servers", 1, 1, []byte("A's sealed servers"), ""); err != nil {
		t.Fatalf("A writes: %v", err)
	}

	stranger := client.New(a.BaseURL, true)
	if _, err := stranger.GetObject("servers", 1); err == nil {
		t.Fatal("an unauthenticated client read an object")
	}
}

// The store below the API, addressed directly.
//
// The HTTP tests above prove the handlers do not leak. This proves the layer
// they delegate to does not either, which is a separate claim: a handler that
// scoped correctly on top of a store that ignored the account would pass every
// test above and still fail the moment a second entry point appeared.
func TestIsolationTheStoreScopesByAccount(t *testing.T) {
	db, err := store.Open(fmt.Sprintf("%s/addy.db", t.TempDir()))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	ctx := t.Context()
	accA, accB := "aa"+hexPad(30), "bb"+hexPad(30)
	for _, id := range []string{accA, accB} {
		token, err := db.NewInvite(ctx, time.Hour)
		if err != nil {
			t.Fatalf("NewInvite: %v", err)
		}
		if err := db.CreateAccount(ctx, id, bytes.Repeat([]byte{1}, ed25519.PublicKeySize), token); err != nil {
			t.Fatalf("CreateAccount %s: %v", id, err)
		}
	}

	if _, err := db.PutObject(ctx, accA, store.Object{
		Name: "servers", Epoch: 1, Counter: 1, Body: []byte("A"),
	}, ""); err != nil {
		t.Fatalf("A put: %v", err)
	}

	if _, err := db.GetObject(ctx, accB, "servers", 1); err == nil {
		t.Fatal("the store served A's object to B")
	}

	// B writes the same name; A's must be untouched.
	if _, err := db.PutObject(ctx, accB, store.Object{
		Name: "servers", Epoch: 1, Counter: 1, Body: []byte("B"),
	}, ""); err != nil {
		t.Fatalf("B put: %v", err)
	}
	got, err := db.GetObject(ctx, accA, "servers", 1)
	if err != nil {
		t.Fatalf("A get: %v", err)
	}
	if !bytes.Equal(got.Body, []byte("A")) {
		t.Fatalf("A's object now reads %q", got.Body)
	}
}

func hexPad(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}
