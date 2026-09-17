package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func withInvite(t *testing.T) (*DB, string) {
	t.Helper()
	db := openTemp(t)
	token, err := db.NewInvite(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInvite: %v", err)
	}
	return db, token
}

const testAccount = "b4e6cf2a2b3e9370f642957d57952c89"

func TestAnInviteIsSpentExactlyOnce(t *testing.T) {
	db, token := withInvite(t)
	ctx := context.Background()
	pub := bytes.Repeat([]byte{1}, 32)

	if err := db.CreateAccount(ctx, testAccount, pub, token); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	// The same token must not mint a second account.
	other := strings.Repeat("a", 32)
	if err := db.CreateAccount(ctx, other, pub, token); !errors.Is(err, ErrInviteSpent) {
		t.Fatalf("second CreateAccount = %v, want ErrInviteSpent", err)
	}
}

// The invite row IS the authorization. An unknown token is not a registration.
func TestAnUnknownOrExpiredInviteIsRefused(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	pub := bytes.Repeat([]byte{1}, 32)

	if err := db.CreateAccount(ctx, testAccount, pub, "not-a-token"); !errors.Is(err, ErrInviteUnknown) {
		t.Fatalf("CreateAccount = %v, want ErrInviteUnknown", err)
	}

	expired, err := db.NewInvite(ctx, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccount(ctx, testAccount, pub, expired); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("CreateAccount = %v, want ErrInviteExpired", err)
	}
}

// A database that holds usable invite tokens is a database whose theft grants
// registrations.
func TestTheInviteTokenIsNotStored(t *testing.T) {
	db, token := withInvite(t)

	var stored []byte
	if err := db.Read().QueryRow(`SELECT token_hash FROM invites`).Scan(&stored); err != nil {
		t.Fatalf("reading the invite row: %v", err)
	}
	if bytes.Contains(stored, []byte(token)) {
		t.Fatal("the invite row contains the plaintext token")
	}
	if len(stored) != 32 {
		t.Errorf("stored value is %d bytes, want a 32-byte hash", len(stored))
	}
}

// The server's only structural check on the roster: sequence numbers are
// contiguous. It holds no key and cannot verify a signature, and does not try.
func TestTheRosterRefusesGapsAndRepeats(t *testing.T) {
	db, token := withInvite(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, testAccount, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}

	if err := db.AppendRoster(ctx, testAccount, 0, []byte("genesis")); err != nil {
		t.Fatalf("appending genesis: %v", err)
	}
	if err := db.AppendRoster(ctx, testAccount, 0, []byte("again")); !errors.Is(err, ErrSeqTaken) {
		t.Fatalf("re-appending seq 0 = %v, want ErrSeqTaken", err)
	}
	if err := db.AppendRoster(ctx, testAccount, 5, []byte("jump")); !errors.Is(err, ErrSeqGap) {
		t.Fatalf("appending seq 5 = %v, want ErrSeqGap", err)
	}
	if err := db.AppendRoster(ctx, testAccount, 1, []byte("second")); err != nil {
		t.Fatalf("appending seq 1: %v", err)
	}

	chain, err := db.Roster(ctx, testAccount, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(chain) != "genesissecond" {
		t.Errorf("chain = %q", chain)
	}
	// And a client can fetch from where it left off.
	tail, err := db.Roster(ctx, testAccount, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "second" {
		t.Errorf("tail = %q", tail)
	}
}

// Last-writer-wins without a conditional PUT is how two devices silently
// destroy each other's work.
func TestAConditionalPutRefusesAStaleETag(t *testing.T) {
	db, token := withInvite(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, testAccount, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}

	first, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: []byte("one")}, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// An unconditional PUT over an existing object is refused outright, and
	// with its OWN error: "you did not send If-Match" and "the one you sent is
	// stale" need different answers, because the first is a client bug and the
	// second is a real conflict a user may have to resolve.
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 2, Body: []byte("two")}, ""); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("unconditional overwrite = %v, want ErrObjectExists", err)
	}

	// The current ETag is accepted.
	second, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 2, Body: []byte("two")}, first)
	if err != nil {
		t.Fatalf("conditional update: %v", err)
	}
	if second == first {
		t.Error("the ETag did not change on a write")
	}

	// And the now-stale one is not.
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 3, Body: []byte("three")}, first); !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("stale PUT = %v, want ErrETagMismatch", err)
	}

	final, err := db.GetObject(ctx, testAccount, "servers", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(final.Body) != "two" || final.Counter != 2 {
		t.Errorf("final = %+v; the stale write must not have landed", final)
	}
}

// An object is keyed by epoch, so a rotation's re-sealed copy does not
// overwrite the one that is still being read.
func TestObjectsAreKeyedByEpoch(t *testing.T) {
	db, token := withInvite(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, testAccount, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}

	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: []byte("old")}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 2, Counter: 1, Body: []byte("new")}, ""); err != nil {
		t.Fatal(err)
	}

	old, err := db.GetObject(ctx, testAccount, "servers", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(old.Body) != "old" {
		t.Error("the epoch 1 object was overwritten by the epoch 2 one")
	}
}

// Deleting an account must take its data with it. "Remove user" deletes their
// prefix and revokes their tokens; it cannot decrypt anything first, so it is a
// deletion rather than an export.
func TestDeletingAnAccountCascades(t *testing.T) {
	db, token := withInvite(t)
	ctx := context.Background()
	if err := db.CreateAccount(ctx, testAccount, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendRoster(ctx, testAccount, 0, []byte("genesis")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: []byte("x")}, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Write().Exec(`DELETE FROM accounts WHERE account_id = ?`, testAccount); err != nil {
		t.Fatal(err)
	}

	var entries, objects int
	if err := db.Read().QueryRow(`SELECT count(*) FROM roster_entries`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if err := db.Read().QueryRow(`SELECT count(*) FROM objects`).Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if entries != 0 || objects != 0 {
		t.Errorf("after deleting the account: %d roster entries and %d objects remain", entries, objects)
	}
}
