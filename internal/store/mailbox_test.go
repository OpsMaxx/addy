package store_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

func mailDB(t *testing.T) (*store.DB, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "addy.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	acct := strings.Repeat("a", 32)
	token, err := db.NewInvite(t.Context(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccount(t.Context(), acct, bytes.Repeat([]byte{1}, ed25519.PublicKeySize), token); err != nil {
		t.Fatal(err)
	}
	return db, acct
}

func dev(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func msg(to, from byte, body string) store.Message {
	return store.Message{ToDevice: dev(to), FromDevice: dev(from), Kind: "clipboard", Sealed: []byte(body)}
}

func TestAMessageWaitsForASleepingDevice(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	if _, err := db.Leave(ctx, acct, msg(2, 1, "sealed clipboard")); err != nil {
		t.Fatalf("Leave: %v", err)
	}

	got, err := db.Collect(ctx, acct, dev(2), 10)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("collected %d messages", len(got))
	}
	if string(got[0].Sealed) != "sealed clipboard" {
		t.Fatalf("body is %q", got[0].Sealed)
	}
	if !bytes.Equal(got[0].FromDevice, dev(1)) {
		t.Fatal("the sender is wrong")
	}
}

// COLLECT DOES NOT DELETE, and that is the design rather than an oversight.
//
// A collect that deleted would lose everything to one dropped connection: the
// rows are gone, the bytes are in a socket buffer that never arrived, and
// neither end can tell that from a successful delivery. Acknowledging by id,
// after the plaintext is on disk, is the only moment anybody knows it landed.
func TestCollectingDoesNotDeliver(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	id, err := db.Leave(ctx, acct, msg(2, 1, "sealed"))
	if err != nil {
		t.Fatal(err)
	}

	// The connection drops here, twice.
	for i := 0; i < 2; i++ {
		got, err := db.Collect(ctx, acct, dev(2), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("attempt %d collected %d; a dropped delivery lost the message", i, len(got))
		}
	}

	// Now it actually arrived.
	n, err := db.Ack(ctx, acct, dev(2), []int64{id})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ack deleted %d rows", n)
	}
	if got, _ := db.Collect(ctx, acct, dev(2), 10); len(got) != 0 {
		t.Fatalf("%d messages survived the ack", len(got))
	}
}

// Ids are a global autoincrement and therefore entirely guessable, so the
// acknowledgement has to be scoped by who is acknowledging.
func TestAnAckCannotDeleteAnotherDevicesMail(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	id, err := db.Leave(ctx, acct, msg(2, 1, "for device two"))
	if err != nil {
		t.Fatal(err)
	}

	// Device three, guessing.
	if n, err := db.Ack(ctx, acct, dev(3), []int64{id}); err != nil || n != 0 {
		t.Fatalf("another device deleted %d messages (err %v)", n, err)
	}
	if got, _ := db.Collect(ctx, acct, dev(2), 10); len(got) != 1 {
		t.Fatal("the message is gone")
	}
}

func TestMailIsScopedToTheRecipient(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	if _, err := db.Leave(ctx, acct, msg(2, 1, "for two")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Leave(ctx, acct, msg(3, 1, "for three")); err != nil {
		t.Fatal(err)
	}

	two, _ := db.Collect(ctx, acct, dev(2), 10)
	three, _ := db.Collect(ctx, acct, dev(3), 10)
	if len(two) != 1 || string(two[0].Sealed) != "for two" {
		t.Fatalf("device two got %v", two)
	}
	if len(three) != 1 || string(three[0].Sealed) != "for three" {
		t.Fatalf("device three got %v", three)
	}
}

func TestMessagesArriveOldestFirst(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	for _, body := range []string{"first", "second", "third"} {
		if _, err := db.Leave(ctx, acct, msg(2, 1, body)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := db.Collect(ctx, acct, dev(2), 10)
	if len(got) != 3 {
		t.Fatalf("collected %d", len(got))
	}
	// A clipboard whose history arrives shuffled is a clipboard that pastes
	// the wrong thing.
	for i, want := range []string{"first", "second", "third"} {
		if string(got[i].Sealed) != want {
			t.Fatalf("position %d is %q, want %q", i, got[i].Sealed, want)
		}
	}
}

// Oldest-wins when the queue is full: refuse the new message rather than evict
// an old one. Silently dropping what somebody just sent is the worse surprise
// of the two, and it is the one they would never find out about.
func TestAFullMailboxRefusesRatherThanEvicts(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	for i := 0; i < store.MaxPendingPerDevice; i++ {
		if _, err := db.Leave(ctx, acct, msg(2, 1, "queued")); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := db.Leave(ctx, acct, msg(2, 1, "one too many")); !errors.Is(err, store.ErrMailboxFull) {
		t.Fatalf("the cap did not hold: %v", err)
	}
	got, _ := db.Collect(ctx, acct, dev(2), store.MaxPendingPerDevice)
	if len(got) != store.MaxPendingPerDevice {
		t.Fatalf("the queue holds %d after a refused write", len(got))
	}
	if string(got[0].Sealed) != "queued" {
		t.Fatal("the oldest message was evicted")
	}
}

func TestAMessageIsCappedInSize(t *testing.T) {
	db, acct := mailDB(t)
	m := msg(2, 1, "")
	m.Sealed = make([]byte, store.MaxMailboxBytes+1)
	if _, err := db.Leave(t.Context(), acct, m); !errors.Is(err, store.ErrMessageTooLarge) {
		t.Fatalf("an oversized message was accepted: %v", err)
	}
}

// An undelivered clipboard entry from three weeks ago is not useful to
// anybody. It is a copy of something secret that outlived every reason to
// keep it.
func TestUndeliveredMailExpires(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	if _, err := db.Leave(ctx, acct, msg(2, 1, "sealed")); err != nil {
		t.Fatal(err)
	}
	// Reach past the API to age it, rather than waiting 48 hours.
	if _, err := db.Write().ExecContext(ctx,
		`UPDATE mailbox SET expires_at = ?`, time.Now().Add(-time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}

	if got, _ := db.Collect(ctx, acct, dev(2), 10); len(got) != 0 {
		t.Fatalf("an expired message was still delivered: %d", len(got))
	}
	if n, _ := db.PendingFor(ctx, acct, dev(2)); n != 0 {
		t.Fatalf("an expired message is still counted: %d", n)
	}
	n, err := db.SweepMailbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the sweep removed %d rows", n)
	}
}

func TestDeletingAnAccountTakesItsMail(t *testing.T) {
	db, acct := mailDB(t)
	ctx := t.Context()

	if _, err := db.Leave(ctx, acct, msg(2, 1, "sealed")); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteAccount(ctx, acct); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	// Through the foreign key, not through a second delete somebody has to
	// remember to write. `addy reset --hard` deletes accounts one by one, and
	// mail left behind would be sealed payloads outliving the account they
	// belonged to on a box whose owner just wiped it.
	var rows int
	if err := db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM mailbox`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("%d messages outlived their account", rows)
	}
}
