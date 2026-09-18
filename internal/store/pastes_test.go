package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

func pasteDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "addy.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAPasteReadsOnceAndThenIsGone(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "acct", []byte("sealed bytes"), time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatalf("CreatePaste: %v", err)
	}

	got, err := db.Burn(ctx, p.ID)
	if err != nil {
		t.Fatalf("first burn: %v", err)
	}
	if string(got.Sealed) != "sealed bytes" {
		t.Fatalf("burn returned %q", got.Sealed)
	}

	if _, err := db.Burn(ctx, p.ID); !errors.Is(err, store.ErrPasteGone) {
		t.Fatalf("second burn: %v, want ErrPasteGone", err)
	}
}

// THE PROPERTY THE FEATURE IS NAMED AFTER: sixteen goroutines, one paste, one
// winner.
//
// What this does NOT do, stated because the opposite is the natural assumption
// and it was mine: it does not catch a read-modify-write implementation of
// Burn. It was tried -- Burn was rewritten as read, check, write back, and
// this test still passed -- because `write.SetMaxOpenConns(1)` serialises
// every write transaction in this package, so both implementations are
// correct today.
//
// It is still worth running. It pins the OBSERVABLE property rather than the
// mechanism, which is the thing that must stay true however the mechanism
// changes, and it is what would go red if the conditional UPDATE and the
// single writer were both lost at once. The invariant it cannot see is pinned
// separately, below.
func TestOnlyOneOfManySimultaneousReadersBurnsAPaste(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "acct", []byte("the secret"), time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}

	const readers = 16
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(readers)

	var mu sync.Mutex
	var wins int
	for i := 0; i < readers; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			if _, err := db.Burn(ctx, p.ID); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	if wins != 1 {
		t.Fatalf("%d of %d readers burned a one-time paste", wins, readers)
	}
}

func TestReadingStatusDoesNotConsumeAView(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "acct", []byte("sealed"), time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}

	// A chat client, a mail scanner and a link previewer, in that order.
	for i := 0; i < 3; i++ {
		if _, err := db.PasteStatus(ctx, p.ID); err != nil {
			t.Fatalf("status %d: %v", i, err)
		}
	}
	// And the human, who still gets it.
	if _, err := db.Burn(ctx, p.ID); err != nil {
		t.Fatalf("the paste burned before the recipient opened it: %v", err)
	}
}

func TestAnExpiredPasteIsGoneRatherThanMissing(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	// Already expired, but well inside its linger window.
	p, err := db.CreatePaste(ctx, "acct", []byte("sealed"), -time.Minute, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}

	// The distinction is the reason deleted_at is a separate column: the
	// sender can tell "they read it" from "I sent the wrong link". Without it
	// both people guess.
	if _, err := db.PasteStatus(ctx, p.ID); !errors.Is(err, store.ErrPasteGone) {
		t.Fatalf("status of an expired paste: %v, want ErrPasteGone", err)
	}
	if _, err := db.Burn(ctx, p.ID); !errors.Is(err, store.ErrPasteGone) {
		t.Fatalf("burning an expired paste: %v, want ErrPasteGone", err)
	}
}

func TestPastTheDeletionDateAddyMakesNoClaim(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "acct", []byte("sealed"), -2*time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PasteStatus(ctx, p.ID); !errors.Is(err, store.ErrPasteNotFound) {
		t.Fatalf("past its deletion date: %v, want ErrPasteNotFound", err)
	}

	n, err := db.SweepPastes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the sweep removed %d rows", n)
	}
	// A ciphertext nobody can read is still a ciphertext somebody is keeping.
	if _, err := db.PasteStatus(ctx, p.ID); !errors.Is(err, store.ErrPasteNotFound) {
		t.Fatalf("after the sweep: %v", err)
	}
}

func TestTheSweepLeavesLivePastesAlone(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	live, err := db.CreatePaste(ctx, "acct", []byte("still good"), time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Expired but lingering: readable no, present yes.
	lingering, err := db.CreatePaste(ctx, "acct", []byte("used"), -time.Minute, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	dead, err := db.CreatePaste(ctx, "acct", []byte("old"), -2*time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}

	if n, err := db.SweepPastes(ctx); err != nil || n != 1 {
		t.Fatalf("sweep removed %d rows (err %v); only the one past its deletion date should go", n, err)
	}
	if _, err := db.PasteStatus(ctx, live.ID); err != nil {
		t.Fatalf("the sweep took a live paste: %v", err)
	}
	if _, err := db.PasteStatus(ctx, lingering.ID); !errors.Is(err, store.ErrPasteGone) {
		t.Fatalf("the sweep took a lingering paste, so its sender can no longer tell it was read: %v", err)
	}
	_ = dead
}

func TestAMultiViewPasteCountsDown(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "acct", []byte("sealed"), time.Hour, time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		got, err := db.Burn(ctx, p.ID)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if got.Views != i {
			t.Fatalf("after read %d the count is %d", i, got.Views)
		}
	}
	if _, err := db.Burn(ctx, p.ID); !errors.Is(err, store.ErrPasteGone) {
		t.Fatalf("a fourth read of a three-view paste: %v", err)
	}
}

func TestAnUnlimitedPasteDoesNotBurn(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	// maxViews 0 is a link, not a one-time paste. Allowed, and the caller is
	// the one who decides.
	p, err := db.CreatePaste(ctx, "acct", []byte("sealed"), time.Hour, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.Burn(ctx, p.ID); err != nil {
			t.Fatalf("read %d of an unlimited paste: %v", i, err)
		}
	}
}

func TestOnlyTheOwnerDeletesAPaste(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	p, err := db.CreatePaste(ctx, "mine", []byte("sealed"), time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePaste(ctx, "theirs", p.ID); !errors.Is(err, store.ErrPasteNotFound) {
		t.Fatalf("another account deleted it: %v", err)
	}
	if _, err := db.PasteStatus(ctx, p.ID); err != nil {
		t.Fatalf("it went anyway: %v", err)
	}
	if err := db.DeletePaste(ctx, "mine", p.ID); err != nil {
		t.Fatalf("the owner could not delete it: %v", err)
	}
}

func TestAListingCarriesNoCiphertext(t *testing.T) {
	db := pasteDB(t)
	ctx := t.Context()

	if _, err := db.CreatePaste(ctx, "mine", []byte("the secret"), time.Hour, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreatePaste(ctx, "theirs", []byte("not mine"), time.Hour, time.Hour, 1); err != nil {
		t.Fatal(err)
	}

	rows, err := db.PastesFor(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the listing has %d rows; one account created one paste", len(rows))
	}
	// A listing that carried every blob would be a way to bulk-collect them
	// without burning any -- the one-time property defeated by the owner's own
	// index page.
	if rows[0].Sealed != nil {
		t.Fatalf("the listing carries the ciphertext: %q", rows[0].Sealed)
	}
}

func TestAPasteIsCappedInSize(t *testing.T) {
	db := pasteDB(t)
	big := make([]byte, store.MaxPasteBytes+1)
	if _, err := db.CreatePaste(t.Context(), "acct", big, time.Hour, time.Hour, 1); !errors.Is(err, store.ErrPasteTooLarge) {
		t.Fatalf("an oversized paste was accepted: %v", err)
	}
}

func TestPasteIDsAreUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := store.NewPasteID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("a paste id repeated after %d draws", i)
		}
		seen[id] = true
		// 16 raw bytes, base64url, unpadded. The id is what an attacker who is
		// scraping can try; the key never reaches the server at all.
		if len(id) != 22 {
			t.Fatalf("a paste id is %d characters: %q", len(id), id)
		}
	}
}

// The single writer, pinned where somebody widening the pool will see it.
//
// This is the invariant that actually makes simultaneous burns impossible
// today, and it is invisible: it lives in store.go for performance reasons
// that have nothing to do with pastes, and nothing in the paste code mentions
// it. Burn is written so that losing this is survivable -- the condition is in
// the UPDATE -- but "survivable" is a claim somebody should have to re-check
// rather than discover.
func TestTheWriterIsSerialised(t *testing.T) {
	db := pasteDB(t)
	// A second writer would be able to begin a transaction while the first is
	// open. With one connection the second Begin blocks until the first is
	// done, so a short deadline is the observable difference.
	first, err := db.Write().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("first transaction: %v", err)
	}
	defer first.Rollback()

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	second, err := db.Write().BeginTx(ctx, nil)
	if err == nil {
		second.Rollback()
		t.Fatal("two write transactions were open at once.\n" +
			"The write pool is no longer serialised. That is allowed, but Burn's " +
			"conditional UPDATE is now the ONLY thing keeping a one-time paste " +
			"one-time -- check every other read-modify-write in this package too.")
	}
}
