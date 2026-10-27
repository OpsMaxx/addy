package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// THE SWEEP HAD NO CALLER, so the backstop store.SweepConflicts describes did
// not exist and an unresolved copy stayed on the relay, charged to quota, for
// ever. This runs the loop Run starts and watches an expired copy go.
func TestTheConflictSweepRunsAndDropsExpiredCopies(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "addy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const account = "b4e6cf2a2b3e9370f642957d57952c89"
	token, err := db.NewInvite(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccount(ctx, account, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}
	if err := db.KeepConflict(ctx, account, store.Conflict{
		Name: "servers", Epoch: 1, Counter: 2, Body: []byte("x"), Device: bytes.Repeat([]byte{1}, 32),
	}); err != nil {
		t.Fatal(err)
	}

	// A negative age makes every copy expired, so the first pass must take it.
	done := make(chan struct{})
	go func() {
		sweepConflicts(ctx, db, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, -time.Second)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		left, err := db.Conflicts(context.Background(), account)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the sweep never dropped the expired conflict copy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep did not stop when its context ended")
	}
}
