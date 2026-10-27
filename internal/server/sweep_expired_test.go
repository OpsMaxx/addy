package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// Mail past its 48 hours and pastes past their deletion date used to stay in
// the database for ever: both sweeps existed and nothing called them.
func TestExpiredMailAndPastesAreSwept(t *testing.T) {
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
	to := bytes.Repeat([]byte{2}, 32)
	if _, err := db.Leave(ctx, account, store.Message{
		ToDevice: to, FromDevice: bytes.Repeat([]byte{3}, 32), Kind: "clipboard", Sealed: []byte("x"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mailbox SET expires_at = 1`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	paste, err := db.CreatePaste(ctx, account, []byte("y"), -2*time.Hour, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}

	go sweepExpired(ctx, db, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)

	deadline := time.Now().Add(5 * time.Second)
	for {
		var mail int
		if err := db.Tx(ctx, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox`).Scan(&mail)
		}); err != nil {
			t.Fatal(err)
		}
		_, perr := db.PasteStatus(ctx, paste.ID)
		if mail == 0 && errors.Is(perr, store.ErrPasteNotFound) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not swept: %d mail rows left, paste lookup error %v", mail, perr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
