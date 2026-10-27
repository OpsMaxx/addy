package server

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/opsmaxx/addy/internal/operator"
	"github.com/opsmaxx/addy/internal/store"
)

// Claiming the console with the wrong account is fixable without sqlite3,
// which a FROM scratch image does not have.
func TestUnclaimLetsTheNextSignInClaim(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetInstanceValue(ctx, operator.OperatorKey, "https://issuer.example\x00wrong"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := Unclaim(ctx, dir, io.Discard); err != nil {
		t.Fatal(err)
	}

	db, err = store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	held, _, err := db.InstanceValue(ctx, operator.OperatorKey)
	if err != nil {
		t.Fatal(err)
	}
	if held != "" {
		t.Fatalf("the console is still claimed by %q", held)
	}
}
