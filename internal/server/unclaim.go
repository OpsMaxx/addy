package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opsmaxx/addy/internal/operator"
	"github.com/opsmaxx/addy/internal/store"
)

// Unclaim forgets who claimed the operator console, so the next person to sign
// in claims it.
//
// A subcommand rather than a line of SQL in the docs, because the image is
// FROM scratch: there is no sqlite3 in it and no shell to run one, so the fix
// for claiming the relay with the wrong account was one nobody on a container
// deployment could follow. Run it with the relay stopped -- a session the
// wrong account already holds lives in the running process until it ends.
func Unclaim(ctx context.Context, dataDir string, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	db, err := store.Open(filepath.Join(dataDir, "addy.db"))
	if err != nil {
		return fmt.Errorf("opening the database at %s: %w", dataDir, err)
	}
	defer db.Close()

	held, _, err := db.InstanceValue(ctx, operator.OperatorKey)
	if err != nil {
		return err
	}
	if held == "" {
		fmt.Fprintln(out, "Nobody has claimed this relay's console; the next sign-in will.")
		return nil
	}
	if err := db.SetInstanceValue(ctx, operator.OperatorKey, ""); err != nil {
		return err
	}
	fmt.Fprintln(out, "The console is unclaimed. Start the relay and sign in as the right account -- now, because the first sign-in claims it.")
	return nil
}
