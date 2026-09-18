package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// Invites, from the console.
//
// THE INVITE ROW IS THE AUTHORIZATION. Registration needs one and the server
// checks nothing else about who is registering -- it cannot, since an account
// is a key the server has never seen. So an operator who cannot mint an invite
// has a relay nobody can join, which is the state this repository was in until
// somebody tried to onboard a device.
//
// Console-only, deliberately. There is no route that creates an invite,
// because a route that did would be a route an attacker with any foothold uses
// to grant themselves a quota slot.

// InviteOptions is what `addy invite` was told.
type InviteOptions struct {
	DataDir string
	TTL     time.Duration
	// List shows what is outstanding instead of minting.
	List bool
	Out  io.Writer
}

func Invite(ctx context.Context, opts InviteOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	dir := opts.DataDir
	if dir == "" {
		dir = DefaultDataDir
	}

	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		return fmt.Errorf("opening the database at %s: %w", dir, err)
	}
	defer db.Close()

	if opts.List {
		return listInvites(ctx, db, out)
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	token, err := db.NewInvite(ctx, ttl)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, `%s

That token is the whole authorization: anyone holding it can register an
account on this relay, once. It expires in %s.

Hand it over the way you would a password -- and prefer a channel the person
already trusts, because a relay cannot tell a stolen invite from a real one.
`, token, ttl)
	return nil
}

func listInvites(ctx context.Context, db *store.DB, out io.Writer) error {
	rows, err := db.Read().QueryContext(ctx, `
		SELECT created_at, expires_at, spent_by, spent_at FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Deliberately NOT the tokens. They are stored as hashes, so they cannot
	// be printed -- and that is the point: an invite list that could reprint
	// tokens would be a list worth stealing.
	fmt.Fprintln(out, "created              expires              state")
	count := 0
	for rows.Next() {
		var created, expires int64
		var spentBy *string
		var spentAt *int64
		if err := rows.Scan(&created, &expires, &spentBy, &spentAt); err != nil {
			return err
		}
		state := "unspent"
		switch {
		case spentAt != nil && spentBy != nil:
			state = "spent by " + (*spentBy)[:12]
		case time.Now().Unix() > expires:
			state = "expired"
		}
		fmt.Fprintf(out, "%-20s %-20s %s\n",
			time.Unix(created, 0).UTC().Format(time.RFC3339),
			time.Unix(expires, 0).UTC().Format(time.RFC3339),
			state)
		count++
	}
	if count == 0 {
		fmt.Fprintln(out, "(none -- `addy invite` mints one)")
	}
	return rows.Err()
}
