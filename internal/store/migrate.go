package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrations are applied in order and identified by their INDEX, tracked in
// SQLite's own user_version pragma.
//
// user_version rather than a migrations table, deliberately: SQLite already
// keeps a durable 32-bit integer in the database header for exactly this, so
// the alternative is a table that exists only to hold one number. Appending to
// this slice is the only supported change -- editing or reordering an entry
// that has already run somewhere changes history on databases that have
// already applied it, and there is no way for the runner to notice.
var migrations = []string{
	// 1. The on-demand TLS allowlist.
	//
	// This table is load-bearing for security, not bookkeeping. certmagic's
	// on-demand issuance asks a DecisionFunc whether it may obtain a
	// certificate for a hostname presented in a ClientHello. A DecisionFunc
	// that returns nil unconditionally turns the box into an open
	// certificate-issuance relay: any stranger points a DNS record at this IP,
	// every connection mints an ACME order, and the account trips Let's
	// Encrypt's rate limit and stops issuing for the domains that are real.
	// So the answer is read from here, and a hostname absent from this table
	// is refused.
	`CREATE TABLE domains (
		hostname   TEXT PRIMARY KEY,
		mode       TEXT NOT NULL,
		backend    TEXT NOT NULL DEFAULT '',
		http80     TEXT NOT NULL DEFAULT '',
		added_at   INTEGER NOT NULL,
		CHECK (mode IN ('terminate', 'proxy', 'passthrough')),
		CHECK (hostname = lower(hostname)),
		CHECK (mode = 'terminate' OR backend <> '')
	)`,

	// 2. Instance-wide flags and small scalars.
	//
	// A key/value table rather than a one-row settings table with a column per
	// setting: every entry here is written by an operator action and read at
	// startup, so migrations would otherwise be dominated by ALTER TABLE for
	// single booleans. The one that matters today is reonboard_required, which
	// `addy panic` and `addy reset --hard` both set and which makes clients
	// refuse to sync until a human has compared the roster head out of band.
	`CREATE TABLE instance (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
}

func (d *DB) migrate(ctx context.Context) error {
	var have int
	if err := d.write.QueryRowContext(ctx, "PRAGMA user_version").Scan(&have); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}
	if have > len(migrations) {
		// Refuse rather than carry on. This is an older binary opening a
		// database a newer one has already upgraded; the tables it is about to
		// read may have changed shape underneath it, and "mostly works" is the
		// worst available outcome for a metadata store.
		return fmt.Errorf(
			"database at %s is at schema version %d but this build only knows %d: upgrade addy",
			d.path, have, len(migrations))
	}

	for i := have; i < len(migrations); i++ {
		stmt := migrations[i]
		version := i + 1
		// Each migration runs in its own transaction with the version bump
		// inside it, so a crash mid-run leaves the database at a version that
		// is actually true rather than one ahead of its schema.
		err := d.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("applying migration %d: %w", version, err)
			}
			// PRAGMA does not accept a bound parameter, and `version` is an
			// int from a loop over a compile-time slice, so there is nothing
			// here an input could reach.
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
				return fmt.Errorf("recording migration %d: %w", version, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
