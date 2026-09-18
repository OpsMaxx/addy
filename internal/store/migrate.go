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

	// 3. Accounts, rosters and objects.
	//
	// EVERYTHING HERE IS T1 METADATA. The roster chain is public by
	// construction -- signed, and holding only device public keys and sealed
	// labels. Objects are opaque bytes the server cannot read. The server holds
	// no key that opens anything in this schema, which is why it can be an
	// ordinary SQLite file.
	//
	// account_id is client-asserted: it arrives as a public key the server has
	// never seen and cannot vouch for, which is the point. An admin issues an
	// invite granting a quota slot; the token is spent by an account the user
	// minted themselves, so a stolen invite costs disk space rather than data.
	`CREATE TABLE accounts (
		account_id    TEXT PRIMARY KEY,
		root_sign_pub BLOB NOT NULL,
		created_at    INTEGER NOT NULL,
		quota_bytes   INTEGER NOT NULL DEFAULT 0,
		CHECK (length(account_id) = 32),
		CHECK (length(root_sign_pub) = 32)
	)`,

	// The roster is stored as entries rather than one blob, so a client can
	// fetch from a sequence number it already has. seq is unique per account,
	// which is the server's only structural check -- it cannot verify a
	// signature it has no key for, and does not try.
	`CREATE TABLE roster_entries (
		account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
		seq        INTEGER NOT NULL,
		wire       BLOB NOT NULL,
		stored_at  INTEGER NOT NULL,
		PRIMARY KEY (account_id, seq)
	)`,

	// Objects: collections, escrow and handoffs, all opaque.
	//
	// The counter is stored beside the object because a reader needs it to
	// check the escrow commitment, and it is T1 metadata the server holds
	// anyway. A server that LIES about it is caught by the commitment, which is
	// the check doing its job rather than a gap.
	`CREATE TABLE objects (
		account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
		name       TEXT NOT NULL,
		epoch      INTEGER NOT NULL,
		counter    INTEGER NOT NULL,
		body       BLOB NOT NULL,
		etag       TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (account_id, name, epoch)
	)`,

	// 4. Conflict copies.
	//
	// Concurrency is last-writer-wins per collection, WITH THE LOSER KEPT. A
	// bare LWW quietly destroys one device's work and tells nobody; keeping the
	// loser as a separately named object turns that into a choice a person
	// makes. Garage has no object versioning, so the copy has to be a real
	// object -- which is also why it needs its own garbage collection, since
	// nothing reclaims it otherwise.
	`CREATE TABLE conflicts (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
		name       TEXT NOT NULL,
		epoch      INTEGER NOT NULL,
		counter    INTEGER NOT NULL,
		body       BLOB NOT NULL,
		-- The device that wrote the LOSING copy, so the chooser can say which
		-- machine it came from rather than offering two anonymous blobs.
		device     BLOB NOT NULL,
		created_at INTEGER NOT NULL
	)`,

	// Invites. THE INVITE ROW IS THE AUTHORIZATION: an invitation record is
	// itself permission to register, bypassing "signups disabled" entirely.
	// That means an instance with no mail server, or an air-gapped one, can
	// still onboard a second user -- the admin creates the invite and hands the
	// token over by any means they like.
	`CREATE TABLE invites (
		token_hash BLOB PRIMARY KEY,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		spent_by   TEXT,
		spent_at   INTEGER,
		CHECK (length(token_hash) = 32)
	)`,

	// 5. One-time pastes.
	//
	// THE SERVER HOLDS NO KEY TO ANY OF THIS. `sealed` is the body AND its
	// metadata -- filename, content type, whatever the sender wrote -- as one
	// ciphertext, because encrypting the body and leaving the metadata in the
	// clear is how a paste service tells you someone sent `id_rsa` without
	// being able to tell you what was in it.
	//
	// The three limits are deliberately THREE COLUMNS and not one, because
	// they are orthogonal questions that a single "is it still good" field
	// conflates:
	//
	//   expires_at  when it stops being readable
	//   max_views   how many times it may be read
	//   deleted_at  when the row itself goes
	//
	// Conflating them loses the case that matters most for a human: a paste
	// that has expired or been burned still EXISTS for a while, so the reader
	// gets "this was used already" instead of "no such paste", and the sender
	// can tell "they read it" from "I sent the wrong link". A row deleted the
	// instant it burned cannot tell those apart, and both people then guess.
	`CREATE TABLE pastes (
		id         TEXT PRIMARY KEY,
		sealed     BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		max_views  INTEGER NOT NULL,
		views      INTEGER NOT NULL DEFAULT 0,
		deleted_at INTEGER NOT NULL,
		owner      TEXT NOT NULL,
		CHECK (length(id) >= 16),
		CHECK (max_views >= 0),
		CHECK (views >= 0),
		CHECK (deleted_at >= expires_at)
	)`,

	`CREATE INDEX pastes_sweep ON pastes (deleted_at)`,
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
