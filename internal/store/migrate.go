package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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

	// 6. Store-and-forward.
	//
	// WebRTC needs both ends awake. A clipboard that only works when the other
	// laptop is on is not a clipboard, and a file transfer that requires
	// choreography is a worse email attachment -- so a payload that cannot be
	// delivered live is left here for the peer to collect.
	//
	// Every row is SEALED TO ONE DEVICE. The server routes on `to_device`, a
	// public key it can compare but not use, and stores bytes it cannot read.
	// That is the same position it is in for objects; what is new is that a
	// message has a recipient, so the server learns who talks to whom inside
	// one account. That is stated in the threat model rather than pretended
	// away: within an account, the relay sees the social graph of the user's
	// own devices, which is a graph of one person.
	//
	// `expires_at` is not optional and not large. A mailbox is a place things
	// accumulate, and an undelivered clipboard entry from three weeks ago is
	// not useful to anybody -- it is a copy of something secret that outlived
	// every reason to keep it.
	`CREATE TABLE mailbox (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id TEXT NOT NULL,
		to_device  BLOB NOT NULL,
		from_device BLOB NOT NULL,
		kind       TEXT NOT NULL,
		sealed     BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE,
		CHECK (length(to_device) = 32),
		CHECK (length(from_device) = 32)
	)`,

	// Delivery reads by recipient and id; the sweep reads by expiry. Two
	// indexes because they are two different scans and the sweep would
	// otherwise be a full table walk on a timer.
	`CREATE INDEX mailbox_delivery ON mailbox (account_id, to_device, id)`,
	`CREATE INDEX mailbox_sweep ON mailbox (expires_at)`,

	// 6. People.
	//
	// A RELAY IS MULTI-USER BY DESIGN and until now it could not name anybody:
	// accounts existed, invites existed, and nothing connected either to a
	// person. So an operator looking at four accounts could not tell whose
	// they were, and a user could not sign in at all — every account had to be
	// handed out by the operator minting a token over SSH.
	//
	// Identity is (issuer, subject), never email. An email address is a
	// display name that providers let people change and reuse; a subject is
	// the identifier the provider promises is stable and unique, and it is
	// only unique WITHIN its issuer — so both halves, always, exactly as the
	// operator claim already does.
	//
	// `email` is stored anyway because it is what a human reads in a list, and
	// refreshed on every sign-in so a changed address does not leave the
	// console showing an old one for ever.
	`CREATE TABLE users (
		user_id    TEXT PRIMARY KEY,
		issuer     TEXT NOT NULL,
		subject    TEXT NOT NULL,
		email      TEXT NOT NULL DEFAULT '',
		name       TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL DEFAULT 0,
		quota_bytes INTEGER NOT NULL DEFAULT 0,
		blocked_at INTEGER,
		UNIQUE (issuer, subject)
	)`,

	// Which person an account belongs to.
	//
	// A SEPARATE TABLE rather than a column on `accounts`, because the
	// relationship is not one the account knows about: an account is created
	// by a device holding a root key, and the only thing tying it to a person
	// is the invite it was registered with. Keeping that link here means
	// `accounts` stays exactly what the protocol says it is, and a relay whose
	// users table was dropped would still serve every account correctly.
	`CREATE TABLE account_owners (
		account_id TEXT PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
		user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
		linked_at  INTEGER NOT NULL
	)`,
	`CREATE INDEX account_owners_by_user ON account_owners (user_id)`,

	// An invite now remembers who it was minted for, so the account that
	// spends it can be attributed without the spender claiming anything.
	//
	// NULL for an invite the operator minted without naming anybody, which is
	// still the right thing for handing one to somebody who has not signed in
	// — the account then belongs to nobody until it does.
	`ALTER TABLE invites ADD COLUMN minted_for TEXT REFERENCES users(user_id)`,

	// Whether the operator has let this person have storage.
	//
	// The `invite` sign-in policy promises that somebody with an account at the
	// identity provider does not get space here without the operator's say-so,
	// and nothing recorded a say-so: everybody signed in could mint their own
	// first invite, which made `invite` the same as `open`. NULL is "not yet",
	// which is every person who existed before this column did.
	`ALTER TABLE users ADD COLUMN admitted_at INTEGER`,
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

	if have > 0 && have < len(migrations) {
		if err := d.snapshot(ctx, have); err != nil {
			return err
		}
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

// snapshot copies the database aside before an upgrade changes its schema.
//
// Migrations only go forward, and an older binary refuses a newer schema (see
// above) -- so without a copy, rolling back an upgrade that went wrong means
// losing every account on the box. VACUUM INTO writes a consistent, compacted
// copy through SQLite itself, which a file copy of a WAL database next to a
// live -wal sidecar is not.
//
// Only when there is something to lose and something about to change: a
// fresh database has nothing in it, and an unchanged schema needs no undo.
// Named by the schema it holds and the time it was taken, so the copy says
// which binary can open it.
//
// The copy is the WHOLE database, objects included, which is most of it. So:
//
//   - Free space is checked first, and a volume too small for the copy is
//     refused with the numbers rather than filled. On the chart's 5Gi claim a
//     database past half of it cannot be copied at all.
//   - It is written under a .partial name and renamed only once complete. A
//     process killed mid-copy -- by a probe, by an operator -- leaves a
//     .partial, which the next start deletes rather than mistaking for a
//     backup.
//   - Only the newest keepSnapshots are kept. Each upgrade adds one the size
//     of the database, and an unbounded pile of them is the next full disk.
func (d *DB) snapshot(ctx context.Context, version int) error {
	stale, _ := filepath.Glob(d.path + ".schema-*.partial")
	for _, p := range stale {
		_ = os.Remove(p)
	}

	need := fileSize(d.path) + fileSize(d.path+"-wal")
	if free, ok := freeSpace(filepath.Dir(d.path)); ok && free < need+need/10 {
		return fmt.Errorf("the database is at schema version %d and this release changes it, "+
			"which needs a copy of it first: about %d MB, and %s has %d MB free.\n"+
			"Nothing was changed. Grow the volume, or free space on it, and start again -- "+
			"or run the previous release, which opens this database as it is",
			version, need>>20, filepath.Dir(d.path), free>>20)
	}

	dest := fmt.Sprintf("%s.schema-%d.%s.bak", d.path, version, time.Now().UTC().Format("20060102T150405Z"))
	partial := strings.TrimSuffix(dest, ".bak") + ".partial"
	if _, err := d.write.ExecContext(ctx, "VACUUM INTO ?", partial); err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("copying the database before upgrading its schema from version %d: %w\n"+
			"Nothing was changed. Free some space on the data volume, or move the database aside yourself, and start again",
			version, err)
	}
	// The same 0600 as the database it copies, for the same reasons -- see
	// restrict.
	if err := os.Chmod(partial, 0o600); err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("securing %s: %w", partial, err)
	}
	if err := os.Rename(partial, dest); err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("naming the copy %s: %w", dest, err)
	}
	pruneSnapshots(d.path)
	return nil
}

// keepSnapshots is how many pre-upgrade copies survive. Three is the last
// upgrade and the two before it: enough to step back through a bad release
// and the one that exposed it, without keeping one per release for ever.
const keepSnapshots = 3

// pruneSnapshots deletes all but the newest keepSnapshots copies. Best effort:
// a copy that will not delete is a full disk later, not a failed upgrade now.
func pruneSnapshots(db string) {
	copies, _ := filepath.Glob(db + ".schema-*.bak")
	sort.Slice(copies, func(i, j int) bool { return modTime(copies[i]).After(modTime(copies[j])) })
	for i := keepSnapshots; i < len(copies); i++ {
		_ = os.Remove(copies[i])
	}
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

func modTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}
