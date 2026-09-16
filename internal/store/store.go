// Package store is addy's metadata database: the roster chain, device records,
// object index, quota accounting, invites and sessions.
//
// It holds T1 METADATA only. No plaintext secret and no decryptable content
// ever reaches this package -- collection contents live in the object store as
// ciphertext addy cannot open, and the keys live on the user's devices. That is
// not a convention to remember; it is the reason this package can be backed by
// an ordinary SQLite file with no encryption at rest.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// The pure-Go driver, deliberately: it is what keeps CGO_ENABLED=0 true for the
// whole binary, which is what makes the six-target cross-compile a loop in a
// shell script rather than six toolchains. It benchmarks at roughly 0.75x the
// cgo driver, which is irrelevant for a relay's metadata volume.
const driver = "sqlite"

// DB is a pair of handles over one SQLite file.
//
// WHY TWO HANDLES. SQLite in WAL mode allows many concurrent readers and
// exactly one writer. The failure this produces under load is SQLITE_BUSY, and
// the wrong fix -- the one that looks right and is reached for first -- is to
// tune the connection pool. Pool size is not the problem: two goroutines
// writing at once is, and no pool setting prevents that.
//
// So writes are serialised by construction, with a write pool capped at one
// connection, and reads get an ordinary pool. A busy_timeout is set on both as
// the second line of defence, for the case a checkpoint or an external process
// holds the file briefly.
type DB struct {
	read  *sql.DB
	write *sql.DB
	path  string
}

// Open opens (creating if absent) the metadata database at path.
func Open(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", path, err)
	}

	// _pragma parameters are applied to every connection in the pool as it is
	// created. Setting them with a one-off Exec after Open would configure
	// whichever connection happened to serve that call and leave every later
	// one on the defaults -- a bug that hides until the pool grows past one.
	//
	// journal_mode=WAL is what allows concurrent readers at all.
	// busy_timeout is milliseconds; 5s is long enough to ride out a checkpoint
	// and short enough that a genuine deadlock still surfaces as an error
	// rather than as a hang nobody can attribute.
	// foreign_keys is OFF by default in SQLite, which silently turns every
	// declared reference into documentation.
	// synchronous=NORMAL is the documented safe pairing with WAL: durable
	// against process crash, and against power loss it can lose the last
	// transaction, which for a relay's metadata is a recomputable loss.
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + abs + "?" + q.Encode()

	write, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %q for writing: %w", abs, err)
	}
	write.SetMaxOpenConns(1)

	read, err := sql.Open(driver, dsn)
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("opening %q for reading: %w", abs, err)
	}

	db := &DB{read: read, write: write, path: abs}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := write.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening %q: %w", abs, err)
	}
	if err := db.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.restrict(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// restrict narrows the database files to 0600.
//
// SQLite creates them with 0644 minus the process umask, and the data
// directory being 0700 is not a reason to leave them that way: the directory's
// mode is one `chmod` by a future operator away from changing, and what is
// inside is the roster chain and every device's public key -- exactly the
// metadata the threat model commits to minimising. Defence that depends on a
// second control staying right is not defence.
//
// The -wal and -shm sidecars are included because SQLite copies the main
// database's permissions to them when it creates them, which means it copies
// whatever they were BEFORE this ran.
func (d *DB) restrict() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := d.path + suffix
		if _, err := os.Stat(path); err != nil {
			// -wal and -shm exist only while a connection is open, and on some
			// platforms not even then. Absent is not a failure.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("checking %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("securing %s: %w", path, err)
		}
	}
	return nil
}

// Close releases both handles. The first error is returned but both are always
// attempted, so a failure on one does not leak the other.
func (d *DB) Close() error {
	var first error
	if d.read != nil {
		if err := d.read.Close(); err != nil {
			first = err
		}
	}
	if d.write != nil {
		if err := d.write.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Path is the absolute path of the database file.
func (d *DB) Path() string { return d.path }

// Read returns the reader pool. Never use it for writes: an INSERT issued here
// would run concurrently with the serialised writer, which is the exact race
// the two-handle split exists to prevent.
func (d *DB) Read() *sql.DB { return d.read }

// Write returns the single-connection writer pool.
func (d *DB) Write() *sql.DB { return d.write }

// Tx runs fn inside a write transaction, rolling back on error or panic.
//
// The rollback-on-panic matters more than it looks: without it a panic in a
// handler leaves the single write connection inside an open transaction, and
// because there is exactly one, every subsequent write in the process blocks
// forever. One missing defer turns a recoverable bug into a wedged server.
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				err = errors.Join(err, rbErr)
			}
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
