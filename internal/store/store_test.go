package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "addy.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAppliesPragmasToEveryConnection(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	// Force the read pool to open several connections at once, then check the
	// pragmas on each. A one-off Exec after Open would have configured only
	// whichever connection served it; this is the assertion that catches that.
	const parallel = 4
	conns := make([]*sql.Conn, parallel)
	for i := range conns {
		c, err := db.Read().Conn(ctx)
		if err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
		conns[i] = c
		t.Cleanup(func() { c.Close() })
	}

	for i, c := range conns {
		var journal string
		if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatalf("conn %d journal_mode: %v", i, err)
		}
		if journal != "wal" {
			t.Errorf("conn %d journal_mode = %q, want wal", i, journal)
		}
		var fk int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatalf("conn %d foreign_keys: %v", i, err)
		}
		if fk != 1 {
			t.Errorf("conn %d foreign_keys = %d, want 1", i, fk)
		}
		var busy int
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
			t.Fatalf("conn %d busy_timeout: %v", i, err)
		}
		if busy != 5000 {
			t.Errorf("conn %d busy_timeout = %d, want 5000", i, busy)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addy.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	var first int
	if err := db.Read().QueryRow("PRAGMA user_version").Scan(&first); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if first != len(migrations) {
		t.Fatalf("user_version = %d after Open, want %d", first, len(migrations))
	}
	db.Close()

	// Reopening must not try to re-run migration 1 -- CREATE TABLE would fail
	// with "table already exists", which is how a naive runner announces
	// itself on the second start rather than the first.
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var second int
	if err := db2.Read().QueryRow("PRAGMA user_version").Scan(&second); err != nil {
		t.Fatalf("user_version after reopen: %v", err)
	}
	if second != first {
		t.Errorf("user_version changed on reopen: %d then %d", first, second)
	}
}

func TestOpenRefusesADatabaseFromANewerBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addy.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Pretend a newer addy has been here and added migrations this build does
	// not have.
	if _, err := db.Write().Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatalf("bumping user_version: %v", err)
	}
	db.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a database from a newer build; it must refuse")
	}
}

func TestTxRollsBackOnError(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	sentinel := errors.New("no")

	err := db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO domains (hostname, route, backend, added_at) VALUES (?, 'local', '', ?)`,
			"a.example", time.Now().Unix()); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx returned %v, want the callback's error", err)
	}

	var n int
	if err := db.Read().QueryRow(`SELECT count(*) FROM domains`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows survived a rolled-back transaction, want 0", n)
	}
}

// The one that matters. With a single write connection, a panic that escapes
// an open transaction leaves that connection permanently inside it, and every
// later write in the process blocks forever -- a wedged server from one missing
// defer. This asserts the writer still works afterwards.
func TestTxRollsBackOnPanicAndTheWriterSurvives(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not propagate; Tx must not swallow it")
			}
		}()
		_ = db.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO domains (hostname, route, backend, added_at) VALUES (?, 'local', '', ?)`,
				"b.example", time.Now().Unix()); err != nil {
				t.Errorf("insert: %v", err)
			}
			panic("boom")
		})
	}()

	// If the transaction were still open this would block until the context
	// deadline rather than returning.
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := db.Tx(deadline, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(deadline,
			`INSERT INTO domains (hostname, route, backend, added_at) VALUES (?, 'local', '', ?)`,
			"c.example", time.Now().Unix())
		return err
	})
	if err != nil {
		t.Fatalf("the writer was wedged by the panicking transaction: %v", err)
	}

	var host string
	if err := db.Read().QueryRow(`SELECT hostname FROM domains`).Scan(&host); err != nil {
		t.Fatalf("select: %v", err)
	}
	if host != "c.example" {
		t.Errorf("hostname = %q; the panicking transaction was not rolled back", host)
	}
}

// The domains table is the on-demand TLS allowlist, so its constraints are a
// security control rather than tidiness: a proxy or passthrough row with an
// empty backend would route a real hostname to nothing, and a mixed-case
// hostname would silently fail to match a lowercased SNI lookup.
func TestDomainsRejectsRowsTheRouterCouldNotUse(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	now := time.Now().Unix()

	cases := []struct {
		name                     string
		hostname, route, backend string
	}{
		{"an unknown route", "a.example", "elsewhere", "127.0.0.1:9000"},
		{"a proxy row with no backend", "b.example", "proxy", ""},
		{"a passthrough row with no backend", "c.example", "passthrough", ""},
		{"a hostname that is not lowercased", "D.example", "local", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := db.Tx(ctx, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx,
					`INSERT INTO domains (hostname, route, backend, added_at) VALUES (?, ?, ?, ?)`,
					c.hostname, c.route, c.backend, now)
				return err
			})
			if err == nil {
				t.Errorf("the database accepted %s", c.name)
			}
		})
	}

	// And the shape that must still work.
	if err := db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO domains (hostname, route, backend, added_at) VALUES (?, 'proxy', ?, ?)`,
			"vault.example", "127.0.0.1:8222", now)
		return err
	}); err != nil {
		t.Fatalf("a valid proxy row was rejected: %v", err)
	}
}
