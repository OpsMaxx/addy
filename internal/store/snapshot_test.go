package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An upgrade that changes the schema leaves a copy of the old database behind.
//
// Migrations only go forward and an older binary refuses a newer schema, so
// without this a rollback costs every account on the box.
func TestASchemaUpgradeSnapshotsTheOldDatabaseFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addy.db")

	// A fresh database has nothing to lose, so it gets no copy.
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.NewInvite(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if got, _ := filepath.Glob(path + ".schema-*.bak"); len(got) != 0 {
		t.Fatalf("a fresh database was snapshotted: %v", got)
	}

	// The next release adds a migration.
	before := len(migrations)
	migrations = append(migrations, `CREATE TABLE snapshot_probe (x INTEGER)`)
	defer func() { migrations = migrations[:before] }()

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	got, _ := filepath.Glob(path + ".schema-*.bak")
	if len(got) != 1 {
		t.Fatalf("expected one snapshot, found %v", got)
	}
	if fi, _ := os.Stat(got[0]); fi.Mode().Perm() != 0o600 {
		t.Errorf("the snapshot is %v; it holds the same metadata as the database", fi.Mode().Perm())
	}

	// The copy is the OLD schema with the old data, which is what a rollback
	// to the previous binary needs to open.
	migrations = migrations[:before]
	old, err := Open(got[0])
	if err != nil {
		t.Fatalf("the previous binary could not open the snapshot: %v", err)
	}
	defer old.Close()
	var invites int
	if err := old.Read().QueryRow(`SELECT count(*) FROM invites`).Scan(&invites); err != nil {
		t.Fatal(err)
	}
	if invites != 1 {
		t.Fatalf("the snapshot holds %d invites, want the 1 from before the upgrade", invites)
	}
}

// A volume too small for the copy is refused with the numbers, before the
// schema is touched -- not filled to the last byte mid-upgrade.
func TestASnapshotThatCannotFitIsRefusedFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addy.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	before := len(migrations)
	migrations = append(migrations, `CREATE TABLE snapshot_probe (x INTEGER)`)
	defer func() { migrations = migrations[:before] }()
	real := freeSpace
	freeSpace = func(string) (int64, bool) { return 1, true }
	defer func() { freeSpace = real }()

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "MB free") {
		t.Fatalf("a full volume gave %v; it should refuse and say how much is needed", err)
	}
	freeSpace = real
	migrations = migrations[:before]
	db, err = Open(path)
	if err != nil {
		t.Fatalf("the refused upgrade changed the database: %v", err)
	}
	db.Close()
}

// A copy killed halfway is deleted, not kept as if it were a backup, and the
// copies stop at keepSnapshots.
func TestSnapshotsArePrunedAndPartialsCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addy.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	partial := path + ".schema-1.20260101T000000Z.partial"
	if err := os.WriteFile(partial, []byte("half a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Older copies than the one about to be made.
	for i := 0; i < keepSnapshots+2; i++ {
		old := fmt.Sprintf("%s.schema-1.2026010%dT000000Z.bak", path, i)
		if err := os.WriteFile(old, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Add(-time.Duration(i+1) * time.Hour)
		if err := os.Chtimes(old, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	before := len(migrations)
	migrations = append(migrations, `CREATE TABLE snapshot_probe (x INTEGER)`)
	defer func() { migrations = migrations[:before] }()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Error("a partial copy from a killed upgrade survived the next one")
	}
	copies, _ := filepath.Glob(path + ".schema-*.bak")
	if len(copies) != keepSnapshots {
		t.Fatalf("%d copies kept, want %d: %v", len(copies), keepSnapshots, copies)
	}
	fresh := false
	for _, c := range copies {
		if fi, _ := os.Stat(c); fi.Size() > 0 {
			fresh = true
		}
	}
	if !fresh {
		t.Error("pruning deleted the copy this upgrade just made")
	}
}
