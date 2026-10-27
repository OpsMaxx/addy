package store

import (
	"context"
	"os"
	"path/filepath"
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
