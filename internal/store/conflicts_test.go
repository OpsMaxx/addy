package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func conflictFixture(t *testing.T) (*DB, context.Context) {
	t.Helper()
	db := openTemp(t)
	ctx := context.Background()
	token, err := db.NewInvite(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccount(ctx, testAccount, bytes.Repeat([]byte{1}, 32), token); err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

// THE POINT: a bare last-writer-wins silently destroys one device's work and
// tells nobody. For `servers` that means a machine added on the laptop is gone
// from the desktop with no error and no symptom.
func TestALosingWriteIsKeptRatherThanDiscarded(t *testing.T) {
	db, ctx := conflictFixture(t)
	laptop := bytes.Repeat([]byte{0xaa}, 32)

	etag, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: []byte("from the desktop")}, "")
	if err != nil {
		t.Fatal(err)
	}

	// The laptop's conditional PUT loses.
	losing := []byte("from the laptop")
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 2, Body: []byte("desktop again")}, etag); err != nil {
		t.Fatal(err)
	}
	if err := db.KeepConflict(ctx, testAccount, Conflict{
		Name: "servers", Epoch: 1, Counter: 2, Body: losing, Device: laptop,
	}); err != nil {
		t.Fatalf("KeepConflict: %v", err)
	}

	got, err := db.Conflicts(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d conflicts kept, want 1", len(got))
	}
	if !bytes.Equal(got[0].Body, losing) {
		t.Error("the losing bytes were not kept")
	}
	// The chooser has to say which machine it came from, rather than offering
	// two anonymous blobs.
	if !bytes.Equal(got[0].Device, laptop) {
		t.Error("the conflict does not name the device that wrote it")
	}
}

func TestAResolvedConflictIsGone(t *testing.T) {
	db, ctx := conflictFixture(t)
	if err := db.KeepConflict(ctx, testAccount, Conflict{
		Name: "vault", Epoch: 1, Counter: 2,
		Body: []byte("x"), Device: bytes.Repeat([]byte{1}, 32),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.Conflicts(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ResolveConflict(ctx, testAccount, got[0].ID); err != nil {
		t.Fatalf("ResolveConflict: %v", err)
	}
	after, err := db.Conflicts(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Errorf("%d conflicts remain after resolving", len(after))
	}
	// Resolving one that is not there must not silently succeed.
	if err := db.ResolveConflict(ctx, testAccount, got[0].ID); err == nil {
		t.Error("resolving a conflict twice succeeded")
	}
}

// Conflict copies are charged against the quota. An account that cannot write
// must not be made to store more by losing races.
func TestConflictCopiesAreChargedAgainstTheQuota(t *testing.T) {
	db, ctx := conflictFixture(t)
	if err := db.SetQuota(ctx, testAccount, 1000); err != nil {
		t.Fatal(err)
	}
	err := db.KeepConflict(ctx, testAccount, Conflict{
		Name: "servers", Epoch: 1, Counter: 2,
		Body: bytes.Repeat([]byte{0}, 4000), Device: bytes.Repeat([]byte{1}, 32),
	})
	if err == nil {
		t.Fatal("a conflict copy over quota was stored")
	}
}

// A backstop, not a policy. Nothing else reclaims these, and an unbounded table
// is an availability problem -- but a conflict that ages out unresolved is work
// somebody lost, so the sweep reports what it dropped rather than burying it.
func TestTheSweepReportsWhatItDropped(t *testing.T) {
	db, ctx := conflictFixture(t)
	for i := 0; i < 3; i++ {
		if err := db.KeepConflict(ctx, testAccount, Conflict{
			Name: "servers", Epoch: 1, Counter: uint64(i + 2),
			Body: []byte("x"), Device: bytes.Repeat([]byte{1}, 32),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing is old enough yet.
	n, err := db.SweepConflicts(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("the sweep dropped %d fresh conflicts", n)
	}

	// With a zero age, everything is.
	n, err = db.SweepConflicts(ctx, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("the sweep dropped %d, want 3", n)
	}
	after, err := db.Conflicts(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Errorf("%d conflicts survived the sweep", len(after))
	}
}

// Oldest first, because a user resolving a backlog wants to start where the
// divergence did.
func TestConflictsComeBackOldestFirst(t *testing.T) {
	db, ctx := conflictFixture(t)
	for _, name := range []string{"first", "second", "third"} {
		if err := db.KeepConflict(ctx, testAccount, Conflict{
			Name: name, Epoch: 1, Counter: 2,
			Body: []byte(name), Device: bytes.Repeat([]byte{1}, 32),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.Conflicts(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d conflicts", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Name != want {
			t.Errorf("position %d is %q, want %q", i, got[i].Name, want)
		}
	}
}
