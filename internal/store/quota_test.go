package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func quotaFixture(t *testing.T) (*DB, context.Context) {
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

// Zero means UNLIMITED and unset means unlimited too. They are the same column
// default, which is why the distinction that matters is named at every use.
func TestZeroQuotaMeansUnlimited(t *testing.T) {
	db, ctx := quotaFixture(t)

	remaining, err := db.Remaining(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != -1 {
		t.Errorf("Remaining() = %d, want -1 for unlimited", remaining)
	}

	// A large write must succeed.
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 1<<20)}, ""); err != nil {
		t.Fatalf("a large write under an unlimited quota: %v", err)
	}
}

// The user is told BEFORE an upload rather than part-way through one. A sync
// that quietly stops on a full disk is worse than having no sync, because the
// user reads it as "synced".
func TestAWriteOverQuotaIsRefusedBeforeItLands(t *testing.T) {
	db, ctx := quotaFixture(t)
	if err := db.SetQuota(ctx, testAccount, 4096); err != nil {
		t.Fatal(err)
	}

	_, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 8192)}, "")
	if !errors.Is(err, ErrOverQuota) {
		t.Fatalf("PutObject = %v, want ErrOverQuota", err)
	}

	// And nothing landed.
	if _, err := db.GetObject(ctx, testAccount, "servers", 1); err == nil {
		t.Error("the refused object was stored anyway")
	}
}

// THE DELTA, NOT THE TOTAL. Replacing a 10 KiB object with a 10 KiB object must
// cost nothing, or a user near their limit could never write again -- which is
// a quota that has turned into a wall.
func TestReplacingAnObjectOfTheSameSizeCostsNothing(t *testing.T) {
	db, ctx := quotaFixture(t)

	body := bytes.Repeat([]byte{0}, 2000)
	etag, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: body}, "")
	if err != nil {
		t.Fatal(err)
	}

	// A quota that leaves almost no headroom.
	used, err := db.UsageBytes(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetQuota(ctx, testAccount, used+10); err != nil {
		t.Fatal(err)
	}

	// Replacing it with the same size must still work.
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 2, Body: bytes.Repeat([]byte{1}, 2000)}, etag); err != nil {
		t.Fatalf("replacing an object of the same size was refused: %v", err)
	}

	// Growing it by more than the headroom must not.
	got, err := db.GetObject(ctx, testAccount, "servers", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 3, Body: bytes.Repeat([]byte{1}, 4000)}, got.ETag); !errors.Is(err, ErrOverQuota) {
		t.Fatalf("growing past the quota = %v, want ErrOverQuota", err)
	}
}

// Summed live rather than counted, so there is no total to drift. The check is
// that usage tracks reality after a sequence of writes, which a counter would
// only do if every path remembered to update it.
func TestUsageIsSummedFromWhatIsActuallyStored(t *testing.T) {
	db, ctx := quotaFixture(t)

	if err := db.AppendRoster(ctx, testAccount, 0, bytes.Repeat([]byte{7}, 300)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 1000)}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "vault", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 500)}, ""); err != nil {
		t.Fatal(err)
	}

	used, err := db.UsageBytes(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if used != 1800 {
		t.Errorf("usage = %d, want 1800 (1000 + 500 objects + 300 roster)", used)
	}

	// The roster is small but not free, and an accounting that ignores a table
	// drifts the moment that table grows.
	if err := db.AppendRoster(ctx, testAccount, 1, bytes.Repeat([]byte{7}, 200)); err != nil {
		t.Fatal(err)
	}
	used2, err := db.UsageBytes(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if used2 != 2000 {
		t.Errorf("usage = %d after a roster entry, want 2000", used2)
	}
}

// An account can be over quota after an admin LOWERS the limit. Clamping to
// zero would hide how far over it is from the person who has to fix it.
func TestAnOverQuotaAccountReportsHowFarOver(t *testing.T) {
	db, ctx := quotaFixture(t)
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 5000)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.SetQuota(ctx, testAccount, 1000); err != nil {
		t.Fatal(err)
	}

	remaining, err := db.Remaining(ctx, testAccount)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != -4000 {
		t.Errorf("Remaining() = %d, want -4000", remaining)
	}
}
