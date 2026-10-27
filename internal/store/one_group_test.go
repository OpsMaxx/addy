package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// ONE EMAIL IS ONE SYNC GROUP.
//
// A second group is not more room. It is a second set of devices that cannot
// see the first — separate key, separate roster, nothing syncing between them
// — and this relay cannot merge them afterwards because it holds no key to
// either. Somebody who ends up with two has lost the use of one with no way
// back, which is why this is refused rather than warned about.
//
// The rule is enforced twice and the second time is the one that counts: an
// invite minted while somebody had nothing is still a valid token after they
// have a group, so only the check at registration actually holds.
func TestOneEmailIsOneSyncGroup(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()

	u, err := d.UpsertUser(ctx, "https://issuer.example", "subject-1", "person@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	// Their first group: minted for them, spent, attributed.
	first, err := d.NewInviteFor(ctx, u.UserID, time.Hour)
	if err != nil {
		t.Fatalf("minting the first invite: %v", err)
	}
	// A SECOND INVITE MINTED BEFORE THEY HAVE ANYTHING is the case that makes
	// the registration check load-bearing: it is valid when issued and must
	// still be refused when spent.
	second, err := d.NewInviteFor(ctx, u.UserID, time.Hour)
	if err != nil {
		t.Fatalf("minting the second invite: %v", err)
	}

	if err := d.CreateAccount(ctx, newAccountID(t), make([]byte, 32), first); err != nil {
		t.Fatalf("creating the first group: %v", err)
	}

	owned, err := d.AccountsOf(ctx, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 {
		t.Fatalf("after one registration they own %d groups, want 1", len(owned))
	}

	// The pre-minted token, spent afterwards.
	err = d.CreateAccount(ctx, newAccountID(t), make([]byte, 32), second)
	if !errors.Is(err, ErrHasAccount) {
		t.Fatalf("spending a second invite gave %v, want ErrHasAccount.\n"+
			"They now hold two sets of devices that cannot see each other, and this relay "+
			"cannot merge them because it holds no key to either.", err)
	}

	// And minting is refused too, so somebody is told before they carry a
	// token to a device rather than after.
	if _, err := d.NewInviteFor(ctx, u.UserID, time.Hour); !errors.Is(err, ErrHasAccount) {
		t.Errorf("minting a further invite gave %v, want ErrHasAccount", err)
	}

	if owned, err = d.AccountsOf(ctx, u.UserID); err != nil || len(owned) != 1 {
		t.Fatalf("they ended with %d groups (err %v), want exactly 1", len(owned), err)
	}

	// SOMEBODY ELSE IS UNAFFECTED — the rule is per person, and a check that
	// refused everybody's second registration would pass the assertions above
	// while breaking the relay.
	other, err := d.UpsertUser(ctx, "https://issuer.example", "subject-2", "other@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := d.NewInviteFor(ctx, other.UserID, time.Hour)
	if err != nil {
		t.Fatalf("minting for a second person: %v", err)
	}
	if err := d.CreateAccount(ctx, newAccountID(t), make([]byte, 32), theirs); err != nil {
		t.Fatalf("a different person could not create their first group: %v", err)
	}

	// An invite minted for NOBODY is outside the rule, deliberately: there is
	// no email to hold to one group. Pinned so the limit is on record rather
	// than assumed covered.
	anon, err := d.NewInviteFor(ctx, "", time.Hour)
	if err != nil {
		t.Fatalf("minting an unattributed invite: %v", err)
	}
	if err := d.CreateAccount(ctx, newAccountID(t), make([]byte, 32), anon); err != nil {
		t.Fatalf("an unattributed invite should still work: %v", err)
	}
}

func newAccountID(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// Admission is recorded per person, starts as "not yet" for everybody, and is
// what the console lists.
func TestAdmissionIsRecordedAndListed(t *testing.T) {
	d := openTemp(t)
	ctx := context.Background()
	u, err := d.UpsertUser(ctx, "https://issuer.example", "subject-1", "person@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.UserAdmitted(ctx, u.UserID); err != nil || ok {
		t.Fatalf("a new person is admitted=%v (%v), want false", ok, err)
	}
	if err := d.SetUserAdmitted(ctx, u.UserID, true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.UserAdmitted(ctx, u.UserID); !ok {
		t.Fatal("admitting did not stick")
	}
	list, err := d.Users(ctx)
	if err != nil || len(list) != 1 || !list[0].Admitted {
		t.Fatalf("the console's list does not show the admission: %+v %v", list, err)
	}
	if err := d.SetUserAdmitted(ctx, "nobody", true); !errors.Is(err, ErrNoUser) {
		t.Errorf("admitting nobody answered %v, want ErrNoUser", err)
	}

	// WITHDRAWING IT TAKES BACK THE INVITE THEY ALREADY HOLD.
	token, err := d.NewInviteFor(ctx, u.UserID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetUserAdmitted(ctx, u.UserID, false); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateAccount(ctx, newAccountID(t), make([]byte, 32), token); !errors.Is(err, ErrInviteUnknown) {
		t.Errorf("an invite minted before admission was withdrawn still registered: %v", err)
	}
}
