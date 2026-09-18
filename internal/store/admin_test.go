package store

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// THE BOUNDARY, ASSERTED RATHER THAN DOCUMENTED. An admin holds availability
// and identity power, never confidentiality -- and the way that is enforced is
// that nothing in the admin view can carry content, because the server holds no
// key for any of it.
//
// This test reads the summary type's own field list. A field added later that
// could carry a label, a payload or a collection's contents fails here, which is
// the only version of this rule that survives somebody being helpful.
func TestTheAdminViewCannotCarryContent(t *testing.T) {
	allowed := map[string]bool{
		"AccountID": true, // the server already knows which account is which
		"CreatedAt": true,
		"Devices":   true,
		"UsedBytes": true,
		"QuotaByte": true,
		"LastSeen":  true,
	}
	typ := reflect.TypeOf(AccountSummary{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("AccountSummary.%s is not in the admin boundary; an admin sees metadata, never content", name)
		}
	}
	if typ.NumField() != len(allowed) {
		t.Errorf("the summary has %d fields and the boundary lists %d", typ.NumField(), len(allowed))
	}
}

func TestTheAdminViewReportsWhatItShould(t *testing.T) {
	db, ctx := quotaFixture(t)

	if err := db.AppendRoster(ctx, testAccount, 0, bytes.Repeat([]byte{7}, 300)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: bytes.Repeat([]byte{0}, 700)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.SetQuota(ctx, testAccount, 5000); err != nil {
		t.Fatal(err)
	}

	got, err := db.Accounts(ctx)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d accounts, want 1", len(got))
	}
	a := got[0]
	if a.AccountID != testAccount {
		t.Errorf("account id = %q", a.AccountID)
	}
	if a.UsedBytes != 1000 {
		t.Errorf("used = %d, want 1000", a.UsedBytes)
	}
	if a.QuotaByte != 5000 {
		t.Errorf("quota = %d, want 5000", a.QuotaByte)
	}
	if a.CreatedAt.IsZero() {
		t.Error("created at is zero")
	}
}

// "Remove user" deletes their prefix and revokes their tokens. It cannot
// decrypt anything first, so it is a deletion rather than an export.
func TestDeletingAnAccountTakesItsDataWithIt(t *testing.T) {
	db, ctx := quotaFixture(t)
	if err := db.AppendRoster(ctx, testAccount, 0, []byte("genesis")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutObject(ctx, testAccount,
		Object{Name: "servers", Epoch: 1, Counter: 1, Body: []byte("x")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.KeepConflict(ctx, testAccount, Conflict{
		Name: "servers", Epoch: 1, Counter: 2,
		Body: []byte("y"), Device: bytes.Repeat([]byte{1}, 32),
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteAccount(ctx, testAccount); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	for _, table := range []string{"roster_entries", "objects", "conflicts"} {
		var n int
		if err := db.Read().QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d rows remain in %s after deleting the account", n, table)
		}
	}

	// Deleting one that is not there must say so rather than silently
	// succeeding.
	if err := db.DeleteAccount(ctx, testAccount); !errors.Is(err, ErrNoAccount) {
		t.Errorf("DeleteAccount on a missing account = %v, want ErrNoAccount", err)
	}
}

// The boundary document must exist and must say the thing it exists to say.
// Published BEFORE the UI, because a boundary discovered from a UI is one
// nobody agreed to.
func TestTheAdminBoundaryIsPublished(t *testing.T) {
	b, err := readRepoFile("docs/ADMIN.md")
	if err != nil {
		t.Fatalf("docs/ADMIN.md: %v", err)
	}
	doc := string(b)
	for _, must := range []string{
		"never CONFIDENTIALITY",
		"deletion, not an export",
		"No telemetry",
	} {
		if !strings.Contains(doc, must) {
			t.Errorf("docs/ADMIN.md does not state %q", must)
		}
	}
}
