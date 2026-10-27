package server_test

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/frontdoor"
	"github.com/opsmaxx/addy/internal/server"
	"github.com/opsmaxx/addy/internal/store"
)

// A box with one account, one unspent invite and a certificate store.
func panicFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ctx := t.Context()

	token, err := db.NewInvite(ctx, time.Hour)
	if err != nil {
		t.Fatalf("NewInvite: %v", err)
	}
	if err := db.CreateAccount(ctx, strings.Repeat("a", 32),
		bytes.Repeat([]byte{1}, ed25519.PublicKeySize), token); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	// A second, still unspent.
	if _, err := db.NewInvite(ctx, time.Hour); err != nil {
		t.Fatalf("NewInvite: %v", err)
	}
	db.Close()

	certs := filepath.Join(dir, frontdoor.CertDir, "acme")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "account.key"), []byte("the ACME account key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openDB(t *testing.T, dir string) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPanicRevokesUnspentInvitesAndBlocksTheInstance(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	if err := server.Panic(t.Context(), server.PanicOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatalf("Panic: %v", err)
	}

	db := openDB(t, dir)
	blocked, at, err := db.Reonboard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("the instance is still serving after a panic")
	}
	if at.IsZero() {
		t.Fatal("reonboard was set with no timestamp")
	}

	// The unspent invite is the one thing on this box an attacker could still
	// SPEND after losing access to it, so it is the one that has to go.
	var unspent int
	if err := db.Read().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM invites WHERE spent_at IS NULL`).Scan(&unspent); err != nil {
		t.Fatal(err)
	}
	if unspent != 0 {
		t.Fatalf("%d unspent invite(s) survived the panic", unspent)
	}

	epoch, err := db.SecretEpoch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 1 {
		t.Fatalf("secret epoch is %d after one panic", epoch)
	}
}

func TestPanicDeletesTheAcmeAccountKey(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	if err := server.Panic(t.Context(), server.PanicOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatalf("Panic: %v", err)
	}

	// Whoever holds this key can ask Let's Encrypt to issue for any domain
	// this instance has already validated, from anywhere. A box that is
	// otherwise clean and still has it is not clean.
	if _, err := os.Stat(filepath.Join(dir, frontdoor.CertDir)); !os.IsNotExist(err) {
		t.Fatalf("the certificate store survived the panic: %v", err)
	}
}

func TestPanicCanKeepCertificates(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	if err := server.Panic(t.Context(), server.PanicOptions{
		DataDir: dir, KeepCerts: true, Out: &out,
	}); err != nil {
		t.Fatalf("Panic: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, frontdoor.CertDir, "acme", "account.key")); err != nil {
		t.Fatalf("-keep-certs deleted them anyway: %v", err)
	}
	// And the rest still happened: the flag is what stops the box serving, and
	// an operator who chose to keep a certificate has not chosen to keep
	// serving.
	db := openDB(t, dir)
	if blocked, _, _ := db.Reonboard(t.Context()); !blocked {
		t.Fatal("-keep-certs also skipped the reonboard flag")
	}
}

func TestPanicSaysWhatItCannotDo(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer
	if err := server.Panic(t.Context(), server.PanicOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	// The single most dangerous thing this command could do is leave an
	// operator believing it un-read what was already read. Every object here
	// was sealed by a client and the server never held a key, so a copied
	// database is exactly as readable afterwards as before -- and the remedy
	// is a hard re-key on a device, which this cannot perform.
	for _, want := range []string{"cannot un-read", "hard re-key"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the panic report does not mention %q:\n%s", want, text)
		}
	}
}

func TestReonboardClearsOnlyFromTheConsole(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer
	if err := server.Panic(t.Context(), server.PanicOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if err := server.Reonboard(t.Context(), server.ReonboardOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Reonboard required since") {
		t.Fatalf("status did not report the block:\n%s", out.String())
	}

	out.Reset()
	if err := server.Reonboard(t.Context(), server.ReonboardOptions{
		DataDir: dir, Clear: true, Out: &out,
	}); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, dir)
	if blocked, _, _ := db.Reonboard(t.Context()); blocked {
		t.Fatal("--clear did not clear it")
	}
}

func TestResetWithoutHardDeletesNothing(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	if err := server.Reset(t.Context(), server.ResetOptions{DataDir: dir, Out: &out}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if !strings.Contains(out.String(), "Nothing was deleted") {
		t.Fatalf("a dry run did not say so:\n%s", out.String())
	}
	db := openDB(t, dir)
	accounts, err := db.Accounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("a dry run left %d accounts", len(accounts))
	}
}

func TestResetListsWhatIsAboutToGo(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer
	_ = server.Reset(t.Context(), server.ResetOptions{DataDir: dir, Out: &out})

	// "Are you sure? [y/N]" is a question nobody has the information to
	// answer. The listing is what makes it answerable, so its absence is a
	// failure of the command rather than of its formatting.
	text := out.String()
	if !strings.Contains(text, strings.Repeat("a", 12)) {
		t.Fatalf("the account was not listed:\n%s", text)
	}
	if !strings.Contains(text, "device(s)") || !strings.Contains(text, "last seen") {
		t.Fatalf("the listing does not say how many devices or when they were last here:\n%s", text)
	}
}

func TestResetHardNeedsTheExactPhrase(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	// A destructive command a reflexive keystroke can complete is one that
	// gets completed reflexively.
	err := server.Reset(t.Context(), server.ResetOptions{
		DataDir: dir, Hard: true, In: strings.NewReader("y\n"), Out: &out,
	})
	if err == nil {
		t.Fatal(`"y" was accepted as confirmation`)
	}
	db := openDB(t, dir)
	if accounts, _ := db.Accounts(t.Context()); len(accounts) != 1 {
		t.Fatal("the account was deleted despite the refusal")
	}
}

func TestResetHardDeletesAndBlocks(t *testing.T) {
	dir := panicFixture(t)
	var out bytes.Buffer

	if err := server.Reset(t.Context(), server.ResetOptions{
		DataDir: dir, Hard: true, In: strings.NewReader("delete everything\n"), Out: &out,
	}); err != nil {
		t.Fatalf("Reset --hard: %v", err)
	}

	db := openDB(t, dir)
	accounts, err := db.Accounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Fatalf("%d account(s) survived a hard reset", len(accounts))
	}
	// Indistinguishable from a panic to a client -- every session ends and the
	// roster it knew is gone -- so it lands in the same state, and a device
	// cannot resync straight through either.
	if blocked, _, _ := db.Reonboard(t.Context()); !blocked {
		t.Fatal("a hard reset left the instance serving")
	}
}
