package frontdoor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExportWritesBothFilesWithSafePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply")
	}
	dir := filepath.Join(t.TempDir(), "frps")
	e := NewExporter(nil, Consumer{Name: "frps", Hosts: []string{"a.example"}, Dir: dir, Group: -1})

	e.Export(context.Background(), "a.example", []byte("CERT"), []byte("KEY"))

	cert, err := os.Stat(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("fullchain.pem: %v", err)
	}
	key, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatalf("privkey.pem: %v", err)
	}
	// The private key must never be world-readable. That is the failure this
	// whole file exists to avoid: a key readable by every other service on the
	// box, put there by the thing that was protecting it.
	if mode := key.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("privkey.pem is %04o; other must have no access", mode)
	}
	if mode := cert.Mode().Perm(); mode&0o022 != 0 {
		t.Errorf("fullchain.pem is %04o; it must not be writable by group or other", mode)
	}
	if got := readFile(t, filepath.Join(dir, "privkey.pem")); got != "KEY" {
		t.Errorf("privkey.pem = %q", got)
	}
	if d := e.Degraded(); len(d) != 0 {
		t.Errorf("Degraded() = %v after a clean export", d)
	}
}

// No temporary file may be left behind, and no consumer may ever observe a
// half-written key.
func TestExportLeavesNoTemporaryFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "frps")
	e := NewExporter(nil, Consumer{Name: "frps", Hosts: []string{"a.example"}, Dir: dir, Group: -1})
	e.Export(context.Background(), "a.example", []byte("CERT"), []byte("KEY"))
	e.Export(context.Background(), "a.example", []byte("CERT2"), []byte("KEY2"))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 2 {
		t.Errorf("directory holds %v, want exactly fullchain.pem and privkey.pem", names)
	}
	if got := readFile(t, filepath.Join(dir, "privkey.pem")); got != "KEY2" {
		t.Errorf("the second export did not replace the key: %q", got)
	}
}

// One consumer failing must not stop the others. frps having a bad directory is
// not a reason for Vaultwarden to run on a stale certificate.
func TestOneConsumerFailingDoesNotStopTheOthers(t *testing.T) {
	good := filepath.Join(t.TempDir(), "vaultwarden")

	// A path whose parent is a FILE cannot be created as a directory.
	blocked := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	e := NewExporter(nil,
		Consumer{Name: "frps", Hosts: []string{"a.example"}, Dir: filepath.Join(blocked, "frps"), Group: -1},
		Consumer{Name: "vaultwarden", Hosts: []string{"a.example"}, Dir: good, Group: -1},
	)
	e.Export(context.Background(), "a.example", []byte("CERT"), []byte("KEY"))

	if _, err := os.Stat(filepath.Join(good, "privkey.pem")); err != nil {
		t.Errorf("vaultwarden did not get its files because frps failed: %v", err)
	}
	degraded := e.Degraded()
	if len(degraded) != 1 || !strings.HasPrefix(degraded[0], "frps:") {
		t.Errorf("Degraded() = %v, want only frps", degraded)
	}
}

// "Written" and "reloaded" are different facts and only one is easy to observe.
// This is the failure that shows up sixty days later as TURNS not working.
func TestAFailedReloadIsItsOwnDegradedState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "turn")
	e := NewExporter(nil, Consumer{
		Name: "turn", Hosts: []string{"a.example"}, Dir: dir, Group: -1,
		Reload: func(context.Context, []byte, []byte) error { return errors.New("signal refused") },
	})
	e.Export(context.Background(), "a.example", []byte("CERT"), []byte("KEY"))

	// The files must still be there: the export succeeded, the reload did not.
	if _, err := os.Stat(filepath.Join(dir, "privkey.pem")); err != nil {
		t.Errorf("a failed reload discarded the exported files: %v", err)
	}
	degraded := e.Degraded()
	if len(degraded) != 1 || !strings.Contains(degraded[0], "did not reload") {
		t.Errorf("Degraded() = %v, want a distinct did-not-reload message", degraded)
	}
}

// A consumer that recovers must stop being reported, or the status is noise
// within a week and nobody reads it.
func TestASuccessfulExportClearsAPreviousFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "turn")
	fail := true
	e := NewExporter(nil, Consumer{
		Name: "turn", Hosts: []string{"a.example"}, Dir: dir, Group: -1,
		Reload: func(context.Context, []byte, []byte) error {
			if fail {
				return errors.New("not yet")
			}
			return nil
		},
	})
	e.Export(context.Background(), "a.example", []byte("C"), []byte("K"))
	if len(e.Degraded()) != 1 {
		t.Fatalf("Degraded() = %v, want one entry", e.Degraded())
	}
	fail = false
	e.Export(context.Background(), "a.example", []byte("C"), []byte("K"))
	if d := e.Degraded(); len(d) != 0 {
		t.Errorf("Degraded() = %v after recovery, want empty", d)
	}
}

// Refusing a certificate because it could not be copied would turn a copy
// problem into an outage.
func TestOnEventNeverAbortsIssuance(t *testing.T) {
	e := NewExporter(
		func(context.Context, string) ([]byte, error) { return nil, errors.New("storage is gone") },
		Consumer{Name: "frps", Hosts: []string{"a.example"}, Dir: t.TempDir(), Group: -1},
	)
	err := e.OnEvent(context.Background(), "cert_obtained", map[string]any{
		"identifier":       "a.example",
		"certificate_path": "certs/a.crt",
		"private_key_path": "certs/a.key",
	})
	if err != nil {
		t.Fatalf("OnEvent returned %v; it must never abort issuance", err)
	}

	// And an event with nothing usable in it must also not abort.
	if err := e.OnEvent(context.Background(), "cert_obtained", map[string]any{}); err != nil {
		t.Fatalf("OnEvent on a malformed event returned %v", err)
	}
}

// Listening for a "cert_renewed" event would mean the renewal -- the case this
// hook exists for -- never fires, because certmagic emits cert_obtained for
// both and distinguishes them with a boolean.
func TestOnEventIgnoresEventsThatAreNotCertObtained(t *testing.T) {
	dir := t.TempDir()
	called := false
	e := NewExporter(
		func(context.Context, string) ([]byte, error) { called = true; return []byte("x"), nil },
		Consumer{Name: "frps", Hosts: []string{"a.example"}, Dir: dir, Group: -1},
	)
	for _, event := range []string{"cert_failed", "cached_managed_cert", "tls_get_certificate"} {
		if err := e.OnEvent(context.Background(), event, map[string]any{"identifier": "a.example"}); err != nil {
			t.Errorf("OnEvent(%q) = %v", event, err)
		}
	}
	if called {
		t.Error("an unrelated event triggered an export")
	}
}

// A consumer that does not want this hostname must not be given it.
func TestExportOnlyReachesConsumersThatWantTheHost(t *testing.T) {
	mine := filepath.Join(t.TempDir(), "mine")
	theirs := filepath.Join(t.TempDir(), "theirs")
	e := NewExporter(nil,
		Consumer{Name: "mine", Hosts: []string{"a.example"}, Dir: mine, Group: -1},
		Consumer{Name: "theirs", Hosts: []string{"b.example"}, Dir: theirs, Group: -1},
	)
	e.Export(context.Background(), "a.example", []byte("C"), []byte("K"))

	if _, err := os.Stat(filepath.Join(mine, "privkey.pem")); err != nil {
		t.Errorf("the matching consumer got nothing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(theirs, "privkey.pem")); err == nil {
		t.Error("a consumer received a certificate for a host it did not ask for")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}
