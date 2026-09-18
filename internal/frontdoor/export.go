package frontdoor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// Certificates have one issuer, and it has to export.
//
// certmagic keeps certificates in its own storage. External coturn (5349), frps
// and Vaultwarden all need PEM FILES ON DISK. Without an export-and-reload hook
// on renewal, TURNS silently stops working about sixty days after install --
// the kind of failure nobody attributes to the right cause, because everything
// else on the box is fine and the certificate in the browser is current.
//
// So addy is the sole ACME client and writes PEM to each consumer's directory
// on every issuance, then signals a reload.

// Consumer is one thing that needs certificates as files.
//
// Reload is a func field rather than an interface because there are three of
// them and they have nothing in common beyond "something changed, go and look".
// An interface with three unrelated implementations and one method is a factory
// for one product wearing a hat.
type Consumer struct {
	Name   string   // "turn", "frps", "vaultwarden": appears in status and in errors
	Hosts  []string // which certificates this consumer needs
	Dir    string   // fullchain.pem and privkey.pem land here; empty means in-process only
	Group  int      // gid that may read privkey.pem; -1 for in-process consumers
	Reload func(ctx context.Context, certPEM, keyPEM []byte) error
}

// Exporter copies issued certificates out to the services that need files.
type Exporter struct {
	mu        sync.Mutex
	consumers []Consumer
	degraded  map[string]string // consumer name -> why, read by status
	load      func(ctx context.Context, key string) ([]byte, error)
}

// SetLoader supplies the storage reader after construction.
//
// It exists because of an ordering problem that produced the nil above: the
// exporter has to be passed to NewACME, and the storage it reads from is
// created BY NewACME. Rather than leaving a caller to remember, NewACME calls
// this itself -- so an exporter built with nil is wired by the time any event
// can reach it.
func (e *Exporter) SetLoader(load func(ctx context.Context, key string) ([]byte, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.load == nil {
		e.load = load
	}
}

func NewExporter(load func(ctx context.Context, key string) ([]byte, error), consumers ...Consumer) *Exporter {
	return &Exporter{
		consumers: consumers,
		degraded:  make(map[string]string),
		load:      load,
	}
}

// OnEvent is certmagic's synchronous event callback. Its own documentation says
// invocations are synchronous and should return quickly, and on an on-demand
// issuance this runs inside a LIVE TLS HANDSHAKE -- so the export happens on its
// own goroutine and this returns immediately.
//
// It returns nil unconditionally, including when every consumer fails. Refusing
// the certificate because addy could not copy it would turn a copy problem into
// an outage, which is a strictly worse trade than serving with a stale copy
// somewhere else on the box.
func (e *Exporter) OnEvent(ctx context.Context, event string, data map[string]any) error {
	// Walking every emit call site in certmagic v0.25.4: cert_obtained is
	// fired by BOTH obtainCert and renewCert, distinguished by a "renewal"
	// boolean. There is no separate cert_renewed event, so listening for one
	// would mean the renewal -- the case this hook exists for -- never fires.
	if event != "cert_obtained" {
		return nil
	}
	name, _ := data["identifier"].(string)
	certKey, _ := data["certificate_path"].(string)
	keyKey, _ := data["private_key_path"].(string)
	if name == "" || certKey == "" || keyKey == "" {
		e.markAll(fmt.Sprintf("cert_obtained for %q carried no storage keys", name))
		return nil
	}

	// WithoutCancel because the issuance context is cancelled the moment
	// issuance returns, which would abort the export the moment it started.
	go e.exportFromStorage(context.WithoutCancel(ctx), name, certKey, keyKey)
	return nil
}

// The event's data map carries STORAGE KEYS, not filesystem paths, despite the
// "_path" suffix on the key names. Reading them back through storage is also
// what keeps this working unchanged if storage ever moves off local disk.
func (e *Exporter) exportFromStorage(ctx context.Context, name, certKey, keyKey string) {
	// A nil loader is a wiring mistake, and it used to be a SIGSEGV that took
	// the whole relay down the first time a certificate was ever obtained --
	// on a box that had been running fine for an hour, at the exact moment
	// everything started working. Degraded and named instead: the certificate
	// is served either way, and what is lost is the copy on disk that TURN and
	// frps read.
	if e.load == nil {
		e.markAll(fmt.Sprintf(
			"no certificate storage was wired into the exporter, so %s could not be copied out to the services that need it as files", name))
		return
	}

	certPEM, err := e.load(ctx, certKey)
	if err != nil {
		e.markAll(fmt.Sprintf("loading certificate for %s: %v", name, err))
		return
	}
	keyPEM, err := e.load(ctx, keyKey)
	if err != nil {
		e.markAll(fmt.Sprintf("loading key for %s: %v", name, err))
		return
	}
	e.Export(ctx, name, certPEM, keyPEM)
}

// Export is the single code path.
//
// The ACME hook reaches it through storage; dev mode reaches it directly with a
// self-signed pair. One path, so dev mode exercises permissions, atomicity and
// reload for real rather than skipping the part most likely to be wrong.
func (e *Exporter) Export(ctx context.Context, host string, certPEM, keyPEM []byte) {
	for _, c := range e.consumers {
		if !slices.Contains(c.Hosts, host) {
			continue
		}
		// Each consumer is independent. frps failing to accept a file must not
		// stop Vaultwarden getting one.
		if err := e.one(ctx, c, certPEM, keyPEM); err != nil {
			e.mark(c.Name, err.Error())
			continue
		}
		e.clear(c.Name)
	}
}

func (e *Exporter) one(ctx context.Context, c Consumer, certPEM, keyPEM []byte) error {
	if c.Dir != "" {
		// 0750 and group-owned. The container runs as a different uid and has
		// to read privkey.pem, so addy-only 0600 does not work -- and
		// world-readable does work, which is how a private key ends up
		// readable by every other service on the box.
		if err := os.MkdirAll(c.Dir, 0o750); err != nil {
			return fmt.Errorf("creating %s: %w", c.Dir, err)
		}
		if c.Group >= 0 {
			if err := os.Chown(c.Dir, -1, c.Group); err != nil {
				return fmt.Errorf("group-owning %s: %w", c.Dir, err)
			}
		}
		if err := writeAtomic(filepath.Join(c.Dir, "fullchain.pem"), certPEM, 0o644, -1); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(c.Dir, "privkey.pem"), keyPEM, 0o640, c.Group); err != nil {
			return err
		}
	}

	if c.Reload == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.Reload(rctx, certPEM, keyPEM); err != nil {
		// "Exported" and "reloaded" are different facts, and only one of them
		// is easy to observe. This is the sixty-day-TURNS failure, so it gets
		// its own message rather than being folded into a write error: the
		// files are current and the service is still running the old
		// certificate, which is valid for the rest of the renewal window.
		return fmt.Errorf("exported, but %s did not reload: %w", c.Name, err)
	}
	return nil
}

// writeAtomic writes to a temporary file in the same directory and renames.
//
// A service that reloads while a key file is half-written reads a truncated PEM
// and comes back up with no TLS at all, which is worse than the stale
// certificate it was replacing.
func writeAtomic(path string, data []byte, mode os.FileMode, gid int) error {
	// Same directory, because os.Rename is only atomic within a filesystem.
	f, err := os.CreateTemp(filepath.Dir(path), ".addy-tmp-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	// fsync before rename. A rename is atomic with respect to other processes,
	// not with respect to a power cut: without this, a reboot at the wrong
	// moment leaves a zero-length privkey.pem that looks like a successful
	// write.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("syncing %s: %w", tmp, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return fmt.Errorf("setting mode on %s: %w", tmp, err)
	}
	if gid >= 0 {
		if err := f.Chown(-1, gid); err != nil {
			f.Close()
			return fmt.Errorf("group-owning %s: %w", tmp, err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}

func (e *Exporter) mark(name, why string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.degraded[name] = why
}

func (e *Exporter) markAll(why string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.consumers {
		e.degraded[c.Name] = why
	}
}

func (e *Exporter) clear(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.degraded, name)
}

// Degraded lists what is not current, sorted, for the status endpoint.
//
// A renewal hook whose failures live only in a log is a hook that does not
// exist: nobody reads the log until TURNS has already been broken for a week.
func (e *Exporter) Degraded() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.degraded))
	for name, why := range e.degraded {
		out = append(out, name+": "+why)
	}
	sort.Strings(out)
	return out
}
