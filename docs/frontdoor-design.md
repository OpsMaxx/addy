# The front door: SNI router, ACME, and certificate export

`DESIGN.md` settles *what* this component does — "addy is the only thing bound
to 80 and 443, and runs an SNI router there" — and this document settles *how*,
down to the type signatures. Everything here is checked against
`certmagic v0.25.4` source, not against memory of its README. Where the API is
surprising, the surprise is written down rather than worked around, because each
one is a silent failure in production.

Package: `internal/frontdoor`.

---

## 1. The SNI peek

### The mechanism, and why not the other two

Three options were on the table:

- **`tls.Server` with `GetConfigForClient`.** Correct for termination, useless
  for passthrough: by the time the callback fires, `crypto/tls` owns the
  connection and has consumed the ClientHello. There is no way to get the
  original bytes back out, and frps must receive them byte-for-byte.
- **Hand-written ClientHello parser.** ~80 lines of length-prefixed parsing over
  bytes an anonymous attacker chose. Every TLS proxy that has written one has
  shipped a panic on a malformed extension list.
- **Chosen: record the bytes, then let `crypto/tls` parse them, then replay.**
  We wrap the connection in a recorder, hand it to `tls.Server` with a config
  whose `GetConfigForClient` captures `ServerName` and immediately returns an
  error to abort, and then build a replay connection over the recorded prefix.
  The parser is the standard library's — the same one that will parse the hello
  for real a microsecond later — and we still hold every byte.

The abort is deliberate. Returning `(nil, nil)` from `GetConfigForClient` lets
the handshake continue until the ServerHello write fails, which works but makes
the control flow depend on a write error. A sentinel error stops it at a known
point.

### The structs

```go
// peekedConn replays the bytes consumed while sniffing the ClientHello. Without
// it the TLS record header is already off the wire, and both crypto/tls and a
// passthrough backend see a handshake that starts mid-message.
type peekedConn struct {
	net.Conn
	r io.Reader // MultiReader(recorded prefix, the raw conn)
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// recorder tees everything read off the wire into buf so the peek can be undone.
// The cap exists because a ClientHello is attacker-supplied: without it, a
// client that sends a 5-byte record header claiming 16 KiB and then dribbles
// costs us a goroutine and 16 KiB for as long as it likes.
type recorder struct {
	conn net.Conn
	buf  bytes.Buffer
	cap  int
}

func (r *recorder) Read(p []byte) (int, error) {
	if r.buf.Len() >= r.cap {
		return 0, errHelloTooLarge
	}
	n, err := r.conn.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

func (r *recorder) Write([]byte) (int, error) { return 0, errPeekOnly }
func (r *recorder) Close() error              { return nil }
func (r *recorder) LocalAddr() net.Addr       { return r.conn.LocalAddr() }
func (r *recorder) RemoteAddr() net.Addr      { return r.conn.RemoteAddr() }
func (r *recorder) SetDeadline(time.Time) error      { return nil }
func (r *recorder) SetReadDeadline(time.Time) error  { return nil }
func (r *recorder) SetWriteDeadline(time.Time) error { return nil }
```

`recorder` implements `net.Conn` only because `tls.Server` demands one. Its
`Write` is a hard error: if `crypto/tls` ever reaches the point of sending a
ServerHello during a peek, that is a bug and it should be loud.

### The peek

```go
var (
	errPeekDone      = errors.New("frontdoor: clienthello captured")
	errPeekOnly      = errors.New("frontdoor: peek connection is read-only")
	errHelloTooLarge = errors.New("frontdoor: clienthello exceeds cap")
)

const (
	helloCap     = 16 << 10       // one TLS record; a legitimate hello fits
	peekDeadline = 10 * time.Second
)

// peekSNI reads just far enough into conn to learn the SNI, and returns a
// connection that still begins with the bytes it read.
func peekSNI(conn net.Conn) (name string, replay net.Conn, err error) {
	// A slow-loris that never finishes its hello must not pin a goroutine. The
	// deadline is cleared before the connection is handed on, so it never
	// applies to the session itself.
	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return "", nil, err
	}

	rec := &recorder{conn: conn, cap: helloCap}
	hsErr := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			return nil, errPeekDone
		},
	}).Handshake()

	if !errors.Is(hsErr, errPeekDone) {
		return "", nil, fmt.Errorf("frontdoor: peek: %w", hsErr)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", nil, err
	}
	return name, &peekedConn{
		Conn: conn,
		r:    io.MultiReader(bytes.NewReader(rec.buf.Bytes()), conn),
	}, nil
}
```

**This was run, not assumed.** A `net.Pipe` client sending
`ServerName: "vault.example.com"`, peeked by the code above, yields the name; and
a second connection peeked and then handed to a real `tls.Server` over the replay
completes its handshake. The replay is therefore known to be byte-exact, which is
the one claim in this section that a reader cannot check by inspection.

Note `name` is captured by the closure and assigned before the error propagates
out of `Handshake` — that is the whole trick. An empty `ServerName` (a client
connecting by IP, or an ancient client with no SNI extension) is a valid outcome
and falls to `DefaultServerName` handling in §5.

### Then: terminate, or splice

Termination cannot call `tls.Server(...)` directly and hand the result to
`http.Server`, because `http.Server.Serve` insists on owning a `net.Listener`.
So the front door feeds accepted connections into one:

```go
// connListener hands already-accepted, already-sniffed connections to
// http.Server.Serve. Nothing in net/http lets a connection be routed after
// accept, so the listener is faked rather than the server rewritten.
type connListener struct {
	conns chan net.Conn
	addr  net.Addr
	done  chan struct{}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *connListener) Close() error   { close(l.done); return nil }
func (l *connListener) Addr() net.Addr { return l.addr }
```

Wired once at startup:

```go
tlsConf := magic.TLSConfig()
// certmagic's TLSConfig sets NextProtos to ACME-TLS/1 ONLY. Serving it as-is
// means every browser negotiates no protocol and h2 is silently off. HTTPS()
// prepends these two internally; we are not calling HTTPS(), so we do it here.
tlsConf.NextProtos = append([]string{"h2", "http/1.1"}, tlsConf.NextProtos...)

terminated := &connListener{conns: make(chan net.Conn), addr: ln.Addr(), done: make(chan struct{})}
go httpsServer.Serve(tls.NewListener(terminated, tlsConf))
```

Passthrough is `io.Copy` in both directions with a half-close, not a library:

```go
// splice moves opaque bytes. CloseWrite on each side is what makes an HTTP
// response with no Content-Length terminate; without it the backend waits for a
// FIN that never arrives and the request hangs until a timeout.
func splice(client, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	go cp(backend, client)
	go cp(client, backend)
	wg.Wait()
	client.Close()
	backend.Close()
}
```

`peekedConn` embeds `net.Conn`, so `CloseWrite` is *not* promoted through the
interface assertion — the embedded field satisfies it but the assertion is on the
wrapper. `peekedConn` therefore forwards it explicitly:

```go
func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
```

This is the kind of detail that produces "frps tunnels hang on large responses"
three weeks later.

---

## 2. Composing with certmagic

### The tension, stated precisely

`DESIGN.md` says use `certmagic.HTTPS()`, not `Listen()`/`TLS()`. Reading
`certmagic.go` in v0.25.4, `HTTPS()` does exactly four things: sets
`DefaultACME.Agreed`, calls `cfg.ManageSync`, **binds `:80` and `:443` itself**,
and puts `am.HTTPChallengeHandler(...)` in front of the `:80` handler. The last
of those is the one that matters; the third is fatal to an SNI router, and its
own doc comment says so — *"To allow very long-lived connections, you should make
your own http.Server values and use this package's Listen(), TLS(), or
Config.TLSConfig() functions."*

So: **`cfg.TLSConfig()` plus our own listeners, plus `HTTPChallengeHandler`
mounted first on our own `:80` mux.** That is not a deviation from the
requirement, it is the requirement's substance with the listener-ownership part
dropped. The real hazard the document was warning about is sharper than "these
functions disable HTTP-01", and worth restating in its actual form:

> `httpSolver.Present` (solvers.go) calls `robustTryListen(":80")`. If the bind
> fails **but the port can be dialled**, it returns `(nil, nil)` — it assumes
> whatever already holds `:80` will answer the challenge, and gives up its own
> server. addy always holds `:80`. So if we do not mount the challenge handler,
> certmagic does not error, does not warn, and does not retry with a different
> solver: every ACME validation just 404s. The identical logic is in
> `tlsALPNSolver.Present` for `:443`.

That one paragraph is the whole reason this section exists.

### What must be wired, exactly

```go
type Config struct {
	Dev     bool
	Email   string
	DataDir string
	Routes  *Table // §5 — also the on-demand allowlist
}

func newCertmagic(c Config, export *Exporter) (*certmagic.Config, *certmagic.ACMEIssuer) {
	certmagic.Default.Storage = &certmagic.FileStorage{Path: filepath.Join(c.DataDir, "certs")}
	certmagic.Default.OnEvent = export.OnEvent // §4

	// Only names an admin configured. A nil DecisionFunc with OnDemand set turns
	// the box into an open issuance relay for anyone who points a DNS record here.
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: c.Routes.Decide,
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = c.Email
	// Both challenges stay ENABLED. We own :80 and :443, so certmagic's solvers
	// will decline to bind and defer to the handlers wired below. Disabling
	// either here would remove the only fallback the other one has.
	certmagic.DefaultACME.DisableHTTPChallenge = false
	certmagic.DefaultACME.DisableTLSALPNChallenge = false

	magic := certmagic.NewDefault()
	issuer := magic.Issuers[0].(*certmagic.ACMEIssuer)
	return magic, issuer
}
```

Three wirings, each load-bearing:

| Wiring | Without it |
|---|---|
| `issuer.HTTPChallengeHandler(mux)` as the **first** thing on `:80` | HTTP-01 404s forever, silently (above) |
| `tlsConf.GetCertificate = magic.GetCertificate` — i.e. use `magic.TLSConfig()` | no certificates at all |
| `acmez.ACMETLS1Protocol` kept in `NextProtos` | TLS-ALPN-01 dies too, so a failed HTTP-01 has no fallback |

`magic.TLSConfig()` gives the second and third for free; we only add `h2` and
`http/1.1` in front. TLS-ALPN-01 then works with no extra code:
`handshake.go` checks `clientHello.SupportedProtos[0] == acmez.ACMETLS1Protocol`
inside `GetCertificate` and serves the challenge certificate. It works only for
names we *terminate*, which is why `:80` is non-negotiable — a passthrough name's
handshake never reaches us.

Do **not** use `certmagic.New(cache, cfg)`: it panics unless the cache already
has `GetConfigForCert` set. `NewDefault()` is the supported path.

---

## 3. The on-demand `DecisionFunc`

The allowlist and the routing table are the same object. A hostname is
certifiable exactly when an admin configured a route for it, and keeping two
structures in sync is how one of them ends up stale and permissive.

```go
// Table is the routing table and the on-demand allowlist at once. It is read on
// every TLS handshake and written by admin actions, so it is a map behind an
// RWMutex — reads vastly outnumber writes and a write is a human clicking a
// button. A sync.Map buys nothing here and costs type safety.
type Table struct {
	mu       sync.RWMutex
	exact    map[string]Route // normalised, lowercase, no trailing dot
	wildcard []Route          // "*.example.com", longest suffix wins
}

func (t *Table) Lookup(sni string) (Route, bool)
func (t *Table) Set(r Route) error   // admin add/edit; validates, then swaps
func (t *Table) Delete(host string)  // admin remove
func (t *Table) Hosts() []string     // for ManageSync and for the portal
```

The refusal path:

```go
var ErrNotConfigured = errors.New("hostname is not configured on this instance")

// Decide is certmagic's OnDemand.DecisionFunc. It runs inside a live TLS
// handshake, so it must not block: a map read under an RLock and nothing else.
func (t *Table) Decide(ctx context.Context, name string) error {
	r, ok := t.Lookup(name)
	if !ok {
		// Deliberately not %q-ing the caller's name into a metric label: an
		// anonymous client controls it and unbounded label cardinality is its
		// own outage. Counted, and logged at debug with a rate limit.
		return fmt.Errorf("%w: %s", ErrNotConfigured, name)
	}
	if r.Mode == Passthrough {
		// A passthrough name's handshake is never terminated here, so on-demand
		// can never legitimately fire for it. If it does, something is
		// misrouted; issuing would be issuing for a name we do not serve.
		return fmt.Errorf("%w: %s is passthrough", ErrNotConfigured, name)
	}
	return nil
}
```

certmagic wraps this as `"decision func: %w"` and aborts issuance
(`handshake.go: checkIfCertShouldBeObtained`). The client sees a handshake
failure, which is correct: we do not serve that name.

One thing `DecisionFunc` deliberately does not do is look at the client. The
`ClientHelloInfo` is reachable via `ctx.Value(certmagic.ClientHelloInfoCtxKey)`
and certmagic's own comment advises against deciding on it. Use it for logging
only.

---

## 4. Certificate export and reload

### Honest scoping first

`DESIGN.md` names three consumers that need PEM on disk. One of them does not,
and saying so is cheaper than a directory nobody reads:

- **Embedded pion/turn** is in-process. It needs a `*tls.Certificate`, not a
  file, and gets one from an `atomic.Pointer` swap with no restart and no
  dropped allocations. **External coturn (`--turn=coturn`) genuinely needs the
  file**, and the file is written unconditionally because `--turn=coturn` can be
  turned on later and a certificate that appears only after a flag flip is a
  support ticket.
- **frps** and **Vaultwarden** are containers. Files, then a reload signal.

### Where it attaches

`certmagic.Config.OnEvent`. Walking every `cfg.emit` call site in v0.25.4, the
event that matters is `cert_obtained`, fired from **both** `obtainCert` and
`renewCert` with `"renewal": false` / `true`. There is no separate
`cert_renewed`. Its data map carries **storage keys, not filesystem paths**:

```
"identifier", "issuer", "renewal",
"storage_path", "certificate_path", "private_key_path", "metadata_path"
```

so the exporter reads them back through `cfg.Storage.Load`. This is what makes
the hook work unchanged if storage is ever moved off local disk.

There is no wrapped-`Storage` approach here, and it was considered: intercepting
`Store` would catch writes, but it would also catch locks, account keys, OCSP
staples and metadata, and it would have to reverse-engineer which key is which
from its shape. `OnEvent` is told.

### The type

```go
// Consumer is one service that needs certificates as files (or, for embedded
// TURN, as an in-memory swap). Reload is a func field and not an interface
// because there are three of them and they have nothing in common beyond
// "something happened, go look at the disk".
type Consumer struct {
	Name   string   // "turn", "frps", "vaultwarden" — appears in errors and status
	Hosts  []string // which certificates this consumer needs
	Dir    string   // fullchain.pem + privkey.pem land here
	Group  int      // gid that may read privkey.pem; -1 for in-process
	Reload func(ctx context.Context, certPEM, keyPEM []byte) error
}

type Exporter struct {
	mu        sync.Mutex
	magic     *certmagic.Config
	consumers []Consumer
	degraded  map[string]error // consumer name -> last failure, read by /status
}
```

### The hook

```go
// OnEvent is certmagic's synchronous event callback — its own doc says
// "invocations are synchronous, so make them return quickly". On an on-demand
// issuance this runs inside a live TLS handshake, so the export runs on its own
// goroutine. context.WithoutCancel because the issuance context is cancelled the
// moment issuance returns, which would abort the export we just started.
func (e *Exporter) OnEvent(ctx context.Context, event string, data map[string]any) error {
	if event != "cert_obtained" {
		return nil
	}
	name, _ := data["identifier"].(string)
	certKey, _ := data["certificate_path"].(string)
	keyKey, _ := data["private_key_path"].(string)
	go e.exportFromStorage(context.WithoutCancel(ctx), name, certKey, keyKey)
	return nil // never abort issuance because an export might fail
}

func (e *Exporter) exportFromStorage(ctx context.Context, name, certKey, keyKey string) {
	certPEM, err := e.magic.Storage.Load(ctx, certKey)
	if err != nil { e.markAll(name, err); return }
	keyPEM, err := e.magic.Storage.Load(ctx, keyKey)
	if err != nil { e.markAll(name, err); return }
	e.Export(ctx, name, certPEM, keyPEM)
}

// Export is the single code path. The ACME hook reaches it through storage;
// --dev reaches it directly with a self-signed pair (§7). One path, so dev
// exercises permissions, atomicity and reload for real.
func (e *Exporter) Export(ctx context.Context, name string, certPEM, keyPEM []byte) {
	for _, c := range e.consumers {
		if !slices.Contains(c.Hosts, name) {
			continue
		}
		// Each consumer is independent: frps failing must not stop Vaultwarden.
		if err := e.one(ctx, c, certPEM, keyPEM); err != nil {
			e.mark(c.Name, err)
			continue
		}
		e.clear(c.Name)
	}
}
```

### What it writes, and with what permissions

```go
func (e *Exporter) one(ctx context.Context, c Consumer, certPEM, keyPEM []byte) error {
	if c.Dir != "" {
		// 0750 and group-owned: the container runs as a different uid and must
		// read privkey.pem, so 0600 addy-only does not work. World-readable
		// does, and is how private keys leak to every other service on the box.
		if err := os.MkdirAll(c.Dir, 0o750); err != nil {
			return err
		}
		if c.Group >= 0 {
			if err := os.Chown(c.Dir, -1, c.Group); err != nil {
				return err
			}
		}
		// Write-temp-then-rename, per file. A service that reloads while a key
		// file is half-written reads a truncated PEM and comes back up with no
		// TLS at all — worse than the stale certificate we were replacing.
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
		// The files are current and the service is running the old certificate.
		// Not an emergency — it is still valid for the rest of the renewal
		// window — but it is exactly the failure that goes unnoticed until TURNS
		// stops working, so it is recorded as degraded, not logged and dropped.
		return fmt.Errorf("exported but %s did not reload: %w", c.Name, err)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode, gid int) error {
	// Same directory, so the rename is atomic; os.Rename across filesystems is not.
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil { f.Close(); return err }
	// fsync before rename: a rename is atomic with respect to other processes,
	// not with respect to a power cut. A zero-length privkey.pem after a reboot
	// is the failure this line prevents.
	if err := f.Sync(); err != nil { f.Close(); return err }
	if err := f.Chmod(mode); err != nil { f.Close(); return err }
	if gid >= 0 {
		if err := f.Chown(-1, gid); err != nil { f.Close(); return err }
	}
	if err := f.Close(); err != nil { return err }
	return os.Rename(f.Name(), path)
}
```

### The three reloads

```go
// Embedded pion/turn: swap the pointer the TLS listener reads on every
// handshake. No restart, no dropped allocations, no file needed.
turnCert.Store(&parsed)   // atomic.Pointer[tls.Certificate]
// the TURNS listener was built once with:
//   &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
//       return turnCert.Load(), nil
//   }}

// frps: SIGHUP via the Docker socket proxy. frps re-reads its TLS files.
// Vaultwarden: restart via the same proxy. It has no reload signal; a restart
// drops in-flight sessions, so it is scheduled, not immediate, and the portal
// says when.
```

### Partial failure, stated

- **One consumer fails, the rest still get their files.** Independent loop.
- **A write fails.** The old certificate is still on disk and still valid — the
  renewal window means there is roughly a month of runway. The consumer is
  marked degraded, retried with backoff (1m, 5m, 15m, then hourly), and
  `addy selftest` re-runs the export and diffs the file against storage, so the
  condition is testable rather than inferred.
- **A write succeeds, the reload fails.** Marked degraded with the distinct
  message above. Retried the same way. This is the sixty-day-TURNS failure, and
  the whole point of naming it separately is that "exported" and "reloaded" are
  different facts and only one of them is easy to observe.
- **Anything degraded makes `/status` unhealthy and the portal show it.** A
  renewal hook whose failures are only in the log is a hook that does not exist.
- **Issuance is never aborted by an export failure.** `OnEvent` returns `nil`
  unconditionally. Refusing the certificate because we could not copy it would
  turn a copy problem into an outage.

---

## 5. Routing table

Three destinations, but only **two** SNI-layer decisions, and the difference is
worth being exact about. `DESIGN.md` lists terminate / reverse-proxy /
passthrough as three peers; reverse-proxying happens *after* TLS termination, so
at the peek the question is only "do we terminate this?". The proxy decision is
made by an `http.Handler` on the terminated side.

```go
type Mode string

const (
	Terminate   Mode = "terminate"   // portal, paste, API — addy's own mux
	Proxy       Mode = "proxy"       // TLS ends here; HTTP goes to a loopback backend
	Passthrough Mode = "passthrough" // bytes go untouched; frps vhost_https only
)

type Route struct {
	Host    string // exact, or "*.example.com"
	Mode    Mode
	Backend string // host:port on loopback. Empty iff Mode == Terminate.
	HTTP80  string // optional :80 backend (frps vhost_http). Empty = redirect. §6
}
```

The configured set, as it actually ends up:

| Host | Mode | Backend |
|---|---|---|
| `addy.example.com` | `Terminate` | — (portal, paste, API) |
| `vault.example.com` | `Proxy` | `127.0.0.1:8222` |
| `hs.example.com` | `Proxy` | `127.0.0.1:8080` |
| `*.tun.example.com` | `Passthrough` | `127.0.0.1:8443` (frps `vhost_https_port`) |

Accept loop:

```go
func (d *Door) serve(conn net.Conn) {
	sni, replay, err := peekSNI(conn)
	if err != nil {
		conn.Close()
		return
	}
	r, ok := d.routes.Lookup(sni)
	if !ok {
		// No route: close. Not a TLS alert, because sending one requires
		// completing enough of a handshake to prove we are the name we are not.
		replay.Close()
		return
	}
	if r.Mode == Passthrough {
		backend, err := d.dialer.DialContext(ctx, "tcp", r.Backend)
		if err != nil {
			replay.Close()
			return
		}
		splice(replay, backend)
		return
	}
	d.terminated.conns <- replay // §1
}
```

An empty SNI resolves through `certmagic.Config.DefaultServerName` if one is
configured, and is otherwise closed. IP-literal SNI is rejected before lookup —
`SubjectQualifiesForCert` would reject it downstream anyway, and rejecting early
keeps it out of the metrics.

On the terminated side, the mux is host-based and one line per proxied service:

```go
mux.Handle("vault.example.com/", httputil.NewSingleHostReverseProxy(vaultURL))
```

with `X-Forwarded-Proto: https` and `X-Forwarded-For` set by the proxy's
`Rewrite`, because both Vaultwarden and headscale generate absolute URLs and will
emit `http://` links otherwise. headscale additionally needs websocket upgrade to
pass through, which `httputil.ReverseProxy` handles natively since Go 1.12 — no
library.

**The preflight question is "is this hostname claimed", not "is this port free".**
`Table.Set` is where that is enforced: it rejects a host already present, and
rejects a wildcard that would shadow an existing exact route. A wizard that asks
for a hostname already in the table refuses with the name of the service holding
it.

---

## 6. Port 80

`:80` is a plain `http.Server` with a three-layer handler, in this order:

```go
var h http.Handler = http.HandlerFunc(d.redirectOrProxy)
h = issuer.HTTPChallengeHandler(h) // MUST be outermost — see §2

httpSrv := &http.Server{
	Handler:           h,
	ReadHeaderTimeout: 10 * time.Second,
}
```

1. **ACME HTTP-01.** `HTTPChallengeHandler` checks `LooksLikeHTTPChallenge` —
   `GET /.well-known/acme-challenge/...` — and answers it, otherwise falls
   through. This is the entire reason `:80` cannot be given to anything else, and
   it works for *every* configured name including passthrough ones, which is the
   only way a passthrough name can be validated at all.

2. **frps `vhost_http`.** frp's plain-HTTP vhosting binds a loopback port, and
   hosts whose route sets `HTTP80` are reverse-proxied to it instead of
   redirected. This is opt-in per host and off by default: a tunnel should be
   reached over HTTPS like everything else, and the `:443` passthrough route
   already covers that case. The carve-out exists because frp users have
   cleartext-HTTP tunnels and silently 301-ing them to a port frp is not serving
   is a bug report, not a security improvement.

3. **Redirect.** Everything else gets `308` to `https://` + same host and path.
   `308`, not `301`: a `301` is cached forever by browsers and turns a
   misconfiguration into a permanent one, and it lets a client downgrade a POST
   to a GET.

```go
func (d *Door) redirectOrProxy(w http.ResponseWriter, r *http.Request) {
	if route, ok := d.routes.Lookup(hostOnly(r.Host)); ok && route.HTTP80 != "" {
		d.vhostHTTP.ServeHTTP(w, r) // reverse proxy to frps vhost_http_port
		return
	}
	u := *r.URL
	u.Scheme, u.Host = "https", hostOnly(r.Host)
	http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
}
```

`:80` never consults the allowlist for the redirect: redirecting an unknown host
to HTTPS costs nothing, and the refusal happens at the TLS handshake where it
belongs.

---

## 7. `--dev`

Dev mode must exercise the real path, so it swaps exactly one thing — the source
of the certificate — and keeps everything else.

**Still runs:** the SNI peek, the routing table, `Table.Decide` (including the
refusal path), `connListener`, TLS termination through
`certmagic.Config.GetCertificate`, the `:80` server, the reverse proxies, the
passthrough splice, and the exporter — files, permissions and reload included.

**Bypassed:** the ACME issuer, HTTP-01, TLS-ALPN-01, and DNS-01. Nothing else.

```go
func devCert(magic *certmagic.Config) error {
	// One self-signed leaf for localhost. ~30 lines of crypto/x509 and no
	// dependency; the alternative is an embedded CA nobody asked for.
	tlsCert, certPEM, keyPEM, err := selfSigned([]string{"localhost"},
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	if err != nil {
		return err
	}
	// Cached as UNMANAGED: certmagic serves it from cache and never tries to
	// renew it, so GetCertificate and the whole handshake path are byte-identical
	// to production instead of a parallel dev branch.
	if _, err := magic.CacheUnmanagedTLSCertificate(context.Background(), tlsCert, nil); err != nil {
		return err
	}
	// The export hook fires on cert_obtained, which never happens in dev, so the
	// exporter is driven directly through its one public entry point. This is
	// what keeps "dev exercises the real code path" true for the part of the
	// system most likely to be wrong.
	exporter.Export(context.Background(), "localhost", certPEM, keyPEM)
	return nil
}
```

`OnDemand` stays configured with the same `DecisionFunc`, and `Issuers` is left
empty. An unknown SNI in dev is therefore refused by the same `Table.Decide` as
in production, and a known one is already in the cache so issuance is never
reached. The dev routing table is seeded with `localhost → Terminate` and, if the
test harness wants one, a passthrough route to a local echo server.

`--dev` also pins `HTTPPort`/`HTTPSPort` to unprivileged defaults
(`certmagic.HTTPPort = 8080`, `HTTPSPort = 8443`) so it runs without root, and
the `addy://` join string carries the self-signed TOFU pin exactly as it would
carry a real one.

---

## 8. Failure modes worth a test

```
TestPeekSNI_ReplaysExactBytes              // a passthrough backend receives the ClientHello byte-for-byte
TestPeekSNI_EmptyServerName                // no SNI extension: routed by DefaultServerName or closed, never panicked
TestPeekSNI_TruncatedHello                 // 3-byte record header then EOF: error, connection closed, no goroutine left
TestPeekSNI_OversizedHello                 // 64 KiB of garbage hits helloCap and is rejected before allocation
TestPeekSNI_SlowlorisDeadline              // a client that dribbles is dropped at peekDeadline
TestPeekSNI_NotTLSOnPort443                // plain HTTP sent to :443 is refused, not misrouted to a backend
TestDecide_RefusesUnconfiguredHost         // the open-issuance-relay case; must return ErrNotConfigured
TestDecide_RefusesPassthroughHost          // a name we never terminate must never be issued for
TestDecide_AllowsConfiguredHost            // the happy path, so the refusal test cannot pass by always refusing
TestTable_ConcurrentSetDuringLookup        // -race: admin edits the table while handshakes read it
TestTable_RejectsDuplicateHostname         // the preflight question: "is this hostname claimed"
TestPort80_ChallengeHandlerIsOutermost     // /.well-known/acme-challenge/x is answered, not 308-redirected
TestPort80_RedirectIs308                   // a POST to :80 keeps its method
TestExport_AtomicOnCrash                   // kill between write and rename: no truncated privkey.pem
TestExport_KeyPermissions                  // privkey.pem is 0640 and group-owned, never world-readable
TestExport_PartialFailureIsolation         // frps write fails; Vaultwarden still gets its files and is not marked degraded
TestExport_ReloadFailureMarksDegraded      // written-but-not-reloaded is its own status, not silence
TestExport_NeverAbortsIssuance             // OnEvent returns nil even when every consumer fails
TestSplice_HalfCloseTerminatesResponse     // CloseWrite forwarded through peekedConn; no hang on a length-less response
TestDev_ExercisesExporter                  // --dev writes real PEM through the same Export path
TestDev_RefusesUnknownSNI                  // the refusal path runs in dev too
```

---

## Dependencies

`certmagic` (mandated by `DESIGN.md`, and it is the ACME client) and its
transitive `acmez`/`libdns`. Nothing else. The SNI peek, the replay, the
listener, the splice, the reverse proxies and the atomic writes are
`crypto/tls`, `net`, `net/http`, `net/http/httputil` and `os`. No proxy library
was added, for the reason `internal/relay` already gives: this is `io.Copy`
between two streams with a bounded buffer, and the risk is unbounded buffering,
which is solved by bounding it rather than by a dependency.
