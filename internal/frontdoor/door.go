package frontdoor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Door owns ports 80 and 443.
//
// It is the only thing on the box bound to either, which is what resolves the
// collision the design found: addy, TURN, Garage, frps, headscale, WireGuard,
// OpenVPN and Vaultwarden all want the same handful of numbers, four of them
// want 443, and three want 80. Everything else binds loopback and is reached
// through here.
//
// That also changes the question a service wizard asks before deploying, from
// "is this port free" -- which is false for every service, because addy took
// 443 at install time -- to "is this hostname claimed", which is the question
// that was actually meant. Table.Set answers it.
type Door struct {
	Routes *Table

	// Handler serves every hostname routed Terminate: the portal, the paste
	// service and the API.
	Handler http.Handler

	// TLSConfig terminates TLS. In production this comes from certmagic; in
	// dev it is the same object with an unmanaged self-signed certificate in
	// its cache, so the handshake path is identical rather than parallel.
	TLSConfig *tls.Config

	// ChallengeHandler wraps the :80 handler with ACME HTTP-01. It MUST be
	// outermost. See acme.go for why leaving it out fails silently.
	ChallengeHandler func(http.Handler) http.Handler

	HTTPSAddr string
	HTTPAddr  string
	Log       *slog.Logger

	dialer     net.Dialer
	terminated *connListener
	httpsSrv   *http.Server
	httpSrv    *http.Server
	proxies    sync.Map // host -> *httputil.ReverseProxy, built lazily
	wg         sync.WaitGroup
}

// Run binds both ports and serves until ctx is cancelled.
func (d *Door) Run(ctx context.Context) error {
	if d.Routes == nil || d.Handler == nil || d.TLSConfig == nil {
		return errors.New("frontdoor: Routes, Handler and TLSConfig are all required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}

	tlsLn, err := net.Listen("tcp", d.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("binding %s: %w", d.HTTPSAddr, err)
	}
	defer tlsLn.Close()

	httpLn, err := net.Listen("tcp", d.HTTPAddr)
	if err != nil {
		tlsLn.Close()
		return fmt.Errorf("binding %s: %w", d.HTTPAddr, err)
	}
	defer httpLn.Close()

	// certmagic's TLSConfig sets NextProtos to the ACME-TLS/1 protocol and
	// nothing else. Serving that as-is means every browser negotiates no
	// protocol and HTTP/2 is silently off -- certmagic.HTTPS() prepends these
	// two internally, and we are deliberately not calling it, so we prepend
	// them here. The ACME entry must stay, or TLS-ALPN-01 dies with it and a
	// failed HTTP-01 has no fallback.
	conf := d.TLSConfig.Clone()
	if !hasProto(conf.NextProtos, "h2") {
		conf.NextProtos = append([]string{"h2", "http/1.1"}, conf.NextProtos...)
	}

	d.terminated = newConnListener(tlsLn.Addr())
	d.httpsSrv = &http.Server{
		Handler:           d.terminatedHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	var h http.Handler = http.HandlerFunc(d.redirectOrVhost)
	if d.ChallengeHandler != nil {
		h = d.ChallengeHandler(h)
	}
	d.httpSrv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	d.wg.Add(3)
	go func() {
		defer d.wg.Done()
		_ = d.httpsSrv.Serve(tls.NewListener(d.terminated, conf))
	}()
	go func() {
		defer d.wg.Done()
		_ = d.httpSrv.Serve(httpLn)
	}()
	go func() {
		defer d.wg.Done()
		d.accept(ctx, tlsLn)
	}()

	<-ctx.Done()

	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = d.httpSrv.Shutdown(shutdown)
	_ = d.httpsSrv.Shutdown(shutdown)
	d.terminated.Close()
	tlsLn.Close()
	httpLn.Close()
	d.wg.Wait()
	return ctx.Err()
}

func hasProto(protos []string, want string) bool {
	for _, p := range protos {
		if p == want {
			return true
		}
	}
	return false
}

func (d *Door) accept(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener during shutdown is the expected end of this
			// loop, not something to log as a failure.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			d.Log.Warn("accept failed", "err", err)
			continue
		}
		go d.serve(ctx, conn)
	}
}

func (d *Door) serve(ctx context.Context, conn net.Conn) {
	sni, replay, err := peekSNI(conn)
	if err != nil {
		// Not a TLS client hello: a port scanner, plain HTTP on 443, a
		// truncated record. Closed without an alert, because sending one would
		// require completing enough of a handshake to assert we are a name we
		// have not resolved yet.
		conn.Close()
		return
	}

	route, ok := d.Routes.Lookup(sni)
	if !ok {
		d.Log.Debug("closing a connection for an unrouted name", "sni", sni, "remote", conn.RemoteAddr())
		replay.Close()
		return
	}

	if route.Mode == Passthrough {
		// frps does its own SNI vhosting and cannot be reverse-proxied by an
		// HTTP server at all, so its bytes go through untouched.
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		backend, err := d.dialer.DialContext(dialCtx, "tcp", route.Backend)
		cancel()
		if err != nil {
			d.Log.Warn("passthrough backend is unreachable", "host", route.Host, "backend", route.Backend, "err", err)
			replay.Close()
			return
		}
		splice(replay, backend)
		return
	}

	// Terminate and Proxy are the same decision here: both end TLS in this
	// process. Whether the decrypted request is served locally or forwarded is
	// decided by an http.Handler, after the handshake.
	d.terminated.hand(replay)
}

// redirectOrVhost is what :80 does once the ACME challenge handler has had its
// look.
//
// The challenge handler is outermost and answers /.well-known/acme-challenge/
// itself. Everything that falls through is either a plain-HTTP tunnel, if the
// route opted into one, or a redirect.
func (d *Door) redirectOrVhost(w http.ResponseWriter, r *http.Request) {
	host := normalise(r.Host)

	if route, ok := d.Routes.Lookup(host); ok && route.HTTP80 != "" {
		// frp users have cleartext-HTTP tunnels. Silently 301-ing them to a
		// port frp is not serving is a bug report, not a security improvement,
		// so this is opt-in per host and off by default.
		d.proxyTo(route.HTTP80).ServeHTTP(w, r)
		return
	}

	// :80 does not consult the allowlist to redirect. Redirecting an unknown
	// host to HTTPS costs nothing and tells an attacker nothing; the refusal
	// belongs at the TLS handshake, where it happens.
	u := *r.URL
	u.Scheme = "https"
	u.Host = host
	// 308 and not 301: a 301 is cached by browsers effectively forever, which
	// turns a temporary misconfiguration into a permanent one, and it also
	// permits a client to downgrade a POST to a GET.
	http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
}

// terminatedHandler dispatches a decrypted request either to addy's own
// handler or to a loopback backend.
func (d *Door) terminatedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalise(r.Host)
		route, ok := d.Routes.Lookup(host)
		if !ok {
			// Reaching here means TLS completed for a name that is no longer
			// routed -- an admin deleted it between the handshake and the
			// request. Refuse rather than fall through to the portal, which
			// would serve addy's own pages under somebody else's hostname.
			http.Error(w, "not configured on this instance", http.StatusMisdirectedRequest)
			return
		}
		if route.Mode == Proxy {
			d.proxyTo(route.Backend).ServeHTTP(w, r)
			return
		}
		d.Handler.ServeHTTP(w, r)
	})
}
