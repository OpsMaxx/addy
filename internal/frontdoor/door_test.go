package frontdoor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// harness stands up a real Door on real loopback ports with a real
// certificate, because every interesting failure in this package is about
// bytes on a socket and none of it is observable from an httptest.Server.
type harness struct {
	door      *Door
	httpsAddr string
	httpAddr  string
	pool      *x509.CertPool
}

func newHarness(t *testing.T, routes *Table, handler http.Handler) *harness {
	t.Helper()

	cert, certPEM, _, err := selfSigned(
		[]string{"addy.test", "vault.test", "a.tun.test"},
		[]net.IP{net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatalf("selfSigned: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust the test certificate")
	}

	d := &Door{
		Routes:    routes,
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		HTTPSAddr: "127.0.0.1:0",
		HTTPAddr:  "127.0.0.1:0",
	}

	// Bind first so the test knows the ports, then hand the listeners over by
	// re-binding inside Run -- simplest is to pick free ports up front.
	d.HTTPSAddr = freePort(t)
	d.HTTPAddr = freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the door did not shut down within 15s")
		}
	})

	h := &harness{door: d, httpsAddr: d.HTTPSAddr, httpAddr: d.HTTPAddr, pool: pool}
	h.waitReady(t)
	return h
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func (h *harness) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", h.httpsAddr)
		if err == nil {
			c.Close()
			c2, err2 := net.Dial("tcp", h.httpAddr)
			if err2 == nil {
				c2.Close()
				return
			}
		}
	}
	t.Fatal("the door never started listening")
}

// client returns an HTTPS client that resolves every hostname to the door and
// trusts its certificate.
func (h *harness) client() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, h.httpsAddr)
			},
			TLSClientConfig: &tls.Config{RootCAs: h.pool},
		},
	}
}

func TestATerminatedHostIsServedByAddysOwnHandler(t *testing.T) {
	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})

	h := newHarness(t, routes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "the portal")
	}))

	resp, err := h.client().Get("https://addy.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the portal" {
		t.Errorf("body = %q, want %q", body, "the portal")
	}
}

func TestAProxiedHostReachesItsBackendWithForwardedHeaders(t *testing.T) {
	var gotHost, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotProto = r.Header.Get("X-Forwarded-Proto")
		io.WriteString(w, "the backend")
	}))
	defer backend.Close()

	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})
	mustSet(t, routes, Route{
		Host: "vault.test", Mode: Proxy,
		Backend: strings.TrimPrefix(backend.URL, "http://"),
	})

	h := newHarness(t, routes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "the portal")
	}))

	resp, err := h.client().Get("https://vault.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the backend" {
		t.Fatalf("body = %q; the request did not reach the backend", body)
	}
	// Vaultwarden and headscale generate absolute URLs. Without these two they
	// emit http:// links from behind an https:// front door, which looks like
	// a certificate problem and is not.
	if gotProto != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", gotProto)
	}
	if gotHost != "vault.test" {
		t.Errorf("backend saw Host %q, want the hostname the client asked for", gotHost)
	}
}

// The whole reason the peek exists: frps does its own SNI vhosting, so the
// bytes must arrive exactly as the client sent them, ClientHello included.
func TestAPassthroughHostReachesItsBackendByteForByte(t *testing.T) {
	cert, _, _, err := selfSigned([]string{"a.tun.test"}, nil)
	if err != nil {
		t.Fatalf("selfSigned: %v", err)
	}

	// A backend that terminates TLS itself, exactly as frps does.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer backendLn.Close()

	sniSeen := make(chan string, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		srv := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				sniSeen <- hello.ServerName
				return nil, nil
			},
		})
		if err := srv.Handshake(); err != nil {
			return
		}
		io.WriteString(srv, "from the tunnel")
		srv.Close()
	}()

	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})
	mustSet(t, routes, Route{Host: "*.tun.test", Mode: Passthrough, Backend: backendLn.Addr().String()})

	h := newHarness(t, routes, http.NotFoundHandler())

	raw, err := net.Dial("tcp", h.httpsAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: "a.tun.test", InsecureSkipVerify: true})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake through the passthrough: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "from the tunnel" {
		t.Errorf("body = %q, want the backend's own response", body)
	}

	select {
	case sni := <-sniSeen:
		// The backend must have seen the SNI itself. If the peek had consumed
		// the hello, this would be empty and frp's vhosting would be blind.
		if sni != "a.tun.test" {
			t.Errorf("the backend saw SNI %q, want a.tun.test", sni)
		}
	case <-time.After(5 * time.Second):
		t.Error("the backend never saw a client hello")
	}
}

// An unrouted name must not reach the portal. Serving addy's own pages under
// somebody else's hostname is the failure this prevents.
func TestAnUnroutedNameIsRefusedAtTheHandshake(t *testing.T) {
	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})
	h := newHarness(t, routes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the portal served a request for an unrouted name")
	}))

	if _, err := h.client().Get("https://stranger.test/"); err == nil {
		t.Fatal("a request for an unrouted name succeeded")
	}
}

// 308 and not 301: a 301 is cached effectively forever, turning a temporary
// misconfiguration permanent, and it lets a client downgrade a POST to a GET.
func TestPortEightyRedirectsWith308AndKeepsTheMethod(t *testing.T) {
	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})
	h := newHarness(t, routes, http.NotFoundHandler())

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+h.httpAddr+"/thing?q=1", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "addy.test"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("status = %d, want 308", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://addy.test/thing?q=1" {
		t.Errorf("Location = %q", loc)
	}
}

// The challenge handler is mounted outermost, so an ACME validation is answered
// rather than redirected to HTTPS -- which is a redirect Let's Encrypt follows
// into a certificate that does not exist yet.
func TestTheChallengeHandlerSeesRequestsBeforeTheRedirect(t *testing.T) {
	routes := NewTable()
	mustSet(t, routes, Route{Host: "addy.test", Mode: Terminate})

	cert, _, _, err := selfSigned([]string{"addy.test"}, nil)
	if err != nil {
		t.Fatalf("selfSigned: %v", err)
	}
	d := &Door{
		Routes:    routes,
		Handler:   http.NotFoundHandler(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		HTTPSAddr: freePort(t),
		HTTPAddr:  freePort(t),
		ChallengeHandler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
					io.WriteString(w, "the key authorization")
					return
				}
				next.ServeHTTP(w, r)
			})
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Run(ctx) }()
	defer func() { cancel(); <-done }()

	h := &harness{httpsAddr: d.HTTPSAddr, httpAddr: d.HTTPAddr}
	h.waitReady(t)

	req, _ := http.NewRequest(http.MethodGet, "http://"+d.HTTPAddr+"/.well-known/acme-challenge/token", nil)
	req.Host = "addy.test"
	resp, err := (&http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; the challenge was redirected instead of answered", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the key authorization" {
		t.Errorf("body = %q", body)
	}
}
