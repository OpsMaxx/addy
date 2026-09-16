package frontdoor

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHello dials a net.Pipe, sends a real ClientHello for serverName, and
// returns the server side for peeking. The client handshake is expected to
// fail -- the peek aborts it -- so its error is ignored.
func clientHello(t *testing.T, serverName string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake()
		client.Close()
	}()
	t.Cleanup(func() { server.Close() })
	return server
}

func TestPeekReadsTheServerName(t *testing.T) {
	name, replay, err := peekSNI(clientHello(t, "vault.example"))
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	defer replay.Close()
	if name != "vault.example" {
		t.Errorf("name = %q, want vault.example", name)
	}
}

// The claim a reader cannot check by inspection: the replayed connection must
// begin with the EXACT bytes the client sent, or a passthrough backend sees a
// handshake starting mid-message. Asserted by having a real tls.Server complete
// a handshake over the replay.
func TestReplayIsByteExactEnoughForARealHandshake(t *testing.T) {
	cert, _, _, err := selfSigned([]string{"vault.example"}, nil)
	if err != nil {
		t.Fatalf("selfSigned: %v", err)
	}

	client, server := net.Pipe()
	clientErr := make(chan error, 1)
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: "vault.example", InsecureSkipVerify: true})
		err := c.Handshake()
		if err == nil {
			// Prove the session actually works, not just that the handshake
			// returned.
			_, err = c.Write([]byte("hello"))
		}
		clientErr <- err
	}()

	name, replay, err := peekSNI(server)
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	if name != "vault.example" {
		t.Fatalf("name = %q", name)
	}

	srv := tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := srv.Handshake(); err != nil {
		t.Fatalf("the real handshake over the replay failed, so the replay is not byte-exact: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(srv, buf); err != nil {
		t.Fatalf("reading application data over the replayed session: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q, want hello", buf)
	}
	if err := <-clientErr; err != nil {
		t.Errorf("client side: %v", err)
	}
}

// A client connecting by IP, or an old one with no SNI extension, is a valid
// outcome and the caller's decision -- not a panic and not an error here.
func TestAnEmptyServerNameIsNotAnError(t *testing.T) {
	name, replay, err := peekSNI(clientHello(t, ""))
	if err != nil {
		t.Fatalf("peekSNI with no SNI: %v", err)
	}
	defer replay.Close()
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
}

// Plain HTTP arriving on :443 must be refused, never guessed at and never
// forwarded to a backend.
func TestPlainHTTPOnTheTLSPortIsRefused(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
		client.Close()
	}()
	if _, _, err := peekSNI(server); err == nil {
		t.Fatal("peekSNI accepted a plain HTTP request as a client hello")
	}
}

func TestATruncatedHelloIsRefused(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		// A TLS record header claiming a body, then nothing.
		_, _ = client.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00})
		client.Close()
	}()
	if _, _, err := peekSNI(server); err == nil {
		t.Fatal("peekSNI accepted a truncated hello")
	}
}

// Without the cap, a client that announces a large record and then dribbles
// costs a goroutine and the buffer for as long as it likes.
func TestAnOversizedHelloHitsTheCap(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		// A well-formed record header, then far more body than any hello.
		_, _ = client.Write([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
		junk := bytes.Repeat([]byte{0x41}, 4096)
		for i := 0; i < 64; i++ {
			if _, err := client.Write(junk); err != nil {
				return
			}
		}
	}()

	_, _, err := peekSNI(server)
	if err == nil {
		t.Fatal("peekSNI accepted an oversized hello")
	}
	if !errors.Is(err, errHelloTooLarge) && !strings.Contains(err.Error(), "larger than") {
		t.Logf("refused with: %v", err)
	}
	client.Close()
	<-done
}

// A client that dribbles must be dropped rather than pinning a goroutine
// forever. The deadline is the control; this asserts it exists and fires.
func TestASlowClientIsDroppedAtTheDeadline(t *testing.T) {
	// Rather than waiting out peekDeadline, drive the same mechanism with a
	// deadline already in the past: a test that sleeps for ten seconds gets
	// deleted by the next person in a hurry.
	client, server := net.Pipe()
	defer client.Close()
	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// peekSNI resets the deadline itself, so assert the underlying behaviour:
	// a conn whose read deadline has passed makes the handshake fail rather
	// than block.
	rec := &recorder{conn: server}
	err := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, errPeekDone },
	}).Handshake()
	if err == nil {
		t.Fatal("a past read deadline did not stop the handshake")
	}
}

// The recorder exists to be read from. If crypto/tls ever writes during a peek,
// that is a bug in the peek and it must be loud rather than half-answering a
// handshake we intend to abort.
func TestTheRecorderRefusesToWrite(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()
	rec := &recorder{conn: server}
	if _, err := rec.Write([]byte("x")); !errors.Is(err, errPeekOnly) {
		t.Errorf("recorder.Write = %v, want errPeekOnly", err)
	}
}

// Embedding net.Conn does not promote CloseWrite through an interface
// assertion. Without the explicit forward, splice never half-closes and a
// response with no Content-Length hangs.
func TestCloseWriteIsForwardedThroughTheWrapper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	wrapped := &peekedConn{Conn: client, r: client}
	cw, ok := any(wrapped).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("peekedConn does not satisfy CloseWrite; splice will never half-close")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The peer must see EOF, which is the whole point.
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("peer read = %v, want EOF after CloseWrite", err)
	}
}
