package frontdoor

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Reading the SNI without consuming it.
//
// Three ways to learn a ClientHello's server name, and only one of them works
// for BOTH of the things the front door has to do:
//
//   - tls.Server with GetConfigForClient is correct for termination and useless
//     for passthrough: by the time the callback fires, crypto/tls owns the
//     connection and has eaten the ClientHello. frps must receive those bytes
//     exactly as the client sent them.
//   - A hand-written ClientHello parser is about eighty lines of length-prefixed
//     parsing over bytes an anonymous attacker chose. Every TLS proxy that has
//     written one has at some point shipped a panic on a malformed extension.
//   - What this does: record the bytes as crypto/tls reads them, let the
//     STANDARD LIBRARY parse the hello, abort the handshake at a known point,
//     and hand on a connection that replays the recording. The parser is the
//     same one that will parse the hello for real a moment later, and we still
//     hold every byte.

var (
	// errPeekDone is a sentinel, not a failure. Returning (nil, nil) from
	// GetConfigForClient would also stop the handshake -- eventually, when the
	// ServerHello write fails -- but that makes the control flow depend on a
	// write error arriving. This stops it at a point we chose.
	errPeekDone = errors.New("frontdoor: client hello captured")

	errPeekOnly      = errors.New("frontdoor: peek connection is read-only")
	errHelloTooLarge = errors.New("frontdoor: client hello exceeds the cap")
)

const (
	// A legitimate ClientHello fits in one TLS record. The cap matters because
	// the hello is attacker-supplied: without it, a client that announces a
	// large record and then dribbles costs a goroutine and the buffer for as
	// long as it cares to.
	helloCap = 16 << 10

	// A slow client that never finishes its hello must not pin a goroutine.
	// Cleared before the connection is handed on, so it never applies to the
	// session itself.
	peekDeadline = 10 * time.Second
)

// recorder tees everything crypto/tls reads into a buffer, so the peek can be
// undone. It implements net.Conn only because tls.Server demands one.
type recorder struct {
	conn net.Conn
	buf  bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	if r.buf.Len() >= helloCap {
		return 0, errHelloTooLarge
	}
	// Never read more than the cap allows, so the buffer cannot overshoot by a
	// whole read.
	if room := helloCap - r.buf.Len(); len(p) > room {
		p = p[:room]
	}
	n, err := r.conn.Read(p)
	if n > 0 {
		r.buf.Write(p[:n])
	}
	return n, err
}

// Write is a hard error. If crypto/tls ever reaches the point of sending a
// ServerHello during a peek, that is a bug in the peek and it should be loud
// rather than half-answering a handshake we intend to abort.
func (r *recorder) Write([]byte) (int, error)          { return 0, errPeekOnly }
func (r *recorder) Close() error                       { return nil }
func (r *recorder) LocalAddr() net.Addr                { return r.conn.LocalAddr() }
func (r *recorder) RemoteAddr() net.Addr               { return r.conn.RemoteAddr() }
func (r *recorder) SetDeadline(time.Time) error        { return nil }
func (r *recorder) SetReadDeadline(t time.Time) error  { return nil }
func (r *recorder) SetWriteDeadline(t time.Time) error { return nil }

// peekedConn replays the bytes consumed while sniffing. Without it the TLS
// record header is already off the wire and both crypto/tls and a passthrough
// backend see a handshake that starts mid-message.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite has to be forwarded EXPLICITLY.
//
// peekedConn embeds net.Conn, so the embedded *net.TCPConn satisfies
// CloseWrite -- but a type assertion is made against the WRAPPER, and the
// wrapper's method set does not promote a method the interface type does not
// declare. Without this, splice never half-closes, and a backend response with
// no Content-Length hangs until something times out. That is the bug that
// surfaces three weeks later as "large responses through the tunnel hang".
func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// peekSNI reads just far enough into conn to learn the server name, and returns
// a connection that still begins with the bytes it read.
//
// An empty name is a valid outcome -- a client connecting by IP, or one with no
// SNI extension -- and is the caller's decision to make, not an error here.
func peekSNI(conn net.Conn) (name string, replay net.Conn, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return "", nil, fmt.Errorf("frontdoor: setting peek deadline: %w", err)
	}

	rec := &recorder{conn: conn}
	hsErr := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// The assignment happens before the error propagates out of
			// Handshake. That is the whole trick.
			name = hello.ServerName
			return nil, errPeekDone
		},
	}).Handshake()

	if !errors.Is(hsErr, errPeekDone) {
		// Anything else means this was not a TLS client hello -- plain HTTP
		// sent to :443, a port scanner, a truncated record. Refused, never
		// guessed at and never forwarded to a backend.
		if hsErr == nil {
			hsErr = errors.New("handshake completed during a peek")
		}
		return "", nil, fmt.Errorf("frontdoor: peek: %w", hsErr)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", nil, fmt.Errorf("frontdoor: clearing peek deadline: %w", err)
	}
	return name, &peekedConn{
		Conn: conn,
		r:    io.MultiReader(bytes.NewReader(rec.buf.Bytes()), conn),
	}, nil
}
