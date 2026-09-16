package frontdoor

import (
	"net"
	"sync"
)

// connListener hands already-accepted, already-sniffed connections to
// http.Server.Serve.
//
// http.Server insists on owning a net.Listener, and nothing in net/http lets a
// connection be routed after it has been accepted. Since the front door has to
// accept first -- it cannot know whether to terminate or splice until it has
// read the SNI -- the listener is the thing that gets faked, rather than the
// server being rewritten.
type connListener struct {
	conns    chan net.Conn
	addr     net.Addr
	done     chan struct{}
	closeOne sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		conns: make(chan net.Conn),
		addr:  addr,
		done:  make(chan struct{}),
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close is idempotent. http.Server.Serve closes its listener on shutdown and
// the door closes it too; closing a channel twice panics, and a panic during
// shutdown is the kind that gets misread as the cause of whatever prompted the
// shutdown.
func (l *connListener) Close() error {
	l.closeOne.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

// hand passes a connection to the HTTP server, or closes it if the door is
// shutting down.
//
// Returning rather than blocking forever matters: without the done case, a
// connection arriving after Shutdown would park a goroutine on a channel nobody
// will ever read, and the process would not exit.
func (l *connListener) hand(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}
