package frontdoor

import (
	"io"
	"net"
	"sync"
)

// The buffer each direction of a splice uses.
//
// Fixed and modest on purpose. "A reliable proxy library with high throughput"
// is the wrong thing to reach for here, because this is not proxying: it is
// io.Copy between two streams of bytes addy cannot read. The throughput risk in
// that shape is unbounded buffering behind a slow reader, and the answer to
// unbounded buffering is to bound it, not to add a dependency.
const spliceBuf = 32 << 10

var spliceBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, spliceBuf)
		return &b
	},
}

// splice moves bytes between a client and a backend until both directions end,
// then closes both.
//
// The half-close is the part that is easy to leave out and expensive to debug.
// An HTTP response with no Content-Length is terminated by the server closing
// its side; if the client's EOF is never propagated as a FIN to the backend,
// the backend waits for a request that has already finished and the exchange
// hangs until a timeout somebody will blame on the network.
func splice(client, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := spliceBufPool.Get().(*[]byte)
		defer spliceBufPool.Put(buf)
		// CopyBuffer rather than Copy: Copy would allocate 32 KiB per
		// direction per connection, and a relay's whole job is many idle
		// connections.
		_, _ = io.CopyBuffer(dst, src, *buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}

	go cp(backend, client)
	go cp(client, backend)
	wg.Wait()

	client.Close()
	backend.Close()
}
