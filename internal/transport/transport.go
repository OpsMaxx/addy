// Package transport is the seam between "addy has a connection to that device"
// and how it got one.
//
// IT EXISTS BEFORE EITHER IMPLEMENTATION DOES, and that ordering is the whole
// point. The design has an open bet -- WebRTC over pion, or a tailcat-style
// overlay -- and the spike that settles it has not been run. A seam written
// after the winner is chosen is a seam shaped like the winner; written before,
// deferring the decision costs nothing, and the loser can be deleted without
// touching anything above it.
//
// What is above it: clipboard send and receive, file transfer, and whatever
// continuity grows into. None of them may import a WebRTC type, a peer
// connection, an ICE candidate or a Tailscale address. If one does, the bet is
// already lost.
//
// THE PAYLOAD IS SEALED REGARDLESS OF PATH. Nothing here is a confidentiality
// boundary: a Conn may be a relayed TURN allocation on someone else's server,
// a direct UDP path across a hostile network, or an overlay with its own
// encryption. The layer above seals to the peer's key before handing bytes
// down, every time, and does not ask which of those it got.
package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

// Peer is a device on this account, named by the only thing both ends already
// agree on: its signing public key from the roster.
//
// NOT an address, a session id, or anything the server assigns. The roster is
// the authority on who exists, so a peer that is not in it cannot be named
// here, and a revoked device stops being nameable the moment the chain says
// so -- without this package needing to know what revocation is.
type Peer struct {
	// PubSign is the device's Ed25519 signing key, 32 bytes.
	PubSign []byte
	// Label is the device's pseudonym, for logs and for anything a human
	// reads. Never used for routing: two devices may share a label, and one
	// device's label changes without its key changing.
	Label string
}

// Transport is one way of reaching peers.
//
// Implementations are expected to be slow to start (ICE gathering, overlay
// login) and to fail often. Nothing here promises a connection: the contract
// is that Dial either returns one or says why, within the caller's context.
type Transport interface {
	// Dial opens a connection to one peer.
	//
	// A context, not a timeout parameter: the caller is usually a user action
	// that can be cancelled, and a transport that cannot be cancelled mid-ICE
	// leaves a spinner nobody can stop.
	Dial(ctx context.Context, peer Peer) (net.Conn, error)

	// Accept blocks until a peer connects, or the context ends.
	//
	// Modelled on net.Listener.Accept rather than a callback, because a
	// callback would run on the transport's own goroutine and every
	// implementation would then need its own answer to "what happens when the
	// handler blocks". A channel-shaped API makes that the caller's problem,
	// where it belongs.
	Accept(ctx context.Context) (net.Conn, Peer, error)

	// Close releases everything the transport holds. Always called; safe to
	// call twice.
	Close() error
}

// ErrPeerOffline is what a transport returns when the peer is reachable in
// principle but is not there now.
//
// Distinct from every other failure because it is the one the caller can do
// something useful about: it is the signal to fall back to store-and-forward
// rather than to report an error. A clipboard that only works when the other
// laptop is awake is not a clipboard, so this error is the hinge the whole
// offline path hangs on.
var ErrPeerOffline = errors.New("transport: that device is not connected")

// ErrNotSupported is for a transport that cannot do something another one can
// -- an overlay with no data channels, say. Callers degrade rather than fail.
var ErrNotSupported = errors.New("transport: not supported by this transport")

// Dialer is the half a sender needs. Split from Transport so that
// store-and-forward, which never accepts anything, can take this and not
// pretend to be a full transport.
type Dialer interface {
	Dial(ctx context.Context, peer Peer) (net.Conn, error)
}

// Chain tries several transports in order and returns the first connection.
//
// Order matters and is the caller's: direct before relayed before
// store-and-forward, because that is decreasing quality, and a chain that
// reordered itself "helpfully" would silently move a user's clipboard onto a
// relay that can see the timing of every copy they make.
//
// A transport answering ErrPeerOffline or ErrNotSupported is passed over. Any
// other error is passed over too, but REMEMBERED: if every transport fails,
// the caller gets all of them joined, because "could not connect" without the
// four reasons is a bug report nobody can act on.
type Chain []Transport

func (c Chain) Dial(ctx context.Context, peer Peer) (net.Conn, error) {
	if len(c) == 0 {
		return nil, errors.New("transport: no transports configured")
	}
	var failures []error
	for _, t := range c {
		conn, err := t.Dial(ctx, peer)
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
		// A cancelled context stops the chain. Trying the next transport after
		// the user has walked away is work nobody is waiting for, and on a
		// laptop it is work that keeps a radio awake.
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(failures...)
}

// DialTimeout is the default a caller with no better idea should use.
//
// Long enough for ICE to gather and fail over a slow network, short enough
// that a person still believes the app is doing something. Neither number is
// defensible alone; what is defensible is that one place decides it.
const DialTimeout = 20 * time.Second
