package transport_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/transport"
)

// A transport that answers however the test needs it to.
type fake struct {
	name string
	err  error
	// tried records that Dial was reached, so a test can prove a transport was
	// SKIPPED rather than merely that it did not win.
	tried *[]string
}

func (f fake) Dial(ctx context.Context, p transport.Peer) (net.Conn, error) {
	*f.tried = append(*f.tried, f.name)
	if f.err != nil {
		return nil, f.err
	}
	c, _ := net.Pipe()
	return c, nil
}
func (f fake) Accept(ctx context.Context) (net.Conn, transport.Peer, error) {
	return nil, transport.Peer{}, transport.ErrNotSupported
}
func (f fake) Close() error { return nil }

func peer() transport.Peer { return transport.Peer{PubSign: make([]byte, 32), Label: "quiet-otter-41"} }

func TestTheChainTakesTheFirstThatWorks(t *testing.T) {
	var tried []string
	c := transport.Chain{
		fake{name: "direct", err: transport.ErrPeerOffline, tried: &tried},
		fake{name: "relay", tried: &tried},
		fake{name: "store-and-forward", tried: &tried},
	}
	conn, err := c.Dial(t.Context(), peer())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	// Order is the caller's and is decreasing quality. A chain that reordered
	// itself "helpfully" would silently move a user's clipboard onto a relay
	// that can see the timing of every copy they make.
	if strings.Join(tried, ",") != "direct,relay" {
		t.Fatalf("tried %v; it should stop at the first success", tried)
	}
}

func TestTheChainReportsEveryReasonItFailed(t *testing.T) {
	var tried []string
	first := errors.New("ICE gathered no candidates")
	second := errors.New("the relay refused the allocation")
	c := transport.Chain{
		fake{name: "direct", err: first, tried: &tried},
		fake{name: "relay", err: second, tried: &tried},
	}

	_, err := c.Dial(t.Context(), peer())
	if err == nil {
		t.Fatal("a chain of failures returned a connection")
	}
	// "could not connect" without the reasons is a bug report nobody can act
	// on, and this is the failure users actually hit.
	for _, want := range []error{first, second} {
		if !errors.Is(err, want) {
			t.Errorf("the joined error does not carry %v: %v", want, err)
		}
	}
}

func TestACancelledDialStopsTheChain(t *testing.T) {
	var tried []string
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	c := transport.Chain{
		fake{name: "direct", err: transport.ErrPeerOffline, tried: &tried},
		fake{name: "relay", err: transport.ErrPeerOffline, tried: &tried},
	}
	if _, err := c.Dial(ctx, peer()); err == nil {
		t.Fatal("a cancelled dial returned a connection")
	}
	// Trying the next transport after the user has walked away is work nobody
	// is waiting for, and on a laptop it is work that keeps a radio awake.
	if len(tried) != 1 {
		t.Fatalf("a cancelled chain tried %v", tried)
	}
}

func TestAnEmptyChainSaysSo(t *testing.T) {
	// Rather than returning a nil connection and a nil error, which is the
	// shape that turns into a nil dereference three layers up.
	if _, err := (transport.Chain{}).Dial(t.Context(), peer()); err == nil {
		t.Fatal("an empty chain returned success")
	}
}
