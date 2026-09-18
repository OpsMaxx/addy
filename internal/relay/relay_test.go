package relay_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/relay"
	"github.com/pion/turn/v5"
)

// A relay on loopback. 127.0.0.1 is a legitimate "public IP" here: the point
// of that field is that TURN puts the address in the protocol, and on loopback
// the address it should put there is loopback.
func start(t *testing.T) *relay.Server {
	t.Helper()
	s, err := relay.Start(relay.Config{
		PublicIP: "127.0.0.1",
		Realm:    "addy.test",
		Port:     freeUDPPort(t),
		Secret:   "a-test-secret-and-nothing-more",
	})
	if err != nil {
		t.Fatalf("relay.Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// THE M0 GATE: a real packet goes in one side and comes out the other.
//
// Not "the server started", not "the credential verifies" -- those both pass
// against a relay that allocates a port and drops everything. Two clients, one
// allocation, one datagram, compared byte for byte.
func TestTheRelayRelaysAnActualPacket(t *testing.T) {
	s := start(t)
	cred := s.Mint("device-one")

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: s.Addr(),
		TURNServerAddr: s.Addr(),
		Conn:           conn,
		Username:       cred.Username,
		Password:       cred.Password,
		Realm:          "addy.test",
	})
	if err != nil {
		t.Fatalf("turn.NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Listen(); err != nil {
		t.Fatalf("client listen: %v", err)
	}

	// The allocation is the relayed address the far side will send to.
	relayed, err := c.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer relayed.Close()

	// The far side: an ordinary UDP socket with no TURN involvement at all,
	// which is the realistic shape -- one peer behind a symmetric NAT using
	// the relay, the other reachable.
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	// Permission for the peer to reach the allocation. Without it TURN drops
	// the inbound packet, which is the anti-amplification rule doing its job.
	payload := []byte("sealed bytes that the relay cannot read")
	go func() {
		for i := 0; i < 10; i++ {
			_, _ = relayed.WriteTo(payload, peer.LocalAddr())
			time.Sleep(50 * time.Millisecond)
		}
	}()

	_ = peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the peer never received the relayed packet: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("the relay altered the payload: %q", buf[:n])
	}
	// It arrived from the ALLOCATION, not from the sender's own socket, which
	// is what proves it went through the relay rather than around it.
	if from.String() == conn.LocalAddr().String() {
		t.Fatal("the packet came direct from the client socket; nothing was relayed")
	}
}

func TestAnExpiredCredentialIsRefused(t *testing.T) {
	s := start(t)

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A credential whose expiry has passed. The username carries it, so this
	// is refused arithmetically -- there is no table of issued credentials to
	// consult, which is the point of deriving them.
	expired := "1:device-one"
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: s.Addr(),
		TURNServerAddr: s.Addr(),
		Conn:           conn,
		Username:       expired,
		Password:       "whatever",
		Realm:          "addy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Allocate(); err == nil {
		t.Fatal("an expired credential was allocated a relay")
	}
}

func TestAForgedPasswordIsRefused(t *testing.T) {
	s := start(t)
	cred := s.Mint("device-one")

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: s.Addr(),
		TURNServerAddr: s.Addr(),
		Conn:           conn,
		// A live username with a password the holder guessed. Relaying is
		// somebody else's bandwidth, so an open relay is an abuse complaint
		// with the operator's name on it.
		Username: cred.Username,
		Password: "not-the-derived-one",
		Realm:    "addy.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Allocate(); err == nil {
		t.Fatal("a forged password was allocated a relay")
	}
}

// The collision that made the port range worth stating rather than defaulting.
func TestTheRelayRangeRefusesToIncludeWireGuardsPort(t *testing.T) {
	_, err := relay.Start(relay.Config{
		PublicIP: "127.0.0.1",
		Secret:   "s",
		Port:     freeUDPPort(t),
		MinPort:  51000,
		MaxPort:  52000,
	})
	if err == nil {
		t.Fatal("a range spanning 51820 was accepted")
	}
	if !strings.Contains(err.Error(), "51820") {
		t.Fatalf("the refusal does not say which port: %v", err)
	}
}

// A relay that guesses its public address allocates addresses nobody can
// reach, and fails only under the NAT conditions it exists for -- which is to
// say it fails in production and works in every test.
func TestTheRelayRefusesToGuessItsPublicAddress(t *testing.T) {
	if _, err := relay.Start(relay.Config{Secret: "s", Port: 0}); err == nil {
		t.Fatal("a relay started with no public IP")
	}
}

func TestTheRelayNeedsASecret(t *testing.T) {
	if _, err := relay.Start(relay.Config{PublicIP: "127.0.0.1"}); err == nil {
		t.Fatal("a relay started with no secret; it would be an open relay")
	}
}
