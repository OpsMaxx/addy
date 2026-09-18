// Package relay is addy's embedded TURN server.
//
// TURN is the fallback when two devices cannot reach each other directly, and
// on the NAT arrangements that matter -- two symmetric NATs, or a corporate
// network that drops UDP to anything it did not initiate -- it is not a
// fallback but the only path. Running one is therefore not optional for a
// product that promises continuity.
//
// IT RELAYS CIPHERTEXT AND LEARNS THE TIMING. That is the honest description.
// A relay sees packet sizes, timing and both endpoints; it cannot read a byte,
// because everything through it is sealed to the peer's key before it is
// handed to the transport. What it can build is a picture of when this user
// copies things, which is why `--turn=coturn` exists to externalise it and why
// direct paths are tried first.
package relay

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v5"
)

// Config is what an operator chooses.
type Config struct {
	// PublicIP is the address peers will be told to send to. TURN allocations
	// carry it in the protocol, so it cannot be inferred from a listening
	// socket behind NAT -- a relay that guesses here allocates addresses
	// nobody can reach, and fails in exactly the network conditions it exists
	// for.
	PublicIP string
	// Realm appears in every credential. The hostname, so an operator reading
	// a packet capture can tell which of their boxes it came from.
	Realm string
	// Port for the UDP listener. 3478 is the registered one.
	Port int
	// MinPort and MaxPort bound the relay range.
	//
	// NARROWED TO EXCLUDE 51820, because WireGuard is on it and an operator
	// who runs both on one box would otherwise find TURN occasionally
	// allocating the port their VPN is listening on -- intermittently, under
	// load, months after install.
	MinPort, MaxPort uint16
	// Secret is the long-term key credentials are derived from. Never sent to
	// a client; the derived password is.
	Secret string
	Log    *slog.Logger
}

// DefaultPortRange is the relay range, chosen to sit clear of the ports a box
// running addy's own service wizards will want.
//
// 49152-65535 is the IANA ephemeral range and is where a TURN server belongs,
// but the top of it collides with nothing and the bottom is busy. 51820
// (WireGuard) sits below this window, which is the collision that made the
// range worth stating rather than defaulting.
const (
	DefaultMinPort uint16 = 52000
	DefaultMaxPort uint16 = 65535
	DefaultPort           = 3478
)

// CredentialTTL is how long a minted TURN credential is good for.
//
// Short, because a credential is a licence to relay traffic through somebody
// else's bandwidth, and the device that holds it has already finished using it
// within seconds. Long enough that a slow ICE gather does not expire mid-way.
const CredentialTTL = 10 * time.Minute

// Server is a running relay.
type Server struct {
	turn   *turn.Server
	secret string
	realm  string
	public string
	port   int

	mu     sync.Mutex
	closed bool
}

// Credential is what a device is given to use the relay. Derived, never
// stored: the server recomputes the password from the username when a client
// presents it, so there is no credential table to leak or to sweep.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// URL is the ICE server URL, ready to hand to a WebRTC stack.
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expiresAt"`
}

// Start binds the relay.
func Start(cfg Config) (*Server, error) {
	if cfg.Secret == "" {
		return nil, errors.New("relay: a TURN secret is required")
	}
	if cfg.PublicIP == "" {
		// Refused rather than guessed. A relay that allocates unreachable
		// addresses fails only under the NAT conditions it exists for, which
		// is to say it fails in production and works in every test.
		return nil, errors.New("relay: a public IP is required; TURN puts it in the protocol and cannot infer it behind NAT")
	}
	ip := net.ParseIP(cfg.PublicIP)
	if ip == nil {
		return nil, fmt.Errorf("relay: %q is not an IP address", cfg.PublicIP)
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.MinPort == 0 || cfg.MaxPort == 0 {
		cfg.MinPort, cfg.MaxPort = DefaultMinPort, DefaultMaxPort
	}
	if cfg.MinPort > cfg.MaxPort {
		return nil, errors.New("relay: the port range is inverted")
	}
	// Stated as a check rather than a comment: an operator narrowing the range
	// by hand can otherwise put WireGuard's port back inside it.
	if cfg.MinPort <= 51820 && 51820 <= cfg.MaxPort {
		return nil, errors.New("relay: the range includes 51820, which WireGuard uses; narrow it")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Realm == "" {
		cfg.Realm = "addy"
	}

	udp, err := net.ListenPacket("udp4", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("relay: binding UDP %d: %w", cfg.Port, err)
	}

	s := &Server{secret: cfg.Secret, realm: cfg.Realm, public: cfg.PublicIP, port: cfg.Port}

	ts, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		// Recomputed per request from the username, which carries its own
		// expiry. The alternative -- a table of issued credentials -- is state
		// that has to be swept, survives a restart it should not, and is one
		// more thing `addy panic` would have to remember to clear.
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			key, ok := s.authenticate(ra.Username, ra.Realm)
			// The userID pion reports in its own logs is the username, which
			// already carries the device -- so an operator reading a relay log
			// can see which device allocated, and still not what it sent.
			return ra.Username, key, ok
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udp,
			RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
				RelayAddress: ip,
				Address:      "0.0.0.0",
				MinPort:      cfg.MinPort,
				MaxPort:      cfg.MaxPort,
			},
		}},
	})
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("relay: starting TURN: %w", err)
	}
	s.turn = ts

	cfg.Log.Info("relay listening",
		"udp", cfg.Port,
		"public_ip", cfg.PublicIP,
		"relay_ports", fmt.Sprintf("%d-%d", cfg.MinPort, cfg.MaxPort),
	)
	return s, nil
}

// Mint issues a short-lived credential for one device.
//
// The RFC 8489 "long-term credential with a time limit" construction:
// username is `<unix expiry>:<device>` and the password is
// HMAC-SHA1(secret, username), base64. The server needs no record of what it
// issued, because it can recompute the password from the username a client
// presents -- and the username carries the expiry, so a stale credential is
// refused arithmetically rather than by lookup.
func (s *Server) Mint(device string) Credential {
	expires := time.Now().Add(CredentialTTL).Unix()
	username := strconv.FormatInt(expires, 10) + ":" + device
	return Credential{
		Username:  username,
		Password:  base64.StdEncoding.EncodeToString(sign(s.secret, username)),
		URL:       fmt.Sprintf("turn:%s:%d?transport=udp", s.public, s.port),
		ExpiresAt: expires,
	}
}

func (s *Server) authenticate(username, realm string) ([]byte, bool) {
	if realm != s.realm {
		return nil, false
	}
	colon := strings.IndexByte(username, ':')
	if colon <= 0 {
		return nil, false
	}
	expires, err := strconv.ParseInt(username[:colon], 10, 64)
	if err != nil {
		return nil, false
	}
	if time.Now().Unix() > expires {
		return nil, false
	}
	// turn.GenerateAuthKey is what pion compares against internally; the
	// password we minted is what the client presents.
	return turn.GenerateAuthKey(username, realm,
		base64.StdEncoding.EncodeToString(sign(s.secret, username))), true
}

func sign(secret, username string) []byte {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return mac.Sum(nil)
}

// Addr is the UDP address the relay is listening on, for a selftest that wants
// to prove a packet really goes through it.
func (s *Server) Addr() string {
	return net.JoinHostPort(s.public, strconv.Itoa(s.port))
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.turn.Close()
}
