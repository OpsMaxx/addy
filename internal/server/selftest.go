package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/store"
)

// Selftest proves a running instance actually works, rather than that its
// process started.
//
// The distinction is the whole point. A relay that is up and cannot relay is
// the worst first impression the product can make, and "the container is
// running" is exactly the evidence that produces it.
//
// quick is what the container healthcheck runs every thirty seconds: it checks
// the instance is answering over its own TLS and stops there. The full run adds
// the checks that need more than one round trip.
func Selftest(ctx context.Context, target string, quick bool) error {
	return SelftestWith(ctx, SelftestOptions{Target: target, Quick: quick})
}

// SelftestOptions is the full run's inputs.
type SelftestOptions struct {
	Target string
	Quick  bool
	// DataDir lets the selftest mint its own invite when it is running ON the
	// box. Without it the cycle needs a token: an invite IS the authorization
	// to register, so a selftest that could register without one would be a
	// selftest that proved the invite check does not work.
	DataDir string
	Invite  string
	// Insecure accepts a self-signed certificate, for `-dev`.
	Insecure bool
	// Connect is the address to dial instead of resolving Target, which
	// still names the host: it is the SNI and the Host header.
	//
	// It exists for the probes. The front door drops every name it has no
	// route for -- `localhost` included, outside dev -- so a probe that
	// targets localhost fails forever, and one that targets the domain goes
	// out through public DNS and depends on the provider hairpinning the
	// box's own address back to it. Dialling loopback while naming the
	// domain asks the question a probe means: does THIS process answer for
	// the name it serves?
	Connect string
}

func SelftestWith(ctx context.Context, opts SelftestOptions) error {
	target := opts.Target
	if target == "" {
		target = os.Getenv("ADDY_DOMAIN")
	}
	if target == "" {
		return errors.New("selftest needs a target: pass -target, or set ADDY_DOMAIN")
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	meta, err := fetchMeta(ctx, target, opts.Connect)
	if err != nil {
		return err
	}
	fmt.Printf("  %s is answering: addy %s (%s)\n", target, meta.Version, meta.Build)

	if opts.Quick {
		return nil
	}

	token, cleanup, err := selftestInvite(ctx, opts)
	if err != nil {
		return err
	}
	defer cleanup()

	return runCycle(ctx, target, token, opts)
}

// selftestInvite obtains a token, and returns the cleanup that removes
// whatever the run created.
//
// A selftest that leaves an account behind is a selftest an operator runs once
// and then stops running, because the admin list fills with debris. The
// cleanup runs on every exit including the failures -- a failed run leaves
// MORE behind than a passing one, which is exactly when tidying matters.
func selftestInvite(ctx context.Context, opts SelftestOptions) (string, func(), error) {
	noop := func() {}
	if opts.Invite != "" {
		return opts.Invite, noop, nil
	}
	if opts.DataDir == "" {
		return "", noop, errors.New(
			"the full selftest needs to register an account, which needs an invite.\n" +
				"Run it on the box with -data, or pass -invite with a token from `addy invite`")
	}
	db, err := store.Open(filepath.Join(opts.DataDir, "addy.db"))
	if err != nil {
		return "", noop, fmt.Errorf("opening the database at %s: %w", opts.DataDir, err)
	}
	token, err := db.NewInvite(ctx, 5*time.Minute)
	if err != nil {
		db.Close()
		return "", noop, err
	}
	return token, func() {
		defer db.Close()
		// Everything the run created, found by the label it registers under
		// rather than remembered across a failure -- a run that panicked
		// halfway has no list to consult, and that is exactly the run that
		// leaves debris.
		clean := context.WithoutCancel(ctx)
		accounts, err := db.Accounts(clean)
		if err != nil {
			return
		}
		for _, a := range accounts {
			if a.Devices == 1 && time.Since(a.CreatedAt) < 10*time.Minute && a.UsedBytes < 4096 {
				// Conservative on purpose: this deletes accounts on somebody's
				// live relay. One device, created in the last ten minutes, and
				// holding less than a page of data is the shape of a selftest
				// account and not of a person's.
				_ = db.DeleteAccount(clean, a.AccountID)
			}
		}
	}, nil
}

// runCycle is the part that proves the thing works rather than that it started.
func runCycle(ctx context.Context, target, invite string, opts SelftestOptions) error {
	base := "https://" + target
	first := client.New(base, opts.Insecure)
	if opts.Connect != "" {
		first.HTTP.Transport.(*http.Transport).DialContext = dialOnly(opts.Connect)
	}

	acct, err := first.Register("selftest-first", invite)
	if err != nil {
		return fmt.Errorf("a device could not mint an account: %w", err)
	}
	if err := first.Login(); err != nil {
		return fmt.Errorf("the new device could not log in: %w", err)
	}
	fmt.Println("  a device minted an account and logged in")

	// The roster, verified under the keys the DEVICE holds rather than any the
	// server offered. A chain verified against a key the server supplied is
	// not verified, and a selftest that skipped that would be checking the
	// wrong thing in the most important place.
	v, err := first.Roster(
		acct.Root.Sign.Public().(ed25519.PublicKey),
		acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		return fmt.Errorf("the roster did not verify from genesis: %w", err)
	}
	fmt.Printf("  the roster verified from genesis: %d device(s), head at seq %d\n", len(v.Devices), v.HeadSeq)

	// A sealed object round-trips. The bytes are opaque here on purpose --
	// this is checking the relay stores and returns what it was given, which
	// is the whole of its job for sync.
	payload := []byte("selftest object, sealed elsewhere")
	if _, err := first.PutObject("selftest", 1, 1, payload, ""); err != nil {
		return fmt.Errorf("an object could not be stored: %w", err)
	}
	back, err := first.GetObject("selftest", 1)
	if err != nil {
		return fmt.Errorf("an object could not be read back: %w", err)
	}
	if !bytes.Equal(back.Body, payload) {
		return fmt.Errorf("the object came back altered: %q", back.Body)
	}
	fmt.Println("  an object round-tripped byte for byte")

	// Store-and-forward, to this same device: the mailbox does not care
	// whether the sender and recipient differ, and a second device would need
	// a full pairing exchange that has its own test.
	me := acct.Device.Sign.Public().(ed25519.PublicKey)
	if _, err := first.LeaveMail(me, "selftest", []byte("sealed message")); err != nil {
		return fmt.Errorf("a message could not be left for an offline device: %w", err)
	}
	mail, err := first.CollectMail()
	if err != nil {
		return fmt.Errorf("mail could not be collected: %w", err)
	}
	if len(mail) == 0 {
		return errors.New("a message was accepted and then not delivered")
	}
	if _, err := first.AckMail([]int64{mail[0].ID}); err != nil {
		return fmt.Errorf("mail could not be acknowledged: %w", err)
	}
	fmt.Printf("  store-and-forward delivered %d message(s) and cleared them\n", len(mail))

	// The relay. What this can check from outside is what the instance TELLS a
	// device; whether a packet is actually relayed is proved by
	// internal/relay's own test, which can watch both ends. Saying which is
	// which matters more than claiming the stronger one.
	turnMode, turnURL, err := first.Turn()
	if err != nil {
		return fmt.Errorf("the instance would not say how to relay: %w", err)
	}
	switch turnMode {
	case "embedded":
		// Issued, not proved. Whether 3478 and the relay range reach this
		// box from outside is a firewall question nothing in here can see,
		// and saying "runs a relay" alone read as if it had been checked.
		fmt.Println("  the instance runs a relay and issued a credential for it;")
		fmt.Println("  NOT checked: that 3478/udp and 61000-65535/udp reach it from outside")
	case "external":
		fmt.Printf("  the instance points devices at an external relay: %s\n", turnURL)
	default:
		fmt.Println("  NO RELAY is configured: devices on networks that need one will not connect")
	}

	fmt.Println("\naddy is working.")
	return nil
}

type meta struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

// dialOnly sends every connection to addr, whatever the URL's host says.
func dialOnly(addr string) func(context.Context, string, string) (net.Conn, error) {
	var d net.Dialer
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
}

func fetchMeta(ctx context.Context, target, connect string) (meta, error) {
	tr := &http.Transport{
		// A self-signed development certificate must not make the
		// healthcheck fail, and this request goes to the instance's own
		// loopback. What is being proved here is that the process answers
		// over TLS at all -- the certificate's trustworthiness is
		// preflight's job, and it uses a real CA to answer it.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if connect != "" {
		tr.DialContext = dialOnly(connect)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}

	url := "https://" + target + "/v1/meta"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return meta{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return meta{}, fmt.Errorf(`%s is not answering over TLS: %w

The relay is not serving. Check its logs; if it has only just started, a first
boot includes a real certificate order and is not instant`, target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return meta{}, fmt.Errorf(`%s answered %s rather than 200

Something is listening and it is not addy, or addy has no route for this
hostname -- which it refuses rather than serving somebody else's name`,
			url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return meta{}, fmt.Errorf("reading %s: %w", url, err)
	}
	var m meta
	if err := json.Unmarshal(body, &m); err != nil {
		return meta{}, fmt.Errorf("%s did not return addy's own metadata: %w", url, err)
	}
	if m.Version == "" {
		return meta{}, fmt.Errorf("%s answered, but not with an addy version; something else is on this hostname", url)
	}
	return m, nil
}
