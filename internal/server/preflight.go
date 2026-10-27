package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
)

// Preflight answers the one question a shell on this box cannot answer for
// itself: can the world reach port 80?
//
// An installer can rule out the causes that are visible from here -- something
// already bound to the port, a local firewall -- and then it is out of options.
// It cannot see a provider firewall, a security group, a NAT rule, or a DNS
// record pointing at a different machine. Every check that tries to infer
// inbound reachability from inside is a check that passes on a box where the
// product will not work.
//
// So this does the only test that exercises the same path the real order will:
// a REAL ACME HTTP-01 ORDER, against Let's Encrypt's STAGING directory. Staging
// because its rate limits are generous and a failed attempt there costs
// nothing, while the same attempt against production burns one of five failed
// validations per hostname per hour -- turning a diagnostic into an outage for
// the rest of the hour.
//
// The error text is the deliverable. It is what distinguishes "the provider
// firewall is closed" from "DNS points somewhere else" from "something else is
// on :80", and no locally-inferred check produces any of those.
func Preflight(ctx context.Context, domain string) error {
	fmt.Printf("preflight: %s\n", domain)

	// Cheap local checks first, so an obvious problem is named in a second
	// rather than after a round trip to a CA.
	switch err := portIsFree(":80"); {
	case err == nil:
		fmt.Println("  port 80 is free on this box")
	case errors.Is(err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		// Binding a privileged port without privilege is a fact about how this
		// command was run, not about the box. Reporting it as "something is
		// already listening" sends the operator to look for a web server that
		// is not there.
		return fmt.Errorf(`cannot bind port 80 as this user: %w

Run preflight with sudo, or grant the capability:
  sudo setcap CAP_NET_BIND_SERVICE=+eip %s`, err, self())
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf(`something is already listening on port 80: %w

addy must own port 80, because that is where the ACME HTTP-01 challenge
arrives. Stop whatever holds it -- often nginx, apache or caddy -- and run
this again`, err)
	default:
		return fmt.Errorf("cannot bind port 80: %w", err)
	}

	if err := resolvesSomewhere(ctx, domain); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "addy-preflight-*")
	if err != nil {
		// Said as what it is. The installer used to report every preflight
		// failure as an unreachable port 80, and this one -- a container
		// image with no /tmp -- sent operators to their provider's firewall.
		return fmt.Errorf(`preflight could not create a scratch directory: %w

This is about where preflight is running, not about the network: nothing
has been sent to a CA. It needs a writable temporary directory -- /tmp, or
wherever TMPDIR points`, err)
	}
	defer os.RemoveAll(dir)

	// A throwaway certmagic, entirely separate from the server's: its own
	// storage, its own account, the staging CA. Nothing it obtains is kept,
	// and nothing it does touches the real instance's account or its rate
	// limits.
	cfg := certmagic.NewDefault()
	cfg.Storage = &certmagic.FileStorage{Path: dir}
	cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptStagingCA,
		Agreed: true,
	})}

	fmt.Println("  ordering a staging certificate (this proves the world can reach port 80)")
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	if err := cfg.ObtainCertSync(ctx, domain); err != nil {
		return fmt.Errorf(`the staging certificate order failed: %w

This is the real test, so the failure above is the real reason. The three
causes, in the order they actually occur:

  1. Port 80 is not reachable from the internet. A provider firewall or
     security group is separate from the firewall on this box, and is not
     visible from a shell here. Open inbound TCP 80 and 443.
  2. DNS for %s does not point at this machine, or has not propagated.
     Check it from off-box, not with a local resolver -- the local one
     answers from /etc/hosts and from a stale cache.
  3. Something else answered the challenge. If another web server is
     configured on this host it may be serving the well-known path.`, err, domain)
	}

	fmt.Println("  the staging order succeeded")
	fmt.Println()
	fmt.Println("This box can obtain a certificate. Nothing obtained here is kept -- the")
	fmt.Println("real order happens on first start, against the production CA.")
	return nil
}

func portIsFree(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// resolvesSomewhere is deliberately a weak check with a strong error.
//
// Comparing the resolved address to this box's own addresses sounds better and
// is wrong: behind NAT, on any cloud instance with a public address it cannot
// see locally, the comparison fails for a box that works perfectly. So this
// only catches the case where the name resolves to nothing at all, and leaves
// the real verdict to the ACME order.
//
// ASKED OF A PUBLIC RESOLVER, NOT THIS BOX'S. The question is whether the
// WORLD can find this name, and the local resolver answers a different one:
// on a Contabo instance `net.DefaultResolver` consults /etc/hosts first and
// reports the hostname as 127.0.1.1, which is true locally and useless here.
// A preflight that prints a loopback address for a name that resolves
// perfectly well in public is a preflight that sends an operator to debug DNS
// that is already correct. Found by running it on a real box.
func resolvesSomewhere(ctx context.Context, domain string) error {
	addrs, via, err := lookupPublic(ctx, domain)
	if err != nil {
		return fmt.Errorf(`%s does not resolve: %w

DNS has to be live BEFORE the certificate can be obtained, not eventually.
Add the record, wait for it, and run this again`, domain, err)
	}
	fmt.Printf("  %s resolves to %v (asked %s)\n", domain, addrs, via)
	return nil
}

// publicResolvers are asked in order. Two, from different operators, because
// one being unreachable is a network policy rather than a DNS answer.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// lookupPublic resolves via a public resolver, falling back to this box's own
// and SAYING SO when it does.
//
// The fallback matters on a box whose egress to port 53 is blocked, which is a
// legitimate configuration -- and there the local answer is the only one
// available. What must not happen is reporting a local answer as though it
// were the public one, which is the bug this replaced.
func lookupPublic(ctx context.Context, domain string) (addrs []string, via string, err error) {
	for _, server := range publicResolvers {
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		got, lookupErr := queryA(lookupCtx, server, domain)
		cancel()
		if lookupErr == nil && len(got) > 0 {
			return got, server, nil
		}
		err = lookupErr
	}

	// Every public resolver refused or was unreachable. The local one is the
	// only answer left, and the caller is told which it got.
	got, localErr := net.DefaultResolver.LookupHost(ctx, domain)
	if localErr != nil {
		if err == nil {
			err = localErr
		}
		return nil, "", err
	}
	return got, "this box's own resolver -- no public resolver was reachable, so this may not be what the world sees", nil
}

// self is the path to this binary, for the setcap hint. A hint naming the
// wrong path is worse than no hint, so an unknowable path degrades to the
// command name rather than guessing.
func self() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "addy"
}
