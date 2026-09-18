// Command addy is the OpsMaxx satellite relay.
//
// It is a single static binary. Everything it does -- relaying, signalling,
// storing opaque blobs, deploying services -- it does without ever holding a
// key that could open a user's data. See THREAT_MODEL.md for what that does and
// does not mean.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/opsmaxx/addy/internal/server"
)

// Stamped by the build script with -ldflags -X. The defaults are what a plain
// `go build` produces, and they are deliberately obvious rather than plausible:
// a version string that looks real but is not is worse in a bug report than one
// that says it was never stamped.
var (
	Version  = "0.0.0-dev"
	BuildSha = "unknown"
)

const usage = `addy -- the OpsMaxx satellite relay

Usage:
  addy <command> [flags]

Commands:
  serve       Run the relay
  preflight   Check this box can actually obtain a certificate, before installing
  selftest    Prove a running instance actually works end to end
  join        Print the addy:// string a device uses to add this instance
  panic       Rotate every secret this box holds and stop serving devices
  reonboard   Show or clear the reonboard-required flag panic and reset set
  reset       Delete every account on this box (--hard), after showing what goes
  version     Print version information

Run "addy <command> -h" for the flags a command takes.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "selftest":
		err = selftest(args)
	case "preflight":
		err = preflight(args)
	case "join":
		err = join(args)
	case "panic":
		err = panicCmd(args)
	case "reonboard":
		err = reonboard(args)
	case "reset":
		err = reset(args)
	case "version", "--version", "-version":
		printVersion()
		return
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "addy: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		// A cancelled context is how a clean shutdown arrives here, not a
		// failure. Exiting non-zero for it would make every orderly stop look
		// like a crash to whatever supervises the process.
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "addy: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("addy %s (%s) %s %s/%s\n",
		Version, BuildSha, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var cfg server.Config
	fs.StringVar(&cfg.DataDir, "data-dir", server.DefaultDataDir, "Directory for the metadata database and local state")
	fs.BoolVar(&cfg.Dev, "dev", false, "Localhost mode: self-signed certificate, no domain, no ACME, blobs on local disk")
	fs.StringVar(&cfg.Addr, "addr", "", "TLS address to bind (default :443, or 127.0.0.1:8443 with -dev)")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", "", "Plain HTTP address to bind (default :80, or 127.0.0.1:8080 with -dev). ACME HTTP-01 arrives here or not at all")
	fs.StringVar(&cfg.Email, "email", "", "Contact address for the ACME account, so the CA can warn you before a renewal fails")
	fs.StringVar(&cfg.Domain, "domain", "", "The hostname this instance answers on. Seeds the routing table on a fresh install")
	fs.BoolVar(&cfg.UI, "ui", false, "Serve the web portal")
	fs.StringVar(&cfg.TurnPublicIP, "turn-public-ip", "",
		"Public IP to advertise for the embedded TURN relay. Without it no relay runs: TURN puts this address in the protocol and cannot infer it behind NAT")
	fs.IntVar(&cfg.TurnPort, "turn-port", 0, "UDP port for the embedded TURN relay (default 3478)")
	fs.StringVar(&cfg.TurnSecret, "turn-secret", "",
		"Long-term secret TURN credentials are derived from. Generated and stored on first run if unset")
	fs.StringVar(&cfg.TurnExternal, "turn", "",
		"Use an external TURN server instead of the embedded one, as turn:host:port. Devices are told to use it and this box relays nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Environment fills in only what a flag did not set. Flags win, because a
	// person typing one on the command line is answering a question the
	// environment answered earlier and less specifically.
	//
	// Only the variables something actually reads are listed. The compose file
	// sets several more for the object store and TURN; those arrive with the
	// milestones that use them, and wiring a variable to nothing now would
	// mean an operator setting it and watching it do nothing.
	envDefault(&cfg.DataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	envDefault(&cfg.Domain, "ADDY_DOMAIN", "")
	envDefault(&cfg.Email, "ADDY_ACME_EMAIL", "")
	envDefault(&cfg.TurnPublicIP, "ADDY_TURN_PUBLIC_IP", "")
	envDefault(&cfg.TurnSecret, "ADDY_TURN_SECRET", "")
	envDefault(&cfg.TurnExternal, "ADDY_TURN_EXTERNAL", "")

	cfg.Version = Version
	cfg.BuildSha = BuildSha

	// Signals are the same event as an orderly shutdown request, so they
	// cancel the same context rather than taking a separate path that would
	// then have to be kept in step with it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.Run(ctx, cfg)
}

func selftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	target := fs.String("target", "", "Instance to test (default: the local one)")
	// -quick is what the container healthcheck runs. It must not perform a
	// full pair/sync/revoke/recover cycle every thirty seconds.
	quick := fs.Bool("quick", false, "Check the instance is answering, without running a full cycle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return server.Selftest(context.Background(), *target, *quick)
}

// preflight answers the one question a shell on the box cannot answer for
// itself: whether the world can reach port 80.
func preflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	domain := fs.String("domain", "", "The hostname to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(domain, "ADDY_DOMAIN", "")
	if *domain == "" {
		return errors.New("preflight needs -domain")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Preflight(ctx, *domain)
}

func join(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	target := fs.String("target", "", "The instance to print a join string for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(target, "ADDY_DOMAIN", "")
	if *target == "" {
		return errors.New("join needs -target, or ADDY_DOMAIN in the environment")
	}
	s, err := server.JoinString(context.Background(), *target)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

// envDefault fills target from the environment if a flag left it empty, and
// falls back to fallback if neither said anything.
func envDefault(target *string, key, fallback string) {
	if *target != "" {
		return
	}
	if v := os.Getenv(key); v != "" {
		*target = v
		return
	}
	*target = fallback
}

// panicCmd is `panic`. Named with the suffix because `panic` is a builtin and
// a function shadowing it in this file would be a trap for the next person to
// add error handling here.
func panicCmd(args []string) error {
	fs := flag.NewFlagSet("panic", flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	keepCerts := fs.Bool("keep-certs", false,
		"Do not delete the ACME account key and certificates. Only when the compromise cannot have touched them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	return server.Panic(context.Background(), server.PanicOptions{
		DataDir: *dataDir, KeepCerts: *keepCerts,
	})
}

func reonboard(args []string) error {
	fs := flag.NewFlagSet("reonboard", flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	clear := fs.Bool("clear", false, "Clear the flag and serve devices again")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	return server.Reonboard(context.Background(), server.ReonboardOptions{
		DataDir: *dataDir, Clear: *clear,
	})
}

func reset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	hard := fs.Bool("hard", false, "Actually delete. Without it, reset only says what would go")
	yes := fs.Bool("yes", false, "Skip the confirmation. For installers and tests, not for people")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	return server.Reset(context.Background(), server.ResetOptions{
		DataDir: *dataDir, Hard: *hard, Yes: *yes,
	})
}
