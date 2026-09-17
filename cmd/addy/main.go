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
  selftest    Prove a running instance actually works end to end
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
	fs.BoolVar(&cfg.UI, "ui", false, "Serve the web portal")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return server.Selftest(context.Background(), *target)
}
