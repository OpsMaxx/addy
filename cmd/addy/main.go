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
	"strings"
	"syscall"
	"time"

	"github.com/opsmaxx/addy/internal/frontdoor"
	"github.com/opsmaxx/addy/internal/server"
	"github.com/opsmaxx/addy/internal/services"
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
  invite      Mint the token a device needs in order to register
  join        Print the addy:// string a device uses to add this instance
  panic       Rotate every secret this box holds and stop serving devices
  reonboard   Show or clear the reonboard-required flag panic and reset set
  reset       Delete every account on this box (--hard), after showing what goes
  unclaim     Forget who claimed the operator console, so the next sign-in claims it
  service     List, check, preview and install the services addy can deploy beside itself
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
	case "invite":
		err = invite(args)
	case "join":
		err = join(args)
	case "panic":
		err = panicCmd(args)
	case "reonboard":
		err = reonboard(args)
	case "reset":
		err = reset(args)
	case "unclaim":
		err = unclaim(args)
	case "service", "services":
		err = service(args)
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
	// THE DEFAULT IS SUPPLIED BY envDefault BELOW, NOT HERE, and that is
	// load-bearing rather than a style choice. envDefault leaves a value alone
	// once something has set it, so a flag declared with a non-empty default is
	// indistinguishable from one the operator passed — and the environment
	// variable is then read, found, and thrown away. Both shipped deployments
	// set ADDY_DATA_DIR (deploy/compose/docker-compose.yml and the Helm
	// StatefulSet), and for as long as this line carried the default they were
	// both silently ignored. Any flag with an ADDY_* variable belongs here with
	// "" and its default in the envDefault call.
	fs.StringVar(&cfg.DataDir, "data-dir", "", "Directory for the metadata database and local state (default "+server.DefaultDataDir+")")
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
	staging := fs.Bool("acme-staging", false,
		"Use Let's Encrypt's staging CA. Certificates are untrusted by browsers; use it when testing on a hostname you do not own, because production rate limits are per registered domain and a hoster's default hostname is shared with every other customer")
	fs.StringVar(&cfg.ACMECA, "acme-ca", "", "ACME directory URL. Overrides -acme-staging")
	fs.StringVar(&cfg.HeadscaleURL, "headscale-url", "",
		"headscale's API base URL, for minting overlay join keys. Usually http://127.0.0.1:8080 when the wizard deployed it")
	fs.StringVar(&cfg.HeadscaleAPIKey, "headscale-apikey", "",
		"headscale API key. Powerful: it can create and delete nodes, users and keys across the whole coordination server")
	fs.StringVar(&cfg.HeadscaleUser, "headscale-user", "addy",
		"headscale user that owns the joined nodes. One per account keeps the node list readable")
	fs.StringVar(&cfg.Signup, "signup", "",
		"Who may sign in besides the operator: `open` gives anybody who signs in an invite on request (right when the provider already IS your membership list, such as Google Workspace Internal), `invite` lets anybody sign in but gives storage only to people you admit from the console's People list, who then set up their own devices, `closed` lets nobody but you sign in (existing members' devices keep syncing). Default: invite")
	fs.StringVar(&cfg.OIDCIssuer, "oidc-issuer", "",
		"Identity provider for the operator portal, as an OIDC issuer URL — https://accounts.google.com for Google. Without all three -oidc flags no portal is served and you administer this relay with the addy command")
	fs.StringVar(&cfg.OIDCClientID, "oidc-client-id", "",
		"OAuth client id for the operator portal. The redirect URI to register with the provider is https://<your-domain>/admin/callback")
	fs.StringVar(&cfg.OIDCClientSecret, "oidc-client-secret", "",
		"OAuth client secret for the operator portal. PREFER THE ENVIRONMENT: leave this unset and put the value in ADDY_OIDC_CLIENT_SECRET, because a secret passed as a flag is in /proc/<pid>/cmdline and every ps on the box. THE FIRST PERSON TO SIGN IN CLAIMS THIS RELAY and everybody after has to be them; without that, every account at the provider would be an administrator here")
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
	// sets several more for the object store; those arrive with the
	// milestone that uses them, and wiring a variable to nothing now would
	// mean an operator setting it and watching it do nothing.
	envDefault(&cfg.DataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	envDefault(&cfg.Domain, "ADDY_DOMAIN", "")
	envDefault(&cfg.Email, "ADDY_ACME_EMAIL", "")
	envDefault(&cfg.TurnPublicIP, "ADDY_TURN_PUBLIC_IP", "")
	envDefault(&cfg.TurnSecret, "ADDY_TURN_SECRET", "")
	envDefault(&cfg.TurnExternal, "ADDY_TURN_EXTERNAL", "")
	envDefault(&cfg.HeadscaleURL, "ADDY_HEADSCALE_URL", "")
	envDefault(&cfg.HeadscaleAPIKey, "ADDY_HEADSCALE_APIKEY", "")
	envDefault(&cfg.Signup, "ADDY_SIGNUP", "invite")
	envDefault(&cfg.OIDCIssuer, "ADDY_OIDC_ISSUER", "")
	envDefault(&cfg.OIDCClientID, "ADDY_OIDC_CLIENT_ID", "")
	// THE SECRET SHOULD COME FROM HERE, not from a flag.
	//
	// systemd expands `${VAR}` in an ExecStart into the argv it executes, so
	// a unit that passes the secret as a flag puts it in /proc/<pid>/cmdline
	// and in every `ps` on the box — which is the thing an EnvironmentFile was
	// chosen to avoid. Read here, the value stays in the process environment,
	// which is readable only by the process owner and root.
	envDefault(&cfg.OIDCClientSecret, "ADDY_OIDC_CLIENT_SECRET", "")

	if cfg.ACMECA == "" && *staging {
		cfg.ACMECA = frontdoor.LetsEncryptStaging
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
	// -quick is what the container healthcheck runs. It must not perform a
	// full register/sync/mail cycle every thirty seconds.
	quick := fs.Bool("quick", false, "Check the instance is answering, without running a full cycle")
	dataDir := fs.String("data", "",
		"Data directory, so a run ON the box can mint its own invite and tidy up after itself")
	inviteToken := fs.String("invite", "",
		"An invite token, for a run from somewhere else. An invite IS the authorization to register, so the cycle needs one")
	insecure := fs.Bool("insecure", false, "Accept a self-signed certificate, for -dev instances")
	connect := fs.String("connect", "",
		"Dial this address (e.g. 127.0.0.1:443) instead of resolving -target, which still names the host. What the probes use: the front door refuses every name but its own, localhost included")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", "")
	return server.SelftestWith(context.Background(), server.SelftestOptions{
		Target:   *target,
		Quick:    *quick,
		DataDir:  *dataDir,
		Invite:   *inviteToken,
		Insecure: *insecure,
		Connect:  *connect,
	})
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

func unclaim(args []string) error {
	fs := flag.NewFlagSet("unclaim", flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	return server.Unclaim(context.Background(), *dataDir, nil)
}

// service is the wizards.
//
// Four verbs and no interactive prompt loop. A wizard that asks nine questions
// at a terminal is a wizard nobody can script, and every answer here is a flag
// so that `addy service install` works the same from a shell, from an
// installer, and from the portal when it grows one.
func service(args []string) error {
	if len(args) == 0 {
		services.List(os.Stdout)
		return nil
	}
	verb, rest := args[0], args[1:]

	fs := flag.NewFlagSet("service "+verb, flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	domain := fs.String("domain", "", "This instance's hostname")
	var set multiFlag
	fs.Var(&set, "set", "KEY=VALUE for a wizard field. Repeatable")

	switch verb {
	case "list":
		services.List(os.Stdout)
		return nil
	case "show", "check", "preview", "install":
		if len(rest) == 0 {
			return fmt.Errorf("`addy service %s` needs a service id; `addy service list` names them", verb)
		}
		id := rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return err
		}
		envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
		envDefault(domain, "ADDY_DOMAIN", "")

		if verb == "show" {
			return services.Show(os.Stdout, id)
		}
		svc, err := services.Find(id)
		if err != nil {
			return err
		}
		cfg := services.Config{
			Values:     set.values(),
			Domain:     *domain,
			DeployDir:  *dataDir,
			DockerHost: os.Getenv("DOCKER_HOST"),
		}
		if verb == "check" {
			services.Report(os.Stdout, svc, services.Check(svc, cfg))
			return nil
		}
		if verb == "preview" {
			// What would be written, before anything is. An operator handed a
			// compose file they have not read is an operator running something
			// they did not author.
			body, err := services.Preview(svc, cfg)
			if err != nil {
				return err
			}
			fmt.Print(body)
			return nil
		}
		return services.Install(os.Stdout, svc, cfg)
	default:
		return fmt.Errorf("unknown `addy service` verb %q; try list, show, check, preview or install", verb)
	}
}

// multiFlag collects repeated -set KEY=VALUE.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	if !strings.Contains(v, "=") {
		return fmt.Errorf("-set wants KEY=VALUE, got %q", v)
	}
	*m = append(*m, v)
	return nil
}

func (m *multiFlag) values() map[string]string {
	out := make(map[string]string, len(*m))
	for _, pair := range *m {
		k, v, _ := strings.Cut(pair, "=")
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// invite mints or lists registration tokens.
//
// Console-only. There is deliberately no route that creates one: a route that
// did would be a route an attacker with any foothold uses to grant themselves
// a quota slot.
func invite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	dataDir := fs.String("data", "", "Data directory (default: "+server.DefaultDataDir+")")
	ttl := fs.Duration("ttl", 24*time.Hour, "How long the token is good for")
	list := fs.Bool("list", false, "Show outstanding invites instead of minting one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	envDefault(dataDir, "ADDY_DATA_DIR", server.DefaultDataDir)
	return server.Invite(context.Background(), server.InviteOptions{
		DataDir: *dataDir, TTL: *ttl, List: *list,
	})
}
