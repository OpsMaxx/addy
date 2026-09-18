package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/opsmaxx/addy/internal/store"
)

// CERTIFICATE STATE, and why panicking deletes it.
//
// certmagic keeps the ACME account key here alongside the issued certificates.
// The account key is a credential: whoever holds it can ask Let's Encrypt to
// issue for any domain this instance has already validated, from anywhere, for
// as long as the authorization lasts. Leaving it in place after a compromise
// means the box is clean and the attacker still has a usable certificate
// authority relationship.
//
// Deleting it costs one issuance -- certmagic registers a new account and
// re-issues on the next request, which is a few seconds of first-connection
// latency, once.
const certDirName = "certmagic"

// PanicOptions is what `addy panic` was told to do.
type PanicOptions struct {
	DataDir string
	// KeepCerts skips deleting the ACME account key and issued certificates.
	// For the case the operator is panicking over something that cannot have
	// touched them -- a leaked invite, say -- and is behind a rate limit they
	// do not want to spend.
	KeepCerts bool
	Out       io.Writer
}

// Panic rotates every secret this box holds that it can rotate, and marks the
// instance as needing a human to re-check its devices before it serves again.
//
// It is deliberately usable while the server is RUNNING. The reonboard flag is
// read from the database on every authenticated request rather than cached at
// startup, so a live instance stops serving within one request of this
// returning -- which matters because the moment an operator runs this is
// precisely the moment nobody is thinking about restarting a service.
func Panic(ctx context.Context, opts PanicOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	dir := opts.DataDir
	if dir == "" {
		dir = DefaultDataDir
	}

	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		return fmt.Errorf("opening the database at %s: %w", dir, err)
	}
	defer db.Close()

	res, err := db.Panic(ctx)
	if err != nil {
		return fmt.Errorf("rotating: %w", err)
	}

	certs := "kept"
	if !opts.KeepCerts {
		// RemoveAll, then report what happened rather than assuming. A failure
		// here must be loud: an operator who is told the ACME account key is
		// gone and finds it still on disk has been given exactly the wrong
		// information at exactly the worst moment.
		path := filepath.Join(dir, certDirName)
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintf(out, "WARNING: the certificate store at %s could not be deleted: %v\n", path, err)
			fmt.Fprintf(out, "         The ACME account key is still on this box. Delete it by hand.\n")
			certs = "COULD NOT BE DELETED"
		} else {
			certs = "deleted; a new account key and certificate are issued on the next connection"
		}
	}

	fmt.Fprintf(out, `addy panic complete.

  Unspent invites revoked   %d
  Accounts on this box      %d
  Certificate store         %s
  Secret epoch              %d
  Reonboard required since  %s

Every device is now refused with 503 until you run:

    addy reonboard --clear

WHAT THIS DID NOT DO, and it is the part that matters most:

  It cannot un-read anything. Every object on this box was sealed by a client
  and this server has never held a key to any of it, so whoever copied the
  database has the same opaque bytes now as before. Rotating here makes the BOX
  safe to keep using. It does not make what left it safe.

  The answer to that is a hard re-key, and it happens on a device, not here:
  the account owner rotates AK_n, every object is re-sealed under the new
  epoch, and anything the attacker copied stops being current. Do that before
  you clear the flag, not after.

  Credentials belonging to services this box merely proxies -- frp, headscale,
  Vaultwarden, OpenVPN -- are NOT rotated. Rotate them where they live.
`,
		res.InvitesRevoked, res.AccountsAffected, certs, res.SecretEpoch,
		res.ReonboardSetAt.UTC().Format(time.RFC3339))
	return nil
}

// ReonboardOptions is what `addy reonboard` was told to do.
type ReonboardOptions struct {
	DataDir string
	Clear   bool
	Out     io.Writer
}

// Reonboard shows or clears the reonboard-required flag.
func Reonboard(ctx context.Context, opts ReonboardOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	dir := opts.DataDir
	if dir == "" {
		dir = DefaultDataDir
	}
	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	blocked, at, err := db.Reonboard(ctx)
	if err != nil {
		return err
	}
	if !opts.Clear {
		if !blocked {
			fmt.Fprintln(out, "This instance is serving normally.")
			return nil
		}
		fmt.Fprintf(out, "Reonboard required since %s. No device is being served.\n",
			at.UTC().Format(time.RFC3339))
		fmt.Fprintln(out, "Clear it with: addy reonboard --clear")
		return nil
	}
	if !blocked {
		fmt.Fprintln(out, "Nothing to clear; this instance is already serving.")
		return nil
	}
	if err := db.ClearReonboard(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "Cleared. Devices are served again.")
	return nil
}

// ResetOptions is what `addy reset` was told to do.
type ResetOptions struct {
	DataDir string
	// Hard deletes every account, roster and object on the box. Without it,
	// reset does nothing but say what a hard reset would destroy -- which is
	// the useful default for a command whose failure mode is total.
	Hard bool
	// Yes skips the confirmation. For an installer or a test, never for a
	// human: the confirmation is the feature.
	Yes bool
	In  io.Reader
	Out io.Writer
}

// Reset destroys the instance's data.
//
// The confirmation LISTS WHAT IS ABOUT TO GO, per account, with when each
// account's devices last checked in. That listing is the whole design of this
// command. "Are you sure? [y/N]" is a question nobody has the information to
// answer; "this deletes 3 accounts, one of which had a device here four
// minutes ago" is a question they do.
//
// A reset leaves the instance in reonboard-required state for the same reason
// a panic does: the two are indistinguishable to a client -- every session
// ends and the roster it knew is gone -- and a device that resynced straight
// through either would be resyncing to a box whose state somebody deliberately
// destroyed.
func Reset(ctx context.Context, opts ResetOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	dir := opts.DataDir
	if dir == "" {
		dir = DefaultDataDir
	}

	db, err := store.Open(filepath.Join(dir, "addy.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	accounts, err := db.Accounts(ctx)
	if err != nil {
		return err
	}
	// Most recently seen first: the account someone is actively using is the
	// one an operator needs to see before pressing return, and it is the one a
	// list sorted by creation date would bury.
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].LastSeen.After(accounts[j].LastSeen) })

	if len(accounts) == 0 {
		fmt.Fprintln(out, "There are no accounts on this box.")
	} else {
		fmt.Fprintf(out, "This will permanently delete %d account(s) from %s:\n\n", len(accounts), dir)
		for _, a := range accounts {
			seen := "never"
			if !a.LastSeen.IsZero() {
				seen = humanAgo(time.Since(a.LastSeen))
			}
			fmt.Fprintf(out, "  %s  %d device(s)  %s used  last seen %s\n",
				a.AccountID[:12], a.Devices, humanBytes(a.UsedBytes), seen)
		}
		fmt.Fprintln(out)
	}

	if !opts.Hard {
		fmt.Fprintln(out, "Nothing was deleted. Add --hard to actually do it.")
		return nil
	}

	if !opts.Yes {
		in := opts.In
		if in == nil {
			in = os.Stdin
		}
		fmt.Fprint(out, `Type "delete everything" to confirm: `)
		line, _ := bufio.NewReader(in).ReadString('\n')
		// An exact phrase rather than "y". A destructive command that a
		// reflexive keystroke can complete is one that gets completed
		// reflexively.
		if strings.TrimSpace(line) != "delete everything" {
			return errors.New("not confirmed; nothing was deleted")
		}
	}

	for _, a := range accounts {
		if err := db.DeleteAccount(ctx, a.AccountID); err != nil {
			return fmt.Errorf("deleting %s: %w", a.AccountID[:12], err)
		}
	}
	if _, err := db.Panic(ctx); err != nil {
		return fmt.Errorf("marking the instance: %w", err)
	}

	fmt.Fprintf(out, "\nDeleted %d account(s). This instance is now in reonboard-required state;\n", len(accounts))
	fmt.Fprintln(out, "clear it with: addy reonboard --clear")
	return nil
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}
