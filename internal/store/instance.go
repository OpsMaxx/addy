package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Instance-wide flags, in the key/value table the schema set aside for them.
//
// A table rather than columns because these are booleans and timestamps that
// arrive one at a time over the life of the project, and a schema migration
// per boolean is a migration per boolean's worth of risk. Nothing here is
// per-account and nothing here is a secret.

// ReonboardKey marks the instance as needing every device to be re-checked by
// a human before it syncs again.
//
// Set by `addy panic` and by `addy reset --hard`. It is deliberately NOT
// cleared by restarting, upgrading, or by any client action: the whole value
// of the flag is that it survives everything an attacker who is still on the
// box would try, and the only thing that clears it is an operator saying so at
// the console.
const ReonboardKey = "reonboard_required"

// SecretEpochKey counts how many times the instance's own secrets have been
// rotated.
//
// It exists so that a client can tell "the server restarted" from "the server
// was panicked", which look identical from the outside -- both end every
// session. The first is routine; the second means somebody believed this box
// was compromised, and a device that syncs straight through it would be
// syncing to a box its owner has disowned.
const SecretEpochKey = "secret_epoch"

func (d *DB) instanceValue(ctx context.Context, key string) (string, time.Time, error) {
	var value string
	var at int64
	err := d.read.QueryRowContext(ctx,
		`SELECT value, updated_at FROM instance WHERE key = ?`, key).Scan(&value, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return value, time.UnixMilli(at), nil
}

func (d *DB) setInstanceValue(ctx context.Context, key, value string) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO instance (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			key, value, time.Now().UnixMilli())
		return err
	})
}

// Reonboard reports whether the instance is in reonboard-required state, and
// when it entered it. A zero time with true is not possible; a zero time with
// false is the ordinary case.
func (d *DB) Reonboard(ctx context.Context) (bool, time.Time, error) {
	value, at, err := d.instanceValue(ctx, ReonboardKey)
	if err != nil {
		return false, time.Time{}, err
	}
	// Any value at all means set. Reading it as a boolean would let a
	// corrupted or truncated value read as "no", and the direction that must
	// not happen is the one that unblocks an instance somebody panicked.
	return value != "", at, nil
}

// ClearReonboard is the operator saying, at the console, that they have
// checked. Nothing a client sends can reach it.
func (d *DB) ClearReonboard(ctx context.Context) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM instance WHERE key = ?`, ReonboardKey)
		return err
	})
}

// SecretEpoch is how many times this instance's own secrets have been rotated.
func (d *DB) SecretEpoch(ctx context.Context) (uint64, error) {
	value, _, err := d.instanceValue(ctx, SecretEpochKey)
	if err != nil || value == "" {
		return 0, err
	}
	var n uint64
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			// Unparseable is treated as zero rather than as an error, so a
			// corrupted counter cannot stop the instance serving. The counter
			// is advisory; the reonboard flag is the one that gates.
			return 0, nil
		}
		n = n*10 + uint64(value[i]-'0')
	}
	return n, nil
}

// PanicResult is what was actually invalidated, so the CLI can report it
// rather than claiming a fixed list.
type PanicResult struct {
	InvitesRevoked   int64
	SecretEpoch      uint64
	ReonboardSetAt   time.Time
	AccountsAffected int
}

// Panic invalidates every credential this box holds that it can invalidate,
// and marks the instance as needing re-onboarding.
//
// SCOPED TO ADDY'S OWN SECRETS, deliberately and with the limit stated where
// someone will read it. Rotating live credentials across five running services
// -- frp tokens, a Vaultwarden admin token, headscale keys, an OpenVPN CA --
// is a configuration-management engine, and a half-built one that rotates
// three of five leaves an operator believing they are clean when they are not.
// What this does rotate, it rotates completely.
//
// What it CANNOT do is the part that matters most, and the CLI says so: it
// cannot un-read anything already read. Every object on this box was sealed by
// a client and the server never held a key to any of it, so an attacker who
// copied the database has the same opaque bytes afterwards as before. The
// answer to that is a hard re-key by the account owner, which happens on a
// device, not here. This makes the box safe to keep using; it does not make
// what left it safe.
//
// Sessions are not in this list because they are not on disk. They live in the
// API's memory and end when it restarts, and the reonboard flag stops the ones
// that do not.
func (d *DB) Panic(ctx context.Context) (*PanicResult, error) {
	epoch, err := d.SecretEpoch(ctx)
	if err != nil {
		return nil, err
	}
	out := &PanicResult{SecretEpoch: epoch + 1}

	err = d.Tx(ctx, func(tx *sql.Tx) error {
		// Unspent invites first. An invite is a quota grant that anyone
		// holding the token can spend, so it is the one thing on this box that
		// an attacker could still use AFTER losing access to it.
		res, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE spent_at IS NULL`)
		if err != nil {
			return err
		}
		out.InvitesRevoked, _ = res.RowsAffected()

		now := time.Now().UnixMilli()
		for key, value := range map[string]string{
			ReonboardKey:   time.UnixMilli(now).UTC().Format(time.RFC3339),
			SecretEpochKey: itoa(epoch + 1),
		} {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO instance (key, value, updated_at) VALUES (?, ?, ?)
				ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				key, value, now); err != nil {
				return err
			}
		}
		out.ReonboardSetAt = time.UnixMilli(now)

		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&out.AccountsAffected)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
