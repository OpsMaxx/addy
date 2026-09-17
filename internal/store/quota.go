package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Quota.
//
// SUMMED LIVE, NEVER COUNTED. There is no stored total, so there is no counter
// to drift -- the cost is a scan per write, which for a relay's volume is free.
// Bitwarden arrived at the same answer for the same reason, and the reason is
// worth stating: a counter that has drifted is indistinguishable from a counter
// that is right, and the only way to find out is the scan you were avoiding.
//
// The other two details that come with it:
//
//   - The remaining allowance is a HARD CAP ON THE READER, never trusted from a
//     Content-Length header. A client that lies about its length otherwise gets
//     to write past the limit and finds out at the end, or does not.
//   - `0` means DISABLED and unset means UNLIMITED. They are genuinely different
//     and they get confused every time they are not named apart, so the column
//     default is 0-as-unlimited and this file says so at every use.

// ErrOverQuota is what a write that would exceed the allowance gets.
//
// The user is told, on the device, BEFORE an upload rather than part-way
// through one. A sync that quietly stops on a full disk is worse than having no
// sync, because the user reads it as "synced".
var ErrOverQuota = errors.New("store: this write would exceed the account's quota")

// QuotaBytes is an account's allowance. Zero means unlimited.
func (d *DB) QuotaBytes(ctx context.Context, accountID string) (int64, error) {
	var q int64
	err := d.read.QueryRowContext(ctx,
		`SELECT quota_bytes FROM accounts WHERE account_id = ?`, accountID).Scan(&q)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNoAccount
	}
	if err != nil {
		return 0, fmt.Errorf("store: reading the quota: %w", err)
	}
	return q, nil
}

// SetQuota sets an account's allowance. Zero is unlimited; there is no way to
// express "disabled" here because an account with no storage is an account that
// should be deleted rather than crippled.
func (d *DB) SetQuota(ctx context.Context, accountID string, bytes int64) error {
	if bytes < 0 {
		return fmt.Errorf("store: a quota cannot be negative")
	}
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE accounts SET quota_bytes = ? WHERE account_id = ?`, bytes, accountID)
		if err != nil {
			return fmt.Errorf("store: setting the quota: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoAccount
		}
		return nil
	})
}

// UsageBytes sums what an account actually occupies, right now.
//
// Objects and roster entries both. The roster is small but it is not free, and
// an accounting that ignores a table is an accounting that drifts the moment
// that table grows.
func (d *DB) UsageBytes(ctx context.Context, accountID string) (int64, error) {
	var objects, roster int64
	if err := d.read.QueryRowContext(ctx,
		`SELECT coalesce(sum(length(body)), 0) FROM objects WHERE account_id = ?`,
		accountID).Scan(&objects); err != nil {
		return 0, fmt.Errorf("store: summing objects: %w", err)
	}
	if err := d.read.QueryRowContext(ctx,
		`SELECT coalesce(sum(length(wire)), 0) FROM roster_entries WHERE account_id = ?`,
		accountID).Scan(&roster); err != nil {
		return 0, fmt.Errorf("store: summing roster entries: %w", err)
	}
	return objects + roster, nil
}

// Remaining is what the client is told BEFORE it uploads.
//
// A negative result is possible and is returned as such rather than clamped: an
// account can be over quota after an admin lowers the limit, and pretending it
// has zero left hides how far over it is from the person who has to fix it.
// Unlimited is reported as -1 so a caller cannot mistake it for "none left".
func (d *DB) Remaining(ctx context.Context, accountID string) (int64, error) {
	quota, err := d.QuotaBytes(ctx, accountID)
	if err != nil {
		return 0, err
	}
	if quota == 0 {
		return -1, nil
	}
	used, err := d.UsageBytes(ctx, accountID)
	if err != nil {
		return 0, err
	}
	return quota - used, nil
}

// checkQuota is called inside a write transaction, with the size the write will
// add.
//
// It computes the delta against what the object CURRENTLY occupies, so
// replacing a 10 KiB object with a 10 KiB object costs nothing -- otherwise a
// user near their limit could never write anything again, which is a quota that
// has turned into a wall.
func checkQuota(ctx context.Context, tx *sql.Tx, accountID string, incoming int64, replacing string, epoch uint64) error {
	var quota int64
	if err := tx.QueryRowContext(ctx,
		`SELECT quota_bytes FROM accounts WHERE account_id = ?`, accountID).Scan(&quota); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoAccount
		}
		return fmt.Errorf("store: reading the quota: %w", err)
	}
	if quota == 0 {
		return nil // unlimited
	}

	var objects, roster, existing int64
	if err := tx.QueryRowContext(ctx,
		`SELECT coalesce(sum(length(body)), 0) FROM objects WHERE account_id = ?`,
		accountID).Scan(&objects); err != nil {
		return fmt.Errorf("store: summing objects: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT coalesce(sum(length(wire)), 0) FROM roster_entries WHERE account_id = ?`,
		accountID).Scan(&roster); err != nil {
		return fmt.Errorf("store: summing roster entries: %w", err)
	}
	if replacing != "" {
		_ = tx.QueryRowContext(ctx,
			`SELECT length(body) FROM objects WHERE account_id = ? AND name = ? AND epoch = ?`,
			accountID, replacing, epoch).Scan(&existing)
	}

	if after := objects + roster - existing + incoming; after > quota {
		return fmt.Errorf("%w: %d bytes would take the account to %d of %d",
			ErrOverQuota, incoming, after, quota)
	}
	return nil
}
