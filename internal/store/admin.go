package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Admin views.
//
// EVERYTHING HERE IS METADATA AND THAT IS ENFORCED BY WHAT IS AVAILABLE, not by
// discipline. There is no query in this file that could return a collection's
// contents, a device label or a paste, because the server holds no key for any
// of them -- an admin reading straight from SQLite sees exactly what these
// functions see.
//
// The boundary is written down in docs/ADMIN.md, published before the UI
// exists. A boundary discovered from a UI is one nobody agreed to.

// AccountSummary is everything an admin can see about an account.
//
// Note what is NOT here: no label, no collection name that is not already a
// fixed protocol constant, no device name. A device shows as a public key and
// a last-seen time, which is what the threat model concedes the server knows.
type AccountSummary struct {
	AccountID string
	// Whoever owns it, or "" for an account nobody has claimed — which is
	// every account registered with an invite that named nobody, and every
	// account that predates the users table.
	OwnerEmail string
	CreatedAt  time.Time
	Devices    int
	UsedBytes  int64
	QuotaByte  int64 // zero means unlimited
	LastSeen   time.Time
}

// Accounts lists every account, for the admin view.
func (d *DB) Accounts(ctx context.Context) ([]AccountSummary, error) {
	rows, err := d.read.QueryContext(ctx, `
		SELECT a.account_id, a.created_at, a.quota_bytes,
		       (SELECT count(*) FROM roster_entries r WHERE r.account_id = a.account_id),
		       coalesce((SELECT sum(length(body)) FROM objects o WHERE o.account_id = a.account_id), 0)
		     + coalesce((SELECT sum(length(wire)) FROM roster_entries r WHERE r.account_id = a.account_id), 0),
		       coalesce((SELECT max(updated_at) FROM objects o WHERE o.account_id = a.account_id), 0),
		       coalesce((SELECT u.email FROM account_owners w
		                   JOIN users u ON u.user_id = w.user_id
		                  WHERE w.account_id = a.account_id), '')
		  FROM accounts a
		 ORDER BY a.created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing accounts: %w", err)
	}
	defer rows.Close()

	var out []AccountSummary
	for rows.Next() {
		var s AccountSummary
		var created, lastSeen int64
		var entries int
		if err := rows.Scan(&s.AccountID, &created, &s.QuotaByte, &entries,
			&s.UsedBytes, &lastSeen, &s.OwnerEmail); err != nil {
			return nil, fmt.Errorf("store: scanning an account: %w", err)
		}
		s.CreatedAt = time.Unix(created, 0)
		if lastSeen > 0 {
			s.LastSeen = time.Unix(lastSeen, 0)
		}
		// The roster entry COUNT is not the device count -- entries include
		// revokes and transitions. The server cannot compute the live set
		// without verifying the chain, which it has no key for, so this is
		// reported as what it is.
		s.Devices = entries
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteAccount removes a user.
//
// IT IS A DELETION, NOT AN EXPORT. It cannot decrypt anything first, so there is
// no version of this that produces readable data -- and the UI says so, offering
// the user's own devices as the only way to get anything out.
func (d *DB) DeleteAccount(ctx context.Context, accountID string) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE account_id = ?`, accountID)
		if err != nil {
			return fmt.Errorf("store: deleting account %s: %w", accountID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoAccount
		}
		return nil
	})
}
