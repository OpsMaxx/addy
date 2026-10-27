package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// People, and which accounts are theirs.
//
// A RELAY IS MULTI-USER BY DESIGN and until this existed it could not name
// anybody. Accounts existed, invites existed, and nothing connected either to
// a person — so an operator looking at four accounts could not tell whose they
// were, and nobody could sign in except the one operator.
//
// WHAT A USER RECORD IS NOT is a way into anybody's data. Signing in proves
// who you are to the relay; it grants no key, and the relay has none to grant.
// A user row is a name to put next to an account id, a quota to enforce, and a
// switch to turn somebody off. Everything a signed-in user can see about their
// own account is what the operator can see about it: counts and bytes.

var (
	// ErrNoUser is a subject nobody has signed in as.
	ErrNoUser = errors.New("store: no such user")
	// ErrBlocked is a user the operator has switched off. Distinct from
	// ErrNoUser so the portal can say which it is: "you have been blocked" and
	// "sign in first" are different sentences and only one of them is worth
	// contacting somebody about.
	ErrBlocked = errors.New("store: that user is blocked")
	// ErrHasAccount is somebody who already has a sync group asking for a
	// second one.
	//
	// ONE EMAIL IS ONE SYNC GROUP. A second group is not more room, it is a
	// second set of devices that cannot see the first: separate key, separate
	// roster, no sync between them — and this relay cannot merge them
	// afterwards, because it holds no key to either. Somebody who ends up with
	// two has lost the use of one and has no way back.
	//
	// Adding a device to the group you have is pairing, which needs no invite
	// and nobody's permission.
	ErrHasAccount = errors.New("store: that user already has a sync group")
)

// User is a person who has signed in to this relay.
type User struct {
	UserID    string
	Issuer    string
	Subject   string
	Email     string
	Name      string
	CreatedAt time.Time
	LastSeen  time.Time
	QuotaByte int64
	Blocked   bool
}

// UpsertUser records a sign-in and returns the person.
//
// Identity is (issuer, subject), NEVER email. An email address is a display
// name that providers let people change and reuse; a subject is the identifier
// the provider promises is stable, and it is only unique within its issuer.
// Matching on email would mean somebody who changed theirs becoming a new
// person, and somebody who inherited a reused one becoming an old one.
//
// The email and name are refreshed on every sign-in, because they are what a
// human reads in a list and a stale one is a small lie that accumulates.
func (d *DB) UpsertUser(ctx context.Context, issuer, subject, email, name string) (*User, error) {
	if issuer == "" || subject == "" {
		return nil, errors.New("store: a user needs an issuer and a subject")
	}
	now := time.Now()

	var u User
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		var blockedAt sql.NullInt64
		err := tx.QueryRowContext(ctx, `
			SELECT user_id, email, name, created_at, quota_bytes, blocked_at
			  FROM users WHERE issuer = ? AND subject = ?`,
			issuer, subject).Scan(&u.UserID, &u.Email, &u.Name, &scanTime{&u.CreatedAt}, &u.QuotaByte, &blockedAt)

		switch {
		case errors.Is(err, sql.ErrNoRows):
			id, idErr := newUserID()
			if idErr != nil {
				return idErr
			}
			u = User{
				UserID:    id,
				Issuer:    issuer,
				Subject:   subject,
				Email:     email,
				Name:      name,
				CreatedAt: now,
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO users (user_id, issuer, subject, email, name, created_at, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, issuer, subject, email, name, now.UnixMilli(), now.UnixMilli())
			return err
		case err != nil:
			return err
		}

		u.Issuer, u.Subject = issuer, subject
		u.Blocked = blockedAt.Valid
		// A BLOCKED USER IS STILL RECORDED AS HAVING TRIED. The alternative —
		// returning early — means an operator who blocked somebody cannot tell
		// whether they have since given up or are still knocking.
		u.LastSeen = now
		if !u.Blocked {
			u.Email, u.Name = email, name
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE users SET last_seen = ?, email = ?, name = ? WHERE user_id = ?`,
			now.UnixMilli(), u.Email, u.Name, u.UserID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: recording the sign-in: %w", err)
	}
	return &u, nil
}

// Users lists everybody who has signed in, with what they own.
func (d *DB) Users(ctx context.Context) ([]UserSummary, error) {
	rows, err := d.read.QueryContext(ctx, `
		SELECT u.user_id, u.email, u.name, u.created_at, u.last_seen,
		       u.quota_bytes, u.blocked_at, u.admitted_at IS NOT NULL,
		       (SELECT count(*) FROM account_owners o WHERE o.user_id = u.user_id),
		       coalesce((SELECT sum(length(b.body))
		                   FROM objects b
		                   JOIN account_owners o2 ON o2.account_id = b.account_id
		                  WHERE o2.user_id = u.user_id), 0)
		  FROM users u
		 ORDER BY u.created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []UserSummary
	for rows.Next() {
		var s UserSummary
		var created, seen int64
		var blockedAt sql.NullInt64
		if err := rows.Scan(&s.UserID, &s.Email, &s.Name, &created, &seen,
			&s.QuotaByte, &blockedAt, &s.Admitted, &s.Accounts, &s.UsedBytes); err != nil {
			return nil, err
		}
		s.CreatedAt = time.UnixMilli(created)
		if seen > 0 {
			s.LastSeen = time.UnixMilli(seen)
		}
		s.Blocked = blockedAt.Valid
		out = append(out, s)
	}
	return out, rows.Err()
}

// UserSummary is a person as the operator console lists them.
//
// Note what is NOT here, and it is the same absence as AccountSummary: no
// device name, no collection contents, nothing from inside an account. A
// person has some accounts, those accounts hold some bytes, and that is the
// whole of what this relay knows about them.
type UserSummary struct {
	UserID    string
	Email     string
	Name      string
	CreatedAt time.Time
	LastSeen  time.Time
	Accounts  int
	UsedBytes int64
	QuotaByte int64
	Blocked   bool
	Admitted  bool
}

// SetUserAdmitted records the operator letting a person have storage, or
// taking that back. It changes nothing a person already has: it decides only
// whether they may mint their own first invite on a relay whose policy is
// `invite`.
//
// WITHDRAWING IT CANCELS THE INVITES THEY ALREADY MINTED. An invite is a valid
// token for 24 hours whoever holds it, so without this a person told "no" kept
// the storage they had asked for a minute earlier.
func (d *DB) SetUserAdmitted(ctx context.Context, userID string, admitted bool) error {
	var at any
	if admitted {
		at = time.Now().UnixMilli()
	}
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET admitted_at = ? WHERE user_id = ?`, at, userID)
		if err != nil {
			return fmt.Errorf("store: admitting %s: %w", userID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoUser
		}
		if admitted {
			return nil
		}
		_, err = tx.ExecContext(ctx,
			`DELETE FROM invites WHERE minted_for = ? AND spent_by IS NULL`, userID)
		return err
	})
}

// UserAdmitted reports whether the operator has admitted a person.
func (d *DB) UserAdmitted(ctx context.Context, userID string) (bool, error) {
	var admitted bool
	err := d.read.QueryRowContext(ctx,
		`SELECT admitted_at IS NOT NULL FROM users WHERE user_id = ?`, userID).Scan(&admitted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNoUser
	}
	return admitted, err
}

// SetUserBlocked switches a person off, or back on.
//
// It does not delete anything. A blocked user cannot sign in and cannot be
// minted an invite; their existing accounts go on working, because their
// devices hold the keys and this relay was never what made those accounts
// theirs. Cutting off sync would need the accounts deleted, which is a
// separate and much louder decision.
func (d *DB) SetUserBlocked(ctx context.Context, userID string, blocked bool) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		var at any
		if blocked {
			at = time.Now().UnixMilli()
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET blocked_at = ? WHERE user_id = ?`, at, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoUser
		}
		return nil
	})
}

// SetUserQuota caps everything one person's accounts hold, together.
func (d *DB) SetUserQuota(ctx context.Context, userID string, bytes int64) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET quota_bytes = ? WHERE user_id = ?`, bytes, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoUser
		}
		return nil
	})
}

// NewInviteFor mints an invite bound to the person it is for.
//
// THE BINDING IS WHAT MAKES ATTRIBUTION HONEST. The account that spends this
// invite becomes theirs without anybody claiming it: the device registering
// presents a token, and the token already says whose it is. A spender that
// asserted its own owner would be a spender the relay had to believe.
func (d *DB) NewInviteFor(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: drawing an invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now()
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		if userID != "" {
			var blockedAt sql.NullInt64
			err := tx.QueryRowContext(ctx,
				`SELECT blocked_at FROM users WHERE user_id = ?`, userID).Scan(&blockedAt)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNoUser
			}
			if err != nil {
				return err
			}
			if blockedAt.Valid {
				return ErrBlocked
			}
			var owns int
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM account_owners WHERE user_id = ?`, userID).Scan(&owns); err != nil {
				return err
			}
			if owns > 0 {
				return ErrHasAccount
			}
		}
		var owner any
		if userID != "" {
			owner = userID
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO invites (token_hash, created_at, expires_at, minted_for) VALUES (?, ?, ?, ?)`,
			hashToken(token), now.Unix(), now.Add(ttl).Unix(), owner)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("store: storing the invite: %w", err)
	}
	return token, nil
}

// AccountsOf lists one person's accounts, for their own view of this relay.
func (d *DB) AccountsOf(ctx context.Context, userID string) ([]AccountSummary, error) {
	all, err := d.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	owned := map[string]bool{}
	rows, err := d.read.QueryContext(ctx,
		`SELECT account_id FROM account_owners WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: reading what %s owns: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		owned[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Filtered in Go rather than joined in SQL, so `Accounts` stays the one
	// place the shape of an account summary is decided. A second query
	// computing the same columns is a second place to get the byte total
	// subtly different.
	out := make([]AccountSummary, 0, len(owned))
	for _, a := range all {
		if owned[a.AccountID] {
			out = append(out, a)
		}
	}
	return out, nil
}

// OwnerOf names the person an account belongs to, or "" for one nobody has
// claimed — which is every account registered with an operator-minted invite
// that named nobody, and every account that predates this table.
func (d *DB) OwnerOf(ctx context.Context, accountID string) (string, error) {
	var userID string
	err := d.read.QueryRowContext(ctx,
		`SELECT user_id FROM account_owners WHERE account_id = ?`, accountID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: reading the owner of %s: %w", accountID, err)
	}
	return userID, nil
}

func newUserID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: drawing a user id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// scanTime reads a millisecond timestamp into a time.Time.
type scanTime struct{ into *time.Time }

func (s *scanTime) Scan(v any) error {
	switch t := v.(type) {
	case int64:
		*s.into = time.UnixMilli(t)
		return nil
	case nil:
		*s.into = time.Time{}
		return nil
	default:
		return fmt.Errorf("store: %T is not a timestamp", v)
	}
}
