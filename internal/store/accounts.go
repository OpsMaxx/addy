package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNoAccount     = errors.New("store: no such account")
	ErrAccountExists = errors.New("store: that account already exists")
	ErrSeqTaken      = errors.New("store: a roster entry already exists at that sequence")
	ErrSeqGap        = errors.New("store: a roster entry would leave a gap")
	ErrETagMismatch  = errors.New("store: the object has changed since it was read")
	// ErrObjectExists is deliberately distinct from ErrETagMismatch. "You did
	// not send If-Match" and "the one you sent is stale" need different
	// answers: the first is a client bug, the second is a real conflict that a
	// user may have to resolve.
	ErrObjectExists  = errors.New("store: that object exists; send If-Match to replace it")
	ErrInviteUnknown = errors.New("store: no such invite")
	ErrInviteSpent   = errors.New("store: that invite has already been spent")
	ErrInviteExpired = errors.New("store: that invite has expired")
)

// CreateAccount registers a client-asserted identity.
//
// THE SERVER VALIDATES NOTHING ABOUT WHO YOU ARE. It stores a public key it has
// never seen and cannot vouch for. What it does check is that the invite is
// real and unspent, because that is the only thing an admin actually controls:
// a quota slot.
func (d *DB) CreateAccount(ctx context.Context, accountID string, rootSignPub []byte, inviteToken string) error {
	if len(accountID) != 32 {
		return fmt.Errorf("store: an account id is 32 hex characters, got %d", len(accountID))
	}
	if len(rootSignPub) != 32 {
		return fmt.Errorf("store: a root signing key is 32 bytes, got %d", len(rootSignPub))
	}

	return d.Tx(ctx, func(tx *sql.Tx) error {
		now := time.Now().Unix()

		hash := hashToken(inviteToken)
		var expires int64
		var spentBy sql.NullString
		// Who the invite was minted for, so the account it creates can be
		// attributed without the registrant claiming anything.
		var mintedFor sql.NullString
		err := tx.QueryRowContext(ctx,
			`SELECT expires_at, spent_by, minted_for FROM invites WHERE token_hash = ?`, hash).
			Scan(&expires, &spentBy, &mintedFor)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInviteUnknown
		}
		if err != nil {
			return fmt.Errorf("store: reading the invite: %w", err)
		}
		if spentBy.Valid {
			return ErrInviteSpent
		}
		if expires < now {
			return ErrInviteExpired
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO accounts (account_id, root_sign_pub, created_at) VALUES (?, ?, ?)`,
			accountID, rootSignPub, now); err != nil {
			return fmt.Errorf("%w: %v", ErrAccountExists, err)
		}
		// Spending the invite in the SAME transaction as creating the account
		// is what stops one token minting two accounts under a race.
		if _, err := tx.ExecContext(ctx,
			`UPDATE invites SET spent_by = ?, spent_at = ? WHERE token_hash = ?`,
			accountID, now, hash); err != nil {
			return fmt.Errorf("store: spending the invite: %w", err)
		}

		// WHOSE ACCOUNT THIS IS, taken from the invite rather than from the
		// device registering.
		//
		// The device presents a token and the token already says who it was
		// minted for, so attribution needs nobody to be believed. A registrant
		// that named its own owner would be one this relay had to trust about
		// a thing it has every reason to lie about.
		//
		// NULL for an invite the operator minted without naming anybody, which
		// is the right thing for one handed to somebody who has not signed in:
		// the account then belongs to nobody until it does.
		if mintedFor.Valid {
			// ONE EMAIL IS ONE SYNC GROUP, and this is where it is enforced
			// rather than at minting.
			//
			// Minting checks too, so somebody is told before they carry a
			// token to a device. But an invite minted while they had nothing
			// is still a valid token afterwards, so the only check that
			// actually holds is the one at the moment the group would come
			// into existence.
			//
			// It is safe as a read-then-write inside this transaction because
			// this store has a single writer: no second registration can land
			// between the count and the insert. An invite minted for nobody is
			// not covered at all — there is no email to hold to one group —
			// which is the deliberate limit of a rule stated in terms of
			// identity.
			var owns int
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM account_owners WHERE user_id = ?`, mintedFor.String).Scan(&owns); err != nil {
				return fmt.Errorf("store: checking what %s already owns: %w", mintedFor.String, err)
			}
			if owns > 0 {
				return ErrHasAccount
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO account_owners (account_id, user_id, linked_at) VALUES (?, ?, ?)
				 ON CONFLICT(account_id) DO NOTHING`,
				accountID, mintedFor.String, time.Now().UnixMilli()); err != nil {
				return fmt.Errorf("store: attributing the account: %w", err)
			}
		}
		return nil
	})
}

// RootSignPub returns an account's root signing key.
//
// A CLIENT MUST NOT VERIFY A CHAIN AGAINST THIS. It is here for the server's own
// bookkeeping and for display; a chain verified against a key the server
// supplied is not verified. Clients hold the key from genesis, from a pairing
// handoff, or by deriving it from the mnemonic.
func (d *DB) RootSignPub(ctx context.Context, accountID string) ([]byte, error) {
	var pub []byte
	err := d.read.QueryRowContext(ctx,
		`SELECT root_sign_pub FROM accounts WHERE account_id = ?`, accountID).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading account %s: %w", accountID, err)
	}
	return pub, nil
}

// AppendRoster stores one entry.
//
// The server checks only that sequence numbers are contiguous, which is the
// most it can do: it holds no key and cannot verify a signature. That is not a
// weakness -- the client verifies the whole chain from genesis before trusting
// any of it, and a server that appended a forged entry would simply be caught.
func (d *DB) AppendRoster(ctx context.Context, accountID string, seq uint64, wire []byte) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		var have sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT max(seq) FROM roster_entries WHERE account_id = ?`, accountID).Scan(&have); err != nil {
			return fmt.Errorf("store: reading the roster head: %w", err)
		}

		var want uint64
		if have.Valid {
			want = uint64(have.Int64) + 1
		}
		switch {
		case seq < want:
			return fmt.Errorf("%w: %d", ErrSeqTaken, seq)
		case seq > want:
			return fmt.Errorf("%w: expected %d, got %d", ErrSeqGap, want, seq)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO roster_entries (account_id, seq, wire, stored_at) VALUES (?, ?, ?, ?)`,
			accountID, seq, wire, time.Now().Unix()); err != nil {
			return fmt.Errorf("store: appending roster entry %d: %w", seq, err)
		}
		return nil
	})
}

// Roster returns the chain from a sequence number onward, concatenated.
func (d *DB) Roster(ctx context.Context, accountID string, from uint64) ([]byte, error) {
	rows, err := d.read.QueryContext(ctx,
		`SELECT wire FROM roster_entries WHERE account_id = ? AND seq >= ? ORDER BY seq`,
		accountID, from)
	if err != nil {
		return nil, fmt.Errorf("store: reading the roster: %w", err)
	}
	defer rows.Close()

	var out []byte
	for rows.Next() {
		var wire []byte
		if err := rows.Scan(&wire); err != nil {
			return nil, fmt.Errorf("store: scanning a roster entry: %w", err)
		}
		out = append(out, wire...)
	}
	return out, rows.Err()
}

// Object is one stored opaque object.
type Object struct {
	Name    string
	Epoch   uint64
	Counter uint64
	Body    []byte
	ETag    string
}

// PutObject stores an object, optionally conditional on its current ETag.
//
// ifMatch empty means CREATE ONLY. An unconditional overwrite is not offered at
// all, because last-writer-wins without a conditional PUT is how two devices
// silently destroy each other's work -- and the loser never finds out.
func (d *DB) PutObject(ctx context.Context, accountID string, o Object, ifMatch string) (string, error) {
	etag := newETag()
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		var current string
		err := tx.QueryRowContext(ctx,
			`SELECT etag FROM objects WHERE account_id = ? AND name = ? AND epoch = ?`,
			accountID, o.Name, o.Epoch).Scan(&current)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if ifMatch != "" {
				return fmt.Errorf("%w: no such object to match", ErrETagMismatch)
			}
		case err != nil:
			return fmt.Errorf("store: reading the object: %w", err)
		default:
			if ifMatch == "" {
				return ErrObjectExists
			}
			if ifMatch != current {
				return fmt.Errorf("%w: have %s", ErrETagMismatch, current)
			}
		}

		// Checked against the size this write ADDS, inside the same
		// transaction that performs it -- so two concurrent writes cannot both
		// see room for the last byte.
		if err := checkQuota(ctx, tx, accountID, int64(len(o.Body)), o.Name, o.Epoch); err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO objects (account_id, name, epoch, counter, body, etag, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(account_id, name, epoch) DO UPDATE SET
			   counter = excluded.counter, body = excluded.body,
			   etag = excluded.etag, updated_at = excluded.updated_at`,
			accountID, o.Name, o.Epoch, o.Counter, o.Body, etag, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("store: writing object %s: %w", o.Name, err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return etag, nil
}

// GetObject reads one object.
func (d *DB) GetObject(ctx context.Context, accountID, name string, epoch uint64) (*Object, error) {
	var o Object
	o.Name, o.Epoch = name, epoch
	err := d.read.QueryRowContext(ctx,
		`SELECT counter, body, etag FROM objects WHERE account_id = ? AND name = ? AND epoch = ?`,
		accountID, name, epoch).Scan(&o.Counter, &o.Body, &o.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading object %s: %w", name, err)
	}
	return &o, nil
}

// NewInvite mints a token and stores only its hash.
//
// THE PLAINTEXT TOKEN IS RETURNED ONCE AND NEVER STORED. A database that holds
// usable invite tokens is a database whose theft grants registrations; one that
// holds hashes is not.
func (d *DB) NewInvite(ctx context.Context, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: drawing an invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now()
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO invites (token_hash, created_at, expires_at) VALUES (?, ?, ?)`,
			hashToken(token), now.Unix(), now.Add(ttl).Unix())
		return err
	})
	if err != nil {
		return "", fmt.Errorf("store: storing the invite: %w", err)
	}
	return token, nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte("addy-invite-v1\x00" + token))
	return sum[:]
}

func newETag() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// A weak ETag would let a conditional PUT succeed when it should not,
		// so this is fatal rather than degraded.
		panic("store: drawing an etag: " + err.Error())
	}
	return hex.EncodeToString(raw)
}
