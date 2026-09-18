package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// One-time pastes.
//
// The server stores an opaque blob and three counters. It cannot read a paste
// it is serving, cannot tell a password-protected one from an ordinary one,
// and does not know how large the plaintext is -- the key never leaves the URL
// fragment, which browsers do not send.
//
// What it CAN see, and what an operator should know it can see: that a paste
// exists, which account created it, roughly how big the ciphertext is, when it
// was created, and each time it was read. That is the T1 metadata floor for a
// service that has to serve a link to somebody who holds no account.

// PasteIDLen is the length of the identifier in raw bytes before encoding. 16
// bytes is 128 bits, which is enough that the id itself is unguessable -- and
// it has to be, because the id is what an attacker who is scraping can try.
// The KEY is separate and never reaches the server at all.
const PasteIDLen = 16

// MaxPasteBytes caps one sealed blob. A paste service is not a file host, and
// an uncapped one on a box whose pitch is "it holds nothing worth attacking"
// is a free bucket for whoever finds it.
const MaxPasteBytes = 1 << 20 // 1 MiB of ciphertext

var (
	// ErrPasteGone means the row is there but may no longer be read: expired,
	// or its views are used up. Deliberately distinct from "not found", and
	// that distinction is the reason `deleted_at` exists separately from
	// `expires_at` -- see the schema comment.
	ErrPasteGone = errors.New("that paste has expired or already been read")
	// ErrPasteNotFound means there is no such id, or the row has been swept.
	ErrPasteNotFound = errors.New("no such paste")
	ErrPasteTooLarge = fmt.Errorf("a paste may be at most %d bytes", MaxPasteBytes)
)

// Paste is the OWNER's view. It is never serialised to an anonymous reader:
// see PublicPaste, and api/paste.go for why they are two types rather than one
// with a flag.
type Paste struct {
	ID        string
	Owner     string
	Sealed    []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	DeletedAt time.Time
	MaxViews  int
	Views     int
}

// NewPasteID returns an unguessable identifier.
func NewPasteID() (string, error) {
	raw := make([]byte, PasteIDLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// RawURLEncoding: no padding to strip in a URL, and no characters that a
	// chat client will decide to treat as punctuation at the end of a
	// sentence.
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CreatePaste stores one sealed blob.
//
// `ttl` is how long it may be read and `linger` is how much longer the row
// stays afterwards so a reader can be told "already used" rather than "never
// existed". maxViews of 0 means unlimited, which is a paste and not a
// one-time paste -- the caller decides, and the portal's default is 1.
func (d *DB) CreatePaste(ctx context.Context, owner string, sealed []byte, ttl, linger time.Duration, maxViews int) (*Paste, error) {
	if len(sealed) == 0 {
		return nil, errors.New("a paste needs a body")
	}
	if len(sealed) > MaxPasteBytes {
		return nil, ErrPasteTooLarge
	}
	if maxViews < 0 {
		return nil, errors.New("a view limit cannot be negative")
	}
	id, err := NewPasteID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	p := &Paste{
		ID:        id,
		Owner:     owner,
		Sealed:    sealed,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		DeletedAt: now.Add(ttl + linger),
		MaxViews:  maxViews,
	}
	err = d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO pastes (id, sealed, created_at, expires_at, max_views, views, deleted_at, owner)
			VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
			p.ID, p.Sealed, p.CreatedAt.UnixMilli(), p.ExpiresAt.UnixMilli(),
			p.MaxViews, p.DeletedAt.UnixMilli(), p.Owner)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// PasteStatus answers "may this be read", WITHOUT consuming a view.
//
// This is what a GET answers. It is separate from Burn because a GET that
// consumed would make the service unusable in practice: every chat client,
// mail scanner and link preview fetches a URL the moment it is pasted, and a
// paste that burns on GET is a paste the recipient never sees. Burning
// requires an explicit POST, which none of those issue.
func (d *DB) PasteStatus(ctx context.Context, id string) (*Paste, error) {
	var p Paste
	var created, expires, deleted int64
	err := d.read.QueryRowContext(ctx, `
		SELECT id, owner, created_at, expires_at, deleted_at, max_views, views
		FROM pastes WHERE id = ?`, id).
		Scan(&p.ID, &p.Owner, &created, &expires, &deleted, &p.MaxViews, &p.Views)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPasteNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CreatedAt = time.UnixMilli(created)
	p.ExpiresAt = time.UnixMilli(expires)
	p.DeletedAt = time.UnixMilli(deleted)

	now := time.Now()
	if now.After(p.DeletedAt) {
		// Swept in all but fact. Reporting it as not-found rather than gone is
		// deliberate: past the deletion date, addy is no longer making any
		// claim about what was here.
		return nil, ErrPasteNotFound
	}
	if now.After(p.ExpiresAt) || (p.MaxViews > 0 && p.Views >= p.MaxViews) {
		return &p, ErrPasteGone
	}
	return &p, nil
}

// Burn consumes one view and returns the sealed blob.
//
// ONE STATEMENT, deliberately, and it is worth being exact about what that
// buys because the obvious claim is wrong.
//
// What makes a simultaneous double-read impossible TODAY is not this statement
// -- it is `write.SetMaxOpenConns(1)` in store.go. Every write transaction in
// this package is serialised on one connection, so even a read-modify-write
// would be safe, and a test cannot tell the two implementations apart. (One
// was written to try; it could not.)
//
// The statement is written this way so the guarantee does not REST on that.
// The single writer is a performance decision made elsewhere for unrelated
// reasons, and the day somebody widens the pool -- a reasonable thing to want
// -- a read-modify-write here would start letting two readers who click at the
// same moment both pass the check. That is not a rounding error for a one-time
// paste: it is the entire property the feature is named after, failing
// silently, under exactly the conditions (a link forwarded to two people) that
// make somebody care.
//
// So the condition lives in the UPDATE, where SQLite decides who wins and
// RowsAffected says whether it was us, and the blob is read inside the same
// transaction. `TestTheWriterIsSerialised` pins the invariant this does not
// need, so that removing it is a deliberate act rather than a surprise.
func (d *DB) Burn(ctx context.Context, id string) (*Paste, error) {
	var out *Paste
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UnixMilli()
		res, err := tx.ExecContext(ctx, `
			UPDATE pastes SET views = views + 1
			WHERE id = ?
			  AND expires_at > ?
			  AND deleted_at > ?
			  AND (max_views = 0 OR views < max_views)`,
			id, now, now)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			// Nothing was consumed. Distinguish "never existed" from "used
			// up" by looking, which is safe now precisely because the update
			// already failed -- there is no race left to lose.
			var exists int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM pastes WHERE id = ? AND deleted_at > ?`, id, now).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return ErrPasteNotFound
			}
			return ErrPasteGone
		}

		var p Paste
		var created, expires, deleted int64
		if err := tx.QueryRowContext(ctx, `
			SELECT id, owner, sealed, created_at, expires_at, deleted_at, max_views, views
			FROM pastes WHERE id = ?`, id).
			Scan(&p.ID, &p.Owner, &p.Sealed, &created, &expires, &deleted, &p.MaxViews, &p.Views); err != nil {
			return err
		}
		p.CreatedAt = time.UnixMilli(created)
		p.ExpiresAt = time.UnixMilli(expires)
		p.DeletedAt = time.UnixMilli(deleted)
		out = &p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeletePaste removes one immediately, for the account that created it.
//
// Scoped by owner in the statement rather than checked beforehand, for the
// same reason Burn is one statement: a check followed by a delete is two
// chances to be wrong about which row is which.
func (d *DB) DeletePaste(ctx context.Context, owner, id string) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM pastes WHERE id = ? AND owner = ?`, id, owner)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrPasteNotFound
		}
		return nil
	})
}

// SweepPastes removes rows past their deletion date.
//
// Separate from expiry on purpose. Expiry stops a paste being READ; this is
// what stops it being STORED, and the gap between them is what lets a reader
// be told "already used" instead of "no such paste". Without a sweep the rows
// accumulate forever -- a ciphertext nobody can read is still a ciphertext
// somebody is keeping.
func (d *DB) SweepPastes(ctx context.Context) (int64, error) {
	var n int64
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM pastes WHERE deleted_at <= ?`, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// PastesFor lists an account's own pastes, newest first. The sealed bodies are
// NOT included: the owner's device already has the plaintext, and a listing
// that carried every ciphertext would be a way to bulk-collect them without
// burning any.
func (d *DB) PastesFor(ctx context.Context, owner string) ([]Paste, error) {
	rows, err := d.read.QueryContext(ctx, `
		SELECT id, created_at, expires_at, deleted_at, max_views, views
		FROM pastes WHERE owner = ? AND deleted_at > ?
		ORDER BY created_at DESC`, owner, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Paste
	for rows.Next() {
		var p Paste
		var created, expires, deleted int64
		if err := rows.Scan(&p.ID, &created, &expires, &deleted, &p.MaxViews, &p.Views); err != nil {
			return nil, err
		}
		p.Owner = owner
		p.CreatedAt = time.UnixMilli(created)
		p.ExpiresAt = time.UnixMilli(expires)
		p.DeletedAt = time.UnixMilli(deleted)
		out = append(out, p)
	}
	return out, rows.Err()
}
