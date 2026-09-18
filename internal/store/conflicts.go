package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Conflict copies.
//
// Concurrency is last-writer-wins per collection, WITH THE LOSER KEPT. A bare
// LWW silently destroys one device's work and tells nobody, which for a
// `servers` list means a machine the user added on the laptop is simply gone
// from the desktop with no error and no symptom.
//
// So the loser is kept as a separately named object and the UI offers a choice.
// For the `vault` collection that means two vaults, and the chooser has to say
// which is which in words a person can act on -- which is why this is budgeted
// here rather than left to "the UI surfaces it".

// Conflict is a losing copy, kept for the chooser.
type Conflict struct {
	ID        int64
	Name      string
	Epoch     uint64
	Counter   uint64
	Body      []byte
	Device    []byte // the device that wrote the losing copy
	CreatedAt time.Time
}

// KeepConflict stores a losing copy.
//
// Called when a client's conditional PUT loses, so the bytes it tried to write
// are not thrown away. The winner is already in `objects`.
func (d *DB) KeepConflict(ctx context.Context, accountID string, c Conflict) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		// Charged against the quota like anything else. A conflict copy is
		// storage, and an account that cannot write cannot be made to store
		// more by losing races.
		if err := checkQuota(ctx, tx, accountID, int64(len(c.Body)), "", 0); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO conflicts (account_id, name, epoch, counter, body, device, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			accountID, c.Name, c.Epoch, c.Counter, c.Body, c.Device, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("store: keeping a conflict copy of %s: %w", c.Name, err)
		}
		return nil
	})
}

// Conflicts lists what is waiting for a choice.
//
// Oldest first, because a user resolving a backlog wants to start where the
// divergence did.
func (d *DB) Conflicts(ctx context.Context, accountID string) ([]Conflict, error) {
	rows, err := d.read.QueryContext(ctx,
		`SELECT id, name, epoch, counter, body, device, created_at
		   FROM conflicts WHERE account_id = ? ORDER BY created_at, id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: listing conflicts: %w", err)
	}
	defer rows.Close()

	var out []Conflict
	for rows.Next() {
		var c Conflict
		var created int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Epoch, &c.Counter, &c.Body, &c.Device, &created); err != nil {
			return nil, fmt.Errorf("store: scanning a conflict: %w", err)
		}
		c.CreatedAt = time.Unix(created, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ResolveConflict drops a copy once the user has chosen.
//
// Nothing reclaims these otherwise, which is the garbage-collection problem the
// design flags: the object store has no versioning, so a conflict copy is a
// real object that stays until something deletes it.
func (d *DB) ResolveConflict(ctx context.Context, accountID string, id int64) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM conflicts WHERE account_id = ? AND id = ?`, accountID, id)
		if err != nil {
			return fmt.Errorf("store: resolving a conflict: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("store: no conflict %d for this account", id)
		}
		return nil
	})
}

// SweepConflicts drops copies older than age.
//
// A BACKSTOP, NOT A POLICY. Conflicts are meant to be resolved by a person, and
// one that ages out unresolved is work somebody lost. The sweep exists because
// nothing else reclaims them and an unbounded table is an availability problem;
// the age is long enough that it is not the normal path, and it returns how many
// it dropped so that number can be surfaced rather than buried.
func (d *DB) SweepConflicts(ctx context.Context, age time.Duration) (int64, error) {
	var n int64
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM conflicts WHERE created_at < ?`, time.Now().Add(-age).Unix())
		if err != nil {
			return fmt.Errorf("store: sweeping conflicts: %w", err)
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}
