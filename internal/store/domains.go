package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Domain is one row of the on-demand TLS allowlist, which is also the front
// door's routing table. See the migration for why this table is a security
// control rather than configuration.
type Domain struct {
	Hostname string
	Mode     string
	Backend  string
	HTTP80   string
}

// Domains returns every configured hostname, oldest first.
func (d *DB) Domains(ctx context.Context) ([]Domain, error) {
	rows, err := d.read.QueryContext(ctx,
		`SELECT hostname, mode, backend, http80 FROM domains ORDER BY added_at, hostname`)
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var dom Domain
		if err := rows.Scan(&dom.Hostname, &dom.Mode, &dom.Backend, &dom.HTTP80); err != nil {
			return nil, fmt.Errorf("scanning a domain: %w", err)
		}
		out = append(out, dom)
	}
	return out, rows.Err()
}

// PutDomain adds or replaces a hostname's route.
//
// The CHECK constraints on the table do the validating, so a caller cannot
// write a row the router could not act on -- a proxy route with no backend, or
// a hostname that is not lowercased and would therefore never match a
// lowercased SNI lookup.
func (d *DB) PutDomain(ctx context.Context, dom Domain) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO domains (hostname, mode, backend, http80, added_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(hostname) DO UPDATE SET
			   mode = excluded.mode, backend = excluded.backend, http80 = excluded.http80`,
			dom.Hostname, dom.Mode, dom.Backend, dom.HTTP80, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("storing domain %s: %w", dom.Hostname, err)
		}
		return nil
	})
}

// DeleteDomain removes a hostname. Removing one that is absent is not an error.
func (d *DB) DeleteDomain(ctx context.Context, hostname string) error {
	return d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM domains WHERE hostname = ?`, hostname)
		if err != nil {
			return fmt.Errorf("deleting domain %s: %w", hostname, err)
		}
		return nil
	})
}
