package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Store-and-forward, for a peer that is not awake.
//
// The live path is a direct connection between two devices. This is what
// happens when there is no live path: the sender seals to the recipient's key
// and leaves it here, and the recipient collects it when it next connects.
//
// The server holds no key to any of it. What it necessarily learns is the
// routing: that device A left something for device B, when, how big, and a
// `kind` string so the recipient can decide whether to fetch it before
// fetching it. Inside one account that is a graph of one person's own devices,
// which is the honest description and the one the threat model uses.

// MaxMailboxBytes caps one sealed message. Store-and-forward is for a
// clipboard entry and a small file, not for a backup: the relay's whole pitch
// is that it holds nothing worth attacking, and an uncapped mailbox is a
// bucket.
const MaxMailboxBytes = 4 << 20 // 4 MiB

// MailboxTTL is how long an undelivered message lives.
//
// Short on purpose. A mailbox is a place things accumulate, and an
// undelivered clipboard entry from three weeks ago is not useful to anybody --
// it is a copy of something secret that outlived every reason to keep it.
const MailboxTTL = 48 * time.Hour

var (
	ErrMailboxFull     = errors.New("that device has too much undelivered mail")
	ErrMessageTooLarge = fmt.Errorf("a message may be at most %d bytes", MaxMailboxBytes)
)

// MaxPendingPerDevice bounds one recipient's queue.
//
// Not a quota decision -- a liveness one. A device that has been off for a
// week comes back to whatever is here, and a queue of ten thousand clipboard
// entries is a device that spends its first five minutes awake downloading
// things its user stopped caring about six days ago. Oldest-wins: the cap
// refuses new mail rather than evicting old, because silently dropping the
// message somebody just sent is the worse surprise of the two.
const MaxPendingPerDevice = 256

// Message is one sealed payload waiting for a device.
type Message struct {
	ID         int64
	AccountID  string
	ToDevice   []byte
	FromDevice []byte
	Kind       string
	Sealed     []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Leave stores one message for a device that is not connected.
func (d *DB) Leave(ctx context.Context, accountID string, m Message) (int64, error) {
	if len(m.ToDevice) != 32 || len(m.FromDevice) != 32 {
		return 0, errors.New("a message names two 32-byte device keys")
	}
	if len(m.Sealed) == 0 {
		return 0, errors.New("a message needs a body")
	}
	if len(m.Sealed) > MaxMailboxBytes {
		return 0, ErrMessageTooLarge
	}
	if m.Kind == "" {
		return 0, errors.New("a message needs a kind")
	}

	now := time.Now()
	var id int64
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		// Counted inside the transaction, so two senders cannot both see room
		// for the last slot. The single writer makes this hold today; doing it
		// here means it keeps holding if that changes.
		var pending int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM mailbox
			WHERE account_id = ? AND to_device = ? AND expires_at > ?`,
			accountID, m.ToDevice, now.UnixMilli()).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaxPendingPerDevice {
			return ErrMailboxFull
		}

		res, err := tx.ExecContext(ctx, `
			INSERT INTO mailbox (account_id, to_device, from_device, kind, sealed, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			accountID, m.ToDevice, m.FromDevice, m.Kind, m.Sealed,
			now.UnixMilli(), now.Add(MailboxTTL).UnixMilli())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// Collect returns up to `limit` messages waiting for one device, oldest first,
// WITHOUT deleting them.
//
// Read and delete are separate calls on purpose. A collect that deleted would
// lose everything to one dropped connection -- the rows are gone, the bytes
// are in a TCP buffer that never arrived, and neither end can tell that from a
// successful delivery. The recipient acknowledges by id once it has the
// plaintext on disk, which is the only moment anyone knows the message
// actually landed.
//
// The cost is that a message can be delivered twice, which the recipient
// deduplicates by id. That is the right way round: a duplicated clipboard
// entry is a nuisance, and a lost one is the feature not working.
func (d *DB) Collect(ctx context.Context, accountID string, toDevice []byte, limit int) ([]Message, error) {
	if len(toDevice) != 32 {
		return nil, errors.New("a device key is 32 bytes")
	}
	if limit <= 0 || limit > MaxPendingPerDevice {
		limit = MaxPendingPerDevice
	}
	rows, err := d.read.QueryContext(ctx, `
		SELECT id, from_device, kind, sealed, created_at, expires_at
		FROM mailbox
		WHERE account_id = ? AND to_device = ? AND expires_at > ?
		ORDER BY id ASC LIMIT ?`,
		accountID, toDevice, time.Now().UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Message
	for rows.Next() {
		m := Message{AccountID: accountID, ToDevice: toDevice}
		var created, expires int64
		if err := rows.Scan(&m.ID, &m.FromDevice, &m.Kind, &m.Sealed, &created, &expires); err != nil {
			return nil, err
		}
		m.CreatedAt = time.UnixMilli(created)
		m.ExpiresAt = time.UnixMilli(expires)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Ack deletes messages the recipient says it has.
//
// Scoped to the account AND the recipient device in the statement, so an
// acknowledgement cannot delete somebody else's mail by guessing an id --
// which matters because ids are a global autoincrement and therefore entirely
// guessable.
func (d *DB) Ack(ctx context.Context, accountID string, toDevice []byte, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(toDevice) != 32 {
		return 0, errors.New("a device key is 32 bytes")
	}
	var deleted int64
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`DELETE FROM mailbox WHERE id = ? AND account_id = ? AND to_device = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, id := range ids {
			res, err := stmt.ExecContext(ctx, id, accountID, toDevice)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			deleted += n
		}
		return nil
	})
	return deleted, err
}

// SweepMailbox removes expired messages.
func (d *DB) SweepMailbox(ctx context.Context) (int64, error) {
	var n int64
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM mailbox WHERE expires_at <= ?`, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// PendingFor counts what is waiting, so a device can decide whether to stay
// awake for it.
func (d *DB) PendingFor(ctx context.Context, accountID string, toDevice []byte) (int, error) {
	var n int
	err := d.read.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM mailbox
		WHERE account_id = ? AND to_device = ? AND expires_at > ?`,
		accountID, toDevice, time.Now().UnixMilli()).Scan(&n)
	return n, err
}
