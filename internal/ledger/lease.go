// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The writer lease and the freeze (RM-326, #580; migrations/0021).
//
// One core writes a ledger at a time. A core acquires the lease before it
// serves, renews it while it runs and releases it when it stops; a second
// core waits. While a core holds it, the database refuses an append from a
// connection that names another writer (OpenAs). A frozen ledger refuses
// every append, whoever asks, until it is thawed.
//
// Leases is a type of its own, not methods on Store: Store offers no call
// that changes anything but the chain's end (LED-003).

// writerSetting is the per-connection setting that names a core as the
// writer; the database's fence compares it with the lease's holder.
const writerSetting = "innsegl.writer"

// SQLSTATEs the fence raises (migrations/0021).
const (
	// FrozenSQLState is raised on an append to a frozen ledger.
	FrozenSQLState = "IN007"
	// NotWriterSQLState is raised on an append from a writer that does not
	// hold a live lease.
	NotWriterSQLState = "IN008"
)

var (
	// ErrFrozen reports a frozen ledger: nothing may take the lease or
	// append until it is thawed.
	ErrFrozen = errors.New("the ledger is frozen")
	// ErrLeaseLost reports that a holder's lease was taken over or released:
	// it must stop writing.
	ErrLeaseLost = errors.New("the writer lease was lost")
)

// WriterLease is the lease as the database holds it.
type WriterLease struct {
	Holder       string
	Epoch        int64
	AcquiredAt   time.Time
	ExpiresAt    time.Time
	FrozenAt     *time.Time
	FrozenReason string
}

// LeaseHeldError reports a live lease another core holds.
type LeaseHeldError struct{ Lease WriterLease }

func (e *LeaseHeldError) Error() string {
	return fmt.Sprintf("the writer lease is held by %s until %s", e.Lease.Holder,
		e.Lease.ExpiresAt.UTC().Format(time.RFC3339))
}

// Leases reads and changes one ledger's writer lease.
type Leases struct{ pool *pgxpool.Pool }

// OpenLeases connects to the ledger database for its lease.
func OpenLeases(ctx context.Context, dsn string) (*Leases, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, classify("open_leases", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, classify("open_leases", err)
	}
	return &Leases{pool: pool}, nil
}

// Close releases the pool.
func (l *Leases) Close() {
	if l != nil && l.pool != nil {
		l.pool.Close()
	}
}

const leaseColumns = `holder, epoch, acquired_at, expires_at, frozen_at, frozen_reason`

// liveColumn says whether a holder's lease has not expired.
const liveColumn = `, holder IS NOT NULL AND expires_at > clock_timestamp()`

// scanLease reads leaseColumns, then whatever extra destinations follow.
func scanLease(row pgx.Row, extra ...any) (WriterLease, error) {
	var (
		w                         WriterLease
		holder, reason            *string
		acquired, expires, frozen *time.Time
	)
	dest := append([]any{&holder, &w.Epoch, &acquired, &expires, &frozen, &reason}, extra...)
	if err := row.Scan(dest...); err != nil {
		return WriterLease{}, err
	}
	if holder != nil {
		w.Holder = *holder
	}
	if acquired != nil {
		w.AcquiredAt = *acquired
	}
	if expires != nil {
		w.ExpiresAt = *expires
	}
	if reason != nil {
		w.FrozenReason = *reason
	}
	w.FrozenAt = frozen
	return w, nil
}

// Status answers the lease, and whether a live one is held.
func (l *Leases) Status(ctx context.Context) (WriterLease, bool, error) {
	var live bool
	w, err := scanLease(l.pool.QueryRow(ctx, `SELECT `+leaseColumns+liveColumn+
		` FROM innsegl.writer_lease WHERE id = 1`), &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return WriterLease{}, false, nil
	}
	if err != nil {
		return WriterLease{}, false, classify("lease_status", err)
	}
	return w, live, nil
}

// inTx runs fn in one transaction holding the lease row locked.
func (l *Leases) inTx(ctx context.Context, op string, fn func(pgx.Tx, WriterLease, bool) (WriterLease, error)) (WriterLease, error) {
	var out WriterLease
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO innsegl.writer_lease (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {
			return err
		}
		var live bool
		cur, err := scanLease(tx.QueryRow(ctx, `SELECT `+leaseColumns+liveColumn+
			` FROM innsegl.writer_lease WHERE id = 1 FOR UPDATE`), &live)
		if err != nil {
			return err
		}
		out, err = fn(tx, cur, live)
		return err
	})
	if err != nil {
		var held *LeaseHeldError
		if errors.Is(err, ErrFrozen) || errors.Is(err, ErrLeaseLost) || errors.As(err, &held) {
			return WriterLease{}, err
		}
		return WriterLease{}, classify(op, err)
	}
	return out, nil
}

func ttlInterval(ttl time.Duration) string {
	return fmt.Sprintf("%d microseconds", ttl.Microseconds())
}

// Acquire takes the lease for holder for ttl. A live lease another holder
// has is a *LeaseHeldError; a frozen ledger is ErrFrozen. Taking the lease
// starts a new epoch, even for the same holder name.
func (l *Leases) Acquire(ctx context.Context, holder string, ttl time.Duration) (WriterLease, error) {
	if strings.TrimSpace(holder) == "" || ttl <= 0 {
		return WriterLease{}, fmt.Errorf("ledger: a lease needs a holder and a positive ttl")
	}
	return l.inTx(ctx, "lease_acquire", func(tx pgx.Tx, cur WriterLease, live bool) (WriterLease, error) {
		if cur.FrozenAt != nil {
			return WriterLease{}, fmt.Errorf("%w since %s: %s", ErrFrozen, cur.FrozenAt.UTC().Format(time.RFC3339), cur.FrozenReason)
		}
		if live && cur.Holder != holder {
			return WriterLease{}, &LeaseHeldError{Lease: cur}
		}
		return scanLease(tx.QueryRow(ctx, `UPDATE innsegl.writer_lease
			   SET holder = $1, epoch = epoch + 1, acquired_at = clock_timestamp(),
			       renewed_at = clock_timestamp(), expires_at = clock_timestamp() + $2::interval
			 WHERE id = 1 RETURNING `+leaseColumns, holder, ttlInterval(ttl)))
	})
}

// Renew extends held's lease by ttl. ErrLeaseLost when another holder or a
// later epoch has it, or it expired; ErrFrozen on a frozen ledger.
func (l *Leases) Renew(ctx context.Context, held WriterLease, ttl time.Duration) (WriterLease, error) {
	return l.inTx(ctx, "lease_renew", func(tx pgx.Tx, cur WriterLease, live bool) (WriterLease, error) {
		if cur.FrozenAt != nil {
			return WriterLease{}, ErrFrozen
		}
		if !live || cur.Holder != held.Holder || cur.Epoch != held.Epoch {
			return WriterLease{}, ErrLeaseLost
		}
		return scanLease(tx.QueryRow(ctx, `UPDATE innsegl.writer_lease
			   SET renewed_at = clock_timestamp(), expires_at = clock_timestamp() + $1::interval
			 WHERE id = 1 RETURNING `+leaseColumns, ttlInterval(ttl)))
	})
}

// Release gives up held's lease, so the next core need not wait for it to
// expire. Releasing a lease already lost is not an error.
func (l *Leases) Release(ctx context.Context, held WriterLease) error {
	_, err := l.inTx(ctx, "lease_release", func(tx pgx.Tx, cur WriterLease, _ bool) (WriterLease, error) {
		if cur.Holder != held.Holder || cur.Epoch != held.Epoch {
			return cur, nil
		}
		_, err := tx.Exec(ctx, `UPDATE innsegl.writer_lease SET holder = NULL, expires_at = NULL WHERE id = 1`)
		return cur, err
	})
	return err
}

// Freeze marks the ledger frozen with reason and ends the current holding:
// the core that held it is refused its next renewal and stops. A ledger
// already frozen keeps its first freeze.
func (l *Leases) Freeze(ctx context.Context, reason string) (WriterLease, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return WriterLease{}, fmt.Errorf("ledger: a freeze needs a reason")
	}
	return l.inTx(ctx, "freeze", func(tx pgx.Tx, cur WriterLease, _ bool) (WriterLease, error) {
		if cur.FrozenAt != nil {
			return cur, nil
		}
		return scanLease(tx.QueryRow(ctx, `UPDATE innsegl.writer_lease
			   SET frozen_at = clock_timestamp(), frozen_reason = $1, holder = NULL, expires_at = NULL
			 WHERE id = 1 RETURNING `+leaseColumns, reason))
	})
}

// Thaw ends a freeze. Thawing a ledger that is not frozen changes nothing.
func (l *Leases) Thaw(ctx context.Context) error {
	_, err := l.inTx(ctx, "thaw", func(tx pgx.Tx, cur WriterLease, _ bool) (WriterLease, error) {
		_, err := tx.Exec(ctx, `UPDATE innsegl.writer_lease SET frozen_at = NULL, frozen_reason = NULL WHERE id = 1`)
		return cur, err
	})
	return err
}
