// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
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
//
// # A holder's presence is a session, not only a row
//
// A core killed with SIGKILL never releases its lease, and the row stays
// live for its whole TTL. Each holder therefore also keeps one connection of
// its own holding a session advisory lock (presenceLockKey). The kernel
// closes a killed process's sockets at once, the database ends the session,
// and the lock is free: a core that obtains it knows the row's holder is
// gone and takes over without waiting out the TTL. A holder that is alive
// keeps the lock, so a live lease still blocks every other core. A holder
// whose host vanished (its session lingering) is taken over when the row
// expires, as before.
type Leases struct {
	pool *pgxpool.Pool
	dsn  string

	mu       sync.Mutex
	presence map[string]*pgx.Conn
}

// presenceLockKey is the session advisory lock a lease holder keeps.
var presenceLockKey = int64(binary.BigEndian.Uint64(
	func() []byte { sum := sha256.Sum256([]byte("innsegl-writer-lease-presence-v1")); return sum[:8] }()))

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
	return &Leases{pool: pool, dsn: dsn, presence: map[string]*pgx.Conn{}}, nil
}

// Close ends every session this Leases opened, holding nothing back: what a
// process that dies does. It releases no lease; Release does that.
func (l *Leases) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	for holder, c := range l.presence {
		// The socket, dropped as a dying process drops it.
		_ = c.PgConn().Conn().Close()
		delete(l.presence, holder)
	}
	l.mu.Unlock()
	if l.pool != nil {
		l.pool.Close()
	}
}

// present makes holder's presence session hold the presence lock, opening
// the session when it has none or it was lost, and answers whether it holds
// the lock now. A failure to reach the ledger answers false.
func (l *Leases) present(ctx context.Context, holder string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.presence[holder]
	if c != nil && c.IsClosed() {
		c = nil
	}
	if c == nil {
		var err error
		if c, err = pgx.Connect(ctx, l.dsn); err != nil {
			delete(l.presence, holder)
			return false
		}
		l.presence[holder] = c
	}
	var got bool
	if err := c.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, presenceLockKey).Scan(&got); err != nil {
		_ = c.Close(ctx)
		delete(l.presence, holder)
		return false
	}
	if !got {
		_ = c.Close(ctx)
		delete(l.presence, holder)
	}
	return got
}

// absent ends holder's presence session, which frees the presence lock.
func (l *Leases) absent(ctx context.Context, holder string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.presence[holder]; c != nil {
		_ = c.Close(context.WithoutCancel(ctx))
		delete(l.presence, holder)
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
// has, whose holder is still present, is a *LeaseHeldError; a live lease
// whose holder's session is gone (a killed core) is taken over at once. A
// frozen ledger is ErrFrozen. Taking the lease starts a new epoch, even for
// the same holder name.
func (l *Leases) Acquire(ctx context.Context, holder string, ttl time.Duration) (WriterLease, error) {
	if strings.TrimSpace(holder) == "" || ttl <= 0 {
		return WriterLease{}, fmt.Errorf("ledger: a lease needs a holder and a positive ttl")
	}
	present := l.present(ctx, holder)
	w, err := l.inTx(ctx, "lease_acquire", func(tx pgx.Tx, cur WriterLease, live bool) (WriterLease, error) {
		if cur.FrozenAt != nil {
			return WriterLease{}, fmt.Errorf("%w since %s: %s", ErrFrozen, cur.FrozenAt.UTC().Format(time.RFC3339), cur.FrozenReason)
		}
		if live && cur.Holder != holder && !present {
			return WriterLease{}, &LeaseHeldError{Lease: cur}
		}
		return scanLease(tx.QueryRow(ctx, `UPDATE innsegl.writer_lease
			   SET holder = $1, epoch = epoch + 1, acquired_at = clock_timestamp(),
			       renewed_at = clock_timestamp(), expires_at = clock_timestamp() + $2::interval
			 WHERE id = 1 RETURNING `+leaseColumns, holder, ttlInterval(ttl)))
	})
	if err != nil {
		l.absent(ctx, holder)
	}
	return w, err
}

// Renew extends held's lease by ttl. ErrLeaseLost when another holder or a
// later epoch has it; ErrFrozen on a frozen ledger. A lease that expired
// while nobody took it (the same holder and epoch) is renewed: no other core
// acquired it, and the fence refused this core's appends while it was
// expired, so a ledger outage longer than the TTL does not stop the core.
func (l *Leases) Renew(ctx context.Context, held WriterLease, ttl time.Duration) (WriterLease, error) {
	// Best effort: a holder that took over an expired lease without the
	// presence lock, or lost its session in a ledger restart, takes it as
	// soon as it is free. The row's holder and epoch decide either way.
	l.present(ctx, held.Holder)
	return l.inTx(ctx, "lease_renew", func(tx pgx.Tx, cur WriterLease, _ bool) (WriterLease, error) {
		if cur.FrozenAt != nil {
			return WriterLease{}, ErrFrozen
		}
		if cur.Holder == "" || cur.Holder != held.Holder || cur.Epoch != held.Epoch {
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
	defer l.absent(ctx, held.Holder)
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
