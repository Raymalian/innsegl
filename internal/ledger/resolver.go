// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The dashboard's alert resolver (RM-330, #506, ADR-0044's 2026-10-03
// amendment).
//
// ADR-0044 put the one write alert resolution needs behind a CLI command
// holding the appender's credential. The amendment lets the dashboard make
// the same write, after a fresh passkey ceremony, through a credential that
// can do nothing else: internal/api's resolver role may SELECT the alert
// events and INSERT into innsegl.alert_resolutions, and that is all. This
// type is that credential's whole Go surface. It has no Append, no Migrate
// and no way to reach either, so a pool handed to it cannot be used for
// anything Store does — which is the point of it being a separate type rather
// than a Store opened on a narrower DSN.
//
// The write itself is the one ResolveAlert makes: the same table, the same
// columns, the same three named refusals. What it adds is a batch, because a
// run whose harness telemetry stopped can raise dozens of alerts that share
// one cause, and one review closes all of them. A batch is all-or-nothing:
// either every alert in it carries this resolution, or none does.

// MaxResolveBatch bounds one batch. A run's alerts are counted in tens; a
// thousand is headroom, not a target, and a bound keeps one request from
// holding a transaction open over an unbounded list.
const MaxResolveBatch = 1000

// ErrBadResolution is a request that names no alert, names one twice, is too
// large, or carries a resolver or reason outside the table's own bounds.
// Nothing was looked up.
var ErrBadResolution = errors.New("ledger: that resolution request is not well-formed")

// AlertResolver writes alert resolutions and nothing else.
type AlertResolver struct {
	pool *pgxpool.Pool
}

// NewAlertResolver wraps a pool. The caller owns the pool and closes it;
// internal/api opens it on the resolver role and proves that role's scope
// before this ever sees it.
func NewAlertResolver(pool *pgxpool.Pool) *AlertResolver {
	return &AlertResolver{pool: pool}
}

// querier is the slice of a pool or a transaction the checks below need.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// CheckOpen answers whether ResolveAlerts would accept eventIDs, without
// writing: every id names an alert, and none is resolved yet. The dashboard
// asks this before it asks a person for their passkey, so a request that
// would be refused is refused before anyone is prompted.
func (r *AlertResolver) CheckOpen(ctx context.Context, eventIDs []string) error {
	if err := checkBatch(eventIDs); err != nil {
		return err
	}
	return checkAlertsOpen(ctx, r.pool, eventIDs)
}

// ResolveAlerts records one resolution for every alert in eventIDs, in one
// transaction, and returns the rows in the order the ids were given.
func (r *AlertResolver) ResolveAlerts(ctx context.Context, eventIDs []string, resolvedBy, reason string) ([]AlertResolution, error) {
	if err := checkBatch(eventIDs); err != nil {
		return nil, err
	}
	if resolvedBy == "" || len(resolvedBy) > maxResolvedByBytes {
		return nil, fmt.Errorf("%w: resolved_by must be 1..%d bytes, got %d",
			ErrBadResolution, maxResolvedByBytes, len(resolvedBy))
	}
	if reason == "" || len(reason) > maxResolutionReasonBytes {
		return nil, fmt.Errorf("%w: reason must be 1..%d bytes, got %d",
			ErrBadResolution, maxResolutionReasonBytes, len(reason))
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("ledger: resolving alerts: %w", err)
	}
	defer func() { discard(tx.Rollback(ctx)) }()

	if cerr := checkAlertsOpen(ctx, tx, eventIDs); cerr != nil {
		return nil, cerr
	}

	rows, err := tx.Query(ctx, `
		INSERT INTO innsegl.alert_resolutions (event_id, resolved_by, reason)
		SELECT id, $2, $3 FROM unnest($1::text[]) AS id
		RETURNING event_id, resolved_by, resolved_at, reason`,
		eventIDs, resolvedBy, reason)
	if err != nil {
		return nil, fmt.Errorf("ledger: resolving alerts: %w", err)
	}
	byID := make(map[string]AlertResolution, len(eventIDs))
	for rows.Next() {
		var res AlertResolution
		var at time.Time
		if serr := rows.Scan(&res.EventID, &res.ResolvedBy, &at, &res.Reason); serr != nil {
			rows.Close()
			return nil, fmt.Errorf("ledger: reading a resolution back: %w", serr)
		}
		res.ResolvedAt = at.UTC()
		byID[res.EventID] = res
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		// Two people resolving the same alert at once: the second insert
		// meets the first's primary key after both passed the check above.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcodeUniqueViolation {
			return nil, fmt.Errorf("%w: %s", ErrAlertAlreadyResolved, pgErr.Detail)
		}
		return nil, fmt.Errorf("ledger: resolving alerts: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("ledger: committing the resolutions: %w", err)
	}

	out := make([]AlertResolution, 0, len(eventIDs))
	for _, id := range eventIDs {
		out = append(out, byID[id])
	}
	return out, nil
}

// checkBatch refuses a batch that names no alert, an empty id, the same id
// twice, or more than MaxResolveBatch ids.
func checkBatch(eventIDs []string) error {
	switch {
	case len(eventIDs) == 0:
		return fmt.Errorf("%w: no event_id given", ErrBadResolution)
	case len(eventIDs) > MaxResolveBatch:
		return fmt.Errorf("%w: %d event_ids, more than the %d one request may resolve",
			ErrBadResolution, len(eventIDs), MaxResolveBatch)
	}
	seen := make(map[string]bool, len(eventIDs))
	for _, id := range eventIDs {
		if id == "" {
			return fmt.Errorf("%w: an event_id is empty", ErrBadResolution)
		}
		if seen[id] {
			return fmt.Errorf("%w: event_id %q is named twice", ErrBadResolution, id)
		}
		seen[id] = true
	}
	return nil
}

// checkAlertsOpen is ResolveAlert's three refusals, for a batch: every id
// names an event, every event is an alert, and no alert is resolved yet.
// The first two name the first offending id; the third names every resolved
// one, because a person choosing what to resolve next needs all of them.
func checkAlertsOpen(ctx context.Context, q querier, eventIDs []string) error {
	rows, err := q.Query(ctx, `
		SELECT e.event_id, e.event_type, r.event_id IS NOT NULL
		  FROM innsegl.events e
		  LEFT JOIN innsegl.alert_resolutions r ON r.event_id = e.event_id
		 WHERE e.event_id = ANY($1::text[])`, eventIDs)
	if err != nil {
		return fmt.Errorf("ledger: looking up alerts: %w", err)
	}
	type found struct {
		eventType string
		resolved  bool
	}
	byID := make(map[string]found, len(eventIDs))
	for rows.Next() {
		var id string
		var f found
		if err := rows.Scan(&id, &f.eventType, &f.resolved); err != nil {
			rows.Close()
			return fmt.Errorf("ledger: reading an alert: %w", err)
		}
		byID[id] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("ledger: looking up alerts: %w", err)
	}

	var resolved []string
	for _, id := range eventIDs {
		f, ok := byID[id]
		switch {
		case !ok:
			return fmt.Errorf("%w: %q", ErrAlertNotFound, id)
		case !resolvableAlertTypes[f.eventType]:
			return fmt.Errorf("%w: %q is a %s event", ErrNotAnAlert, id, f.eventType)
		case f.resolved:
			resolved = append(resolved, id)
		}
	}
	if len(resolved) > 0 {
		slices.Sort(resolved)
		return fmt.Errorf("%w: %s", ErrAlertAlreadyResolved, strings.Join(resolved, ", "))
	}
	return nil
}

// discard swallows the deferred rollback's error. After a commit it is
// pgx.ErrTxClosed; after a refusal the refusal is already the answer, and a
// rollback that fails on a broken connection changes nothing the caller can
// act on. A named function rather than a blank assignment, because errcheck
// runs with check-blank here.
func discard(error) {}
