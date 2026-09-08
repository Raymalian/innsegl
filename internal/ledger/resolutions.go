// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
)

// Alert resolution (RM-102, #167, ADR-0044).
//
// #167's decision keeps the two alert event types — unattributed_signature_detected
// and ledger_drift_detected — in innsegl.events, permanently and unchanged, and
// puts the operator's judgement about one in a SEPARATE table,
// innsegl.alert_resolutions (migration 0003), keyed by the alert's event_id.
// "Open" is derived: an alert event with no row here. This file is the write
// side of that table; internal/api reads it back, read-only, alongside the
// alert events themselves.
//
// This lives on Store rather than in a new package because it is the same
// database and the same writer credential as every other method here — the
// separation #167 draws is "which TABLE", not "which service". internal/api's
// Store, by contrast, never gets this credential at all (FD §7, doc 05 §1):
// see the ADR for why the resolve path is a CLI subcommand
// (`innsegl resolve-alert`) rather than a route on the read-only query API.

// The two alert event types a resolution may name. doc 02 §3 calls both rows
// "Alert:"; nothing else in the eleven-member enum is one, and this table
// exists to resolve exactly these two.
var resolvableAlertTypes = map[string]bool{
	event.EventTypeUnattributedSignatureDetected: true,
	event.EventTypeLedgerDriftDetected:           true,
}

// Bounds mirrored from migrations/0003_alert_resolutions.sql's CHECK
// constraints, so a bad call is refused with a Go error naming the field
// rather than a raw SQLSTATE from the database.
const (
	maxResolvedByBytes       = 256
	maxResolutionReasonBytes = 2048
)

// Alert resolution errors. Each is distinct because each is a different
// operator mistake: resolving something that was never appended, resolving
// something that is not an alert, and re-resolving something already closed.
var (
	// ErrAlertNotFound: no event in this ledger carries that event_id.
	ErrAlertNotFound = errors.New("ledger: no event with that event_id")
	// ErrNotAnAlert: the event_id names a real event, but not one of the two
	// alert types this table exists to resolve.
	ErrNotAnAlert = errors.New("ledger: that event is not an alert")
	// ErrAlertAlreadyResolved: innsegl.alert_resolutions already holds a row
	// for this event_id. event_id is its PRIMARY KEY (migration 0003), so
	// this is the UNIQUE violation surfaced as a named error rather than a
	// bare SQLSTATE.
	ErrAlertAlreadyResolved = errors.New("ledger: that alert already has a resolution")
)

// AlertResolution is one row of innsegl.alert_resolutions, as written or read
// back.
type AlertResolution struct {
	EventID    string
	ResolvedBy string
	ResolvedAt time.Time
	Reason     string
}

// ResolveAlert records that a human reviewed the alert event named by
// eventID, and returns the row as the database has it.
//
// It is deliberately not idempotent: a second call for the same eventID is
// ErrAlertAlreadyResolved rather than a silent success or an overwrite. An
// operator's second, different resolvedBy/reason for the same alert is a
// correction that wants a person to look at both, not code picking one.
func (s *Store) ResolveAlert(ctx context.Context, eventID, resolvedBy, reason string) (AlertResolution, error) {
	if eventID == "" {
		return AlertResolution{}, fmt.Errorf("ledger: resolving an alert: event_id is empty")
	}
	if resolvedBy == "" || len(resolvedBy) > maxResolvedByBytes {
		return AlertResolution{}, fmt.Errorf(
			"ledger: resolving alert %s: resolved_by must be 1..%d bytes, got %d",
			eventID, maxResolvedByBytes, len(resolvedBy))
	}
	if reason == "" || len(reason) > maxResolutionReasonBytes {
		return AlertResolution{}, fmt.Errorf(
			"ledger: resolving alert %s: reason must be 1..%d bytes, got %d",
			eventID, maxResolutionReasonBytes, len(reason))
	}

	var eventType string
	err := s.pool.QueryRow(ctx,
		`SELECT event_type FROM innsegl.events WHERE event_id = $1`, eventID).Scan(&eventType)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return AlertResolution{}, fmt.Errorf("%w: %q", ErrAlertNotFound, eventID)
	case err != nil:
		return AlertResolution{}, fmt.Errorf("ledger: looking up alert %s: %w", eventID, err)
	}
	if !resolvableAlertTypes[eventType] {
		return AlertResolution{}, fmt.Errorf("%w: %q is a %s event", ErrNotAnAlert, eventID, eventType)
	}

	var out AlertResolution
	var resolvedAt time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO innsegl.alert_resolutions (event_id, resolved_by, reason)
		VALUES ($1, $2, $3)
		RETURNING event_id, resolved_by, resolved_at, reason`,
		eventID, resolvedBy, reason,
	).Scan(&out.EventID, &out.ResolvedBy, &resolvedAt, &out.Reason)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcodeUniqueViolation {
			return AlertResolution{}, fmt.Errorf("%w: %q", ErrAlertAlreadyResolved, eventID)
		}
		return AlertResolution{}, fmt.Errorf("ledger: resolving alert %s: %w", eventID, err)
	}
	out.ResolvedAt = resolvedAt.UTC()
	return out, nil
}

// pgerrcodeUniqueViolation is Postgres's own SQLSTATE for a UNIQUE
// constraint, unlike IN001/IN002/IN003: innsegl.alert_resolutions carries no
// custom trigger, so its one constraint (event_id PRIMARY KEY) reports
// through Postgres's ordinary vocabulary rather than this project's.
const pgerrcodeUniqueViolation = "23505"
