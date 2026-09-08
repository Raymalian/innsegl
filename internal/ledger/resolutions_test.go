// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// TC-ALR — alert resolution (RM-102, #167, ADR-0044).
//
// #167's decision: the two alert event types stay in innsegl.events,
// permanently and unchanged; resolving one is a row in a SEPARATE table keyed
// by the alert's event_id, outside the protected event_type enum and outside
// the events_append_only trigger. These cases prove both halves: a resolution
// can be written, read back and — unlike an event — mutated or removed; the
// alert it resolves is untouched either way.

func driftAlertBody(subjectEventID, idempotencyKey string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldIdempotencyKey: idempotencyKey,
		event.FieldSubjectEventID: subjectEventID,
		event.FieldReason:         "commit_recorded claims a Rekor entry that the log does not contain",
	}
}

func unattributedAlertBody(rekorUUID, idempotencyKey string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:       event.SchemaVersion,
		event.FieldEventType:           event.EventTypeUnattributedSignatureDetected,
		event.FieldSource:              event.SourceReconciler,
		event.FieldIdempotencyKey:      idempotencyKey,
		event.FieldCertificateIdentity: "spiffe://innsegl.dev/agent/deadbeef/cafef00d/run-planted",
		event.FieldRekorEntryUUID:      rekorUUID,
		event.FieldRekorLogIndex:       int64(7),
	}
}

// ALR-001 — a resolution can be written, is keyed by the alert's event_id, and
// is genuinely mutable: unlike innsegl.events, a raw UPDATE and a raw DELETE
// against innsegl.alert_resolutions both succeed. That is the schema half of
// #167's decision — the migration is not covered by events_append_only — and
// it is proved through raw SQL for the same reason LED-003 is: the point is
// what the DATABASE refuses, not what the Go API declines to offer.
func TestALR001ResolutionIsWritableAndGenuinelyMutable(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	seed := appendOrFailLedger(ctx, t, s, driftAlertBody("01a072b2-cdda-774e-a0e2-889ec5ac33fa", "alr-001-drift"))
	eventID := memberString(t, seed, event.FieldEventID)

	before := time.Now().UTC()
	res, err := s.ResolveAlert(ctx, eventID, "kody@example.com", "sigstore reset under a surviving ledger; no action needed")
	if err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}
	if res.EventID != eventID {
		t.Errorf("EventID = %q, want %q", res.EventID, eventID)
	}
	if res.ResolvedBy != "kody@example.com" {
		t.Errorf("ResolvedBy = %q", res.ResolvedBy)
	}
	if res.Reason == "" {
		t.Error("Reason is empty")
	}
	if res.ResolvedAt.Before(before.Add(-time.Second)) || res.ResolvedAt.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("ResolvedAt = %v, want close to now (%v)", res.ResolvedAt, before)
	}

	// Unlike an event, a resolution row tolerates a direct UPDATE.
	conn := rawConn(t, dsn)
	if _, uerr := conn.Exec(ctx,
		`UPDATE innsegl.alert_resolutions SET reason = 'revised' WHERE event_id = $1`, eventID); uerr != nil {
		t.Errorf("UPDATE innsegl.alert_resolutions: %v; #167 requires this table to be mutable, unlike innsegl.events", uerr)
	}

	// And a direct DELETE. #167: "A resolution row can be deleted; the alert
	// it resolves cannot. That asymmetry is real and is the price of staying
	// inside the current schema version."
	if _, derr := conn.Exec(ctx,
		`DELETE FROM innsegl.alert_resolutions WHERE event_id = $1`, eventID); derr != nil {
		t.Errorf("DELETE FROM innsegl.alert_resolutions: %v; #167 requires this table to be prunable", derr)
	}

	// The alert event itself is untouched by any of the above: still exactly
	// one row, at its original chain position, unresolved again now that the
	// resolution was deleted.
	chainPosition, ok := seed[event.FieldChainPosition].(int64)
	if !ok {
		t.Fatalf("appended drift alert carries no chain_position: %+v", seed)
	}
	rec, err := s.EventAt(ctx, chainPosition)
	if err != nil {
		t.Fatalf("EventAt: %v", err)
	}
	if rec[event.FieldEventID] != eventID {
		t.Errorf("the alert event itself changed: %+v", rec)
	}
}

// ALR-005 — the three ways resolving an alert is refused, and each is a
// distinct, named error a caller can act on rather than a generic failure.
func TestALR005ResolveAlertIsRefusedForAnUnknownAnAlreadyResolvedAndANonAlertEvent(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	t.Run("an empty event_id is refused before any statement runs", func(t *testing.T) {
		if _, err := s.ResolveAlert(ctx, "", "kody", "a reason"); err == nil {
			t.Error("ResolveAlert with an empty event_id succeeded")
		}
	})

	t.Run("unknown event_id", func(t *testing.T) {
		_, err := s.ResolveAlert(ctx, "01a072b2-cdda-774e-a0e2-889ec5ac33fa", "kody", "no such alert exists")
		if !errors.Is(err, ErrAlertNotFound) {
			t.Fatalf("ResolveAlert(unknown) = %v, want ErrAlertNotFound", err)
		}
	})

	t.Run("an event that is not an alert type", func(t *testing.T) {
		notAnAlert := appendOrFailLedger(ctx, t, s, storeBody(9001))
		eventID := memberString(t, notAnAlert, event.FieldEventID)

		_, err := s.ResolveAlert(ctx, eventID, "kody", "attempted on a tool_call event")
		if !errors.Is(err, ErrNotAnAlert) {
			t.Fatalf("ResolveAlert(non-alert) = %v, want ErrNotAnAlert", err)
		}
	})

	t.Run("an alert already resolved", func(t *testing.T) {
		seed := appendOrFailLedger(ctx, t, s, unattributedAlertBody(strings.Repeat("c", 64), "alr-005-unattributed"))
		eventID := memberString(t, seed, event.FieldEventID)

		if _, err := s.ResolveAlert(ctx, eventID, "kody", "first resolution"); err != nil {
			t.Fatalf("first ResolveAlert: %v", err)
		}
		_, err := s.ResolveAlert(ctx, eventID, "someone-else", "second resolution")
		if !errors.Is(err, ErrAlertAlreadyResolved) {
			t.Fatalf("second ResolveAlert = %v, want ErrAlertAlreadyResolved", err)
		}
	})

	t.Run("an empty resolved_by or reason is refused before any statement runs", func(t *testing.T) {
		seed := appendOrFailLedger(ctx, t, s, driftAlertBody("01a072b2-cdda-774e-a0e2-889ec5ac33fb", "alr-005-empty"))
		eventID := memberString(t, seed, event.FieldEventID)

		if _, err := s.ResolveAlert(ctx, eventID, "", "a reason"); err == nil {
			t.Error("ResolveAlert with an empty resolved_by succeeded")
		}
		if _, err := s.ResolveAlert(ctx, eventID, "kody", ""); err == nil {
			t.Error("ResolveAlert with an empty reason succeeded")
		}
	})
}

func appendOrFailLedger(ctx context.Context, t *testing.T, s *Store, body event.Fields) event.Fields {
	t.Helper()
	rec, err := s.Append(ctx, body)
	if err != nil {
		t.Fatalf("append %v: %v", body[event.FieldEventType], err)
	}
	return rec
}
