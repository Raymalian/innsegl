// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
)

// RM-330 (#506), ADR-0044's 2026-10-03 amendment: the dashboard resolves an
// alert, or every open alert in a group, through AlertResolver — a narrow
// writer that holds no Append and no Migrate, only the write the removed
// resolve-alert CLI made. These cases prove the batch is one
// all-or-nothing write, and that it refuses exactly what ResolveAlert does.

func newAlertResolver(t *testing.T, dsn string) *AlertResolver {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewAlertResolver(pool)
}

func resolutionCount(ctx context.Context, t *testing.T, dsn string) int {
	t.Helper()
	var n int
	if err := rawConn(t, dsn).QueryRow(ctx,
		`SELECT count(*) FROM innsegl.alert_resolutions`).Scan(&n); err != nil {
		t.Fatalf("counting resolutions: %v", err)
	}
	return n
}

func TestRM330ResolveAlertsResolvesEveryAlertInTheBatch(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)
	r := newAlertResolver(t, dsn)

	var ids []string
	for i, key := range []string{"rm330-a", "rm330-b", "rm330-c"} {
		rec := appendOrFailLedger(ctx, t, s, driftAlertBody("01a072b2-cdda-774e-a0e2-889ec5ac33f"+string(rune('0'+i)), key))
		ids = append(ids, memberString(t, rec, event.FieldEventID))
	}

	if err := r.CheckOpen(ctx, ids); err != nil {
		t.Fatalf("CheckOpen on three open alerts: %v", err)
	}
	got, err := r.ResolveAlerts(ctx, ids, "Test Operator", "the harness was restarted mid-run")
	if err != nil {
		t.Fatalf("ResolveAlerts: %v", err)
	}
	if len(got) != len(ids) {
		t.Fatalf("got %d resolutions, want %d", len(got), len(ids))
	}
	for i, res := range got {
		if res.EventID != ids[i] || res.ResolvedBy != "Test Operator" ||
			res.Reason != "the harness was restarted mid-run" || res.ResolvedAt.IsZero() {
			t.Errorf("resolution %d = %+v", i, res)
		}
	}
	// Read back through the ordinary writer: the CLI's own refusal now holds.
	if _, err := s.ResolveAlert(ctx, ids[1], "kody", "again"); !errors.Is(err, ErrAlertAlreadyResolved) {
		t.Errorf("ResolveAlert after a batch resolution = %v, want ErrAlertAlreadyResolved", err)
	}
}

func TestRM330ResolveAlertsIsAllOrNothing(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)
	r := newAlertResolver(t, dsn)

	open := memberString(t, appendOrFailLedger(ctx, t, s,
		unattributedAlertBody(strings.Repeat("d", 64), "rm330-open")), event.FieldEventID)
	closed := memberString(t, appendOrFailLedger(ctx, t, s,
		unattributedAlertBody(strings.Repeat("e", 64), "rm330-closed")), event.FieldEventID)
	if _, err := s.ResolveAlert(ctx, closed, "kody", "first"); err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}
	before := resolutionCount(ctx, t, dsn)

	if err := r.CheckOpen(ctx, []string{open, closed}); !errors.Is(err, ErrAlertAlreadyResolved) {
		t.Errorf("CheckOpen with one resolved alert = %v, want ErrAlertAlreadyResolved", err)
	}
	_, err := r.ResolveAlerts(ctx, []string{open, closed}, "Test Operator", "batch")
	if !errors.Is(err, ErrAlertAlreadyResolved) {
		t.Fatalf("ResolveAlerts with one resolved alert = %v, want ErrAlertAlreadyResolved", err)
	}
	if !strings.Contains(err.Error(), closed) {
		t.Errorf("the refusal does not name the resolved alert %s: %v", closed, err)
	}
	if after := resolutionCount(ctx, t, dsn); after != before {
		t.Errorf("a refused batch wrote %d rows; it must write none", after-before)
	}
}

func TestRM330ResolveAlertsRefusals(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)
	r := newAlertResolver(t, dsn)

	alert := memberString(t, appendOrFailLedger(ctx, t, s,
		driftAlertBody("01a072b2-cdda-774e-a0e2-889ec5ac33fc", "rm330-refusals")), event.FieldEventID)
	notAnAlert := memberString(t, appendOrFailLedger(ctx, t, s, storeBody(9330)), event.FieldEventID)

	tooMany := make([]string, MaxResolveBatch+1)
	for i := range tooMany {
		tooMany[i] = alert
	}

	cases := []struct {
		name   string
		ids    []string
		by     string
		reason string
		want   error
	}{
		{"no event ids", nil, "kody", "why", ErrBadResolution},
		{"an empty event id", []string{""}, "kody", "why", ErrBadResolution},
		{"the same id twice", []string{alert, alert}, "kody", "why", ErrBadResolution},
		{"more than a batch", tooMany, "kody", "why", ErrBadResolution},
		{"an empty resolver", []string{alert}, "", "why", ErrBadResolution},
		{"a resolver too long", []string{alert}, strings.Repeat("k", maxResolvedByBytes+1), "why", ErrBadResolution},
		{"an empty reason", []string{alert}, "kody", "", ErrBadResolution},
		{"a reason too long", []string{alert}, "kody", strings.Repeat("r", maxResolutionReasonBytes+1), ErrBadResolution},
		{"an unknown event", []string{"01a072b2-cdda-774e-a0e2-889ec5ac33fd"}, "kody", "why", ErrAlertNotFound},
		{"an event that is not an alert", []string{notAnAlert}, "kody", "why", ErrNotAnAlert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := r.ResolveAlerts(ctx, c.ids, c.by, c.reason); !errors.Is(err, c.want) {
				t.Errorf("ResolveAlerts = %v, want %v", err, c.want)
			}
		})
	}
	if n := resolutionCount(ctx, t, dsn); n != 0 {
		t.Errorf("refused calls wrote %d rows", n)
	}

	t.Run("CheckOpen refuses the same ids, without a resolver or reason", func(t *testing.T) {
		if err := r.CheckOpen(ctx, nil); !errors.Is(err, ErrBadResolution) {
			t.Errorf("CheckOpen(nil) = %v", err)
		}
		if err := r.CheckOpen(ctx, []string{notAnAlert}); !errors.Is(err, ErrNotAnAlert) {
			t.Errorf("CheckOpen(non-alert) = %v", err)
		}
	})
}

// A closed pool is an unreachable ledger: the error is neither a refusal nor
// a success, and names the operation.
func TestRM330ResolveAlertsOnAClosedPool(t *testing.T) {
	t.Parallel()
	_, dsn := newStore(t)
	ctx := testCtx(t, time.Minute)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	pool.Close()
	r := NewAlertResolver(pool)
	ids := []string{"01a072b2-cdda-774e-a0e2-889ec5ac33fe"}
	for name, err := range map[string]error{
		"CheckOpen":     r.CheckOpen(ctx, ids),
		"ResolveAlerts": func() error { _, e := r.ResolveAlerts(ctx, ids, "kody", "why"); return e }(),
	} {
		if err == nil || errors.Is(err, ErrAlertNotFound) || errors.Is(err, ErrBadResolution) {
			t.Errorf("%s on a closed pool = %v, want an unreachable-ledger error", name, err)
		}
	}
}
