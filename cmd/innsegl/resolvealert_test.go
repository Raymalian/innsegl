// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// The command around alert resolution: flag handling and exit statuses here
// (ALR-006, stubbed — the seam is resolveAlertDeps.open, same shape as
// reap.go's reapDeps and reconcile.go's reconcileEngines), the real write
// against a real Postgres in ALR-007 below. Whether ResolveAlert itself
// enforces #167's three refusals is internal/ledger's ALR-005, against a real
// Postgres; nothing here repeats that proof.

func minimalResolveAlertArgs(extra ...string) []string {
	return append([]string{
		"-dsn", "postgres://innsegl@127.0.0.1:5432/innsegl",
		"-event-id", "01a072b2-cdda-774e-a0e2-889ec5ac33fa",
		"-resolved-by", "kody@example.com",
		"-reason", "sigstore reset under a surviving ledger; no action needed",
	}, extra...)
}

// stubResolver answers with a fixed result or error.
type stubResolver struct {
	res   ledger.AlertResolution
	err   error
	calls []struct{ eventID, resolvedBy, reason string }
}

func (s *stubResolver) ResolveAlert(_ context.Context, eventID, resolvedBy, reason string) (ledger.AlertResolution, error) {
	s.calls = append(s.calls, struct{ eventID, resolvedBy, reason string }{eventID, resolvedBy, reason})
	return s.res, s.err
}

func stubResolveOpen(r resolver, err error, closed *bool) func(context.Context, string) (resolver, func(), error) {
	return func(context.Context, string) (resolver, func(), error) {
		if err != nil {
			return nil, nil, err
		}
		return r, func() {
			if closed != nil {
				*closed = true
			}
		}, nil
	}
}

// ALR-006 — flag handling and the three exit statuses, against a stub so the
// seam (not a Postgres) is what is measured.
func TestALR006ResolveAlertCommand(t *testing.T) {
	t.Run("succeeds, calls through with exactly the flags given, and closes what it opened", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		stub := &stubResolver{res: ledger.AlertResolution{
			EventID: "01a072b2-cdda-774e-a0e2-889ec5ac33fa", ResolvedBy: "kody@example.com",
			Reason: "sigstore reset under a surviving ledger; no action needed",
		}}
		var closed bool
		deps := resolveAlertDeps{open: stubResolveOpen(stub, nil, &closed)}

		code := runResolveAlertCommand(minimalResolveAlertArgs(), &stdout, &stderr, deps)

		if code != exitOK {
			t.Fatalf("code = %d, want exitOK (%d); stderr=%s", code, exitOK, stderr.String())
		}
		if !closed {
			t.Error("the command did not close what it opened")
		}
		if len(stub.calls) != 1 {
			t.Fatalf("ResolveAlert called %d times, want 1", len(stub.calls))
		}
		got := stub.calls[0]
		if got.eventID != "01a072b2-cdda-774e-a0e2-889ec5ac33fa" ||
			got.resolvedBy != "kody@example.com" ||
			got.reason != "sigstore reset under a surviving ledger; no action needed" {
			t.Errorf("ResolveAlert called with %+v, want the flags given", got)
		}
		if !strings.Contains(stdout.String(), "01a072b2-cdda-774e-a0e2-889ec5ac33fa") {
			t.Errorf("stdout = %q, want the resolved event named", stdout.String())
		}
	})

	t.Run("writes JSON when asked", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		stub := &stubResolver{res: ledger.AlertResolution{
			EventID: "01a072b2-cdda-774e-a0e2-889ec5ac33fa", ResolvedBy: "kody@example.com",
			Reason: "test",
		}}
		deps := resolveAlertDeps{open: stubResolveOpen(stub, nil, nil)}

		code := runResolveAlertCommand(minimalResolveAlertArgs("-json"), &stdout, &stderr, deps)

		if code != exitOK {
			t.Fatalf("code = %d, want exitOK", code)
		}
		var out resolveAlertJSON
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("stdout is not JSON: %v: %s", err, stdout.String())
		}
		if out.EventID != "01a072b2-cdda-774e-a0e2-889ec5ac33fa" {
			t.Errorf("EventID = %q", out.EventID)
		}
	})

	t.Run("a required flag missing is exitUsage, and names the flag", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"dsn", []string{"-event-id", "e", "-resolved-by", "k", "-reason", "r"}, "-dsn"},
			{"event-id", []string{"-dsn", "d", "-resolved-by", "k", "-reason", "r"}, "-event-id"},
			{"resolved-by", []string{"-dsn", "d", "-event-id", "e", "-reason", "r"}, "-resolved-by"},
			{"reason", []string{"-dsn", "d", "-event-id", "e", "-resolved-by", "k"}, "-reason"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := runResolveAlertCommand(tc.args, &stdout, &stderr, resolveAlertDeps{})
				if code != exitUsage {
					t.Fatalf("code = %d, want exitUsage (%d)", code, exitUsage)
				}
				if !strings.Contains(stderr.String(), tc.want) {
					t.Errorf("stderr = %q, want it to name %q", stderr.String(), tc.want)
				}
			})
		}
	})

	t.Run("an unexpected trailing argument is exitUsage", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runResolveAlertCommand(minimalResolveAlertArgs("extra"), &stdout, &stderr, resolveAlertDeps{})
		if code != exitUsage {
			t.Fatalf("code = %d, want exitUsage", code)
		}
		if !strings.Contains(stderr.String(), "innsegl resolve-alert:") {
			t.Errorf("stderr = %q, want the subcommand named", stderr.String())
		}
	})

	t.Run("a ledger that cannot be opened is exitResolveInconclusive, and nothing is called", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		deps := resolveAlertDeps{open: stubResolveOpen(nil, errors.New("connection refused"), nil)}

		code := runResolveAlertCommand(minimalResolveAlertArgs(), &stdout, &stderr, deps)

		if code != exitResolveInconclusive {
			t.Fatalf("code = %d, want exitResolveInconclusive (%d)", code, exitResolveInconclusive)
		}
		if !strings.Contains(stderr.String(), "INCONCLUSIVE") {
			t.Errorf("stderr = %q, want it to say INCONCLUSIVE", stderr.String())
		}
	})

	t.Run("a refusal from ResolveAlert is exitResolveRefused", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		stub := &stubResolver{err: ledger.ErrAlertAlreadyResolved}
		deps := resolveAlertDeps{open: stubResolveOpen(stub, nil, nil)}

		code := runResolveAlertCommand(minimalResolveAlertArgs(), &stdout, &stderr, deps)

		if code != exitResolveRefused {
			t.Fatalf("code = %d, want exitResolveRefused (%d)", code, exitResolveRefused)
		}
		if !strings.Contains(stderr.String(), "REFUSED") {
			t.Errorf("stderr = %q, want it to say REFUSED", stderr.String())
		}
	})

	t.Run("-h prints usage naming the subcommand and exits zero", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runResolveAlertCommand([]string{"-h"}, &stdout, &stderr, resolveAlertDeps{})
		if code != exitOK {
			t.Fatalf("code = %d, want exitOK", code)
		}
		if !strings.Contains(stderr.String(), "innsegl resolve-alert") {
			t.Errorf("stderr = %q, want usage naming the subcommand", stderr.String())
		}
	})
}

// ALR-007 — end to end, through the shipped command, against a real
// Postgres: a real alert is appended by the ledger owner, `innsegl
// resolve-alert` resolves it exactly as an operator would run it, and the
// resolution is read back both through internal/ledger and via raw SQL — the
// same "real Postgres, never a mock" rule cmd/innsegl's other integration
// cases already run under (see apiharness_test.go).
func TestALR007ResolveAlertCommandAgainstARealLedger(t *testing.T) {
	ownerDSN, _ := freshLedgerDB(t)
	ctx := t.Context()

	owner, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(owner.Close)

	seed, err := owner.Append(ctx, event.Fields{
		event.FieldSchemaVersion:       event.SchemaVersion,
		event.FieldEventType:           event.EventTypeUnattributedSignatureDetected,
		event.FieldSource:              event.SourceReconciler,
		event.FieldIdempotencyKey:      "alr-007-unattributed",
		event.FieldCertificateIdentity: "spiffe://innsegl.dev/agent/deadbeef/cafef00d/run-planted",
		event.FieldRekorEntryUUID:      strings.Repeat("d", 64),
		event.FieldRekorLogIndex:       int64(9),
	})
	if err != nil {
		t.Fatalf("append unattributed alert: %v", err)
	}
	eventID, ok := seed[event.FieldEventID].(string)
	if !ok || eventID == "" {
		t.Fatalf("seeded alert carries no event_id: %+v", seed)
	}

	var stdout, stderr bytes.Buffer
	code := resolveAlertCommand([]string{
		"-dsn", ownerDSN,
		"-event-id", eventID,
		"-resolved-by", "kody@example.com",
		"-reason", "confirmed benign in a scratch environment",
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("resolveAlertCommand = %d, want exitOK; stderr=%s", code, stderr.String())
	}

	// Read the resolution back, independently of the command that wrote it.
	res, err := owner.ResolveAlert(ctx, eventID, "someone-else", "double check")
	if !errors.Is(err, ledger.ErrAlertAlreadyResolved) {
		t.Fatalf("a second resolution attempt = %v, want ErrAlertAlreadyResolved "+
			"(the CLI's resolution should already be there): res=%+v", err, res)
	}
}
