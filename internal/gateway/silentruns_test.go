// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// TestSilentRunCandidatesEnumeratesEveryNonRetiredRun proves
// SilentRunCandidates.Candidates against a real chain: a run that was only
// ever registered, a run the reaper withdrew, and a retired run -- the
// third excluded, the first two present with the facts
// internal/ledger/runstate.go's own rule reads.
func TestSilentRunCandidatesEnumeratesEveryNonRetiredRun(t *testing.T) {
	f := newRealChainFixture(t)
	r := NewMCPRegistrar()

	active, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "silentruns-active",
		IdempotencyKey: "silentruns-active-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register (active): %v", err)
	}

	withdrawn, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "silentruns-withdrawn",
		IdempotencyKey: "silentruns-withdrawn-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register (withdrawn): %v", err)
	}
	// The reaper's own withdrawal, appended directly -- this file is about
	// the enumeration, not about the reaper, so the event is built by hand
	// exactly as internal/spire/reaper.go's own expiryEventBody does.
	if _, appendErr := f.store.Append(t.Context(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldRunID:          withdrawn.RunID,
		event.FieldSpiffeID:       withdrawn.SPIFFEID,
		event.FieldSource:         event.SourceReaper,
		event.FieldIdempotencyKey: "silentruns-withdrawn-expiry",
	}); appendErr != nil {
		t.Fatalf("append run_expired: %v", appendErr)
	}

	retired, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "silentruns-retired",
		IdempotencyKey: "silentruns-retired-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register (retired): %v", err)
	}
	if _, retireErr := r.Retire(t.Context(), retired.RunID); retireErr != nil {
		t.Fatalf("Retire: %v", retireErr)
	}

	enum, err := OpenSilentRunCandidates(t.Context(), f.dsn)
	if err != nil {
		t.Fatalf("OpenSilentRunCandidates: %v", err)
	}
	t.Cleanup(enum.Close)

	candidates, err := enum.Candidates(t.Context())
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}

	byID := map[string]SilentRun{}
	for _, c := range candidates {
		byID[c.RunID] = c
	}

	if _, ok := byID[retired.RunID]; ok {
		t.Errorf("the retired run %q was enumerated as a candidate; retired runs must be excluded", retired.RunID)
	}

	activeCand, ok := byID[active.RunID]
	if !ok {
		t.Fatalf("the active run %q was not enumerated", active.RunID)
	}
	if activeCand.Facts.Retired {
		t.Errorf("active run's Facts.Retired = true, want false")
	}
	if !activeCand.Facts.WithdrawnAt.IsZero() {
		t.Errorf("active run's Facts.WithdrawnAt = %v, want zero (never withdrawn)", activeCand.Facts.WithdrawnAt)
	}
	if activeCand.Facts.LastActivityAt.IsZero() {
		t.Error("active run's Facts.LastActivityAt is zero, want its registration to count as activity")
	}

	withdrawnCand, ok := byID[withdrawn.RunID]
	if !ok {
		t.Fatalf("the withdrawn run %q was not enumerated", withdrawn.RunID)
	}
	if withdrawnCand.Facts.WithdrawnAt.IsZero() {
		t.Error("withdrawn run's Facts.WithdrawnAt is zero, want the reaper's run_expired instant")
	}
	if !withdrawnCand.Facts.WithdrawalStands() {
		t.Error("withdrawn run's own withdrawal does not stand, want it to (nothing newer contradicts it)")
	}

	// The enumeration feeds a real Backstop.Sweep directly.
	registrar := NewMCPRegistrar()
	backstop, err := NewBackstop(BackstopConfig{
		Registrar: registrar,
		Horizon:   1 * time.Nanosecond,
		Now:       func() time.Time { return time.Now().Add(24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}
	retiredNow, sweepErr := backstop.Sweep(t.Context(), candidates)
	if sweepErr != nil {
		t.Fatalf("Sweep: %v", sweepErr)
	}
	var sawActive, sawWithdrawn bool
	for _, id := range retiredNow {
		if id == active.RunID {
			sawActive = true
		}
		if id == withdrawn.RunID {
			sawWithdrawn = true
		}
	}
	if !sawActive || !sawWithdrawn {
		t.Errorf("Sweep retired %v, want both %q and %q past a horizon this far in the future",
			retiredNow, active.RunID, withdrawn.RunID)
	}
}
