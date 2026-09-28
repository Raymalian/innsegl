// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// GID-010: every lifecycle decision, each on its own defining input, plus
// the unset input that must refuse. GID-011: the silence backstop and the
// session-end signal retire through the Registrar fake, and a later
// request of a retired conversation decides Adopt -- never Continue or
// Restore.

// ---------------------------------------------------------------------------
// GID-010: the decision table.
// ---------------------------------------------------------------------------

func TestGID010DecisionUnsetInputRefuses(t *testing.T) {
	p := NewPolicy()
	got, err := p.Decide(context.Background(), LifecycleInput{})
	if err != nil {
		t.Fatalf("Decide(zero value) returned an error: %v", err)
	}
	if got != DecisionRefuse {
		t.Errorf("Decide(zero value) = %v, want DecisionRefuse (the zero value); an unset input must refuse", got)
	}
}

func TestGID010DecisionContinueWhenFoundActiveSameRun(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: "main"},
		Prior:      RunMapping{RunID: "run-1", SessionID: "s1", AgentID: "main"},
		Found:      true,
		PriorState: ledger.RunActive,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionContinue {
		t.Errorf("Decide(found, active, same session+agent) = %v, want DecisionContinue", got)
	}
}

func TestGID010DecisionRestoreWhenFoundLapsedSameRun(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: "main"},
		Prior:      RunMapping{RunID: "run-1", SessionID: "s1", AgentID: "main"},
		Found:      true,
		PriorState: ledger.RunLapsed,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionRestore {
		t.Errorf("Decide(found, lapsed, same session+agent) = %v, want DecisionRestore", got)
	}
}

func TestGID010DecisionNewWhenNotFoundRoot(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:    Identification{SessionID: "s1", AgentID: mainAgentID},
		Found: false,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionNew {
		t.Errorf("Decide(not found, root) = %v, want DecisionNew", got)
	}
}

func TestGID010DecisionNewWhenNotFoundChildResolvedByTree(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:          Identification{SessionID: "s1", AgentID: "sub-1"},
		ParentRunID: "run-parent",
		Found:       false,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionNew {
		t.Errorf("Decide(not found, child with resolved parent) = %v, want DecisionNew", got)
	}
}

func TestGID010DecisionForkWhenFingerprintMatchesAnotherSessionActive(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:          Identification{SessionID: "s2", AgentID: mainAgentID},
		Fingerprint: "fp-1",
		Prior:       RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID, Fingerprint: "fp-1"},
		Found:       true,
		PriorState:  ledger.RunActive,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionFork {
		t.Errorf("Decide(fingerprint match, another session, active) = %v, want DecisionFork", got)
	}
}

func TestGID010DecisionForkWhenFingerprintMatchesAnotherSessionLapsed(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:          Identification{SessionID: "s2", AgentID: mainAgentID},
		Fingerprint: "fp-1",
		Prior:       RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID, Fingerprint: "fp-1"},
		Found:       true,
		PriorState:  ledger.RunLapsed,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionFork {
		t.Errorf("Decide(fingerprint match, another session, lapsed) = %v, want DecisionFork", got)
	}
}

func TestGID010DecisionAdoptWhenSameRunRetired(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID},
		Found:      true,
		PriorState: ledger.RunRetired,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionAdopt {
		t.Errorf("Decide(same session, retired) = %v, want DecisionAdopt", got)
	}
}

func TestGID010DecisionAdoptWhenFingerprintMatchedRunRetired(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:          Identification{SessionID: "s2", AgentID: mainAgentID},
		Fingerprint: "fp-1",
		Prior:       RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID, Fingerprint: "fp-1"},
		Found:       true,
		PriorState:  ledger.RunRetired,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionAdopt {
		t.Errorf("Decide(fingerprint match, another session, retired) = %v, want DecisionAdopt", got)
	}
}

// TestGID010DecisionAdoptWhenAbandoned proves this file's own documented
// choice (lifecycle.go's doc comment, "Abandoned decides the same way
// retired does"): a prior this deployment will no longer mint for cannot be
// Continued or Restored, and it was not Refused because it was read
// cleanly, so it decides Adopt exactly as a retired prior does.
func TestGID010DecisionAdoptWhenAbandoned(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID},
		Found:      true,
		PriorState: ledger.RunAbandoned,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionAdopt {
		t.Errorf("Decide(same session, abandoned) = %v, want DecisionAdopt", got)
	}
}

func TestGID010DecisionRefusesWhenFoundWithUnreadablePriorState(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{RunID: "run-1", SessionID: "s1", AgentID: mainAgentID},
		Found:      true,
		PriorState: "not-a-real-state",
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionRefuse {
		t.Errorf("Decide(found, unreadable PriorState) = %v, want DecisionRefuse", got)
	}
}

func TestGID010DecisionRefusesWhenFoundWithNoRunID(t *testing.T) {
	p := NewPolicy()
	in := LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{SessionID: "s1", AgentID: mainAgentID}, // no RunID
		Found:      true,
		PriorState: ledger.RunActive,
	}
	got, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionRefuse {
		t.Errorf("Decide(found, no RunID) = %v, want DecisionRefuse", got)
	}
}

// ---------------------------------------------------------------------------
// GID-011: the silence backstop.
// ---------------------------------------------------------------------------

func TestGID011BackstopRetiresRunSilentPastHorizonThroughRegistrar(t *testing.T) {
	reg := &fakeRegistrar{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{
		Registrar: reg,
		Horizon:   24 * time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	candidates := []SilentRun{
		{RunID: "run-silent", Facts: ledger.RunFacts{LastActivityAt: now.Add(-48 * time.Hour)}},
	}
	retired, err := bs.Sweep(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 1 || retired[0] != "run-silent" {
		t.Errorf("Sweep retired = %v, want [run-silent]", retired)
	}
	if len(reg.calls) != 1 || reg.calls[0] != "retire" {
		t.Errorf("Registrar.calls = %v, want exactly one \"retire\"", reg.calls)
	}
}

func TestGID011BackstopSkipsRunInsideHorizon(t *testing.T) {
	reg := &fakeRegistrar{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{
		Registrar: reg,
		Horizon:   7 * 24 * time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	candidates := []SilentRun{
		{RunID: "run-recent", Facts: ledger.RunFacts{LastActivityAt: now.Add(-1 * time.Hour)}},
	}
	retired, err := bs.Sweep(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired = %v, want none (inside the horizon)", retired)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none", reg.calls)
	}
}

func TestGID011BackstopSkipsAlreadyRetiredCandidate(t *testing.T) {
	reg := &fakeRegistrar{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{
		Registrar: reg,
		Horizon:   time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	candidates := []SilentRun{
		{RunID: "run-already-retired", Facts: ledger.RunFacts{
			Retired:     true,
			RetiredAt:   now.Add(-100 * 24 * time.Hour),
			WithdrawnAt: now.Add(-200 * 24 * time.Hour),
		}},
	}
	retired, err := bs.Sweep(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired = %v, want none (already retired)", retired)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none: an already-retired candidate must not be retired again", reg.calls)
	}
}

func TestGID011BackstopContinuesPastARegistrarErrorAndJoinsIt(t *testing.T) {
	reg := &fakeRegistrar{err: errors.New("registrar unavailable")}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{
		Registrar: reg,
		Horizon:   time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	candidates := []SilentRun{
		{RunID: "run-a", Facts: ledger.RunFacts{LastActivityAt: now.Add(-48 * time.Hour)}},
		{RunID: "run-b", Facts: ledger.RunFacts{LastActivityAt: now.Add(-48 * time.Hour)}},
	}
	retired, err := bs.Sweep(context.Background(), candidates)
	if err == nil {
		t.Fatal("Sweep returned no error even though the Registrar refused every retire")
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired = %v, want none: the Registrar refused both", retired)
	}
	if len(reg.calls) != 2 {
		t.Errorf("Registrar.calls = %v, want two attempts: a failure on the first must not stop the second", reg.calls)
	}
}

func TestGID011NewBackstopDefaultsZeroHorizonToSevenDays(t *testing.T) {
	reg := &fakeRegistrar{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{
		Registrar: reg,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}
	if bs.horizon != DefaultBackstopHorizon {
		t.Errorf("NewBackstop with a zero Horizon used %s, want DefaultBackstopHorizon (%s)",
			bs.horizon, DefaultBackstopHorizon)
	}

	// Six days silent must survive the default seven-day horizon.
	retired, err := bs.Sweep(context.Background(), []SilentRun{
		{RunID: "run-six-days", Facts: ledger.RunFacts{LastActivityAt: now.Add(-6 * 24 * time.Hour)}},
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired = %v, want none: six days is inside the seven-day default", retired)
	}
}

func TestGID011NewBackstopRefusesNegativeHorizon(t *testing.T) {
	_, err := NewBackstop(BackstopConfig{Registrar: &fakeRegistrar{}, Horizon: -time.Hour})
	if err == nil {
		t.Fatal("NewBackstop accepted a negative horizon")
	}
}

func TestGID011NewBackstopRefusesNoRegistrar(t *testing.T) {
	_, err := NewBackstop(BackstopConfig{})
	if err == nil {
		t.Fatal("NewBackstop accepted a configuration with no Registrar")
	}
}

func TestGID011NewBackstopDefaultsNilNowToTimeNow(t *testing.T) {
	reg := &fakeRegistrar{}
	bs, err := NewBackstop(BackstopConfig{Registrar: reg, Horizon: time.Millisecond})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	// last is measured against the REAL clock, ten milliseconds in the
	// past, against a one-millisecond horizon. If bs.now were anything
	// other than a live time.Now -- a zero func, or pinned to some other
	// instant -- this would not read as silence past the horizon and
	// nothing would be retired.
	last := time.Now().Add(-10 * time.Millisecond)
	retired, err := bs.Sweep(context.Background(), []SilentRun{
		{RunID: "run-past", Facts: ledger.RunFacts{LastActivityAt: last}},
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 1 || retired[0] != "run-past" {
		t.Errorf("Sweep retired = %v, want [run-past]: bs.now must default to a live time.Now", retired)
	}
}

// ---------------------------------------------------------------------------
// GID-011: the session-end signal, redesigned as mark-then-sweep (#380 code
// review, 2026-09-28): a signal over this gateway's unauthenticated
// loopback endpoint must be safe to forge, so SessionEnded only ever marks
// a session -- see lifecycle.go's own doc comment on the section for the
// full argument. testClock is this file's own tiny mutable clock, so a
// test can advance past the grace period without a real sleep.
// ---------------------------------------------------------------------------

// testClock is a mutable *time.Time a test can Advance, handed to
// NewSessionEnder (and, where needed, NewBackstop) as its Now function, so
// "past the grace period" is a deterministic step rather than a real sleep.
type testClock struct{ t time.Time }

func newTestClock(start time.Time) *testClock { return &testClock{t: start} }

func (c *testClock) Now() time.Time          { return c.t }
func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestGID011SessionEndedOnlyMarksAndDoesNotRetire(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	if err := mappings.Insert(context.Background(), RunMapping{
		RunID: "run-main", SessionID: "s1", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}

	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, nil)
	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}

	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none: a signal must never retire by itself", reg.calls)
	}
	if got := signals.Len(); got != 1 {
		t.Errorf("SessionEndSignals.Len() = %d, want 1: the signal must be recorded somewhere", got)
	}
}

func TestNewSessionEnderDefaultsAZeroGraceAndANilClock(t *testing.T) {
	ender := NewSessionEnder(NewSessionEndSignals(0), &fakeMappingStore{}, &fakeRegistrar{}, 0, nil)
	if ender.grace != DefaultSessionEndGrace {
		t.Errorf("grace = %v, want DefaultSessionEndGrace (%v)", ender.grace, DefaultSessionEndGrace)
	}
	if ender.now == nil {
		t.Fatal("now was left nil instead of defaulting to time.Now")
	}
	if got := ender.now(); time.Since(got) > time.Minute {
		t.Errorf("now() = %v, does not look like the live clock", got)
	}
}

func TestGID011SessionEndedRefusesAnEmptySessionID(t *testing.T) {
	ender := NewSessionEnder(NewSessionEndSignals(0), &fakeMappingStore{}, &fakeRegistrar{}, time.Minute, nil)
	if err := ender.SessionEnded(context.Background(), ""); err == nil {
		t.Fatal("SessionEnded(\"\") returned no error")
	}
}

// ---------------------------------------------------------------------------
// Sweep: retires only once the grace period has passed uncancelled.
// ---------------------------------------------------------------------------

func TestGID011SweepRetiresTheMainAgentRunAfterTheGracePeriod(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	if err := mappings.Insert(context.Background(), RunMapping{
		RunID: "run-main", SessionID: "s1", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, clock.Now)

	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}

	// Inside the grace period: Sweep retires nothing yet.
	clock.Advance(30 * time.Second)
	if retired, err := ender.Sweep(context.Background()); err != nil || len(retired) != 0 {
		t.Fatalf("Sweep inside the grace period retired %v (err %v), want none", retired, err)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none while still inside the grace period", reg.calls)
	}

	// Past the grace period, uncancelled: Sweep retires through the
	// Registrar, and clears the mark.
	clock.Advance(time.Minute)
	retired, err := ender.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 1 || retired[0] != "run-main" {
		t.Fatalf("Sweep retired %v, want exactly [run-main]", retired)
	}
	if len(reg.calls) != 1 || reg.calls[0] != "retire" {
		t.Errorf("Registrar.calls = %v, want exactly one \"retire\"", reg.calls)
	}
	if got := signals.Len(); got != 0 {
		t.Errorf("SessionEndSignals.Len() after Sweep retired the mark = %d, want 0", got)
	}
}

// TestGID011ARequestWithinGraceCancelsTheSignalAndSweepRetiresNothing is
// review case (a): a session-end signal followed by a request within the
// grace period leaves the run continuing -- Cancel is what a request does
// (identity.go's IdentityGuard.Check calls it), tested here directly against
// SessionEndSignals and SessionEnder without the whole Guard, since this is
// entirely SessionEnder's own contract.
func TestGID011ARequestWithinGraceCancelsTheSignalAndSweepRetiresNothing(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	if err := mappings.Insert(context.Background(), RunMapping{
		RunID: "run-main", SessionID: "s1", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, clock.Now)

	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}

	// A request from s1's main agent arrives within the grace period --
	// exactly what IdentityGuard.Check does on every permitted request.
	clock.Advance(10 * time.Second)
	signals.Cancel("s1")

	// Now well past what would have been the grace period, had the signal
	// stood: Sweep retires nothing, because there is nothing left marked.
	clock.Advance(2 * time.Minute)
	retired, err := ender.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Fatalf("Sweep retired %v after the signal was cancelled, want none: the run must simply continue", retired)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none: a cancelled signal must never retire", reg.calls)
	}
}

func TestGID011SweepIgnoresOtherSessionsAndSubagents(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	ctx := context.Background()
	if err := mappings.Insert(ctx, RunMapping{RunID: "run-other-session", SessionID: "s2", AgentID: mainAgentID}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	if err := mappings.Insert(ctx, RunMapping{RunID: "run-subagent", SessionID: "s1", AgentID: "sub-1"}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}

	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	ender := NewSessionEnder(NewSessionEndSignals(0), mappings, reg, time.Minute, clock.Now)
	if err := ender.SessionEnded(ctx, "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}
	clock.Advance(2 * time.Minute)

	retired, err := ender.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired %v, want none: session s1 has no main-agent mapping of its own", retired)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none: session s1 has no main-agent mapping of its own", reg.calls)
	}
}

func TestGID011SweepIsANoOpWhenNoMappingKnown(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, clock.Now)

	if err := ender.SessionEnded(context.Background(), "never-seen"); err != nil {
		t.Fatalf("SessionEnded(unknown session) returned an error: %v", err)
	}
	clock.Advance(2 * time.Minute)
	retired, err := ender.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 0 {
		t.Errorf("Sweep retired %v, want none", retired)
	}
	if len(reg.calls) != 0 {
		t.Errorf("Registrar.calls = %v, want none", reg.calls)
	}
	// An unknown session's mark is cleared rather than swept forever.
	if got := signals.Len(); got != 0 {
		t.Errorf("SessionEndSignals.Len() = %d, want 0: an unknown session's mark must not linger", got)
	}
}

// erroringMappingStore is a MappingStore whose BySessionAgent always
// refuses -- lifecycle_fakes_test.go's shared fakeMappingStore has no error
// injection point (by design: it is the contract's own simple double), so
// this local double exists only to prove Sweep reports a lookup failure
// rather than reading found=false out of an error return.
type erroringMappingStore struct{ err error }

func (erroringMappingStore) Insert(context.Context, RunMapping) error { return nil }

func (m erroringMappingStore) BySessionAgent(context.Context, string, string) (RunMapping, bool, error) {
	return RunMapping{}, false, m.err
}

func (erroringMappingStore) ByFingerprint(context.Context, Fingerprint) ([]RunMapping, error) {
	return nil, nil
}

var _ MappingStore = erroringMappingStore{}

func TestGID011SweepPropagatesAMappingLookupError(t *testing.T) {
	mappings := erroringMappingStore{err: errors.New("mapping store unavailable")}
	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	ender := NewSessionEnder(NewSessionEndSignals(0), mappings, &fakeRegistrar{}, time.Minute, clock.Now)
	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := ender.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep returned no error even though the mapping lookup failed")
	}
}

func TestGID011SweepPropagatesARegistrarError(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{err: errors.New("registrar unavailable")}
	if err := mappings.Insert(context.Background(), RunMapping{
		RunID: "run-main", SessionID: "s1", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}

	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	ender := NewSessionEnder(NewSessionEndSignals(0), mappings, reg, time.Minute, clock.Now)
	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := ender.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep returned no error even though the Registrar refused")
	}
}

// ---------------------------------------------------------------------------
// SessionEndSignals: bounded the same reasoning tree.go's own pending-spawn
// table already gives -- review case (c)'s "map size" half.
// ---------------------------------------------------------------------------

func TestSessionEndSignalsIsBoundedAndEvictsTheOldestMark(t *testing.T) {
	signals := NewSessionEndSignals(2)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)

	signals.Mark("s1", now)
	signals.Mark("s2", now.Add(time.Second))
	if got := signals.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	// A third, distinct session over capacity evicts the oldest (s1).
	signals.Mark("s3", now.Add(2*time.Second))
	if got := signals.Len(); got != 2 {
		t.Fatalf("Len() after a third mark over capacity = %d, want 2 (bounded)", got)
	}
	if due := signals.Due(0, now.Add(3*time.Second)); len(due) != 2 {
		t.Fatalf("Due() = %v, want exactly s2 and s3", due)
	} else {
		for _, id := range due {
			if id == "s1" {
				t.Errorf("s1 survived past capacity; the oldest mark should have been evicted")
			}
		}
	}
}

func TestSessionEndSignalsReMarkingAKnownSessionDoesNotGrowTheTable(t *testing.T) {
	signals := NewSessionEndSignals(0)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	signals.Mark("s1", now)
	signals.Mark("s1", now.Add(time.Minute)) // re-signalled: restarts the grace period
	if got := signals.Len(); got != 1 {
		t.Fatalf("Len() after re-marking the same session = %d, want 1", got)
	}
	if due := signals.Due(90*time.Second, now.Add(2*time.Minute)); len(due) != 0 {
		t.Errorf("Due() = %v, want none: the re-mark should have restarted the grace period", due)
	}
}

func TestSessionEndSignalsCancelOnAnUnknownSessionIsANoOp(t *testing.T) {
	signals := NewSessionEndSignals(0)
	signals.Cancel("never-marked") // must not panic
	if got := signals.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestSessionEndSignalsMarkIgnoresAnEmptySessionID(t *testing.T) {
	signals := NewSessionEndSignals(0)
	signals.Mark("", time.Now())
	if got := signals.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0: an empty session id must never be tracked", got)
	}
}

// ---------------------------------------------------------------------------
// GID-011: a later request of a retired conversation decides Adopt, never
// Continue or Restore -- backstop-retired and session-ended alike.
// ---------------------------------------------------------------------------

func TestGID011ARequestAfterABackstopRetirementIsAdoptedNeverContinuedOrRestored(t *testing.T) {
	reg := &fakeRegistrar{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	bs, err := NewBackstop(BackstopConfig{Registrar: reg, Horizon: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	if _, sweepErr := bs.Sweep(context.Background(), []SilentRun{
		{RunID: "run-lapsed-too-long", Facts: ledger.RunFacts{LastActivityAt: now.Add(-48 * time.Hour)}},
	}); sweepErr != nil {
		t.Fatalf("Sweep: %v", sweepErr)
	}
	if _, ok := reg.retired["run-lapsed-too-long"]; !ok {
		t.Fatalf("the backstop did not retire run-lapsed-too-long through the Registrar; got %v", reg.retired)
	}

	// The conversation speaks again: the caller reads the chain, finds the
	// backstop's own run_retired, and asks the policy what to do about it.
	p := NewPolicy()
	got, err := p.Decide(context.Background(), LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{RunID: "run-lapsed-too-long", SessionID: "s1", AgentID: mainAgentID},
		Found:      true,
		PriorState: ledger.RunRetired,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionAdopt {
		t.Errorf("Decide after a backstop retirement = %v, want DecisionAdopt", got)
	}
	if got == DecisionContinue || got == DecisionRestore {
		t.Errorf("a retired run must never be Continued or Restored; got %v", got)
	}
}

func TestGID011ARequestAfterASessionEndIsAdoptedNeverContinuedOrRestored(t *testing.T) {
	mappings := &fakeMappingStore{}
	reg := &fakeRegistrar{}
	if err := mappings.Insert(context.Background(), RunMapping{
		RunID: "run-main", SessionID: "s1", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}

	clock := newTestClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	ender := NewSessionEnder(NewSessionEndSignals(0), mappings, reg, time.Minute, clock.Now)
	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}
	clock.Advance(2 * time.Minute) // past the grace period, uncancelled
	if _, err := ender.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, ok := reg.retired["run-main"]; !ok {
		t.Fatalf("Sweep did not retire run-main through the Registrar; got %v", reg.retired)
	}

	p := NewPolicy()
	got, err := p.Decide(context.Background(), LifecycleInput{
		ID:         Identification{SessionID: "s1", AgentID: mainAgentID},
		Prior:      RunMapping{RunID: "run-main", SessionID: "s1", AgentID: mainAgentID},
		Found:      true,
		PriorState: ledger.RunRetired,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got != DecisionAdopt {
		t.Errorf("Decide after a session-end retirement = %v, want DecisionAdopt", got)
	}
	if got == DecisionContinue || got == DecisionRestore {
		t.Errorf("a retired run must never be Continued or Restored; got %v", got)
	}
}
