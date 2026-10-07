// SPDX-License-Identifier: Apache-2.0

package gateway

// lifecycle_realchain_test.go — RM-235 (#380). Carried from wave 1
// (supervisor, 2026-09-28): "GID-011 is catalogued as an integration test
// and so far is proven with fakes only (#379), so this issue adds the
// real-chain run of the backstop and session-end retire." lifecycle_test.go's
// own GID-011 cases (fakeRegistrar, fakeMappingStore) stay -- this file adds
// the same two claims against realChainFixture's real *ledger.Store, a real
// Postgres-backed PostgresMappingStore, and register_agent/retire_agent's
// own configured path, never a fake ledger.

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// TestGID011RealChainBackstopRetiresASilentRunThroughTheRealMCPPath: a run
// registered through the real MCP path, silent past the backstop's horizon,
// is retired by Backstop.Sweep through the SAME Registrar -- run_retired
// lands on the real chain and the SPIRE entry is gone.
func TestGID011RealChainBackstopRetiresASilentRunThroughTheRealMCPPath(t *testing.T) {
	f := newRealChainFixture(t)
	registrar := NewMCPRegistrar()

	out, err := registrar.Register(t.Context(), RegisterInput{
		AgentType:      "gid011-realchain-backstop",
		IdempotencyKey: "gid011-realchain-backstop-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := f.ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after registration, want 1", got)
	}

	backstop, err := NewBackstop(BackstopConfig{
		Registrar: registrar,
		Horizon:   1 * time.Nanosecond,
		Now:       func() time.Time { return time.Now().Add(24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewBackstop: %v", err)
	}

	facts := ledger.RunFacts{RegisteredAt: time.Now().Add(-time.Hour)}
	retired, err := backstop.Sweep(t.Context(), []SilentRun{{RunID: out.RunID, Facts: facts}})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(retired) != 1 || retired[0] != out.RunID {
		t.Fatalf("Sweep retired %v, want exactly [%q]", retired, out.RunID)
	}

	regs := f.eventsFor(t, out.RunID)
	var sawRetired bool
	for _, rec := range regs {
		if rec[event.FieldEventType] == event.EventTypeRunRetired {
			sawRetired = true
		}
	}
	if !sawRetired {
		t.Fatalf("no run_retired event was appended to the real chain for %q; events: %v", out.RunID, regs)
	}
	if got := f.ids.entryCount(); got != 0 {
		t.Errorf("SPIRE holds %d entries after the backstop retired the run, want 0", got)
	}
}

// TestGID011RealChainSessionEndSweepRetiresTheMainAgentRunAfterGraceThroughTheRealMCPPath:
// the session-end signal (ADR-0058 decision 7a), REDESIGNED so that receiving
// one never itself retires anything (#380 code review, 2026-09-28: a signal
// over an unauthenticated loopback socket must be safe to forge). A signal
// only marks the session; SessionEnder.Sweep retires the main agent's run,
// found through a real PostgresMappingStore row, through the SAME
// Registrar, only once the mark has stood uncancelled past its grace period
// -- run_retired lands on the real chain only then, not on the signal
// itself.
func TestGID011RealChainSessionEndSweepRetiresTheMainAgentRunAfterGraceThroughTheRealMCPPath(t *testing.T) {
	f := newRealChainFixture(t)
	registrar := NewMCPRegistrar()

	const sessionID = "gid011-realchain-session-end-session"
	out, err := registrar.Register(t.Context(), RegisterInput{
		AgentType:      "gid011-realchain-session-end",
		IdempotencyKey: "gid011-realchain-session-end-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := f.mapping.Insert(t.Context(), RunMapping{
		RunID: out.RunID, SessionID: sessionID, AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("Insert mapping row: %v", err)
	}

	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, f.mapping, registrar, time.Millisecond, nil)
	if err := ender.SessionEnded(t.Context(), sessionID); err != nil {
		t.Fatalf("SessionEnded: %v", err)
	}

	// The signal alone retires nothing: nothing has swept yet.
	var sawRetiredBeforeSweep bool
	for _, rec := range f.eventsFor(t, out.RunID) {
		if rec[event.FieldEventType] == event.EventTypeRunRetired {
			sawRetiredBeforeSweep = true
		}
	}
	if sawRetiredBeforeSweep {
		t.Fatal("run_retired was appended to the chain from SessionEnded alone, before any Sweep; " +
			"a signal must never retire by itself")
	}

	time.Sleep(5 * time.Millisecond) // past the 1ms grace configured above
	retired, sweepErr := ender.Sweep(t.Context())
	if sweepErr != nil {
		t.Fatalf("Sweep: %v", sweepErr)
	}
	if len(retired) != 1 || retired[0] != out.RunID {
		t.Fatalf("Sweep retired %v, want exactly [%q]", retired, out.RunID)
	}

	var sawRetired bool
	for _, rec := range f.eventsFor(t, out.RunID) {
		if rec[event.FieldEventType] == event.EventTypeRunRetired {
			sawRetired = true
		}
	}
	if !sawRetired {
		t.Fatalf("no run_retired event was appended to the real chain for %q", out.RunID)
	}
	if got := f.ids.entryCount(); got != 0 {
		t.Errorf("SPIRE holds %d entries after the session-end sweep retired the run, want 0", got)
	}
	if got := signals.Len(); got != 0 {
		t.Errorf("SessionEndSignals still tracks %d session(s) after Sweep retired it, want 0", got)
	}
}

// TestGID011RealChainALaterRequestOfThatConversationIsAdoptedNeverRevived:
// GID-011's own pass condition, against the real chain -- once a run is
// retired (here, through session-end), the SAME (session, agent)'s prior
// mapping, re-read through a RunStateReader over the real chain, decides
// Adopt and nothing else. ADR-0058 decision 8: resumption after retirement
// is adoption, never revival.
func TestGID011RealChainALaterRequestOfThatConversationIsAdoptedNeverRevived(t *testing.T) {
	f := newRealChainFixture(t)
	registrar := NewMCPRegistrar()

	const sessionID = "gid011-realchain-adopt-session"
	out, err := registrar.Register(t.Context(), RegisterInput{
		AgentType:      "gid011-realchain-adopt",
		IdempotencyKey: "gid011-realchain-adopt-key",
		Workspace:      realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	prior := RunMapping{RunID: out.RunID, SessionID: sessionID, AgentID: mainAgentID}
	if insertErr := f.mapping.Insert(t.Context(), prior); insertErr != nil {
		t.Fatalf("Insert mapping row: %v", insertErr)
	}
	ender := NewSessionEnder(NewSessionEndSignals(0), f.mapping, registrar, time.Millisecond, nil)
	if endErr := ender.SessionEnded(t.Context(), sessionID); endErr != nil {
		t.Fatalf("SessionEnded: %v", endErr)
	}
	time.Sleep(5 * time.Millisecond) // past the 1ms grace configured above
	if _, sweepErr := ender.Sweep(t.Context()); sweepErr != nil {
		t.Fatalf("Sweep: %v", sweepErr)
	}

	states := NewCredentialRunStates(f.dir, ledger.DefaultRestoreHorizon, nil)
	state, err := states.RunState(t.Context(), out.RunID)
	if err != nil {
		t.Fatalf("RunState: %v", err)
	}
	if state != ledger.RunRetired {
		t.Fatalf("RunState after session-end = %q, want %q", state, ledger.RunRetired)
	}

	decision, err := (Policy{}).Decide(t.Context(), LifecycleInput{
		ID:         Identification{SessionID: sessionID, AgentID: mainAgentID},
		Prior:      prior,
		Found:      true,
		PriorState: state,
		Now:        time.Now(),
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision != DecisionAdopt {
		t.Errorf("decision = %v, want DecisionAdopt (never DecisionContinue or DecisionRestore: "+
			"a retired run is never revived)", decision)
	}
}

// TestGID011RealChainTheSameSessionIsAdoptedAfterItsRunIsRetired drives the
// guard, not just the policy, through real register_agent: one (session,
// agent) registers, its run is retired, and its next request must be issued
// a NEW run. The adoption cannot reuse the key that registered the retired
// run: register_agent answers that key with the retired run (a revival) or,
// once the input differs, DUPLICATE_REQUEST on every request after.
func TestGID011RealChainTheSameSessionIsAdoptedAfterItsRunIsRetired(t *testing.T) {
	f := newRealChainFixture(t)
	registrar := NewMCPRegistrar()
	states := NewCredentialRunStates(f.dir, ledger.DefaultRestoreHorizon, nil)
	workspaces := &fakeWorkspaceResolver{ws: realChainWorkspace()}
	sessionWorkspaces := NewSessionWorkspaces(0)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid011-same-session", AgentID: mainAgentID}
	sessionWorkspaces.Record(id.SessionID, "", fixtureDirectory)
	guard, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: f.mapping, Tree: &fakeTreeLinker{}, Policy: NewPolicy(), Registrar: registrar,
		Workspaces: workspaces, RunStates: states,
		SessionEndSignals: NewSessionEndSignals(0), SessionWorkspaces: sessionWorkspaces,
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}

	r1, refusal := guard.Check(identityRequest(t, id, "hello", ""))
	if refusal != nil {
		t.Fatalf("first request refused: %+v", refusal)
	}
	first := mustRunID(t, r1)
	if _, retireErr := registrar.Retire(t.Context(), first); retireErr != nil {
		t.Fatalf("Retire: %v", retireErr)
	}

	// The branch moved between the two requests, as it does when a session
	// switches worktree: the adoption's input is not the first run's input.
	workspaces.ws.Branch = "dev/elsewhere"
	r2, refusal := guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal != nil {
		t.Fatalf("request after retirement refused: %s", refusal.Reason)
	}
	second := mustRunID(t, r2)
	if second == first {
		t.Fatalf("request after retirement was handed the retired run %q; a retired run is never revived", first)
	}
	m, found, err := f.mapping.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found || m.RunID != second || m.AdoptedFromRunID != first {
		t.Fatalf("mapping after adoption = %+v (found=%v err=%v), want run %q adopting %q", m, found, err, second, first)
	}
}
