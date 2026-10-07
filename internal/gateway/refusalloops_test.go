// SPDX-License-Identifier: Apache-2.0

package gateway

// refusalloops_test.go — RM-334 (#532): the identity guard refuses what it
// cannot identify (ADR-0058 decision 11), and never refuses a legitimate agent
// in a permanent loop. Every case here was a loop measured against the real
// chain: real register_agent, the real idempotency store and the real ledger.
//
// The shared cause: register_agent's idempotency key is fixed per (session,
// agent[, adopted run]), but the request content was rebuilt each time from
// state that changes. A key that already names a registration on the chain is
// finished, so it is replayed exactly as recorded, never re-decided.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// lapsedOverride reads the runs in lapsed as lapsed and every other run off
// the chain: a run idle past the reaper's grace, without waiting for one.
type lapsedOverride struct {
	RunStateReader
	lapsed map[string]bool
}

func (l *lapsedOverride) RunState(ctx context.Context, runID string) (string, error) {
	if l.lapsed[runID] {
		return ledger.RunLapsed, nil
	}
	return l.RunStateReader.RunState(ctx, runID)
}

// failingInserts fails the next N mapping inserts.
type failingInserts struct {
	MappingStore
	remaining atomic.Int32
}

func (f *failingInserts) Insert(ctx context.Context, m RunMapping) error {
	if f.remaining.Load() > 0 {
		f.remaining.Add(-1)
		return errors.New("mapping insert failed")
	}
	return f.MappingStore.Insert(ctx, m)
}

// spireOutage fails the next N RegisterRun calls the way a stopped
// spire-server does: after the ledger append, retryable.
type spireOutage struct {
	*gwIdentities
	remaining atomic.Int32
}

func (s *spireOutage) RegisterRun(ctx context.Context, reg spire.Registration) (spire.Entry, error) {
	if s.remaining.Load() > 0 {
		s.remaining.Add(-1)
		return spire.Entry{}, &spire.Error{Class: spire.ClassIdentityUnavailable, Op: "create",
			Message: "spire-server is down", Retryable: true}
	}
	return s.gwIdentities.RegisterRun(ctx, reg)
}

// failFirstRegister fails the first Register before it reaches register_agent
// at all: nothing claimed, nothing appended.
type failFirstRegister struct {
	Registrar
	failed atomic.Bool
}

func (f *failFirstRegister) Register(ctx context.Context, in RegisterInput) (RegisteredRun, error) {
	if f.failed.CompareAndSwap(false, true) {
		return RegisteredRun{}, mcp.Errorf(mcp.ClassLedgerUnavailable, "", "the ledger is down")
	}
	return f.Registrar.Register(ctx, in)
}

// loopFixture is the real chain plus a guard over it.
type loopFixture struct {
	*realChainFixture
	states  *lapsedOverride
	sw      *SessionWorkspaces
	tree    *fakeTreeLinker
	inserts *failingInserts
	guard   *IdentityGuard
}

func newLoopFixture(t *testing.T, outage *spireOutage, registrar Registrar) *loopFixture {
	t.Helper()
	f := newRealChainFixture(t)
	if outage != nil {
		outage.gwIdentities = f.ids
		literal, err := identity.New(identity.ModeLiteral, "")
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		restore, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
			Identities: outage, Runs: f.dir, Ledger: f.store,
			Idempotency: mcp.NewIdempotencyStore(gwPool(t, f.dsn)), ParentID: gwParentID, Pseudonyms: literal,
		})
		if err != nil {
			t.Fatalf("ConfigureRegisterAgent: %v", err)
		}
		t.Cleanup(restore)
	}
	if registrar == nil {
		registrar = NewMCPRegistrar()
	}
	lf := &loopFixture{
		realChainFixture: f,
		states: &lapsedOverride{
			RunStateReader: NewCredentialRunStates(f.dir, f.store, ledger.DefaultRestoreHorizon, nil),
			lapsed:         map[string]bool{},
		},
		sw:      NewSessionWorkspaces(0),
		tree:    &fakeTreeLinker{},
		inserts: &failingInserts{MappingStore: f.mapping},
	}
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: lf.inserts, Tree: lf.tree, Policy: NewPolicy(), Registrar: registrar,
		Workspaces: &fakeWorkspaceResolver{}, RunStates: lf.states,
		SessionEndSignals: NewSessionEndSignals(0), SessionWorkspaces: lf.sw,
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}
	lf.guard = g
	return lf
}

func loopStated(branch, task string) StatedWorkspace {
	return StatedWorkspace{Cwd: fixtureDirectory, Repo: realChainRepo, Branch: branch, Task: task}
}

// permit sends one request and fails the test unless it is forwarded.
func (lf *loopFixture) permit(t *testing.T, id Identification, brief, assistant string) string {
	t.Helper()
	r, ref := lf.guard.Check(identityRequest(t, id, brief, assistant))
	if ref != nil {
		t.Fatalf("request refused: %d %s", ref.Status, ref.Reason)
	}
	return mustRunID(t, r)
}

// outage sends one request and fails the test unless it is a 503 with
// Retry-After: a dependency is down, so the harness tries again.
func (lf *loopFixture) outage(t *testing.T, id Identification, brief, assistant string) *Refusal {
	t.Helper()
	_, ref := lf.guard.Check(identityRequest(t, id, brief, assistant))
	if ref == nil || ref.Status != http.StatusServiceUnavailable || ref.RetryAfter <= 0 {
		t.Fatalf("refusal = %+v, want 503 with Retry-After", ref)
	}
	return ref
}

// runUnder reads the run the chain registered under key.
func (lf *loopFixture) runUnder(t *testing.T, key string) string {
	t.Helper()
	rec, found, err := lf.store.EventByIdempotencyKey(t.Context(), key)
	if err != nil || !found {
		t.Fatalf("no registration under %q: found=%v err=%v", key, found, err)
	}
	runID, ok := rec[event.FieldRunID].(string)
	if !ok {
		t.Fatalf("the event under %q names no run: %v", key, rec)
	}
	return runID
}

// registered reads the run_registered of runID back off the chain.
func (lf *loopFixture) registered(t *testing.T, runID string) event.Fields {
	t.Helper()
	for _, rec := range lf.eventsFor(t, runID) {
		if rec[event.FieldEventType] == event.EventTypeRunRegistered {
			return rec
		}
	}
	t.Fatalf("run %q has no run_registered on the chain", runID)
	return nil
}

// TestGID015RestoreOfAnAdoptedRunReplaysItsOwnRegistration: a session that
// adopted after its run was retired, and whose adopted run then lapsed, is
// restored under the ADOPTED run's own key -- never the retired run's, which
// named the retired run (INVARIANT_VIOLATION) or a different request
// (DUPLICATE_REQUEST) until the adopted run was retired too.
func TestGID015RestoreOfAnAdoptedRunReplaysItsOwnRegistration(t *testing.T) {
	for _, tc := range []struct {
		name               string
		adoptBranch, adopt string
	}{
		{"same task", "main", realChainTask},
		{"the branch moved before the adoption", "dev/rm-300-x", "rm-300"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lf := newLoopFixture(t, nil, nil)
			id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid015", AgentID: mainAgentID}
			lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

			first := lf.permit(t, id, "hello", "")
			if _, err := NewMCPRegistrar().Retire(t.Context(), first); err != nil {
				t.Fatalf("Retire: %v", err)
			}
			lf.sw.RecordStated(id.SessionID, "", loopStated(tc.adoptBranch, tc.adopt))
			second := lf.permit(t, id, "hello", "hi")
			if second == first {
				t.Fatalf("the adoption was handed the retired run %q", first)
			}

			lf.states.lapsed[second] = true
			for i := range 3 {
				if got := lf.permit(t, id, "hello", "hi again"); got != second {
					t.Fatalf("attempt %d restored run %q, want the adopted run %q", i, got, second)
				}
			}
		})
	}
}

// TestGID016RestoreAfterTheRecogniserVersionChangedReplaysTheRecordedKey: the
// key holds the recogniser's version, so a restore that recomputed it minted
// under a fresh key with no branch and failed "run_registered requires
// branch" on every request.
func TestGID016RestoreAfterTheRecogniserVersionChangedReplaysTheRecordedKey(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid016", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))
	first := lf.permit(t, id, "hello", "")

	lf.states.lapsed[first] = true
	id.Version = "2.2"
	for i := range 2 {
		if got := lf.permit(t, id, "hello", "hi"); got != first {
			t.Fatalf("attempt %d restored run %q, want %q", i, got, first)
		}
	}
}

// TestGID017ANewRunWhoseMappingWasNotStoredIsReplayedNotReDecided: the first
// registration reached the chain, its mapping row did not, and the branch
// moved. The key is finished: the next request replays what the chain
// recorded under it, so it is the same run, not DUPLICATE_REQUEST for ever.
func TestGID017ANewRunWhoseMappingWasNotStoredIsReplayedNotReDecided(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid017", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

	// Two failures: the insert is retried once, then the request is a 503.
	lf.inserts.remaining.Store(2)
	ref := lf.outage(t, id, "hello", "")
	if !strings.Contains(ref.Reason, "mapping") {
		t.Errorf("reason = %q, want it to name the mapping that could not be stored", ref.Reason)
	}
	first := lf.runUnder(t, idempotencyKeyFor(id))

	lf.sw.RecordStated(id.SessionID, "", loopStated("dev/rm-302-z", "rm-302"))
	for i := range 3 {
		if got := lf.permit(t, id, "hello", "hi"); got != first {
			t.Fatalf("attempt %d was run %q, want the run already registered under the key, %q", i, got, first)
		}
	}
	m, found, err := lf.mapping.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found || m.RunID != first {
		t.Fatalf("mapping = %+v (found=%v err=%v), want run %q", m, found, err, first)
	}
}

// TestGID017OneFailedMappingInsertIsRetriedInPlace: a single failed insert is
// retried before the request is answered, so the request is forwarded and the
// row is stored.
func TestGID017OneFailedMappingInsertIsRetriedInPlace(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid017-once", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

	lf.inserts.remaining.Store(1)
	run := lf.permit(t, id, "hello", "")
	m, found, err := lf.mapping.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found || m.RunID != run {
		t.Fatalf("mapping = %+v (found=%v err=%v), want run %q", m, found, err, run)
	}
}

// TestGID018AnAdoptionWhoseMappingWasNotStoredIsReplayedNotReDecided: the same
// as GID-017 for an adoption, whose key names the retired run it adopts.
func TestGID018AnAdoptionWhoseMappingWasNotStoredIsReplayedNotReDecided(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid018", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

	first := lf.permit(t, id, "hello", "")
	if _, err := NewMCPRegistrar().Retire(t.Context(), first); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	lf.inserts.remaining.Store(2)
	lf.outage(t, id, "hello", "hi")
	adopted := lf.runUnder(t, adoptionKeyFor(id, first))

	lf.sw.RecordStated(id.SessionID, "", loopStated("dev/rm-301-y", "rm-301"))
	for i := range 3 {
		if got := lf.permit(t, id, "hello", "hi again"); got != adopted {
			t.Fatalf("attempt %d was run %q, want the adopting run %q", i, got, adopted)
		}
	}
	m, found, err := lf.mapping.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found || m.RunID != adopted || m.AdoptedFromRunID != first {
		t.Fatalf("mapping = %+v (found=%v err=%v), want run %q adopting %q", m, found, err, adopted, first)
	}
}

// TestGID018AKeyWhoseRunWasRetiredSinceIsAdopted: a registration whose mapping
// was never stored, retired since, is not handed to the next request: the
// mapping is repaired and the request adopts.
func TestGID018AKeyWhoseRunWasRetiredSinceIsAdopted(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid018-retired", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

	lf.inserts.remaining.Store(2)
	lf.outage(t, id, "hello", "")
	first := lf.runUnder(t, idempotencyKeyFor(id))
	if _, err := NewMCPRegistrar().Retire(t.Context(), first); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	got := lf.permit(t, id, "hello", "hi")
	if got == first {
		t.Fatalf("the request was handed the retired run %q", first)
	}
	m, found, err := lf.mapping.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found || m.RunID != got || m.AdoptedFromRunID != first {
		t.Fatalf("mapping = %+v (found=%v err=%v), want run %q adopting %q", m, found, err, got, first)
	}
}

// subagentFixture registers a main agent and records its spawn of a subagent.
func subagentFixture(t *testing.T, lf *loopFixture, session, prompt, spawnType string) (parent string, sub Identification) {
	t.Helper()
	main := Identification{Harness: "claude-code", Version: "2.1", SessionID: session, AgentID: mainAgentID}
	lf.sw.RecordStated(session, "", loopStated(realChainBranch, realChainTask))
	parent = lf.permit(t, main, "hello", "")
	if err := lf.tree.RecordSpawn(t.Context(), PendingSpawn{
		ParentRunID: parent, SessionID: session, Prompt: prompt, AgentType: spawnType,
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	return parent, Identification{Harness: "claude-code", Version: "2.1", SessionID: session, AgentID: "a1b2c3d4e5f6a7b8c"}
}

// TestGID019ASubagentRetriedAfterASpireOutageKeepsItsParent: the first
// registration reached the chain and SPIRE was down. The spawn was consumed
// on the first attempt, so the retry had no parent and the ledger refused it
// ("idempotency_key already names a different event") for ever.
func TestGID019ASubagentRetriedAfterASpireOutageKeepsItsParent(t *testing.T) {
	outage := &spireOutage{}
	lf := newLoopFixture(t, outage, nil)
	parent, sub := subagentFixture(t, lf, "gid019", "explore the code", "Explore")
	st := loopStated(realChainBranch, realChainTask)
	st.AgentType = "Explore"
	lf.sw.RecordStated(sub.SessionID, sub.AgentID, st)

	outage.remaining.Store(1)
	lf.outage(t, sub, "explore the code", "")
	for i := range 3 {
		run := lf.permit(t, sub, "explore the code", "")
		if got := lf.registered(t, run)[event.FieldParentRunID]; got != parent {
			t.Fatalf("attempt %d: run %q recorded parent %v, want %q", i, run, got, parent)
		}
	}
}

// TestGID020ASubagentRetriedAfterAnOutageKeepsItsAgentType: with no
// hook-stated type, the first attempt was the spawn's type (plan) and the
// retry, with the spawn consumed, "subagent": DUPLICATE_REQUEST for ever.
func TestGID020ASubagentRetriedAfterAnOutageKeepsItsAgentType(t *testing.T) {
	outage := &spireOutage{}
	lf := newLoopFixture(t, outage, nil)
	parent, sub := subagentFixture(t, lf, "gid020", "plan it", "Plan")

	outage.remaining.Store(1)
	lf.outage(t, sub, "plan it", "")
	for i := range 2 {
		run := lf.permit(t, sub, "plan it", "")
		rec := lf.registered(t, run)
		if rec[event.FieldAgentType] != "plan" || rec[event.FieldParentRunID] != parent {
			t.Fatalf("attempt %d: run %q recorded agent_type %v parent %v, want plan and %q",
				i, run, rec[event.FieldAgentType], rec[event.FieldParentRunID], parent)
		}
	}
}

// TestGID020ASpawnIsKeptUntilItsChildIsRegistered: a registration that failed
// before reaching register_agent does not lose the spawn it was linked by, so
// the retry is registered under its parent rather than as a root.
func TestGID020ASpawnIsKeptUntilItsChildIsRegistered(t *testing.T) {
	registrar := &failFirstRegister{Registrar: NewMCPRegistrar()}
	lf := newLoopFixture(t, nil, registrar)
	// The main agent's own first registration is the one that fails.
	main := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid020-keep", AgentID: mainAgentID}
	lf.sw.RecordStated(main.SessionID, "", loopStated(realChainBranch, realChainTask))
	lf.outage(t, main, "hello", "")
	parent := lf.permit(t, main, "hello", "")

	registrar.failed.Store(false)
	if err := lf.tree.RecordSpawn(t.Context(), PendingSpawn{
		ParentRunID: parent, SessionID: main.SessionID, Prompt: "review it", AgentType: "Reviewer",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	sub := Identification{Harness: "claude-code", Version: "2.1", SessionID: main.SessionID, AgentID: "b1b2c3d4e5f6a7b8c"}
	lf.outage(t, sub, "review it", "")
	run := lf.permit(t, sub, "review it", "")
	rec := lf.registered(t, run)
	if rec[event.FieldParentRunID] != parent || rec[event.FieldAgentType] != "reviewer" {
		t.Fatalf("run %q recorded parent %v agent_type %v, want %q and reviewer",
			run, rec[event.FieldParentRunID], rec[event.FieldAgentType], parent)
	}
	m, found, err := lf.mapping.BySessionAgent(t.Context(), sub.SessionID, sub.AgentID)
	if err != nil || !found || m.ParentRunID != parent || m.AgentTypeVerbatim != "Reviewer" {
		t.Fatalf("mapping = %+v (found=%v err=%v), want parent %q and type Reviewer", m, found, err, parent)
	}
}

// TestGID020AKeyBoundToOtherContentThatRecordedNothingMovesOn: a key whose
// earlier call never reached the chain, but bound the key to other content,
// is answered DUPLICATE_REQUEST by the idempotency store for ever. Nothing
// was recorded under it, so the registration moves to a key named by its own
// content.
func TestGID020AKeyBoundToOtherContentThatRecordedNothingMovesOn(t *testing.T) {
	lf := newLoopFixture(t, nil, nil)
	id := Identification{Harness: "claude-code", Version: "2.1", SessionID: "gid020-bound", AgentID: mainAgentID}
	lf.sw.RecordStated(id.SessionID, "", loopStated(realChainBranch, realChainTask))

	idem := mcp.NewIdempotencyStore(gwPool(t, lf.dsn))
	_, err := idem.Do(t.Context(), mcp.Call{
		Tool: string(mcp.ToolRegisterAgent), Key: idempotencyKeyFor(id),
		Params: map[string]any{"agent_type": mainAgentID, "task_id": "an-older-task"},
	}, func(context.Context) (any, error) { return nil, errors.New("refused before any effect") })
	if err == nil {
		t.Fatal("binding the key: want the refusal back")
	}

	first := lf.permit(t, id, "hello", "")
	if got := lf.registered(t, first)[event.FieldTaskRef]; got != realChainTask {
		t.Fatalf("run %q recorded task %v, want %q", first, got, realChainTask)
	}
	// The mapping is stored, so the next request continues it.
	if got := lf.permit(t, id, "hello", "hi"); got != first {
		t.Fatalf("second request was run %q, want %q", got, first)
	}
}

// TestGID021ATransientStoreFaultIsAnOutageNotARefusal: a retryable ledger
// fault, and a Postgres connection fault, are a dependency that is down: 503
// with Retry-After. A fault that is not retryable stays 403.
func TestGID021ATransientStoreFaultIsAnOutageNotARefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"retryable store error", &ledger.StoreError{Class: ledger.ClassLedgerUnavailable, Op: "read",
			Retryable: true, Err: errors.New("connection reset")}, http.StatusServiceUnavailable},
		{"store error that is not retryable", &ledger.StoreError{Class: ledger.ClassInvariantViolation, Op: "read",
			Err: errors.New("stored event is not readable")}, http.StatusForbidden},
		{"connection exception", &pgconn.PgError{Code: "08006", Message: "connection failure"}, http.StatusServiceUnavailable},
		{"admin shutdown", &pgconn.PgError{Code: "57P01", Message: "terminating connection"}, http.StatusServiceUnavailable},
		{"cannot connect now", &pgconn.PgError{Code: "57P03", Message: "the database system is starting up"}, http.StatusServiceUnavailable},
		{"query canceled is not an outage", &pgconn.PgError{Code: "57014", Message: "canceling statement"}, http.StatusForbidden},
		{"constraint violation", &pgconn.PgError{Code: "23505", Message: "duplicate key"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdentityFixture(t)
			id := Identification{SessionID: "s1", AgentID: mainAgentID}
			if err := f.mappings.Insert(t.Context(), RunMapping{
				RunID: "run-x", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
			}); err != nil {
				t.Fatalf("seed Insert: %v", err)
			}
			f.runStates.err = tc.err

			_, ref := f.guard.Check(identityRequest(t, id, "hello", "hi"))
			if ref == nil || ref.Status != tc.want {
				t.Fatalf("refusal = %+v, want %d", ref, tc.want)
			}
			if tc.want == http.StatusServiceUnavailable && ref.RetryAfter <= 0 {
				t.Errorf("a 503 with no Retry-After: %+v", ref)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The error paths of the replay, through the fakes.
// ---------------------------------------------------------------------------

// scriptedRegistrar answers Register with each of errs in turn, then as the
// fake registrar does.
type scriptedRegistrar struct {
	*fakeRegistrar
	errs []error
}

func (s *scriptedRegistrar) Register(ctx context.Context, in RegisterInput) (RegisteredRun, error) {
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		s.calls = append(s.calls, "register")
		s.lastSeen = in
		return RegisteredRun{}, err
	}
	return s.fakeRegistrar.Register(ctx, in)
}

// guardWith rebuilds f's guard over registrar and mappings.
func guardWith(t *testing.T, f *identityFixture, registrar Registrar, mappings MappingStore) *IdentityGuard {
	t.Helper()
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: mappings, Tree: f.tree, Policy: NewPolicy(), Registrar: registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}
	return g
}

var errKeyBound = mcp.Errorf(mcp.ClassDuplicateRequest, "", "%w", mcp.ErrKeyNamesADifferentRequest)

// TestGID015RestoreReplaysEveryRecordedMember: the restore input is the
// registration as recorded, key and branch and parent included.
func TestGID015RestoreReplaysEveryRecordedMember(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: "a1b2c3d4e5f6a7b8c"}
	if err := f.mappings.Insert(t.Context(), RunMapping{RunID: "run-r", SessionID: id.SessionID, AgentID: id.AgentID}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-r", ledger.RunLapsed)
	recorded := RunRegistration{AgentType: "plan", TaskID: "t", Repo: "acme/r", IdempotencyKey: "k-recorded",
		Branch: "dev/x", ParentRunID: "run-p", ForkedFromRunID: "run-f"}
	f.runStates.register("run-r", recorded)

	if _, ref := f.guard.Check(identityRequest(t, id, "hello", "hi")); ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	if got, want := f.registrar.lastSeen, recorded.replay(); got != want {
		t.Errorf("restore input = %+v, want %+v", got, want)
	}
}

// TestGID015ARestoreThatCannotBeReplayedSaysWhatToDo: a registration with no
// recorded key, and a replay register_agent refuses, each name `innsegl
// retire`.
func TestGID015ARestoreThatCannotBeReplayedSaysWhatToDo(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		err  error
	}{
		{"no recorded key", "", nil},
		{"replay refused", "k-r", mcp.Errorf(mcp.ClassInvariantViolation, "run-r", "named another run")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdentityFixture(t)
			id := Identification{SessionID: "s1", AgentID: mainAgentID}
			if err := f.mappings.Insert(t.Context(), RunMapping{RunID: "run-r", SessionID: id.SessionID, AgentID: id.AgentID}); err != nil {
				t.Fatalf("seed Insert: %v", err)
			}
			f.runStates.set("run-r", ledger.RunLapsed)
			f.runStates.register("run-r", RunRegistration{AgentType: mainAgentID, TaskID: "t", Repo: "acme/r", IdempotencyKey: tc.key})
			f.registrar.err = tc.err

			_, ref := f.guard.Check(identityRequest(t, id, "hello", "hi"))
			if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, "`innsegl retire run-r`") {
				t.Fatalf("refusal = %+v, want 403 naming `innsegl retire run-r`", ref)
			}
		})
	}
}

// TestGID017TheKeyLookupFailingIsRefusedNotGuessed: a key lookup that fails
// registers nothing; a ledger outage is a 503.
func TestGID017TheKeyLookupFailingIsRefusedNotGuessed(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	f.runStates.keyErrs = map[string]error{idempotencyKeyFor(id): &ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "event", Retryable: true, Err: errors.New("down")}}

	_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
	if ref == nil || ref.Status != http.StatusServiceUnavailable {
		t.Fatalf("refusal = %+v, want 503", ref)
	}
	if len(f.registrar.calls) != 0 {
		t.Errorf("registrar calls = %v, want none", f.registrar.calls)
	}
}

// contentKeyOfFixture is the content key a main agent of the identity
// fixture registers under once its own key is bound to other content.
func contentKeyOfFixture(id Identification) string {
	return contentKeyFor(idempotencyKeyFor(id), RegisterInput{AgentType: mainAgentID, Workspace: Workspace{Task: "task-1"}})
}

// TestGID020TheContentKeyIsLookedUpBeforeItIsUsed: a content key the chain
// already holds is replayed, and a lookup of it that fails registers nothing.
func TestGID020TheContentKeyIsLookedUpBeforeItIsUsed(t *testing.T) {
	t.Run("already registered", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		reg := &scriptedRegistrar{fakeRegistrar: f.registrar, errs: []error{errKeyBound}}
		g := guardWith(t, f, reg, f.mappings)
		f.runStates.register("run-content", RunRegistration{AgentType: mainAgentID, TaskID: "task-1",
			Repo: "acme/id-test", Branch: "main", IdempotencyKey: contentKeyOfFixture(id)})
		f.runStates.set("run-content", ledger.RunActive)

		r, ref := g.Check(identityRequest(t, id, "hello", ""))
		if ref != nil {
			t.Fatalf("refused: %+v", ref)
		}
		if got := mustRunID(t, r); got != "run-content" {
			t.Errorf("run = %q, want run-content", got)
		}
		if f.registrar.lastSeen.IdempotencyKey != contentKeyOfFixture(id) {
			t.Errorf("replayed under %q, want the content key", f.registrar.lastSeen.IdempotencyKey)
		}
	})
	t.Run("lookup fails", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		reg := &scriptedRegistrar{fakeRegistrar: f.registrar, errs: []error{errKeyBound}}
		g := guardWith(t, f, reg, f.mappings)
		f.runStates.keyErrs = map[string]error{contentKeyOfFixture(id): errors.New("unreadable")}

		_, ref := g.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, contentKeyOfFixture(id)) {
			t.Fatalf("refusal = %+v, want 403 naming the content key", ref)
		}
		if len(f.registrar.calls) != 1 {
			t.Errorf("registrar calls = %v, want only the first", f.registrar.calls)
		}
	})
}

// TestGID018AReplayThatCannotFinishIsRefusedWithAReason: the replayed run's
// state cannot be read, its retired run's mapping cannot be stored, or
// register_agent refuses the replay.
func TestGID018AReplayThatCannotFinishIsRefusedWithAReason(t *testing.T) {
	seed := func(t *testing.T, f *identityFixture, id Identification, state string) {
		t.Helper()
		f.runStates.register("run-k", RunRegistration{AgentType: mainAgentID, TaskID: "task-1",
			Repo: "acme/id-test", Branch: "main", IdempotencyKey: idempotencyKeyFor(id)})
		f.runStates.set("run-k", state)
	}
	t.Run("state unreadable", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		seed(t, f, id, ledger.RunActive)
		f.runStates.stateErrs = map[string]error{"run-k": errors.New("unreadable")}
		_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, `state of run "run-k"`) {
			t.Fatalf("refusal = %+v, want 403 naming the run whose state could not be read", ref)
		}
	})
	t.Run("retired, mapping not stored", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		seed(t, f, id, ledger.RunRetired)
		g := guardWith(t, f, f.registrar, failingInsertMappingStore{fakeMappingStore: f.mappings.fakeMappingStore})
		_, ref := g.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || ref.Status != http.StatusServiceUnavailable {
			t.Fatalf("refusal = %+v, want 503", ref)
		}
		if len(f.registrar.calls) != 0 {
			t.Errorf("registrar calls = %v, want none before the retired run's row is stored", f.registrar.calls)
		}
	})
	t.Run("replay refused", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		seed(t, f, id, ledger.RunActive)
		f.registrar.err = mcp.Errorf(mcp.ClassInvariantViolation, "run-k", "named another run")
		_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, "`innsegl retire run-k`") {
			t.Fatalf("refusal = %+v, want 403 naming `innsegl retire run-k`", ref)
		}
	})
}

// TestGID012EveryRefusalSaysWhatCanBeDone: a registration refused, and each
// of the lifecycle policy's refusals, name what an operator can do.
func TestGID012EveryRefusalSaysWhatCanBeDone(t *testing.T) {
	t.Run("parent no longer recordable", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: "a1b2c3d4e5f6a7b8c"}
		f.sessionWorkspaces.Record("s1", id.AgentID, fixtureDirectory)
		if err := f.tree.RecordSpawn(t.Context(), PendingSpawn{ParentRunID: "run-p", SessionID: "s1", Prompt: "do it"}); err != nil {
			t.Fatalf("RecordSpawn: %v", err)
		}
		f.registrar.err = mcp.Errorf(mcp.ClassRunAlreadyRetired, "", "parent retired")
		_, ref := f.guard.Check(identityRequest(t, id, "do it", ""))
		if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, "Spawn it again from the parent session") {
			t.Fatalf("refusal = %+v, want 403 saying to spawn it again", ref)
		}
		// The spawn is held for the agent, so the retry is the same request.
		f.registrar.err = nil
		if _, ref := f.guard.Check(identityRequest(t, id, "do it", "")); ref != nil {
			t.Fatalf("retry refused: %+v", ref)
		}
		if f.registrar.lastSeen.ParentRunID != "run-p" {
			t.Errorf("retry registered with parent %q, want run-p", f.registrar.lastSeen.ParentRunID)
		}
	})
	t.Run("any other registration refusal", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		f.registrar.err = mcp.Errorf(mcp.ClassInvariantViolation, "", "task_id is not an identifier")
		_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Reason, "a new session registers under a key of its own") {
			t.Fatalf("refusal = %+v, want 403 naming a new session", ref)
		}
	})
	t.Run("no agent", func(t *testing.T) {
		f := newIdentityFixture(t)
		_, ref := f.guard.Check(identityRequest(t, Identification{SessionID: "s1"}, "hello", ""))
		if ref == nil || !strings.Contains(ref.Reason, "names no session or no agent") {
			t.Fatalf("refusal = %+v, want it to name the missing agent", ref)
		}
	})
	t.Run("mapping names no run", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		if err := f.mappings.Insert(t.Context(), RunMapping{SessionID: id.SessionID, AgentID: id.AgentID}); err != nil {
			t.Fatalf("seed Insert: %v", err)
		}
		_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || !strings.Contains(ref.Reason, "names no run; a new session") {
			t.Fatalf("refusal = %+v, want it to name the empty mapping row", ref)
		}
	})
	t.Run("unreadable state", func(t *testing.T) {
		f := newIdentityFixture(t)
		id := Identification{SessionID: "s1", AgentID: mainAgentID}
		if err := f.mappings.Insert(t.Context(), RunMapping{RunID: "run-odd", SessionID: id.SessionID, AgentID: id.AgentID}); err != nil {
			t.Fatalf("seed Insert: %v", err)
		}
		f.runStates.set("run-odd", "sideways")
		_, ref := f.guard.Check(identityRequest(t, id, "hello", ""))
		if ref == nil || !strings.Contains(ref.Reason, `read as "sideways"`) || !strings.Contains(ref.Reason, "`innsegl retire run-odd`") {
			t.Fatalf("refusal = %+v, want it to name the state and `innsegl retire run-odd`", ref)
		}
	})
	t.Run("a decision this guard does not know", func(t *testing.T) {
		f := newIdentityFixture(t)
		g, err := NewIdentityGuard(IdentityGuardConfig{
			Mappings: f.mappings, Tree: f.tree, Policy: &fakePolicy{decision: Decision(99)}, Registrar: f.registrar,
			Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
		})
		if err != nil {
			t.Fatalf("NewIdentityGuard: %v", err)
		}
		_, ref := g.Check(identityRequest(t, Identification{SessionID: "s1", AgentID: mainAgentID}, "hello", ""))
		if ref == nil || !strings.Contains(ref.Reason, "decision 99") {
			t.Fatalf("refusal = %+v, want it to name the decision", ref)
		}
	})
}

// chainRuns and chainKeys are the run directory and the ledger's key read,
// as maps.
type chainRuns map[string]mcp.CredentialRun

func (c chainRuns) CredentialRun(_ context.Context, runID string) (mcp.CredentialRun, bool, error) {
	run, ok := c[runID]
	return run, ok, nil
}

type chainKeys struct {
	events map[string]event.Fields
	err    error
}

func (c chainKeys) EventByIdempotencyKey(_ context.Context, key string) (event.Fields, bool, error) {
	rec, ok := c.events[key]
	return rec, ok, c.err
}

// TestGID015TheChainReaderAnswersARegistrationByItsKey: the reader behind
// RegistrationByKey, over each answer the chain can give.
func TestGID015TheChainReaderAnswersARegistrationByItsKey(t *testing.T) {
	runs := chainRuns{"run-1": {RunID: "run-1", AgentType: "plan", TaskID: "t", Repo: "acme/r",
		Branch: "main", ParentRunID: "run-p", ForkedFromRunID: "run-f", IdempotencyKey: "k1"}}
	keys := chainKeys{events: map[string]event.Fields{
		"k1":      {event.FieldEventType: event.EventTypeRunRegistered, event.FieldRunID: "run-1"},
		"k-sig":   {event.FieldEventType: "commit_signed", event.FieldRunID: "run-1"},
		"k-lost":  {event.FieldEventType: event.EventTypeRunRegistered, event.FieldRunID: "run-gone"},
		"k-norun": {event.FieldEventType: event.EventTypeRunRegistered},
	}}
	r := NewCredentialRunStates(runs, keys, 0, nil)

	reg, found, err := r.RegistrationByKey(t.Context(), "k1")
	want := RunRegistration{AgentType: "plan", TaskID: "t", Repo: "acme/r", RunID: "run-1", IdempotencyKey: "k1",
		Branch: "main", ParentRunID: "run-p", ForkedFromRunID: "run-f"}
	if err != nil || !found || reg != want {
		t.Errorf("k1 = %+v found=%v err=%v, want %+v", reg, found, err, want)
	}
	if _, found, err := r.RegistrationByKey(t.Context(), "k-none"); err != nil || found {
		t.Errorf("an unused key: found=%v err=%v, want not found", found, err)
	}
	if _, _, err := r.RegistrationByKey(t.Context(), "k-sig"); err == nil || !strings.Contains(err.Error(), "commit_signed") {
		t.Errorf("a key naming another event: err = %v, want a refusal naming it", err)
	}
	if _, _, err := r.RegistrationByKey(t.Context(), "k-norun"); err == nil || !strings.Contains(err.Error(), "names no run") {
		t.Errorf("a registration naming no run: err = %v, want a refusal", err)
	}
	if _, _, err := r.RegistrationByKey(t.Context(), "k-lost"); err == nil {
		t.Error("a key naming a run the directory does not know: want an error")
	}
	broken := NewCredentialRunStates(runs, chainKeys{err: errors.New("down")}, 0, nil)
	if _, _, err := broken.RegistrationByKey(t.Context(), "k1"); err == nil || !strings.Contains(err.Error(), `"k1"`) {
		t.Errorf("a failed read: err = %v, want it to name the key", err)
	}
}

// TestGID019AChildAppendedBeforeItsParentWasRetiredIsReplayed: a child's
// run_registered reached the chain under a live parent, SPIRE was down, and
// the parent was retired before the retry. The retry is the recorded child,
// healed: the edge was valid when it was appended, and the chain already holds
// it. It is not RUN_ALREADY_RETIRED on every re-run.
func TestGID019AChildAppendedBeforeItsParentWasRetiredIsReplayed(t *testing.T) {
	outage := &spireOutage{}
	lf := newLoopFixture(t, outage, nil)
	registrar := NewMCPRegistrar()

	parent, err := registrar.Register(t.Context(), RegisterInput{
		AgentType: "orchestrator", IdempotencyKey: "gid019-parent", Workspace: realChainWorkspace(),
	})
	if err != nil {
		t.Fatalf("register the parent: %v", err)
	}
	child := RegisterInput{
		AgentType: "explore", IdempotencyKey: "gid019-child", Workspace: realChainWorkspace(),
		ParentRunID: parent.RunID,
	}
	outage.remaining.Store(1)
	if _, err := registrar.Register(t.Context(), child); err == nil {
		t.Fatal("the outage did not interrupt the child's registration")
	}
	childRun := lf.runUnder(t, "gid019-child")
	if _, err := registrar.Retire(t.Context(), parent.RunID); err != nil {
		t.Fatalf("retire the parent: %v", err)
	}

	for i := range 2 {
		out, err := registrar.Register(t.Context(), child)
		if err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
		if out.RunID != childRun {
			t.Fatalf("retry %d named run %q, want the recorded child %q", i, out.RunID, childRun)
		}
	}
	if got := lf.ids.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries, want 1: the child's, the parent's retired", got)
	}
}
