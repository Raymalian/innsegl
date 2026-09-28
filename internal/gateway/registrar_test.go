// SPDX-License-Identifier: Apache-2.0

package gateway

// registrar_test.go — RM-231 (#376): MCPRegistrar, the contract's Registrar
// implemented on internal/mcp/gateway.go's wrapper.
//
// internal/mcp's own gateway_test.go (GID-001..003) already proves
// RegisterRunForGateway and RetireRunForGateway reach register_agent's and
// retire_agent's configured paths correctly — one run per first request, a
// replay restoring a lapsed run, an idempotent retire. This file does not
// re-prove any of that. What is new here, and what only this file can
// prove, is MCPRegistrar's own translation: RegisterInput's Workspace into
// mcp.GatewayRegistration and back, and Restore's one added check — that a
// replay actually names the run it was asked to restore.
//
// The idempotency claim underneath register_agent is a real
// *mcp.IdempotencyStore on a real, throwaway Postgres (gwpgharness_test.go);
// everything else — SPIRE, the ledger, the run directory — is a small fake
// satisfying internal/mcp's own exported interfaces, the same shape
// internal/mcp's tests use for the identical reason (register_agent_test.go
// and retire_agent_test.go's own headers).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

const (
	gwTrustDomain = "innsegl.dev"
	gwParentID    = "spiffe://innsegl.dev/spire/agent/x509pop/node-gw-registrar-test"
	gwRepo        = "github.com/acme/gateway-registrar-test"
	gwBranch      = "main"
	gwTask        = "rm231"
)

// ---------------------------------------------------------------------------
// Fakes for internal/mcp's exported interfaces. Simple by design: the rules
// they stand in for (SPIRE entry uniqueness, the ledger's hash chain) are
// already proven against internal/mcp's own doubles and, at the contract
// layer, against real containerised SPIRE (RM-015). What this file needs
// from them is only that they behave, so MCPRegistrar's own translation is
// what the assertions are about.
// ---------------------------------------------------------------------------

// gwIdentities is one fake satisfying both mcp.RegisterAgentIdentities and
// mcp.RetireAgentEntries — one SPIRE double for both configs, the same way
// retire_agent_test.go's retireEntries is shared with get_credential's tests.
type gwIdentities struct {
	mu      sync.Mutex
	trust   string
	entries map[string]spire.Entry
	seq     int
}

func newGWIdentities() *gwIdentities {
	return &gwIdentities{trust: gwTrustDomain, entries: map[string]spire.Entry{}}
}

func (f *gwIdentities) TrustDomain() string { return f.trust }

func (f *gwIdentities) RegisterRun(_ context.Context, reg spire.Registration) (spire.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := reg.Run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Entry{}, err
	}
	if _, dup := f.entries[id]; dup {
		return spire.Entry{}, &spire.Error{
			Class: spire.ClassDuplicateRequest, Op: "register_agent", RunID: reg.Run.RunID,
			Message: "entry already exists",
		}
	}
	f.seq++
	ttl := reg.TTL
	if ttl == 0 {
		ttl = spire.DefaultRunTTL
	}
	e := spire.Entry{ID: fmt.Sprintf("entry-%d", f.seq), SPIFFEID: id, ParentID: reg.ParentID, Selectors: reg.Selectors, TTL: ttl}
	f.entries[id] = e
	return e, nil
}

func (f *gwIdentities) LookupRun(_ context.Context, run spire.RunRef) (spire.Entry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Entry{}, false, err
	}
	e, ok := f.entries[id]
	return e, ok, nil
}

func (f *gwIdentities) RetireRun(_ context.Context, run spire.RunRef) (spire.Retirement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Retirement{}, err
	}
	e, ok := f.entries[id]
	if !ok {
		return spire.Retirement{}, nil
	}
	delete(f.entries, id)
	return spire.Retirement{EntryID: e.ID, Deleted: true}, nil
}

func (f *gwIdentities) entryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// gwLedger is a minimal fake of mcp.RegisterAgentLedger / mcp.RetireAgentLedger.
// Unlike internal/mcp's own retireLedger it builds no real hash chain — the
// chain itself is internal/ledger's own proof, exercised by internal/mcp's
// and internal/ledger's tests, not re-proved here — but it does RETAIN every
// appended event, because retire_agent's own retire() re-reads the run
// directory immediately after its append (earliestRetiredAt, ADR-0020 §5)
// and expects to see what it just wrote. gwRuns below reads retirement out
// of this store dynamically, the same relationship retire_agent_test.go's
// retireLedger/retireRuns pair has, for the identical reason: a run's
// retirement is a fact ABOUT THE LEDGER, and a fake that answered it from a
// second, independently-maintained map could disagree with what the ledger
// itself was just told.
type gwLedger struct {
	mu     sync.Mutex
	next   int64
	base   time.Time
	calls  int
	stored []event.Fields
	err    error
}

func newGWLedger() *gwLedger { return &gwLedger{base: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)} }

// fail makes every subsequent Append return err instead of recording
// anything — a ledger outage, from register_agent's own point of view.
func (l *gwLedger) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

func (l *gwLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	l.next++
	l.calls++
	rec := body.Clone()
	rec[event.FieldEventID] = fmt.Sprintf("0192f0a0-0000-7000-9100-%012d", l.next)
	rec[event.FieldTS] = event.NewTimestamp(l.base.Add(time.Duration(l.next) * time.Millisecond)).String()
	l.stored = append(l.stored, rec)
	return rec, nil
}

// retiredAt is the EARLIEST run_retired for runID, zero if there is none —
// the same rule doc 02 requires every reader of a doubled event to apply
// (I4), mirrored from retire_agent_test.go's retireLedger.retiredAt.
func (l *gwLedger) retiredAt(runID string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	var earliest time.Time
	for _, rec := range l.stored {
		if rec[event.FieldEventType] != event.EventTypeRunRetired || rec[event.FieldRunID] != runID {
			continue
		}
		raw, ok := rec[event.FieldTS].(string)
		if !ok {
			continue
		}
		ts, err := event.ParseTimestamp(raw)
		if err != nil {
			continue
		}
		if earliest.IsZero() || ts.Time().Before(earliest) {
			earliest = ts.Time()
		}
	}
	return earliest
}

// gwRuns is a minimal fake of mcp.CredentialRuns. Existence, the SPIFFE id
// and the repository are test-set (rememberAs); retirement is read out of
// source, never test-set, so it agrees with whatever the ledger was just
// told — see gwLedger's own comment.
type gwRuns struct {
	mu     sync.Mutex
	known  map[string]bool
	spiffe map[string]string
	repo   map[string]string
	source *gwLedger
}

func newGWRuns(source *gwLedger) *gwRuns {
	return &gwRuns{
		known: map[string]bool{}, spiffe: map[string]string{}, repo: map[string]string{},
		source: source,
	}
}

func (r *gwRuns) rememberAs(runID, spiffeID, repo string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.known[runID] = true
	r.spiffe[runID] = spiffeID
	r.repo[runID] = repo
}

func (r *gwRuns) CredentialRun(_ context.Context, runID string) (mcp.CredentialRun, bool, error) {
	r.mu.Lock()
	known := r.known[runID]
	out := mcp.CredentialRun{RunID: runID, SPIFFEID: r.spiffe[runID], Repo: r.repo[runID]}
	r.mu.Unlock()
	if !known {
		return mcp.CredentialRun{}, false, nil
	}
	out.RetiredAt = r.source.retiredAt(runID)
	return out, true, nil
}

// ---------------------------------------------------------------------------
// The fixture: register_agent and retire_agent, wired onto the fakes above
// and a real idempotency store.
// ---------------------------------------------------------------------------

type gwFixture struct {
	ids  *gwIdentities
	ledg *gwLedger
	runs *gwRuns
}

func newGWFixture(t *testing.T) *gwFixture {
	t.Helper()
	pgc := requireGWPG(t)
	dsn := gwFreshDSN(t, pgc)
	gwMigrate(t, dsn)
	idem := mcp.NewIdempotencyStore(gwPool(t, dsn))

	ids := newGWIdentities()
	ledg := newGWLedger()
	runs := newGWRuns(ledg)
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	restoreReg, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities:  ids,
		Runs:        runs,
		Ledger:      ledg,
		Idempotency: idem,
		ParentID:    gwParentID,
		Pseudonyms:  literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreReg)

	restoreRet, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: runs, Entries: ids, Ledger: ledg,
	})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRet)

	return &gwFixture{ids: ids, ledg: ledg, runs: runs}
}

func gwWorkspace() Workspace { return Workspace{Repo: gwRepo, Branch: gwBranch, Task: gwTask} }

// ---------------------------------------------------------------------------
// Register: reaches register_agent and translates its reply.
// ---------------------------------------------------------------------------

func TestMCPRegistrarRegisterReachesRegisterAgentAndTranslatesTheReply(t *testing.T) {
	f := newGWFixture(t)
	r := NewMCPRegistrar()

	out, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "gw-registrar-test",
		IdempotencyKey: "registrar-key-1",
		Workspace:      gwWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if out.RunID == "" || out.SPIFFEID == "" || out.ExpiresAt == "" {
		t.Fatalf("Register returned %+v, want a run id, a SPIFFE id and an expiry", out)
	}
	if got := f.ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after one registration, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Restore: replays with the prior idempotency key and returns the same run.
// ---------------------------------------------------------------------------

func TestMCPRegistrarRestoreReplaysWithThePriorKeyAndReturnsTheSameRun(t *testing.T) {
	f := newGWFixture(t)
	r := NewMCPRegistrar()
	in := RegisterInput{
		AgentType:      "gw-registrar-test",
		IdempotencyKey: "registrar-key-2",
		Workspace:      gwWorkspace(),
	}

	first, err := r.Register(t.Context(), in)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f.runs.rememberAs(first.RunID, first.SPIFFEID, gwRepo)

	// The run lapses: its SPIRE entry is withdrawn (exactly GID-002's own
	// scenario, one level up — through MCPRegistrar rather than the wrapper
	// directly).
	f.ids.mu.Lock()
	f.ids.entries = map[string]spire.Entry{}
	f.ids.mu.Unlock()

	second, err := r.Restore(t.Context(), RunMapping{RunID: first.RunID}, in)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if second.RunID != first.RunID {
		t.Fatalf("Restore returned run %q, want the original %q", second.RunID, first.RunID)
	}
	if got := f.ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after the restore, want 1", got)
	}
}

// Restore's one added check: a replay that names a run other than the one
// asked to be restored is refused rather than handed back silently.
func TestMCPRegistrarRestoreRefusesAMismatchedMapping(t *testing.T) {
	newGWFixture(t)
	r := NewMCPRegistrar()
	in := RegisterInput{
		AgentType:      "gw-registrar-test",
		IdempotencyKey: "registrar-key-3",
		Workspace:      gwWorkspace(),
	}

	_, err := r.Restore(t.Context(), RunMapping{RunID: "run-does-not-match-anything"}, in)
	if err == nil {
		t.Fatalf("Restore with a mismatched prior mapping was accepted")
	}
	var classified *mcp.Error
	if !errors.As(err, &classified) {
		t.Fatalf("the refusal is %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != mcp.ClassInvariantViolation {
		t.Errorf("class = %q, want %q", classified.Class, mcp.ClassInvariantViolation)
	}
}

// A failure register_agent's own mint path returns is surfaced by Restore
// unchanged, exactly as Register surfaces one — Restore's own added check
// (the run-id comparison) never runs, because there is no run to compare.
func TestMCPRegistrarRestoreSurfacesARegistrationFailure(t *testing.T) {
	f := newGWFixture(t)
	f.ledg.fail(errors.New("a ledger failure nobody classified"))
	r := NewMCPRegistrar()

	_, err := r.Restore(t.Context(), RunMapping{RunID: "run-whatever"}, RegisterInput{
		AgentType:      "gw-registrar-test",
		IdempotencyKey: "registrar-key-3-mint-failure",
		Workspace:      gwWorkspace(),
	})
	if err == nil {
		t.Fatalf("Restore with a failing ledger was accepted")
	}
	var classified *mcp.Error
	if !errors.As(err, &classified) {
		t.Fatalf("the refusal is %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != mcp.ClassInvariantViolation {
		t.Errorf("class = %q, want %q", classified.Class, mcp.ClassInvariantViolation)
	}
}

// ---------------------------------------------------------------------------
// Retire: reaches retire_agent.
// ---------------------------------------------------------------------------

func TestMCPRegistrarRetireReachesRetireAgent(t *testing.T) {
	f := newGWFixture(t)
	r := NewMCPRegistrar()

	reg, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "gw-registrar-test",
		IdempotencyKey: "registrar-key-4",
		Workspace:      gwWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// retire_agent's own gate 2 resolves run_id through the run directory
	// (mcp.CredentialRuns); gwRuns is a bare map, so the run this test just
	// registered has to be told to it, exactly as newGWFixture's other
	// tests already do before restoring or retiring a run.
	f.runs.rememberAs(reg.RunID, reg.SPIFFEID, gwRepo)

	retiredAt, err := r.Retire(t.Context(), reg.RunID)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retiredAt == "" {
		t.Fatalf("Retire returned no retired_at")
	}
	if got := f.ids.entryCount(); got != 0 {
		t.Fatalf("SPIRE holds %d entries after retirement, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// ForkedFromRunID: forwarded exactly as given, never decided here (#380).
// ---------------------------------------------------------------------------

// TestMCPRegistrarForwardsForkedFromRunIDToRegisterAgent proves
// RegisterInput.ForkedFromRunID (lifecycle_contract.go) reaches
// run_registered on the real chain this fixture builds, through
// MCPRegistrar.Register -> registerThrough -> mcp.GatewayRegistration ->
// register_agent's own unexported forkedFromRunID.
func TestMCPRegistrarForwardsForkedFromRunIDToRegisterAgent(t *testing.T) {
	f := newGWFixture(t)
	r := NewMCPRegistrar()

	origin, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "gw-registrar-origin",
		IdempotencyKey: "registrar-fork-origin-key",
		Workspace:      gwWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register (origin): %v", err)
	}

	fork, err := r.Register(t.Context(), RegisterInput{
		AgentType:       "gw-registrar-fork",
		IdempotencyKey:  "registrar-fork-key",
		Workspace:       gwWorkspace(),
		ForkedFromRunID: origin.RunID,
	})
	if err != nil {
		t.Fatalf("Register (fork): %v", err)
	}
	if fork.RunID == origin.RunID {
		t.Fatalf("the fork registered as the same run as its origin")
	}

	var found bool
	for _, rec := range f.ledg.stored {
		if rec[event.FieldRunID] != fork.RunID || rec[event.FieldEventType] != event.EventTypeRunRegistered {
			continue
		}
		found = true
		if got := rec[event.FieldForkedFromRunID]; got != origin.RunID {
			t.Errorf("forked_from_run_id = %v, want the origin run %q", got, origin.RunID)
		}
	}
	if !found {
		t.Fatalf("no run_registered event was recorded for the fork %q", fork.RunID)
	}
}

// ---------------------------------------------------------------------------
// ResumesRetiredParent: forwarded exactly as given, never decided here.
// ---------------------------------------------------------------------------

// Without ResumesRetiredParent, naming a retired run as a parent is refused
// (MCP-082) — through MCPRegistrar exactly as through register_agent
// directly. With it set — which only a LifecyclePolicy's Adopt decision may
// do (ADR-0058 decision 8) — the identical retired parent is accepted. This
// is the one member registerThrough forwards without alteration, and this
// test is what proves the forwarding actually happens.
func TestMCPRegistrarForwardsResumesRetiredParentToRegisterAgent(t *testing.T) {
	f := newGWFixture(t)
	r := NewMCPRegistrar()

	parent, err := r.Register(t.Context(), RegisterInput{
		AgentType:      "gw-registrar-parent",
		IdempotencyKey: "registrar-parent-key",
		Workspace:      gwWorkspace(),
	})
	if err != nil {
		t.Fatalf("Register (parent): %v", err)
	}
	f.runs.rememberAs(parent.RunID, parent.SPIFFEID, gwRepo)
	if _, retireErr := r.Retire(t.Context(), parent.RunID); retireErr != nil {
		t.Fatalf("Retire (parent): %v", retireErr)
	}

	if _, refusedErr := r.Register(t.Context(), RegisterInput{
		AgentType:      "gw-registrar-child",
		IdempotencyKey: "registrar-child-key-refused",
		Workspace:      gwWorkspace(),
		ParentRunID:    parent.RunID,
	}); refusedErr == nil {
		t.Fatalf("naming a retired parent without ResumesRetiredParent was accepted")
	} else {
		var classified *mcp.Error
		if !errors.As(refusedErr, &classified) {
			t.Fatalf("the refusal is %T (%v), not an IP §4 classified error", refusedErr, refusedErr)
		}
		if classified.Class != mcp.ClassRunAlreadyRetired {
			t.Errorf("class = %q, want %q", classified.Class, mcp.ClassRunAlreadyRetired)
		}
	}

	child, err := r.Register(t.Context(), RegisterInput{
		AgentType:            "gw-registrar-child",
		IdempotencyKey:       "registrar-child-key-adopted",
		Workspace:            gwWorkspace(),
		ParentRunID:          parent.RunID,
		ResumesRetiredParent: true,
	})
	if err != nil {
		t.Fatalf("Register with ResumesRetiredParent set: %v", err)
	}
	if child.RunID == "" {
		t.Fatalf("Register with ResumesRetiredParent set returned no run id")
	}
}
