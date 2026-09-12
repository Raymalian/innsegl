// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// observe_session, RM-128 (#207), E11. Doc 07 MCP-050 … MCP-054.
//
// WHAT IS REAL HERE AND WHAT IS NOT
//
// The three tools this one composes are the SHIPPED ones, installed through
// their own shipped Configure functions and called in process — the same move
// SignCommitThroughGetCredential makes, and for the same reason. If
// observe_session registered through a stand-in, "exactly one run registered"
// (MCP-050) and "never a second identity" (MCP-051) would be assertions about
// the stand-in's bookkeeping rather than about the ledger's UNIQUE
// idempotency_key and register_agent's derived run id, which are what actually
// hold those properties.
//
// So the ledger and the idempotency store are a real Postgres, the working
// tree describe_workspace reads is a real git repository, and the marker
// directory is a real directory on a real filesystem — including the case
// where it genuinely cannot be written to, which is a filesystem refusal and
// not a stubbed error.
//
// SPIRE is a fake (raSPIRE, plus the deletion retire_agent needs). Doc 07
// classes these rows at layer C, where IP §2 admits one, and what they are
// about is this tool's own decision procedure: which run a session id names,
// and what a stop does when it cannot finish.

const (
	// osSessionID is a harness session id in the shape a harness actually
	// emits: a lowercase UUID. osForeignSessionID is the shape a DIFFERENT
	// harness emits — uppercase, with an underscore — and it is here because
	// E11 exists so that a second harness can participate. A grammar that
	// admitted only this project's own spelling would close the door this
	// epic opened.
	osSessionID        = "9d64755c-06fa-4f77-84ee-68f3933c9e35"
	osForeignSessionID = "SESS_01JQ8Z.4K7"

	// osSecret keys the per-run token. Configured, so that the credential
	// handle a start returns is the whole handle and not most of it.
	osSecret = "deployment-secret-for-rm-128"

	// osBranch is the branch the fixture repository is on, and osTask is what
	// describe_workspace folds it to. Written out rather than derived, so a
	// change in the fold is a failure here and not a silent agreement.
	osBranch = "dev/rm128-observe-session"
	osTask   = "rm128"
	osRemote = "git@github.com:Example-Org/Example-Repo.git"
	osRepo   = "github.com/Example-Org/Example-Repo"
)

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

// osEnv is observe_session on top of the shipped describe_workspace,
// register_agent and retire_agent.
type osEnv struct {
	spire     *osSPIRE
	runs      *osChainRuns
	ledger    *ledger.Store
	idem      *IdempotencyStore
	markerDir string
	tree      workspaceTree
}

// osSetup installs all four tools for the test's duration. mutate, when
// non-nil, is the seam a case uses to change observe_session's own
// configuration before it is installed.
func osSetup(t *testing.T, mutate func(*ObserveSessionConfig)) *osEnv {
	t.Helper()
	idem, dsn := newStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	tree := newWorkspaceTree(t, osRemote)
	// A feature branch, because the task a session registers under is folded
	// from the branch it is standing on and `main` would fold to a task that
	// says nothing about whether the fold ran.
	run(t, tree.repo, "checkout", "-q", "-b", osBranch)
	configureWorkspace(t, tree.projects, tree.projects)

	env := &osEnv{
		spire:     &osSPIRE{raSPIRE: newRASPIRE(raTrustDomain)},
		runs:      &osChainRuns{store: lg},
		ledger:    lg,
		idem:      idem,
		markerDir: t.TempDir(),
		tree:      tree,
	}

	// Identity mode `literal`, as every other in-package fixture uses: the
	// assertions below are about which run a session names, not about what a
	// SPIFFE ID's first two segments say. PRI-003 measures `pseudonymous`.
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	restoreRegister, err := ConfigureRegisterAgent(RegisterAgentConfig{
		Identities: env.spire, Runs: env.runs, Ledger: lg, Idempotency: idem,
		ParentID: raParentID, TTL: 5 * time.Minute, Pseudonyms: literal,
		RunTokenSecret: osSecret,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreRegister)

	restoreRetire, err := ConfigureRetireAgent(RetireAgentConfig{
		Runs: env.runs, Entries: env.spire, Ledger: lg,
	})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRetire)

	cfg := ObserveSessionConfig{MarkerDir: env.markerDir}
	if mutate != nil {
		mutate(&cfg)
	}
	restoreObserve, err := ConfigureObserveSession(cfg)
	if err != nil {
		t.Fatalf("ConfigureObserveSession: %v", err)
	}
	t.Cleanup(restoreObserve)
	return env
}

// start and stop call the tool the way the transport does.
func (e *osEnv) start(t *testing.T, sessionID string) (observeSessionOut, error) {
	t.Helper()
	return observeSession(t.Context(), nil, observeSessionIn{
		SessionID: sessionID, Phase: ObserveSessionPhaseStart, CWD: e.tree.repo,
	})
}

func (e *osEnv) stop(t *testing.T, sessionID string) (observeSessionOut, error) {
	t.Helper()
	return observeSession(t.Context(), nil, observeSessionIn{
		SessionID: sessionID, Phase: ObserveSessionPhaseStop,
	})
}

// mustStart and mustStop fail the test on any error. A stop that errors is a
// failure of the tool's headline promise, so it is never tolerated by a helper.
func (e *osEnv) mustStart(t *testing.T, sessionID string) observeSessionOut {
	t.Helper()
	out, err := e.start(t, sessionID)
	if err != nil {
		t.Fatalf("observe_session start %s: %v", sessionID, err)
	}
	return out
}

func (e *osEnv) mustStop(t *testing.T, sessionID string) observeSessionOut {
	t.Helper()
	out, err := e.stop(t, sessionID)
	if err != nil {
		t.Fatalf("observe_session stop %s refused with %v. A stop never blocks "+
			"(IP §4): a retry storm was measured at nine deep when it did", sessionID, err)
	}
	return out
}

// countEvents walks the whole chain and counts one event type for one run. The
// chain, not a spy: "exactly one run_registered" is a claim about what was
// appended, and only the ledger knows that.
func (e *osEnv) countEvents(t *testing.T, runID, eventType string) int {
	t.Helper()
	n := 0
	for _, rec := range e.chain(t) {
		if id, isString := rec[event.FieldRunID].(string); !isString || id != runID {
			continue
		}
		if kind, isString := rec[event.FieldEventType].(string); isString && kind == eventType {
			n++
		}
	}
	return n
}

func (e *osEnv) chain(t *testing.T) []event.Fields {
	t.Helper()
	head, err := e.ledger.Head(t.Context())
	if err != nil {
		t.Fatalf("ledger.Head: %v", err)
	}
	if head.IsEmpty() {
		return nil
	}
	records, err := e.ledger.Events(t.Context(), 1, head.Position)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	return records
}

// ---------------------------------------------------------------------------
// SPIRE: raSPIRE plus the deletion retire_agent performs.
// ---------------------------------------------------------------------------

type osSPIRE struct {
	*raSPIRE
	// stopMu guards this type's own fields, and is deliberately not called mu:
	// raSPIRE has one, and a shadowing name would make every lock below read
	// as though it guarded the entries it does not.
	stopMu    sync.Mutex
	retireErr error
	retired   []spire.RunRef
}

func (f *osSPIRE) RetireRun(_ context.Context, run spire.RunRef) (spire.Retirement, error) {
	f.stopMu.Lock()
	f.retired = append(f.retired, run)
	failure := f.retireErr
	f.stopMu.Unlock()
	if failure != nil {
		return spire.Retirement{}, failure
	}
	id, err := run.SPIFFEID(f.trustDomain)
	if err != nil {
		return spire.Retirement{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, held := f.entries[id]
	if !held {
		// IP §4: retiring a run SPIRE holds no entry for is a success with
		// nothing deleted.
		return spire.Retirement{}, nil
	}
	delete(f.entries, id)
	return spire.Retirement{EntryID: entry.ID, Deleted: true}, nil
}

// ---------------------------------------------------------------------------
// The run directory, read out of the chain.
// ---------------------------------------------------------------------------

// osChainRuns answers what a run is from the events the ledger actually holds.
//
// internal/rundir is the shipped one and cannot be used here — it imports
// internal/mcp, so an in-package test importing it is an import cycle — so
// this reads the same values out of the same place rather than out of a
// literal a test set. That matters for MCP-053 in particular: the ORIGINAL
// retirement instant has to come from the chain, or "the original timestamp"
// would be a value this file chose.
type osChainRuns struct {
	mu    sync.Mutex
	store *ledger.Store
	// err, when set, is every lookup failing: the ledger outage of MCP-054.
	err error
}

func (d *osChainRuns) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

func (d *osChainRuns) CredentialRun(ctx context.Context, runID string) (CredentialRun, bool, error) {
	d.mu.Lock()
	failure := d.err
	d.mu.Unlock()
	if failure != nil {
		return CredentialRun{}, false, failure
	}

	head, err := d.store.Head(ctx)
	if err != nil {
		return CredentialRun{}, false, err
	}
	if head.IsEmpty() {
		return CredentialRun{}, false, nil
	}
	records, err := d.store.Events(ctx, 1, head.Position)
	if err != nil {
		return CredentialRun{}, false, err
	}

	var (
		run   CredentialRun
		found bool
	)
	for _, rec := range records {
		if id, isString := rec[event.FieldRunID].(string); !isString || id != runID {
			continue
		}
		kind, isString := rec[event.FieldEventType].(string)
		if !isString {
			return CredentialRun{}, false, fmt.Errorf("an event for %q carries no event_type", runID)
		}
		switch kind {
		case event.EventTypeRunRegistered:
			run.RunID = runID
			run.SPIFFEID, _ = rec[event.FieldSpiffeID].(string)   //nolint:errcheck // an absent member reads as empty, which is what the directory reports
			run.AgentType, _ = rec[event.FieldAgentType].(string) //nolint:errcheck // same
			run.TaskID, _ = rec[event.FieldTaskRef].(string)      //nolint:errcheck // same
			found = true
		case event.EventTypeRunRetired:
			at := osInstant(rec)
			// The EARLIEST, which is what retire_agent is entitled to answer
			// a later caller with (ADR-0020 §5).
			if run.RetiredAt.IsZero() || at.Before(run.RetiredAt) {
				run.RetiredAt = at
			}
		}
	}
	return run, found, nil
}

func osInstant(rec event.Fields) time.Time {
	raw, isString := rec[event.FieldTS].(string)
	if !isString {
		return time.Time{}
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		return time.Time{}
	}
	return ts.Time()
}

// osMarkerPath is where a session's marker lands. Derived the way the tool
// derives it and asserted against the tool's own answer in MCP-050, so a test
// cannot quietly agree with a bug by recomputing it the same wrong way.
func osMarkerPath(dir, sessionID string) string {
	return filepath.Join(dir, observeSessionMarkerName(sessionID))
}

// osError renders a refusal the way the transport does.
//
// Classify and not errors.As: server.go answers a failed tool call with
// Classify(err), and observe_session returns the errors register_agent and
// describe_workspace raised rather than rewrapping them — a SPIRE failure
// arrives as *spire.Error, which is Classified but not *Error. Asserting on
// errors.As would be asserting on a shape the caller never sees.
func osError(t *testing.T, err error) *Error {
	t.Helper()
	if err == nil {
		t.Fatal("the call succeeded; this case is about a refusal")
	}
	classified := Classify(err)
	if !classified.Class.Valid() {
		t.Fatalf("refused with %q, which is not one of IP §4's eleven classes: %v",
			string(classified.Class), err)
	}
	return classified
}

// ---------------------------------------------------------------------------
// MCP-050 — start then stop.
// ---------------------------------------------------------------------------

// TestMCP050ObserveSessionStartThenStopRegistersAndRetiresExactlyOneRun.
//
// Doc 07: "Exactly one run registered and retired; session id maps to it."
//
// The whole of the reference shim's SessionStart and SessionEnd, in one tool:
// the workspace is resolved, the run is registered under a key derived from
// the session id, the marker records the mapping, and the stop finds the run
// by session id alone — the caller never has to have kept the run id, which is
// the bookkeeping that moved in here.
func TestMCP050ObserveSessionStartThenStopRegistersAndRetiresExactlyOneRun(t *testing.T) {
	env := osSetup(t, nil)

	started := env.mustStart(t, osSessionID)
	if started.RunID == "" {
		t.Fatal("a start returned no run id; the session has no identity")
	}
	if !started.Registered {
		t.Error("the first start reports registered=false; this call is the one that made the run")
	}
	if !started.Known {
		t.Error("the first start reports known=false for a session it has just recorded")
	}
	if started.Retired {
		t.Error("a fresh session is reported retired")
	}
	// The CREDENTIAL HANDLE, which is what IP §4 says a start returns. A run
	// id alone is not one: without the token the run cannot get a credential
	// where a deployment configures a run-token secret, and this one does.
	if started.SPIFFEID == "" || started.ExpiresAt == "" {
		t.Errorf("start returned an incomplete credential handle: %+v", started)
	}
	if want := RunToken(osSecret, started.RunID); started.RunToken != want {
		t.Errorf("run_token = %q, want the run's own token; a start that omits it "+
			"hands back a run that cannot be credentialed", started.RunToken)
	}
	// The WORKSPACE, resolved through describe_workspace rather than derived a
	// second time here (E11's whole rule).
	if started.Repo != osRepo || started.Branch != osBranch || started.Task != osTask {
		t.Errorf("start resolved repo=%q branch=%q task=%q, want %q / %q / %q",
			started.Repo, started.Branch, started.Task, osRepo, osBranch, osTask)
	}
	if started.Worktree != "" {
		t.Errorf("worktree = %q for the repository's own tree, want empty; sign_commit "+
			"reads an empty worktree as the repository itself (MCP-029)", started.Worktree)
	}
	if started.AgentType != observeSessionDefaultAgentType {
		t.Errorf("agent_type = %q, want the default %q",
			started.AgentType, observeSessionDefaultAgentType)
	}

	if n := env.countEvents(t, started.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered for %s, want exactly 1", n, started.RunID)
	}
	// THE MAPPING IS ON THE MCP'S OWN VOLUME. This is the marker file that
	// used to live beside the harness, and the assertion is that it is here
	// and names this run.
	marker := osMarkerPath(env.markerDir, osSessionID)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("no marker for session %s: %v", osSessionID, err)
	}

	stopped := env.mustStop(t, osSessionID)
	if !stopped.Retired || stopped.RetiredAt == "" {
		t.Fatalf("stop did not retire the run: %+v", stopped)
	}
	if stopped.RunID != started.RunID {
		t.Errorf("stop retired %q, start registered %q; the session id did not map to "+
			"the run", stopped.RunID, started.RunID)
	}
	if _, err := event.ParseTimestamp(stopped.RetiredAt); err != nil {
		t.Errorf("retired_at %q is not a doc 02 §1 instant: %v", stopped.RetiredAt, err)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRetired); n != 1 {
		t.Errorf("the chain holds %d run_retired for %s, want exactly 1", n, started.RunID)
	}
	// I1: the identity is gone with the run, not left behind on a timer.
	if env.spire.entryCount() != 0 {
		t.Errorf("SPIRE still holds %d entries after the stop; retirement deletes the entry",
			env.spire.entryCount())
	}
}

// TestMCP050AForeignHarnessSessionIDIsAccepted.
//
// E11 exists so that a harness other than the reference one can participate,
// and a session id is the one value such a harness supplies verbatim. Holding
// it to doc 02 §5's identifier grammar — lowercase, hyphens only — would
// refuse an uppercase or underscored id and close the door this epic opened,
// for no benefit: the id is never a path segment (the marker name is a digest)
// and never an identity component.
func TestMCP050AForeignHarnessSessionIDIsAccepted(t *testing.T) {
	env := osSetup(t, nil)

	started := env.mustStart(t, osForeignSessionID)
	if started.RunID == "" {
		t.Fatalf("a foreign harness's session id was accepted and produced no run: %+v", started)
	}
	if started.SessionID != osForeignSessionID {
		t.Errorf("session_id came back as %q, want %q verbatim",
			started.SessionID, osForeignSessionID)
	}
	stopped := env.mustStop(t, osForeignSessionID)
	if stopped.RunID != started.RunID {
		t.Errorf("stop found %q for a session that started %q", stopped.RunID, started.RunID)
	}
}

// TestMCP050TwoSessionsInOneTreeAreTwoRuns.
//
// The session id is what separates them. Two harness sessions standing in the
// same repository on the same branch derive the same agent_type and the same
// task, so the only thing that can keep them apart is the key — and the key is
// the session's. If it were not, the second session would replay the first's
// registration and two sessions would share one identity.
func TestMCP050TwoSessionsInOneTreeAreTwoRuns(t *testing.T) {
	env := osSetup(t, nil)

	first := env.mustStart(t, osSessionID)
	second := env.mustStart(t, osForeignSessionID)
	if first.RunID == second.RunID {
		t.Fatalf("two sessions in one tree both registered %s; a session id that does "+
			"not separate runs is a session id that is not in the key", first.RunID)
	}
	if !second.Registered {
		t.Error("the second session reports registered=false; it is its own run")
	}
}

// ---------------------------------------------------------------------------
// MCP-051 — a duplicate start.
// ---------------------------------------------------------------------------

// TestMCP051ADuplicateStartReturnsTheSameRunAndNeverASecondIdentity.
//
// Doc 07: "Same run returned; never a second identity." IP §6.6.
//
// The guarantee is not this tool's marker: it is register_agent's derived run
// id and the idempotency store's UNIQUE key, which is exactly why the start
// path calls the shipped register_agent again rather than short-circuiting on
// the marker. A second identity would show up here as a second
// `run_registered` in the chain or a second SPIRE entry, and both are counted.
func TestMCP051ADuplicateStartReturnsTheSameRunAndNeverASecondIdentity(t *testing.T) {
	env := osSetup(t, nil)

	first := env.mustStart(t, osSessionID)
	second := env.mustStart(t, osSessionID)

	if second.RunID != first.RunID {
		t.Fatalf("a duplicate start returned %q, the first returned %q; one session, "+
			"two identities", second.RunID, first.RunID)
	}
	if second.Registered {
		t.Error("a duplicate start reports registered=true; it did not make this run")
	}
	if second.RunToken != first.RunToken {
		t.Error("a duplicate start returned a different run token; a resumed session " +
			"cannot keep working without the one it was given")
	}
	if second.SPIFFEID != first.SPIFFEID || second.Task != first.Task {
		t.Errorf("a duplicate start described the run differently: %+v vs %+v", second, first)
	}
	if n := env.countEvents(t, first.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered after two starts, want exactly 1", n)
	}
	if got := env.spire.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries after two starts, want exactly 1", got)
	}
}

// TestMCP051ADuplicateStartFromAnotherTreeStillReturnsTheSameRun.
//
// A session is registered once, and its task is fixed then. Re-deriving the
// workspace on every start would let a session that moved between worktrees
// present a different task under the same key — which the idempotency store
// refuses as DUPLICATE_REQUEST, turning an ordinary second start into a
// refusal. So a start for a session already recorded replays the MARKER's own
// agent_type and task, and the derivation is only performed when there is
// nothing recorded yet.
func TestMCP051ADuplicateStartFromAnotherTreeStillReturnsTheSameRun(t *testing.T) {
	env := osSetup(t, nil)
	first := env.mustStart(t, osSessionID)

	// A linked worktree on its own branch, which folds to a different task.
	run(t, env.tree.repo, "worktree", "add", "-b", "dev/rm999-elsewhere", ".worktrees/elsewhere")
	second, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart,
		CWD: filepath.Join(env.tree.repo, ".worktrees", "elsewhere"),
	})
	if err != nil {
		t.Fatalf("a second start from another tree was refused: %v", err)
	}
	if second.RunID != first.RunID || second.Task != first.Task {
		t.Errorf("the session's run changed when it moved tree: %+v, was %+v", second, first)
	}
}

// ---------------------------------------------------------------------------
// MCP-052 — a stop for a session that never started.
// ---------------------------------------------------------------------------

// TestMCP052AStopForASessionThatNeverStartedSucceeds.
//
// Doc 07: "Success with terminal state; never an error, never a block."
//
// A shim cannot guarantee ordering: a stop can arrive for a session whose
// start never reached this deployment, or whose start reached a previous
// container. Refusing would be answered by the harness the way exit 2 was —
// with a retry storm measured at nine deep — and there is nothing for a retry
// to converge on.
func TestMCP052AStopForASessionThatNeverStartedSucceeds(t *testing.T) {
	env := osSetup(t, nil)

	stopped := env.mustStop(t, osSessionID)
	if stopped.Known {
		t.Error("a stop for a session that never started reports known=true")
	}
	if stopped.RunID != "" {
		t.Errorf("run_id = %q for a session with no run", stopped.RunID)
	}
	if stopped.Retired {
		t.Error("a stop for a session that never started claims it retired something")
	}
	if stopped.Detail == "" {
		t.Error("the terminal state carries no detail; a caller is told nothing about " +
			"why the stop found nothing")
	}
	if len(env.chain(t)) != 0 {
		t.Errorf("a stop for an unknown session appended %d events; it must write nothing",
			len(env.chain(t)))
	}
}

// ---------------------------------------------------------------------------
// MCP-053 — a second stop.
// ---------------------------------------------------------------------------

// TestMCP053ASecondStopReturnsTheOriginalRetirementTimestamp.
//
// Doc 07: "Success with the original retirement timestamp." IP §4 requires the
// same of retire_agent, and this tool must not weaken it: a second stop that
// reported "now" would tell a reader the session ended at the moment the
// duplicate arrived.
func TestMCP053ASecondStopReturnsTheOriginalRetirementTimestamp(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)

	first := env.mustStop(t, osSessionID)
	if !first.Retired || first.RetiredAt == "" {
		t.Fatalf("the first stop did not retire: %+v", first)
	}
	second := env.mustStop(t, osSessionID)
	third := env.mustStop(t, osSessionID)

	for i, got := range []observeSessionOut{second, third} {
		if !got.Retired {
			t.Errorf("stop %d reports retired=false for a retired session", i+2)
		}
		if got.RetiredAt != first.RetiredAt {
			t.Errorf("stop %d answered %q, the first retirement was at %q; a later stop "+
				"must be told the original instant", i+2, got.RetiredAt, first.RetiredAt)
		}
		if got.RunID != started.RunID {
			t.Errorf("stop %d named run %q, want %q", i+2, got.RunID, started.RunID)
		}
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRetired); n != 1 {
		t.Errorf("three stops appended %d run_retired events, want exactly 1", n)
	}
}

// TestMCP053AStartForARetiredSessionReportsTheTerminalStateRatherThanResurrecting.
//
// THE TRAP #213 NAMES, met from this tool's side.
//
// A run id is a pure function of (agent_type, task, idempotency_key), so a
// start for a session id that has already been stopped would derive the SAME
// run id, and register_agent would replay its recorded reply — correctly
// refusing to resurrect the identity, and handing the caller a run that cannot
// get a credential or sign. That is a dead identity returned as though it were
// a live one.
//
// So the marker OUTLIVES the retirement rather than being deleted with it, and
// a start that meets a retired marker reports the terminal state. It does not
// refuse: the reference shim's SessionStart never blocks, because refusing the
// operator's own session stops them working on their own machine.
func TestMCP053AStartForARetiredSessionReportsTheTerminalStateRatherThanResurrecting(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)
	stopped := env.mustStop(t, osSessionID)

	again, err := env.start(t, osSessionID)
	if err != nil {
		t.Fatalf("a start for a retired session was refused: %v", err)
	}
	if !again.Retired || again.RetiredAt != stopped.RetiredAt {
		t.Errorf("a start for a retired session answered %+v; it must report the "+
			"terminal state with the original instant %q", again, stopped.RetiredAt)
	}
	if again.Registered {
		t.Error("a start for a retired session reports registered=true; nothing was registered")
	}
	if again.RunID != started.RunID {
		t.Errorf("the terminal state names run %q, the session's run was %q",
			again.RunID, started.RunID)
	}
	if again.Detail == "" {
		t.Error("the terminal state carries no detail, so a caller cannot tell a live " +
			"run from a retired one without comparing fields")
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered after a start on a retired session, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// MCP-054 — the ledger is gone, and the stop still returns.
// ---------------------------------------------------------------------------

// TestMCP054AStopWithTheLedgerUnavailableReturnsRatherThanRefuses.
//
// Doc 07: "Returns rather than refuses; the failure is reported, the stop is
// not retried into a storm." IP §6.4, §6.11.
//
// This is the one requirement that decides the shape of the whole stop path.
// The harness's answer to a refused stop was measured: exit 2 produced nine
// repeated invocations before the harness gave up. An MCP tool's equivalent of
// exit 2 is an error result, so a stop that cannot retire must SUCCEED and say
// what went wrong in the reply — and it must keep the marker, so the next stop
// for the same session still has the run id to retry with.
func TestMCP054AStopWithTheLedgerUnavailableReturnsRatherThanRefuses(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)

	// A classified ledger failure, because that is what a real outage
	// produces: internal/ledger raises *StoreError with IP §4's own spellings
	// and credentialLedgerError carries the class across.
	env.runs.fail(&ledger.StoreError{
		Class: string(ClassLedgerUnavailable), Op: "credential_run", Retryable: true,
		Err: errors.New("dial tcp: connect: connection refused"),
	})

	stopped := env.mustStop(t, osSessionID)
	if stopped.Retired {
		t.Error("a stop that could not reach the ledger claims the run is retired")
	}
	if stopped.RunID != started.RunID {
		t.Errorf("the stop named run %q, want %q; a caller that cannot see which run "+
			"was not retired cannot report it", stopped.RunID, started.RunID)
	}
	if stopped.Detail == "" {
		t.Fatal("a stop that could not retire reported nothing; the failure has to be " +
			"visible or the run silently stays Active")
	}
	if !strings.Contains(stopped.Detail, string(ClassLedgerUnavailable)) {
		t.Errorf("detail %q does not name the class that stopped it", stopped.Detail)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRetired); n != 0 {
		t.Errorf("the chain holds %d run_retired after a failed stop, want 0", n)
	}

	// THE MARKER OUTLIVES A FAILED RETIREMENT. The reference shim deleted it
	// on the way in and measured the consequence: three runs registered the
	// previous afternoon, still Active seventeen hours later, with no marker
	// left to retry from.
	if _, err := os.Stat(osMarkerPath(env.markerDir, osSessionID)); err != nil {
		t.Fatalf("the marker was removed by a stop that did not retire: %v", err)
	}

	env.runs.fail(nil)
	recovered := env.mustStop(t, osSessionID)
	if !recovered.Retired || recovered.RetiredAt == "" {
		t.Fatalf("the retry after the outage did not retire the run: %+v", recovered)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRetired); n != 1 {
		t.Errorf("the chain holds %d run_retired after the retry, want exactly 1", n)
	}
}

// TestMCP054AStopNeverRefusesWhateverFails sweeps every way the stop path can
// fail and requires each one to come back as a reply.
//
// One case per failure rather than one assertion over all of them: what the
// requirement forbids is a refusal on ANY path, and a sweep that stopped at
// the first is a sweep that proves the first.
func TestMCP054AStopNeverRefusesWhateverFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		// arrange breaks something after the session has started.
		arrange func(t *testing.T, env *osEnv)
	}{
		{
			name: "the ledger is gone",
			arrange: func(_ *testing.T, env *osEnv) {
				env.runs.fail(&ledger.StoreError{
					Class: string(ClassLedgerUnavailable), Op: "credential_run", Retryable: true,
					Err: errors.New("connection refused"),
				})
			},
		},
		{
			name: "SPIRE refuses to delete the entry",
			arrange: func(_ *testing.T, env *osEnv) {
				env.spire.retireErr = &spire.Error{
					Class: spire.ClassIdentityUnavailable, Op: "retire_agent",
					Message: "connection refused", Retryable: true,
				}
			},
		},
		{
			name: "retire_agent is not configured",
			arrange: func(t *testing.T, _ *osEnv) {
				restore, err := ConfigureRetireAgent(RetireAgentConfig{})
				if err == nil {
					t.Cleanup(restore)
					t.Fatal("an empty retire_agent configuration was accepted")
				}
				// Uninstall it the only way this seam allows: install a
				// configuration over the top and restore to nothing.
				retireMu.Lock()
				previous := retireActive
				retireActive = nil
				retireMu.Unlock()
				t.Cleanup(func() {
					retireMu.Lock()
					retireActive = previous
					retireMu.Unlock()
				})
			},
		},
		{
			name: "the marker cannot be updated",
			arrange: func(t *testing.T, env *osEnv) {
				// The retirement lands and recording it does not. Blocked by
				// a directory standing where the bytes are written, not by a
				// permission bit: a chmod is a no-op for uid 0, and a case
				// that quietly passes under root proves nothing.
				osBlockTheMarkerWrite(t, env, osSessionID)
			},
		},
		{
			name: "the marker is unreadable",
			arrange: func(t *testing.T, env *osEnv) {
				marker := osMarkerPath(env.markerDir, osSessionID)
				if err := os.Remove(marker); err != nil {
					t.Fatalf("removing the marker: %v", err)
				}
				if err := os.Mkdir(marker, 0o700); err != nil {
					t.Fatalf("replacing the marker with a directory: %v", err)
				}
			},
		},
		{
			name: "the marker is not a marker",
			arrange: func(t *testing.T, env *osEnv) {
				if err := os.WriteFile(osMarkerPath(env.markerDir, osSessionID),
					[]byte("not json"), 0o600); err != nil {
					t.Fatalf("corrupting the marker: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := osSetup(t, nil)
			env.mustStart(t, osSessionID)
			tc.arrange(t, env)

			stopped, err := env.stop(t, osSessionID)
			if err != nil {
				t.Fatalf("the stop refused with %v. Every failure path returns rather "+
					"than refuses (IP §4): a retry storm was measured at nine deep", err)
			}
			if stopped.Detail == "" {
				t.Errorf("the stop reported nothing about the failure: %+v", stopped)
			}
		})
	}
}

// osBlockTheMarkerWrite makes the next marker write for one session fail,
// whatever uid the tests run as: a directory stands where the bytes go, so
// os.WriteFile cannot create the file and no permission bit is involved.
//
// It leaves the marker's own name alone, so a marker already there still
// reads back — which is what the stop path needs.
func osBlockTheMarkerWrite(t *testing.T, env *osEnv, sessionID string) {
	t.Helper()
	blocked := filepath.Join(env.markerDir, observeSessionPartialName(sessionID))
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatalf("blocking the marker write: %v", err)
	}
}

// TestMCP054AStartThatRegisteredAndCouldNotRecordTheMappingRefusesRetryably.
//
// The other half of the asymmetry at the top of observesession.go, and the
// worse half: the run EXISTS and the only route from a session id back to it
// does not. Left as a success, this would be the shim's measured failure —
// runs still Active a day later with nothing left to retry from — so it
// refuses, retryably, and the retry converges because the registration replays
// under the same key.
func TestMCP054AStartThatRegisteredAndCouldNotRecordTheMappingRefusesRetryably(t *testing.T) {
	env := osSetup(t, nil)
	osBlockTheMarkerWrite(t, env, osSessionID)

	_, err := env.start(t, osSessionID)
	got := osError(t, err)
	if got.Class != ClassLedgerUnavailable {
		t.Errorf("error_class = %s, want %s", got.Class, ClassLedgerUnavailable)
	}
	if !got.Retryable {
		t.Error("the refusal is not retryable, and the retry is the whole repair")
	}
	if got.RunID == "" {
		t.Error("the refusal names no run; the run exists and an operator needs to know " +
			"which one has no mapping")
	}
	if n := env.countEvents(t, got.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered, want 1: the registration happened "+
			"and only the mapping did not", n)
	}

	// The retry, once the volume is usable again: the same run, and still one
	// registration.
	if err := os.Remove(filepath.Join(env.markerDir,
		observeSessionPartialName(osSessionID))); err != nil {
		t.Fatalf("unblocking the marker write: %v", err)
	}
	recovered := env.mustStart(t, osSessionID)
	if recovered.RunID != got.RunID {
		t.Errorf("the retry registered %q, the first attempt registered %q",
			recovered.RunID, got.RunID)
	}
	if n := env.countEvents(t, recovered.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered after the retry, want 1", n)
	}
}

// TestMCP054AnUnwritableMarkerVolumeRefusesAStart.
//
// The asymmetry that decides this tool. A STOP that cannot write its marker
// still retired the run, so the write is bookkeeping and a failure is reported
// and moved past. A START that cannot write its marker has registered a run
// nothing will ever find again — the mapping is the only route from a session
// id back to it — so it refuses, retryably, and the retry converges: the
// registration replays under the same key and the marker is written the second
// time.
//
// LEDGER_UNAVAILABLE, and not a new class: IP §4's vocabulary is closed and
// protected (doc 08 §3). It is the one of the eleven that tells the caller
// what the situation warrants, which is the same reading observe_tool_call
// records for its own body volume.
func TestMCP054AnUnwritableMarkerVolumeRefusesAStart(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("the volume is not mounted"), 0o600); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}
	env := osSetup(t, func(cfg *ObserveSessionConfig) {
		cfg.MarkerDir = filepath.Join(blocked, "sessions")
	})

	_, err := env.start(t, osSessionID)
	got := osError(t, err)
	if got.Class != ClassLedgerUnavailable {
		t.Errorf("error_class = %s, want %s", got.Class, ClassLedgerUnavailable)
	}
	if !got.Retryable {
		t.Error("the refusal is not retryable, but the retry is what converges: the " +
			"registration replays under the same key and the marker is written")
	}
}

// TestMCP054AStartRefusesWhenTheIdentityCannotBeIssued.
//
// A start MAY refuse, and must: IP §6.1 requires attributed work to be
// impossible without an identity, and a session handed no run has none. The
// classes are register_agent's own, carried through unchanged — this tool
// invents none of them (doc 08 §3).
func TestMCP054AStartRefusesWhenTheIdentityCannotBeIssued(t *testing.T) {
	env := osSetup(t, nil)
	env.spire.registerErr = &spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "register_agent",
		Message: "connection refused", Retryable: true,
	}

	_, err := env.start(t, osSessionID)
	got := osError(t, err)
	if got.Class != ClassIdentityUnavailable {
		t.Errorf("error_class = %s, want %s — register_agent's class, unchanged",
			got.Class, ClassIdentityUnavailable)
	}
	if _, statErr := os.Stat(osMarkerPath(env.markerDir, osSessionID)); statErr == nil {
		t.Error("a start that could not register wrote a marker; a later stop would " +
			"try to retire a run that does not exist")
	}
}

// ---------------------------------------------------------------------------
// The refusals a malformed call earns, and the configuration gates.
// ---------------------------------------------------------------------------

// TestObserveSessionRefusesAMalformedCall. Every one of these is
// INVARIANT_VIOLATION, because IP §4's vocabulary is closed and none of the
// other ten describes a caller that sent the wrong arguments.
func TestObserveSessionRefusesAMalformedCall(t *testing.T) {
	env := osSetup(t, nil)

	for _, tc := range []struct {
		name string
		in   observeSessionIn
		want string
	}{
		{
			name: "no session id",
			in:   observeSessionIn{Phase: ObserveSessionPhaseStart, CWD: env.tree.repo},
			want: "session_id",
		},
		{
			name: "a session id that could be a path",
			in: observeSessionIn{
				SessionID: "../../etc/passwd", Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
			},
			want: "session_id",
		},
		{
			name: "a session id longer than the key can carry",
			in: observeSessionIn{
				SessionID: strings.Repeat("s", MaxObserveSessionIDBytes+1),
				Phase:     ObserveSessionPhaseStart, CWD: env.tree.repo,
			},
			want: "session_id",
		},
		{
			name: "no phase",
			in:   observeSessionIn{SessionID: osSessionID, CWD: env.tree.repo},
			want: "phase",
		},
		{
			name: "a phase that is neither",
			in: observeSessionIn{
				SessionID: osSessionID, Phase: "restart", CWD: env.tree.repo,
			},
			want: "phase",
		},
		{
			name: "a start with no cwd",
			in:   observeSessionIn{SessionID: osSessionID, Phase: ObserveSessionPhaseStart},
			want: "cwd",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := observeSession(t.Context(), nil, tc.in)
			got := osError(t, err)
			if got.Class != ClassInvariantViolation {
				t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
			}
			if !strings.Contains(got.Message, tc.want) {
				t.Errorf("the refusal does not name %s: %s", tc.want, got.Message)
			}
		})
	}
}

// TestObserveSessionRefusesAStartItCannotResolve. describe_workspace's own
// refusals, carried through: a cwd outside the mount, a path that is not a
// working tree. The message is the one describe_workspace wrote, because a
// second wording for one failure sends a shim author to the wrong file.
func TestObserveSessionRefusesAStartItCannotResolve(t *testing.T) {
	env := osSetup(t, nil)

	for _, tc := range []struct{ name, cwd string }{
		{"outside the mount", filepath.Join(env.tree.projects, "..", "elsewhere")},
		{"not a working tree", filepath.Join(env.tree.projects, "no-such-directory")},
		{"a relative path", "relative/path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := observeSession(t.Context(), nil, observeSessionIn{
				SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: tc.cwd,
			})
			got := osError(t, err)
			if got.Class != ClassInvariantViolation {
				t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
			}
			if _, statErr := os.Stat(osMarkerPath(env.markerDir, osSessionID)); statErr == nil {
				t.Error("a start that could not resolve its workspace wrote a marker")
			}
		})
	}
}

// TestObserveSessionRefusesAStartOnACorruptMarker.
//
// The asymmetry again. A stop reads a corrupt marker, reports it and returns —
// there is nothing a refusal would achieve and a storm is what it would cost.
// A start cannot: continuing would register a SECOND run for a session that
// may already have one, and the marker is the only thing that would have said
// so. Refusing leaves the file for an operator to look at.
func TestObserveSessionRefusesAStartOnACorruptMarker(t *testing.T) {
	env := osSetup(t, nil)
	if err := os.WriteFile(osMarkerPath(env.markerDir, osSessionID),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupting the marker: %v", err)
	}

	_, err := env.start(t, osSessionID)
	got := osError(t, err)
	if got.Class != ClassInvariantViolation {
		t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
	}
	if len(env.chain(t)) != 0 {
		t.Error("a start on a corrupt marker registered a run anyway")
	}
}

// TestObserveSessionRefusesAStartWhenTheMarkerCannotBeRead covers the other
// half of the same gate: a marker that exists and cannot be opened at all.
func TestObserveSessionRefusesAStartWhenTheMarkerCannotBeRead(t *testing.T) {
	env := osSetup(t, nil)
	marker := osMarkerPath(env.markerDir, osSessionID)
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatalf("replacing the marker with a directory: %v", err)
	}

	_, err := env.start(t, osSessionID)
	if got := osError(t, err); got.Class != ClassInvariantViolation {
		t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
	}
}

// TestObserveSessionUsesTheCallersAgentTypeAndTask. IP §4 makes both optional,
// so both have to be honoured when present and defaulted when absent — a
// harness that knows it is starting a reviewer on ticket 118 should not have
// its answer folded out of a branch name.
func TestObserveSessionUsesTheCallersAgentTypeAndTask(t *testing.T) {
	env := osSetup(t, nil)

	out, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
		AgentType: "reviewer", Task: "jira-118",
	})
	if err != nil {
		t.Fatalf("observe_session start: %v", err)
	}
	if out.AgentType != "reviewer" || out.Task != "jira-118" {
		t.Errorf("agent_type=%q task=%q, want reviewer / jira-118", out.AgentType, out.Task)
	}
	// The branch is still the tree's own: the caller names the task, never
	// the branch, because doc 02 stores `branch` verbatim.
	if out.Branch != osBranch {
		t.Errorf("branch = %q, want the tree's own %q", out.Branch, osBranch)
	}
}

// TestObserveSessionRefusesAnAgentTypeThatIsNotAnIdentifier. The refusal is
// register_agent's, carried through: agent_type is a component of the run's
// SPIFFE ID and doc 02 §5's grammar is where that is decided, once.
func TestObserveSessionRefusesAnAgentTypeThatIsNotAnIdentifier(t *testing.T) {
	env := osSetup(t, nil)

	_, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
		AgentType: "Not An Identifier!",
	})
	if got := osError(t, err); got.Class != ClassInvariantViolation {
		t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
	}
}

// TestObserveSessionIsBoundAndRefusesWhenUnconfigured. A bound tool with no
// dependencies behind it is a defect in the wiring, and IP §4 has no "internal
// error" class (ADR-0016) — so it is alert-level, and it says which.
func TestObserveSessionIsBoundAndRefusesWhenUnconfigured(t *testing.T) {
	observeSessionMu.Lock()
	previous := observeSessionActive
	observeSessionActive = nil
	observeSessionMu.Unlock()
	t.Cleanup(func() {
		observeSessionMu.Lock()
		observeSessionActive = previous
		observeSessionMu.Unlock()
	})

	for _, phase := range []string{ObserveSessionPhaseStart, ObserveSessionPhaseStop} {
		t.Run(phase, func(t *testing.T) {
			_, err := observeSession(t.Context(), nil, observeSessionIn{
				SessionID: osSessionID, Phase: phase, CWD: "/projects/x",
			})
			got := osError(t, err)
			if got.Class != ClassInvariantViolation {
				t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
			}
			if !strings.Contains(got.Message, string(ToolObserveSession)) {
				t.Errorf("the refusal does not name the tool: %s", got.Message)
			}
		})
	}
}

// TestConfigureObserveSessionRefusesAConfigurationItCannotRunOn. Each missing
// dependency is a gate, and an operator finds out at start-up rather than when
// a harness does.
func TestConfigureObserveSessionRefusesAConfigurationItCannotRunOn(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"no marker volume", "marker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := ConfigureObserveSession(ObserveSessionConfig{})
			if err == nil {
				t.Cleanup(restore)
				t.Fatal("a configuration with no marker volume was accepted")
			}
			got := osError(t, err)
			if got.Class != ClassInvariantViolation {
				t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
			}
			if !strings.Contains(got.Message, tc.want) {
				t.Errorf("the refusal does not name %s: %s", tc.want, got.Message)
			}
		})
	}
}

// TestConfigureObserveSessionRefusesARelativeMarkerVolume. A relative path
// resolves against whatever directory this process happens to be in, which is
// not a defensible place for the mapping every stop depends on —
// describe_workspace refuses its own relative root for the same reason.
func TestConfigureObserveSessionRefusesARelativeMarkerVolume(t *testing.T) {
	restore, err := ConfigureObserveSession(ObserveSessionConfig{MarkerDir: "sessions"})
	if err == nil {
		t.Cleanup(restore)
		t.Fatal("a relative marker volume was accepted")
	}
	if got := osError(t, err); got.Class != ClassInvariantViolation {
		t.Errorf("error_class = %s, want %s", got.Class, ClassInvariantViolation)
	}
}

// TestConfigureObserveSessionRestoresWhatWasThere. The restore function is how
// a test — and a deployment rolling a configuration — puts back what it found.
func TestConfigureObserveSessionRestoresWhatWasThere(t *testing.T) {
	first := t.TempDir()
	restoreFirst, err := ConfigureObserveSession(ObserveSessionConfig{MarkerDir: first})
	if err != nil {
		t.Fatalf("ConfigureObserveSession: %v", err)
	}
	t.Cleanup(restoreFirst)

	second := t.TempDir()
	restoreSecond, err := ConfigureObserveSession(ObserveSessionConfig{MarkerDir: second})
	if err != nil {
		t.Fatalf("ConfigureObserveSession: %v", err)
	}
	restoreSecond()

	observeSessionMu.RLock()
	got := observeSessionActive
	observeSessionMu.RUnlock()
	if got == nil || got.markerDir != first {
		t.Fatalf("restoring left %+v installed, want the marker volume %q", got, first)
	}
}

// TestObserveSessionMarkerNameIsNotTheSessionID.
//
// Two things at once, and both matter.
//
// A session id is a caller's string, and the file name is derived from a
// DIGEST of it rather than from the string itself — so no session id can name
// a path, and two session ids differing only in case cannot collide into one
// marker on a case-insensitive filesystem, which is what the operator's own
// machine often is.
func TestObserveSessionMarkerNameIsNotTheSessionID(t *testing.T) {
	name := observeSessionMarkerName(osSessionID)
	if strings.Contains(name, osSessionID) {
		t.Errorf("the marker for %s is named %q; the caller's string is the file name",
			osSessionID, name)
	}
	if name == observeSessionMarkerName(strings.ToUpper(osSessionID)) {
		t.Error("two session ids differing only in case share one marker; on a " +
			"case-insensitive filesystem that is two sessions with one run")
	}
	if strings.ContainsAny(name, `/\.`) {
		t.Errorf("the marker name %q carries a path separator or a dot", name)
	}
}

// TestObserveSessionWritesTheMarkerAtomically. A marker read back by a stop
// decides whether a run is retired at all, and a torn file reads as corrupt —
// which a start refuses on. The bytes go to a temporary name and are moved
// onto the final one, so an interrupted write leaves no marker rather than a
// marker that strands a session.
func TestObserveSessionWritesTheMarkerAtomically(t *testing.T) {
	env := osSetup(t, nil)
	env.mustStart(t, osSessionID)

	entries, err := os.ReadDir(env.markerDir)
	if err != nil {
		t.Fatalf("reading the marker volume: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("the marker volume holds %d entries after one start, want 1: %v",
			len(entries), entries)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat %s: %v", entries[0].Name(), err)
	}
	if perm := info.Mode().Perm(); perm != observeSessionMarkerMode {
		t.Errorf("the marker is mode %v, want %v; it names a run a caller could "+
			"then sign under", perm, observeSessionMarkerMode)
	}
}

// TestObserveSessionSendsNoSessionIDToTheLedger.
//
// The event schema does not change (E11's rule): doc 02 §3 has no member for a
// harness session id, and adding one would be a major release. The link
// between a session and its run is the idempotency key, which IS recorded —
// so an operator can still ask "which session was this" of the chain.
func TestObserveSessionSendsNoSessionIDToTheLedger(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)

	var registered event.Fields
	for _, rec := range env.chain(t) {
		kind, isString := rec[event.FieldEventType].(string)
		if isString && kind == event.EventTypeRunRegistered {
			registered = rec
		}
	}
	if registered == nil {
		t.Fatal("no run_registered was appended")
	}
	key, isString := registered[event.FieldIdempotencyKey].(string)
	if !isString {
		t.Fatal("run_registered carries no idempotency_key")
	}
	if !strings.Contains(key, osSessionID) {
		t.Errorf("idempotency_key = %q; it is the only recorded link from a session "+
			"back to its run, and it does not name the session", key)
	}
	if len(key) > event.MaxIdempotencyKeyBytes {
		t.Errorf("idempotency_key is %d bytes, doc 02 §2 bounds it at %d",
			len(key), event.MaxIdempotencyKeyBytes)
	}
	for name, value := range registered {
		text, isString := value.(string)
		if !isString || name == event.FieldIdempotencyKey {
			continue
		}
		if strings.Contains(text, osSessionID) {
			t.Errorf("%s carries the session id (%q); doc 02 §3 has no member for one",
				name, text)
		}
	}
	if started.RunID == "" {
		t.Fatal("no run")
	}
}

// TestObserveSessionKeyIsDerivedAndBounded. The caller does not choose the
// idempotency key: ADR-0004 requires one where IP §4 gives the tool one, and
// IP §4 gives this tool none. Deriving it from the session id is what makes
// two starts for one session one registration, and it is what stops a caller
// recording one session twice under two keys.
func TestObserveSessionKeyIsDerivedAndBounded(t *testing.T) {
	longest := strings.Repeat("s", MaxObserveSessionIDBytes)
	key := observeSessionKey(longest)
	if len(key) > event.MaxIdempotencyKeyBytes {
		t.Errorf("the key for the longest admissible session id is %d bytes, doc 02 §2 "+
			"bounds it at %d", len(key), event.MaxIdempotencyKeyBytes)
	}
	if observeSessionKey("a") == observeSessionKey("b") {
		t.Error("two session ids derive one key")
	}
	if !strings.Contains(key, longest) {
		t.Errorf("the key %q does not name the session; it is the only recorded link "+
			"between the two", key)
	}
}

// TestObserveSessionMarkerRoundTrips is the marker's own contract: what a
// start writes is what a stop reads, field for field. It is asserted directly
// because every other case reaches the marker through the tool, and a marker
// that lost a field would show up there as a vaguer failure somewhere else.
func TestObserveSessionMarkerRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := observeSessionMarker{
		SessionID: osSessionID, RunID: "run-42", SPIFFEID: "spiffe://innsegl.dev/agent/a/b/run-42",
		ExpiresAt: "2026-09-12T18:00:00.000Z", AgentType: "session", Task: osTask,
		Repo: osRepo, Worktree: "w", Branch: osBranch,
	}
	if err := observeSessionWriteMarker(dir, want); err != nil {
		t.Fatalf("writing the marker: %v", err)
	}
	got, found, err := observeSessionReadMarker(dir, osSessionID)
	if err != nil || !found {
		t.Fatalf("reading the marker back: found=%v err=%v", found, err)
	}
	if got != want {
		t.Errorf("the marker round-tripped as %+v, want %+v", got, want)
	}

	_, found, err = observeSessionReadMarker(dir, "no-such-session")
	if err != nil || found {
		t.Errorf("an absent marker reported found=%v err=%v, want false and no error", found, err)
	}
}

// TestObserveSessionMarkerWriteReportsAVolumeItCannotUse covers the write
// helper's own refusals, which the tool turns into a retryable class.
func TestObserveSessionMarkerWriteReportsAVolumeItCannotUse(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}
	if err := observeSessionWriteMarker(filepath.Join(blocked, "sessions"),
		observeSessionMarker{SessionID: osSessionID, RunID: "run-42"}); err == nil {
		t.Fatal("writing to a volume that is a regular file succeeded")
	}

	// A directory standing where the marker file belongs: MkdirAll succeeds
	// and the rename cannot.
	dir := t.TempDir()
	if err := os.Mkdir(osMarkerPath(dir, osSessionID), 0o700); err != nil {
		t.Fatalf("preparing the occupied name: %v", err)
	}
	if err := observeSessionWriteMarker(dir,
		observeSessionMarker{SessionID: osSessionID, RunID: "run-42"}); err == nil {
		t.Fatal("writing over a directory succeeded")
	}
}

// TestObserveSessionIsOnTheSurfaceAndBinds. The eighth name of IP §4, and the
// last of RM-131's three to arrive.
func TestObserveSessionIsOnTheSurfaceAndBinds(t *testing.T) {
	srv, err := New(Config{Version: "v0.0.0-observesession"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	bound := srv.BoundTools()
	found := false
	for _, name := range bound {
		if name == ToolObserveSession {
			found = true
		}
	}
	if !found {
		t.Fatalf("the server does not bind %s: %v", ToolObserveSession, bound)
	}
	if missing := srv.MissingTools(); len(missing) != 0 {
		t.Errorf("MissingTools() is %v; all eight IP §4 tools are bound", missing)
	}
	if len(bound) != len(ToolNames()) {
		t.Errorf("the server binds %d of the %d IP §4 tools", len(bound), len(ToolNames()))
	}
}
