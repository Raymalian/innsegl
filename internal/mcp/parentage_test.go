// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// MCP-079 … MCP-082 — a run's parent is resolved in the MCP, on every path a
// run can be registered by (RM-156, #259).
//
// # What was measured
//
// 21 registrations out of 185 carried a parent. The lookup worked; it existed
// on ONE of the three paths. The reference shim resolved the edge itself,
// reading a sibling marker out of its own cache, and the other two paths — the
// first-sight registration a tool call makes for a session nobody announced,
// and the signer, which has no agent or session identifier in its environment
// at all — sent nothing, because neither holds a run id to send.
//
// So the lookup moves into the MCP, which is the only component that holds the
// durable session → run mapping. A harness sends its OWN session identifier;
// the MCP answers with the run. Nothing about runs is any harness's business,
// which is the whole of E11.
//
// # Nothing is backfilled, and nothing here may grow to
//
// The registrations already on the chain keep no parent. Inferring one from
// timing or from a shared working directory is the inference IP §3 E7 forbids,
// and an edge in an append-only record is permanent whether or not it is
// right. These cases are all about what a registration RECORDS from what it
// was told, and none of them reads a clock.

// ---------------------------------------------------------------------------
// MCP-079 — the subagent-start path.
// ---------------------------------------------------------------------------

// osStartWithParentSession is a start that names its parent the way a HARNESS
// does: by the parent's session id, never by a run id.
func osStartWithParentSession(t *testing.T, e *osEnv, sessionID, parentSessionID string) (observeSessionOut, error) {
	t.Helper()
	return observeSession(t.Context(), nil, observeSessionIn{
		SessionID:       sessionID,
		Phase:           ObserveSessionPhaseStart,
		CWD:             e.tree.repo,
		ParentSessionID: parentSessionID,
	})
}

// MCP-079: a session started under a parent SESSION records the parent's run.
//
// This is the shim's SubagentStart, after the lookup moved. The harness sends
// two session ids and no run id at all; the run the edge names is the MCP's
// answer, not the caller's claim.
func TestMCP079AParentSessionIsResolvedToItsRun(t *testing.T) {
	env := osSetup(t, nil)

	parent := env.mustStart(t, "parent-session")
	if parent.RunID == "" {
		t.Fatal("the parent session has no run id")
	}

	child, err := osStartWithParentSession(t, env, "child-session", "parent-session")
	if err != nil {
		t.Fatalf("starting a session under parent-session: %v", err)
	}
	if child.RunID == parent.RunID {
		t.Fatal("the child reused the parent's run id; two sessions are two runs")
	}

	body := registeredBody(t, env, child.RunID)
	got, ok := body[event.FieldParentRunID]
	if !ok {
		t.Fatalf("run_registered for the child carries no %s. The harness named its "+
			"parent by session and the MCP is what resolves that; without the resolution "+
			"the ledger holds two runs and no relation", event.FieldParentRunID)
	}
	if got != parent.RunID {
		t.Errorf("%s = %v, want the parent session's run %s", event.FieldParentRunID, got, parent.RunID)
	}

	// AND THE HARNESS'S OWN IDENTIFIER IS NOWHERE ON THE CHAIN (E4). doc 02 §3
	// has no member for a session id and gains none: what is recorded is the
	// run the identifier resolved to.
	for _, member := range body {
		if s, isString := member.(string); isString && strings.Contains(s, "parent-session") {
			t.Errorf("the parent's SESSION id reached the chain as %q; only the run it "+
				"resolves to belongs on it (E4)", s)
		}
	}
}

// A parent session this deployment has never seen leaves a ROOT RUN, and is
// not a refusal.
//
// The asymmetry is deliberate and it is about cost. A refused start gives the
// session no identity — the reference shim's SubagentStart exits 2 and the
// subagent does no work — so refusing here trades a whole session's identity
// and activity record for an edge. The edge is what a reader would have liked;
// the record is what this system exists to keep.
func TestAnUnknownParentSessionLeavesARootRun(t *testing.T) {
	env := osSetup(t, nil)

	child, err := osStartWithParentSession(t, env, "child-session", "never-registered")
	if err != nil {
		t.Fatalf("a start under an unknown parent session was refused: %v.\n"+
			"A subagent whose parent never registered is a root run, and refusing costs "+
			"it its identity and every tool call it goes on to make", err)
	}
	body := registeredBody(t, env, child.RunID)
	if v, present := body[event.FieldParentRunID]; present {
		t.Errorf("a root run recorded %s = %q; absent and empty are different (doc 02 §1), "+
			"and this run has no parent to name", event.FieldParentRunID, v)
	}
	if child.Detail == "" {
		t.Error("nothing said the parent could not be resolved; a silently dropped edge " +
			"is indistinguishable from a run that never named one")
	}
}

// A parent session that has ENDED likewise leaves a root run.
//
// register_agent refuses a retired parent outright (MCP-082), so a resolution
// that sent one on would turn an ended parent session into a refused child.
// What this tool knows about is the marker, so what it can drop is a
// retirement it performed itself.
func TestARetiredParentSessionLeavesARootRun(t *testing.T) {
	env := osSetup(t, nil)

	env.mustStart(t, "parent-session")
	env.mustStop(t, "parent-session")

	child, err := osStartWithParentSession(t, env, "child-session", "parent-session")
	if err != nil {
		t.Fatalf("a start under an ended parent session was refused: %v", err)
	}
	if v, present := registeredBody(t, env, child.RunID)[event.FieldParentRunID]; present {
		t.Errorf("%s = %q was recorded for a parent whose session had ended; retirement is "+
			"terminal (IP §6.2) and a run that has ended did not start this one",
			event.FieldParentRunID, v)
	}
	if !strings.Contains(child.Detail, "parent-session") {
		t.Errorf("detail = %q; it has to name the session whose ending cost the edge", child.Detail)
	}
}

// A parent marker that cannot be read costs the edge and not the session.
//
// The asymmetry with the start's OWN marker is deliberate. A start refuses on
// an unreadable marker of its own session, because registering over one would
// give that session a second identity; this is a DIFFERENT session's marker and
// nothing is about to be written to it, so the cost of continuing is one
// missing edge rather than a duplicate run.
func TestAnUnreadableParentMarkerCostsTheEdgeAndNotTheSession(t *testing.T) {
	env := osSetup(t, nil)

	env.mustStart(t, "parent-session")
	corrupt := filepath.Join(env.markerDir, observeSessionMarkerName("parent-session"))
	if err := os.WriteFile(corrupt, []byte("not a marker"), 0o600); err != nil {
		t.Fatalf("corrupting the parent's marker: %v", err)
	}

	child, err := osStartWithParentSession(t, env, "child-session", "parent-session")
	if err != nil {
		t.Fatalf("a start was refused over ANOTHER session's unreadable marker: %v", err)
	}
	if v, present := registeredBody(t, env, child.RunID)[event.FieldParentRunID]; present {
		t.Errorf("%s = %q was recorded from a marker that could not be read", event.FieldParentRunID, v)
	}
	if !strings.Contains(child.Detail, "parent-session") {
		t.Errorf("detail = %q; it has to name the marker that could not be read", child.Detail)
	}
}

// A marker that parses and names no run is a marker with no answer in it.
//
// Nothing this tool writes can be in that state — a marker is written from a
// registration that returned a run — but a marker is a file on a disk that
// outlives the process that wrote it, and a reader that trusted its shape would
// record an EMPTY parent. doc 02 §1 admits no empty-string placeholder, so that
// is a refused append rather than a root run, on a path where a root run is the
// right answer.
func TestAParentMarkerNamingNoRunLeavesARootRun(t *testing.T) {
	env := osSetup(t, nil)

	blank := filepath.Join(env.markerDir, observeSessionMarkerName("parent-session"))
	if err := os.WriteFile(blank, []byte(`{"session_id":"parent-session"}`), 0o600); err != nil {
		t.Fatalf("writing a marker with no run: %v", err)
	}

	child, err := osStartWithParentSession(t, env, "child-session", "parent-session")
	if err != nil {
		t.Fatalf("a start under a marker naming no run was refused: %v", err)
	}
	if v, present := registeredBody(t, env, child.RunID)[event.FieldParentRunID]; present {
		t.Errorf("%s = %q came out of a marker that names no run", event.FieldParentRunID, v)
	}
}

// A session that names ITSELF as its parent is refused, and registers nothing.
func TestASessionCannotBeItsOwnParent(t *testing.T) {
	env := osSetup(t, nil)

	before := len(env.chain(t))
	out, err := osStartWithParentSession(t, env, "child-session", "child-session")
	if err == nil {
		t.Fatalf("a session named itself as its own parent and was accepted: %+v.\n"+
			"A cycle of length one is a parent chain a reader never leaves", out)
	}
	if got := Classify(err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
	if after := len(env.chain(t)); after != before {
		t.Errorf("the chain grew from %d to %d on a refused start", before, after)
	}
}

// Two arguments naming two different parents is a contradiction the caller has
// to resolve, not one this tool may resolve for it.
func TestTwoParentsForOneRunAreRefused(t *testing.T) {
	env := osSetup(t, nil)

	parent := env.mustStart(t, "parent-session")
	other := env.mustStart(t, "other-session")

	before := len(env.chain(t))
	_, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID:       "child-session",
		Phase:           ObserveSessionPhaseStart,
		CWD:             env.tree.repo,
		ParentRunID:     other.RunID,
		ParentSessionID: "parent-session",
	})
	if err == nil {
		t.Fatalf("parent_run_id %s and parent_session_id parent-session (%s) both named a "+
			"parent and neither was refused; the record cannot be amended",
			other.RunID, parent.RunID)
	}
	if got := Classify(err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
	// The resolved run is deliberately NOT quoted back: a refusal that named
	// it would map a session to a run for a caller that could not otherwise ask.
	if strings.Contains(Classify(err).Message, parent.RunID) {
		t.Errorf("the refusal quoted the resolved run %s; that is an oracle over the "+
			"marker store: %s", parent.RunID, Classify(err).Message)
	}
	if after := len(env.chain(t)); after != before {
		t.Errorf("the chain grew from %d to %d on a refused start", before, after)
	}
}

// Naming the same parent twice, in both vocabularies, is not a contradiction.
func TestTwoArgumentsAgreeingAboutOneParentAreAccepted(t *testing.T) {
	env := osSetup(t, nil)

	parent := env.mustStart(t, "parent-session")
	child, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID:       "child-session",
		Phase:           ObserveSessionPhaseStart,
		CWD:             env.tree.repo,
		ParentRunID:     parent.RunID,
		ParentSessionID: "parent-session",
	})
	if err != nil {
		t.Fatalf("two arguments naming ONE parent were refused: %v", err)
	}
	if got := registeredBody(t, env, child.RunID)[event.FieldParentRunID]; got != parent.RunID {
		t.Errorf("%s = %v, want %s", event.FieldParentRunID, got, parent.RunID)
	}
}

// A parent_session_id that is not a session id is refused by the SAME grammar
// observe_session holds its own session_id to.
//
// One grammar, so an id this tool would resolve and then refuse to start is
// impossible.
func TestAMalformedParentSessionIDIsRefused(t *testing.T) {
	env := osSetup(t, nil)

	before := len(env.chain(t))
	if _, err := osStartWithParentSession(t, env, "child-session", "../../etc/passwd"); err == nil {
		t.Fatal("a parent_session_id that looks like a path was accepted")
	}
	if after := len(env.chain(t)); after != before {
		t.Errorf("the chain grew from %d to %d on a refused start", before, after)
	}
}

// ---------------------------------------------------------------------------
// MCP-080 — the first-sight path.
// ---------------------------------------------------------------------------

// MCP-080: a tool call that registers a session nobody announced records the
// parent it was told about.
//
// This is the path RM-142 opened and the one that could never carry an edge:
// it holds no run id, so before this it registered every first-sight run as a
// root run — and it is exactly the path a harness reaches when its start was
// refused, which is when knowing what spawned the run matters most.
func TestMCP080AFirstSightRegistrationResolvesItsParent(t *testing.T) {
	env := osiSetup(t)

	parent := env.mustStart(t, "parent-session")

	in := bySession("unannounced-session", env.tree.repo)
	in.ParentSessionID = "parent-session"
	env.mustObserve(t, in)

	body := registeredBodyForSession(t, env.osEnv, "unannounced-session")
	got, ok := body[event.FieldParentRunID]
	if !ok {
		t.Fatalf("the first-sight registration carries no %s. This is the path that holds "+
			"no run id, so it is the path the resolution had to reach", event.FieldParentRunID)
	}
	if got != parent.RunID {
		t.Errorf("%s = %v, want the parent session's run %s", event.FieldParentRunID, got, parent.RunID)
	}
}

// And a first-sight registration with no parent named is still a root run: the
// argument is optional on this path exactly as it is on the other.
func TestAFirstSightRegistrationWithNoParentIsARootRun(t *testing.T) {
	env := osiSetup(t)

	env.mustObserve(t, bySession("unannounced-session", env.tree.repo))

	body := registeredBodyForSession(t, env.osEnv, "unannounced-session")
	if v, present := body[event.FieldParentRunID]; present {
		t.Errorf("a root run recorded %s = %q", event.FieldParentRunID, v)
	}
}

// ---------------------------------------------------------------------------
// MCP-081 — the signer's path, and MCP-082, the refusals.
// ---------------------------------------------------------------------------

// MCP-081: register_agent records a parent it was given by run id, having
// checked it.
//
// This is the signer's path. It has no agent or session identifier in its
// environment, so it names the parent by the run id a pointer gave it — and a
// pointer is exactly the thing that goes stale, which is why the check below
// is the same call's business.
func TestMCP081AValidatedParentIsRecordedOnTheRunIDPath(t *testing.T) {
	env := osSetup(t, nil)

	parent := env.mustStart(t, "parent-session")
	child, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      "orchestrator",
		TaskID:         "rm156",
		IdempotencyKey: "signer-commit-1",
		Repo:           osRepo,
		Branch:         osBranch,
		ParentRunID:    parent.RunID,
	})
	if err != nil {
		t.Fatalf("register_agent under a live parent: %v", err)
	}
	if got := registeredBody(t, env, child.RunID)[event.FieldParentRunID]; got != parent.RunID {
		t.Errorf("%s = %v, want %s", event.FieldParentRunID, got, parent.RunID)
	}

	// AND THE EDGE IS READABLE THE OTHER WAY ROUND. An edge nothing can follow
	// is bookkeeping; this is what makes it an answer (LED-040).
	children, err := env.ledger.ChildRuns(t.Context(), parent.RunID)
	if err != nil {
		t.Fatalf("ChildRuns: %v", err)
	}
	if len(children) != 1 || children[0] != child.RunID {
		t.Errorf("ChildRuns(%s) = %v, want [%s]", parent.RunID, children, child.RunID)
	}
}

// MCP-082: a parent that does not exist, one that has been retired, and one
// that is the run itself are each refused, and each leaves the chain untouched.
//
// Until this, the argument was COPIED: held to doc 02 §5's grammar by the
// schema validator on the way into the ledger and to nothing else, so any
// well-formed string became a permanent edge to a run that need never have
// existed.
func TestMCP082AnUnusableParentIsRefusedAndNothingIsAppended(t *testing.T) {
	env := osSetup(t, nil)

	retired := env.mustStart(t, "ended-session")
	env.mustStop(t, "ended-session")

	// The run id this call will derive, so the self-reference case can name it
	// before the call is made. It is a pure function of the three arguments
	// (registerAgentRunID), which is what makes that possible at all.
	selfKey := "signer-commit-self"
	self := registerAgentRunID(registerAgentIn{
		AgentType: "orchestrator", TaskID: "rm156", IdempotencyKey: selfKey,
	})

	cases := []struct {
		name   string
		key    string
		parent string
		class  Class
	}{
		{
			name:   "a run this ledger has never held",
			key:    "signer-commit-absent",
			parent: "run-000000000000000000000000000000",
			class:  ClassRunNotFound,
		},
		{
			name:   "a run that has been retired",
			key:    "signer-commit-retired",
			parent: retired.RunID,
			class:  ClassRunAlreadyRetired,
		},
		{
			name:   "the run itself",
			key:    selfKey,
			parent: self,
			class:  ClassInvariantViolation,
		},
		{
			name:   "a string that is not a run id",
			key:    "signer-commit-malformed",
			parent: "not a run id",
			class:  ClassInvariantViolation,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(env.chain(t))
			out, err := registerAgent(t.Context(), nil, registerAgentIn{
				AgentType:      "orchestrator",
				TaskID:         "rm156",
				IdempotencyKey: tc.key,
				Repo:           osRepo,
				Branch:         osBranch,
				ParentRunID:    tc.parent,
			})
			if err == nil {
				t.Fatalf("parent_run_id %q was accepted and produced %+v.\n"+
					"An edge is permanent; one that names a run that is not there is "+
					"permanently wrong", tc.parent, out)
			}
			if got := Classify(err).Class; got != tc.class {
				t.Errorf("class = %s, want %s (%s)", got, tc.class, Classify(err).Message)
			}
			if after := len(env.chain(t)); after != before {
				t.Errorf("the chain grew from %d to %d on a refused registration; "+
					"a refusal appends nothing", before, after)
			}
		})
	}
}

// A LAPSED parent is accepted, because silence is not an ending.
//
// The reaper withdraws a credential from a run that went quiet, and a quiet
// orchestrator — waiting on a provider limit, or on a human — is exactly the
// run whose subagent is registering. Reading the withdrawal as terminal is the
// defect #258 closed; it must not come back through this check.
func TestAWithdrawnParentIsStillAParent(t *testing.T) {
	env := raSetup(t, 0, nil)
	env.runs.expire("run-quiet-parent", env.clock.Now().Add(-time.Hour))

	out, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      raAgentType,
		TaskID:         raTaskID,
		IdempotencyKey: "reg-under-a-quiet-parent",
		Repo:           raRepo,
		Branch:         raBranch,
		ParentRunID:    "run-quiet-parent",
	})
	if err != nil {
		t.Fatalf("a run whose parent's credential the reaper withdrew was refused: %v.\n"+
			"Silence is not an ending (RM-155, #258): the parent is waiting, not over", err)
	}
	events := env.runRegisteredFor(t, out.RunID)
	if len(events) != 1 {
		t.Fatalf("run_registered count = %d, want 1", len(events))
	}
	if got := events[0][event.FieldParentRunID]; got != "run-quiet-parent" {
		t.Errorf("%s = %v, want run-quiet-parent", event.FieldParentRunID, got)
	}
}

// A REPLAYED registration is not re-checked, and that is what keeps a resumed
// run working after its parent has ended.
//
// The run id derives from (agent_type, task, idempotency_key) and not from the
// parent, so a second call cannot move the edge in any case. Re-checking on a
// replay would refuse a child an identity it already holds — which is how
// observe_session answers a duplicate start, and how a reaped run gets its
// SPIRE entry healed.
func TestAReplayIsNotRefusedBecauseItsParentHasSinceEnded(t *testing.T) {
	env := raSetup(t, 0, nil)
	env.runs.remember("run-live-parent")

	in := registerAgentIn{
		AgentType:      raAgentType,
		TaskID:         raTaskID,
		IdempotencyKey: "reg-replayed-under-a-parent",
		Repo:           raRepo,
		Branch:         raBranch,
		ParentRunID:    "run-live-parent",
	}
	first, err := registerAgent(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}

	env.runs.retire("run-live-parent", env.clock.Now())

	second, err := registerAgent(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("a replay was refused because the parent had been retired since: %v.\n"+
			"The run already exists and its edge is already written; the replay is how a "+
			"resumed run gets its identity back", err)
	}
	if second.RunID != first.RunID {
		t.Errorf("replay named %s, want %s", second.RunID, first.RunID)
	}
	if got := len(env.runRegisteredFor(t, first.RunID)); got != 1 {
		t.Errorf("run_registered count = %d, want 1", got)
	}
}

// A deployment with no run directory cannot check a parent, so it does not
// record one: the call is refused rather than writing an edge on trust.
//
// Runs is optional — nil turns healing off — and a deployment in that state
// registers root runs exactly as it always did.
func TestAParentCannotBeRecordedWithoutARunDirectory(t *testing.T) {
	env := raSetup(t, 0, func(c *RegisterAgentConfig) { c.Runs = nil })

	before := len(env.runRegisteredFor(t, ""))
	_, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      raAgentType,
		TaskID:         raTaskID,
		IdempotencyKey: "reg-no-directory",
		Repo:           raRepo,
		Branch:         raBranch,
		ParentRunID:    "run-unknowable",
	})
	if err == nil {
		t.Fatal("a parent was recorded by a deployment that cannot check one")
	}
	if got := Classify(err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
	if after := len(env.runRegisteredFor(t, "")); after != before {
		t.Error("something was appended on a refused registration")
	}

	// And a ROOT run on the same deployment is untouched.
	if _, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      raAgentType,
		TaskID:         raTaskID,
		IdempotencyKey: "reg-no-directory-root",
		Repo:           raRepo,
		Branch:         raBranch,
	}); err != nil {
		t.Errorf("a root run was refused by a deployment with no directory: %v", err)
	}
}

// A directory that cannot answer is a dependency outage, and its own class
// reaches the caller rather than a second wording for it.
func TestADirectoryOutageIsReportedAsItself(t *testing.T) {
	env := raSetup(t, 0, nil)
	env.runs.mu.Lock()
	env.runs.err = errors.New("the ledger is unreachable")
	env.runs.mu.Unlock()

	_, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      raAgentType,
		TaskID:         raTaskID,
		IdempotencyKey: "reg-directory-down",
		Repo:           raRepo,
		Branch:         raBranch,
		ParentRunID:    "run-live-parent",
	})
	if err == nil {
		t.Fatal("a parent was recorded although the directory could not be asked")
	}
	if !strings.Contains(Classify(err).Message, "unreachable") {
		t.Errorf("the directory's own failure did not reach the caller: %s", Classify(err).Message)
	}
}

// ---------------------------------------------------------------------------
// A SECOND HARNESS.
// ---------------------------------------------------------------------------

// No path may depend on one harness's variables.
//
// This drives both resolving paths with identifiers in a shape the reference
// harness never emits — uppercase, underscored, dotted — and with no run id
// anywhere in either call. What comes back is the same edge.
//
// It is the claim E11 is for. The reference shim resolved the parent from a
// file layout of its own, so the edge existed for one harness and for no
// other; after this, the only thing a harness has to know is the id it already
// has for the session that spawned the one it is starting.
func TestASecondHarnessGetsTheSameEdgeFromItsOwnIdentifiers(t *testing.T) {
	env := osiSetup(t)

	const (
		foreignParent = "SESS_01JQ8Z.4K7"
		foreignChild  = "AGENT_01JQ8Z.9M2"
		foreignLate   = "AGENT_01JQ8Z.7P4"
	)

	parent := env.mustStart(t, foreignParent)

	// Path one: the harness announces the child.
	child, err := osStartWithParentSession(t, env.osEnv, foreignChild, foreignParent)
	if err != nil {
		t.Fatalf("a second harness's start was refused: %v", err)
	}

	// Path two: the harness announces nothing and a tool call arrives.
	late := bySession(foreignLate, env.tree.repo)
	late.ParentSessionID = foreignParent
	env.mustObserve(t, late)

	for _, runID := range []string{child.RunID, runIDForSession(t, env.osEnv, foreignLate)} {
		got := registeredBody(t, env.osEnv, runID)[event.FieldParentRunID]
		if got != parent.RunID {
			t.Errorf("run %s recorded %s = %v, want %s. A path that answered differently "+
				"would be a path that depends on one harness's variables",
				runID, event.FieldParentRunID, got, parent.RunID)
		}
	}

	// And the parent can be asked what it started, which is the question the
	// edge exists to answer.
	children, err := env.ledger.ChildRuns(t.Context(), parent.RunID)
	if err != nil {
		t.Fatalf("ChildRuns: %v", err)
	}
	if len(children) != 2 {
		t.Errorf("ChildRuns(%s) = %v, want both of this harness's runs", parent.RunID, children)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// runIDForSession returns the run a session id names, read off the marker
// store the way a stop does.
func runIDForSession(t *testing.T, e *osEnv, sessionID string) string {
	t.Helper()
	marker, found, err := observeSessionReadMarker(e.markerDir, sessionID)
	if err != nil || !found {
		t.Fatalf("no marker for session %q: found=%v err=%v", sessionID, found, err)
	}
	return marker.RunID
}

// registeredBodyForSession is registeredBody, reached from a session id.
func registeredBodyForSession(t *testing.T, e *osEnv, sessionID string) event.Fields {
	t.Helper()
	return registeredBody(t, e, runIDForSession(t, e, sessionID))
}
