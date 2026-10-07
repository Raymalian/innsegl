// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// MCP-081 and MCP-082 — a run's parent, named by run id, is checked before it
// is recorded (RM-156, #259). MCP-079 and MCP-080 resolved a parent named by
// session id through observe_session, which is deprecated (ADR-0071); their
// cases went with it.
//
// # Nothing is backfilled, and nothing here may grow to
//
// The registrations already on the chain keep no parent. Inferring one from
// timing or from a shared working directory is the inference IP §3 E7 forbids,
// and an edge in an append-only record is permanent whether or not it is
// right. These cases are all about what a registration RECORDS from what it
// was told, and none of them reads a clock.

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
	env := raSetup(t, 0, nil)

	parent := ptRegister(t, env, "parent-run", "")
	child := ptRegister(t, env, "signer-commit-1", parent.RunID)
	events := env.runRegisteredFor(t, child.RunID)
	if len(events) != 1 {
		t.Fatalf("run_registered count = %d, want 1", len(events))
	}
	if got := events[0][event.FieldParentRunID]; got != parent.RunID {
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
	env := raSetup(t, 0, nil)

	retired := ptRegister(t, env, "ended-run", "")
	env.runs.retire(retired.RunID, env.clock.Now())

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
			before := ptChainLen(t, env)
			out, err := registerAgent(t.Context(), nil, registerAgentIn{
				AgentType:      "orchestrator",
				TaskID:         "rm156",
				IdempotencyKey: tc.key,
				Repo:           raRepo,
				Branch:         raBranch,
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
			if after := ptChainLen(t, env); after != before {
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
// the gateway restores a run, and how a reaped run gets its
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

	before := ptChainLen(t, env)
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
	if after := ptChainLen(t, env); after != before {
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

// ptRegister registers one run through register_agent and records it in the
// run directory, so a later registration can name it as a parent.
func ptRegister(t *testing.T, env *raEnv, key, parent string) registerAgentOut {
	t.Helper()
	out, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      "orchestrator",
		TaskID:         "rm156",
		IdempotencyKey: key,
		Repo:           raRepo,
		Branch:         raBranch,
		ParentRunID:    parent,
	})
	if err != nil {
		t.Fatalf("register_agent %s (parent %q): %v", key, parent, err)
	}
	env.runs.remember(out.RunID)
	return out
}

// ptChainLen is how many events the chain holds: a refusal appends none.
func ptChainLen(t *testing.T, env *raEnv) int64 {
	t.Helper()
	n, err := env.ledger.Count(t.Context())
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// MCP-100 — a re-run of an appended registration is not refused by a parent
// retired since (RM-334, #532).
// ---------------------------------------------------------------------------

// keyBlindLedger is a ledger that cannot be asked what a key names.
type keyBlindLedger struct{ RegisterAgentLedger }

// keyReadFailsLedger is a ledger whose key read fails.
type keyReadFailsLedger struct {
	RegisterAgentLedger
	err error
}

func (l keyReadFailsLedger) EventByIdempotencyKey(context.Context, string) (event.Fields, bool, error) {
	return nil, false, l.err
}

// mcp100Child registers a child of a live parent whose SPIRE entry is not
// created (the append succeeded), then retires the parent: the state a retry
// meets.
func mcp100Child(t *testing.T, env *raEnv, key string) registerAgentIn {
	t.Helper()
	env.runs.remember("run-live-parent")
	in := registerAgentIn{
		AgentType: raAgentType, TaskID: raTaskID, IdempotencyKey: key,
		Repo: raRepo, Branch: raBranch, ParentRunID: "run-live-parent",
	}
	env.identities.mu.Lock()
	env.identities.registerErr = &spire.Error{Class: spire.ClassIdentityUnavailable, Op: "create",
		Message: "spire-server is down", Retryable: true}
	env.identities.mu.Unlock()
	if _, err := registerAgent(t.Context(), nil, in); err == nil {
		t.Fatal("the outage did not interrupt the registration")
	}
	env.identities.mu.Lock()
	env.identities.registerErr = nil
	env.identities.mu.Unlock()
	env.runs.retire("run-live-parent", env.clock.Now())
	return in
}

// MCP-100: the re-run of a registration the chain already holds is the
// recorded run, given its identity, though its parent was retired after the
// append. The parent was checked when the edge was written.
func TestMCP100AnAppendedChildIsNotRefusedForAParentRetiredSince(t *testing.T) {
	env := raSetup(t, 0, nil)
	in := mcp100Child(t, env, "mcp100-appended")

	before := ptChainLen(t, env)
	out, err := registerAgent(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("the re-run was refused: %v", err)
	}
	if got := len(env.runRegisteredFor(t, out.RunID)); got != 1 {
		t.Errorf("run_registered count = %d, want 1", got)
	}
	if after := ptChainLen(t, env); after != before {
		t.Errorf("the re-run appended %d events, want none", after-before)
	}
}

// MCP-100: what the exception does not cover keeps checkParent's refusal: a
// different parent under the same key, a ledger that cannot be asked, and a
// key read that fails, which is reported as itself.
func TestMCP100TheExceptionIsOnlyForTheRecordedEdge(t *testing.T) {
	t.Run("another parent under the key", func(t *testing.T) {
		env := raSetup(t, 0, nil)
		in := mcp100Child(t, env, "mcp100-other-parent")
		env.runs.remember("run-other-parent")
		env.runs.retire("run-other-parent", env.clock.Now())
		in.ParentRunID = "run-other-parent"
		_, err := registerAgent(t.Context(), nil, in)
		if got := Classify(err).Class; got != ClassRunAlreadyRetired {
			t.Fatalf("class = %s (%v), want %s", got, err, ClassRunAlreadyRetired)
		}
	})
	t.Run("a ledger that cannot be asked", func(t *testing.T) {
		env := raSetup(t, 0, nil)
		in := mcp100Child(t, env, "mcp100-blind")
		restore := reconfigure(t, func(c *RegisterAgentConfig) { c.Ledger = keyBlindLedger{c.Ledger} })
		defer restore()
		_, err := registerAgent(t.Context(), nil, in)
		if got := Classify(err).Class; got != ClassRunAlreadyRetired {
			t.Fatalf("class = %s (%v), want %s", got, err, ClassRunAlreadyRetired)
		}
	})
	t.Run("the key read fails", func(t *testing.T) {
		env := raSetup(t, 0, nil)
		in := mcp100Child(t, env, "mcp100-read-fails")
		restore := reconfigure(t, func(c *RegisterAgentConfig) {
			c.Ledger = keyReadFailsLedger{RegisterAgentLedger: c.Ledger, err: &ledger.StoreError{
				Class: ledger.ClassLedgerUnavailable, Op: "event", Retryable: true, Err: errors.New("down")}}
		})
		defer restore()
		_, err := registerAgent(t.Context(), nil, in)
		if c := Classify(err); c.Class != ClassLedgerUnavailable || !c.Retryable {
			t.Fatalf("classified %+v, want LEDGER_UNAVAILABLE, retryable", c)
		}
	})
}

// reconfigure reinstalls the current register_agent configuration with
// mutate applied.
func reconfigure(t *testing.T, mutate func(*RegisterAgentConfig)) func() {
	t.Helper()
	cfg, err := registerAgentConfigured()
	if err != nil {
		t.Fatalf("registerAgentConfigured: %v", err)
	}
	next := *cfg
	mutate(&next)
	restore, err := ConfigureRegisterAgent(next)
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	return restore
}
