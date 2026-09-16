// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// observe_tool_call named by SESSION rather than by run — RM-142 (#226), E11.
// Doc 07 MCP-061 … MCP-066.
//
// # What was measured, and what these cases hold
//
// Runs in the ledger by agent type: 101 `orchestrator`, 69 `general-purpose`,
// 3 `session`. A subagent got an identity every time; the operator's own
// session almost never did. `SessionStart` works — driven against a running
// deployment it minted a run at once — but it runs ONCE, at the moment the
// deployment is least likely to be up, and it is deliberately non-blocking, so
// nothing ever tried again.
//
// The larger loss is the one these cases are really about. `observe_tool_call`
// required a run id, so a shim whose start was refused had no run id and could
// not record tool calls either: the session lost its identity AND every call
// it made. So the tool takes a session id as an alternative, resolves it
// through observe_session's own start path, and the first tool call after the
// deployment appears establishes the identity.
//
// # The fixture is observe_session's, plus this tool
//
// Deliberately. The claim under test is that there is ONE definition of what
// starting a session means (E11), so these cases run against the real
// describe_workspace, register_agent, retire_agent and observe_session that
// osSetup installs, on a real ledger, a real idempotency store and real marker
// and body volumes. A stub for the session path would prove the opposite of
// what is wanted: that this file has a registration path of its own.

// osiEnv is observe_session's whole stack with observe_tool_call in front of
// it, sharing the ledger, the idempotency store and the run directory.
type osiEnv struct {
	*osEnv
	bodyDir string
}

// osiSetup installs both tools for the test's duration.
//
// The run-token secret is osSecret, the one register_agent is configured with,
// so the run-id path is the authenticated one it is in a real deployment and
// the session path is measured against that rather than against a deployment
// with the gate switched off.
func osiSetup(t *testing.T) *osiEnv {
	t.Helper()
	env := osSetup(t, nil)
	body := t.TempDir()
	restore, err := ConfigureObserveToolCall(ObserveToolCallConfig{
		Runs:           env.runs,
		Ledger:         env.ledger,
		Idempotency:    env.idem,
		BodyDir:        body,
		RunTokenSecret: osSecret,
	})
	if err != nil {
		t.Fatalf("ConfigureObserveToolCall: %v", err)
	}
	t.Cleanup(restore)
	return &osiEnv{osEnv: env, bodyDir: body}
}

// observe calls the tool the way the transport does.
func (e *osiEnv) observe(t *testing.T, in observeToolCallIn) (observeToolCallOut, error) {
	t.Helper()
	return observeToolCall(t.Context(), nil, in)
}

// mustObserve fails the test on any refusal.
func (e *osiEnv) mustObserve(t *testing.T, in observeToolCallIn) observeToolCallOut {
	t.Helper()
	out, err := e.observe(t, in)
	if err != nil {
		t.Fatalf("observe_tool_call refused where it had to succeed: %v", err)
	}
	return out
}

// bySession is the call a shim makes after this issue: its own session id, the
// directory the harness said the event happened in, and nothing else it had to
// keep.
func bySession(sessionID, cwd string) observeToolCallIn {
	return observeToolCallIn{SessionID: sessionID, CWD: cwd, Tool: otcTool, Body: otcBody}
}

// storedBodies lists the digests kept on the body volume, run directory by run
// directory. It is how "nothing was stored" is asked of the filesystem rather
// than of the tool's own reply.
func (e *osiEnv) storedBodies(t *testing.T) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(e.bodyDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the body volume: %v", err)
	}
	return found
}

// events is the whole chain's length. "Nothing was appended" is a claim about
// the ledger, so it is asked of the ledger.
func (e *osiEnv) events(t *testing.T) int {
	t.Helper()
	return len(e.chain(t))
}

// ---------------------------------------------------------------------------
// MCP-061 — the session that was never started.
// ---------------------------------------------------------------------------

// TestMCP061AToolCallNamingAnUnseenSessionRegistersItAndIsRecorded. Doc 07
// MCP-061, and the case the issue says matters most: a session whose start was
// refused because the deployment was down is registered by its NEXT tool call,
// and that call is recorded.
//
// No start happens here at all — the deployment simply never saw one, which is
// exactly what a refused SessionStart leaves behind.
func TestMCP061AToolCallNamingAnUnseenSessionRegistersItAndIsRecorded(t *testing.T) {
	env := osiSetup(t)

	out := env.mustObserve(t, bySession(osSessionID, env.tree.repo))
	if !out.Stored {
		t.Error("the reply says the body was not stored; a call that could not store refuses")
	}
	if out.Digest == "" {
		t.Error("the reply carries no digest")
	}

	// The session now HAS a run, and a start finds the same one rather than
	// making a second: Registered is false because this call already did it.
	replay := env.mustStart(t, osSessionID)
	if replay.RunID == "" {
		t.Fatal("the session has no run after a tool call named it")
	}
	if replay.Registered {
		t.Error("the start registered the run, so the tool call did not: the identity " +
			"was not recovered, it was merely deferred to the next start")
	}
	if n := env.countEvents(t, replay.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered for %s, want exactly 1", n, replay.RunID)
	}
	if n := env.countEvents(t, replay.RunID, event.EventTypeToolCall); n != 1 {
		t.Errorf("the chain holds %d tool_call for %s, want exactly 1 — the call that "+
			"created the identity must itself be recorded", n, replay.RunID)
	}
	if bodies := env.storedBodies(t); len(bodies) != 1 {
		t.Errorf("the body volume holds %v, want exactly one body", bodies)
	}
}

// TestMCP061TheRecoveredRunIsTheSessionsOwnIdentity. The run a tool call
// creates must be the run a start would have created: same agent type, same
// task, same workspace. A recovery that registered something else would leave
// the session with an identity nothing else agrees about.
func TestMCP061TheRecoveredRunIsTheSessionsOwnIdentity(t *testing.T) {
	env := osiSetup(t)

	env.mustObserve(t, bySession(osSessionID, env.tree.repo))
	recovered := env.mustStart(t, osSessionID)

	// A second session started the ordinary way, in the same tree. Its run is
	// a different run, and everything ABOUT the identity is the same.
	ordinary := env.mustStart(t, osForeignSessionID)

	if recovered.RunID == ordinary.RunID {
		t.Fatal("two sessions share one run")
	}
	if recovered.AgentType != ordinary.AgentType {
		t.Errorf("agent_type is %q for a recovered session and %q for one that started "+
			"normally", recovered.AgentType, ordinary.AgentType)
	}
	if recovered.Task != ordinary.Task {
		t.Errorf("task is %q recovered and %q normally", recovered.Task, ordinary.Task)
	}
	if recovered.Repo != ordinary.Repo || recovered.Branch != ordinary.Branch {
		t.Errorf("workspace is %s@%s recovered and %s@%s normally",
			recovered.Repo, recovered.Branch, ordinary.Repo, ordinary.Branch)
	}
}

// TestMCP061ARecoveredSessionTakesTheCallersAgentType. The measurement in the
// issue is a count BY AGENT TYPE, so a recovery that labelled every session
// `session` would answer the wrong question for a harness whose sessions are
// not.
func TestMCP061ARecoveredSessionTakesTheCallersAgentType(t *testing.T) {
	env := osiSetup(t)

	in := bySession(osSessionID, env.tree.repo)
	in.AgentType = "orchestrator"
	env.mustObserve(t, in)

	if got := env.mustStart(t, osSessionID).AgentType; got != "orchestrator" {
		t.Errorf("the recovered run is a %q; the caller said orchestrator", got)
	}
}

// ---------------------------------------------------------------------------
// MCP-062 — the session that already has a run.
// ---------------------------------------------------------------------------

// TestMCP062AToolCallNamingAKnownSessionUsesItsRunAndRegistersNothing. Doc 07
// MCP-062. The ordinary case, and the one that runs thousands of times a day:
// the start worked, and every tool call after it names the session rather than
// a run id the shim had to write down.
//
// No cwd, deliberately. A session this deployment already holds needs no
// workspace derived, so a shim that has one need not carry it on every event.
func TestMCP062AToolCallNamingAKnownSessionUsesItsRunAndRegistersNothing(t *testing.T) {
	env := osiSetup(t)
	started := env.mustStart(t, osSessionID)

	env.mustObserve(t, observeToolCallIn{SessionID: osSessionID, Tool: otcTool, Body: otcBody})

	if n := env.countEvents(t, started.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered for %s; the tool call registered a "+
			"second identity for a session that already had one", n, started.RunID)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeToolCall); n != 1 {
		t.Errorf("the chain holds %d tool_call for %s, want exactly 1", n, started.RunID)
	}
}

// TestMCP062TheSessionPathNeedsNoRunToken. The run token exists because a run
// id is PUBLIC: it is in the Agent-Run trailer of every commit, on the
// dashboard and in the query API, so knowing one proves nothing (runtoken.go).
// A caller on this path names no run id, so there is no public value for a
// token to make insufficient — and requiring one would refuse exactly the
// caller this path exists for, whose start never returned a token at all.
func TestMCP062TheSessionPathNeedsNoRunToken(t *testing.T) {
	env := osiSetup(t)
	started := env.mustStart(t, osSessionID)

	// The run-id path with no token is still refused, in the same deployment,
	// in the same test: the gate is untouched, not switched off.
	if _, err := env.observe(t, observeToolCallIn{
		RunID: started.RunID, Tool: otcTool, Body: otcBody,
	}); err == nil {
		t.Fatal("the run-id path accepted a call with no run token")
	} else if got := osError(t, err).Class; got != ClassRunNotFound {
		t.Errorf("an untokened run-id call is %s, want %s", got, ClassRunNotFound)
	}

	env.mustObserve(t, observeToolCallIn{SessionID: osSessionID, Tool: otcTool, Body: otcBody})
}

// ---------------------------------------------------------------------------
// MCP-063 — both named.
// ---------------------------------------------------------------------------

// TestMCP063NamingBothARunAndItsSessionIsAccepted. Doc 07 MCP-063, first half.
// A caller that holds both is not guessing about anything, so there is nothing
// to refuse.
func TestMCP063NamingBothARunAndItsSessionIsAccepted(t *testing.T) {
	env := osiSetup(t)
	started := env.mustStart(t, osSessionID)

	env.mustObserve(t, observeToolCallIn{
		RunID: started.RunID, SessionID: osSessionID,
		RunToken: started.RunToken, Tool: otcTool, Body: otcBody,
	})

	if n := env.countEvents(t, started.RunID, event.EventTypeToolCall); n != 1 {
		t.Errorf("the chain holds %d tool_call for %s, want exactly 1", n, started.RunID)
	}
}

// TestMCP063NamingARunAndADifferentSessionIsRefused. Doc 07 MCP-063, second
// half, and the reason the rule is a refusal rather than a precedence order:
// the answer is going into an APPEND-ONLY record. A tool implementing "run_id
// wins" would attribute one observed call to whichever of two identities the
// caller happened to list first, permanently.
func TestMCP063NamingARunAndADifferentSessionIsRefused(t *testing.T) {
	env := osiSetup(t)
	mine := env.mustStart(t, osSessionID)
	other := env.mustStart(t, osForeignSessionID)

	_, err := env.observe(t, observeToolCallIn{
		RunID: other.RunID, SessionID: osSessionID,
		RunToken: other.RunToken, Tool: otcTool, Body: otcBody,
	})
	if got := osError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("a disagreement is %s, want %s", got, ClassInvariantViolation)
	}

	for _, runID := range []string{mine.RunID, other.RunID} {
		if n := env.countEvents(t, runID, event.EventTypeToolCall); n != 0 {
			t.Errorf("the chain holds %d tool_call for %s after a refusal", n, runID)
		}
	}
	if bodies := env.storedBodies(t); len(bodies) != 0 {
		t.Errorf("the body volume holds %v after a refusal", bodies)
	}
}

// ---------------------------------------------------------------------------
// MCP-064 — neither named.
// ---------------------------------------------------------------------------

// TestMCP064NamingNeitherARunNorASessionIsRefused. Doc 07 MCP-064.
//
// INVARIANT_VIOLATION and not RUN_NOT_FOUND, which is a change from before
// this issue: an empty run_id used to mean "that run does not exist". It now
// means the request named no identity at all, which is a different thing to
// say and the one observe_session says for a missing session_id. The no-oracle
// rule is untouched — a caller learns nothing here it did not itself send.
func TestMCP064NamingNeitherARunNorASessionIsRefused(t *testing.T) {
	env := osiSetup(t)

	_, err := env.observe(t, observeToolCallIn{Tool: otcTool, Body: otcBody})
	if got := osError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("a call naming no identity is %s, want %s", got, ClassInvariantViolation)
	}
	if bodies := env.storedBodies(t); len(bodies) != 0 {
		t.Errorf("the body volume holds %v after a refusal", bodies)
	}
}

// TestMCP064ASessionIDIsHeldToObserveSessionsOwnGrammar. One definition of
// what a session id may be (E11): a malformed one is refused here exactly as
// observe_session refuses it, and reaches no dependency.
func TestMCP064ASessionIDIsHeldToObserveSessionsOwnGrammar(t *testing.T) {
	env := osiSetup(t)

	for name, sessionID := range map[string]string{
		"a path":       "../../etc/passwd",
		"a separator":  "sess/ion",
		"a space":      "sess ion",
		"far too long": strings.Repeat("s", MaxObserveSessionIDBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := env.observe(t, bySession(sessionID, env.tree.repo))
			if got := osError(t, err).Class; got != ClassInvariantViolation {
				t.Errorf("session_id %q is %s, want %s", sessionID, got, ClassInvariantViolation)
			}
		})
	}
	if n := env.events(t); n != 0 {
		t.Errorf("the chain holds %d events after four malformed session ids", n)
	}
}

// ---------------------------------------------------------------------------
// MCP-065 — a first-sight registration with no workspace.
// ---------------------------------------------------------------------------

// TestMCP065AnUnseenSessionWithNoCWDIsRefusedAndRegistersNothing. Doc 07
// MCP-065.
//
// observe_session's start resolves the workspace through describe_workspace,
// which refuses an empty cwd because "this server's own directory is not a
// defensible default for it". A tool call that CREATES a session is a start,
// so it meets the same refusal, in the same words. The alternative would be to
// register the run against a guessed repository and branch — permanently, in
// an append-only record.
func TestMCP065AnUnseenSessionWithNoCWDIsRefusedAndRegistersNothing(t *testing.T) {
	env := osiSetup(t)

	_, err := env.observe(t, observeToolCallIn{
		SessionID: osSessionID, Tool: otcTool, Body: otcBody,
	})
	refusal := osError(t, err)
	if refusal.Class != ClassInvariantViolation {
		t.Errorf("an unseen session with no cwd is %s, want %s",
			refusal.Class, ClassInvariantViolation)
	}
	if !strings.Contains(refusal.Message, "cwd") {
		t.Errorf("the refusal does not name cwd, so a shim author cannot act on it: %q",
			refusal.Message)
	}

	if n := env.events(t); n != 0 {
		t.Errorf("the chain holds %d events after a refused first-sight registration", n)
	}
	if bodies := env.storedBodies(t); len(bodies) != 0 {
		t.Errorf("the body volume holds %v after a refusal", bodies)
	}
	if _, err := os.Stat(osMarkerPath(env.markerDir, osSessionID)); err == nil {
		t.Error("a marker was written for a session that was not registered")
	}
}

// ---------------------------------------------------------------------------
// MCP-066 — a session that has already been stopped.
// ---------------------------------------------------------------------------

// TestMCP066AToolCallNamingARetiredSessionDoesNotResurrectIt. Doc 07 MCP-066.
//
// #207 kept the marker AFTER the retirement precisely so a start on a stopped
// session reports the terminal state rather than deriving the same dead run id
// and handing back an identity that can no longer sign. A tool call naming a
// retired session is the same call in a different spelling, so it gets the
// same answer: refused, with I4's class, and nothing appended.
func TestMCP066AToolCallNamingARetiredSessionDoesNotResurrectIt(t *testing.T) {
	env := osiSetup(t)
	started := env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	_, err := env.observe(t, bySession(osSessionID, env.tree.repo))
	refusal := osError(t, err)
	if refusal.Class != ClassRunAlreadyRetired {
		t.Errorf("a tool call on a retired session is %s, want %s",
			refusal.Class, ClassRunAlreadyRetired)
	}

	if n := env.countEvents(t, started.RunID, event.EventTypeToolCall); n != 0 {
		t.Errorf("the chain holds %d tool_call for the retired run %s", n, started.RunID)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the chain holds %d run_registered for %s; the session was resurrected",
			n, started.RunID)
	}
	if bodies := env.storedBodies(t); len(bodies) != 0 {
		t.Errorf("the body volume holds %v after a refusal", bodies)
	}
}
