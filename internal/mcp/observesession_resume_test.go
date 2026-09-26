// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// RM-191 (#311): a session resumed on a retired marker is recorded, not
// dropped.
//
// Before this, a start on a marker whose run this tool had retired answered
// with the terminal state and registered nothing. The resumed session then had
// no run, and everything it did reached the ledger under none. A start there
// now registers a NEW run for the resumed session and names the retired run as
// its parent, through the parent_run_id register_agent already records. No new
// event, no new member.
//
// The fixture is osSetup: the shipped describe_workspace, register_agent and
// retire_agent over a real ledger, so "registered once" is a claim about the
// chain and not about a stand-in.

// rm191RegisteredCount counts every run_registered on the chain.
func rm191RegisteredCount(t *testing.T, e *osEnv) int {
	t.Helper()
	n := 0
	for _, rec := range e.chain(t) {
		if rec[event.FieldEventType] == event.EventTypeRunRegistered {
			n++
		}
	}
	return n
}

// osUnblockTheMarkerWrite undoes osBlockTheMarkerWrite.
func osUnblockTheMarkerWrite(t *testing.T, env *osEnv, sessionID string) {
	t.Helper()
	if err := os.Remove(filepath.Join(env.markerDir, observeSessionPartialName(sessionID))); err != nil {
		t.Fatalf("unblocking the marker write: %v", err)
	}
}

// The resume itself: a new run, parented on the one the session had.
func TestRM191AStartOnARetiredMarkerRegistersANewRunParentedOnTheRetiredOne(t *testing.T) {
	env := osSetup(t, nil)
	first := env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	resumed, err := env.start(t, osSessionID)
	if err != nil {
		t.Fatalf("a start on a retired marker was refused: %v", err)
	}
	if resumed.Retired || resumed.RetiredAt != "" {
		t.Fatalf("a resumed session was answered with the terminal state %+v; its later "+
			"work would reach the ledger under no run", resumed)
	}
	if !resumed.Registered {
		t.Error("a resume reports registered=false; a new run was due")
	}
	if resumed.RunID == "" || resumed.RunID == first.RunID {
		t.Fatalf("the resumed session names run %q; it must be a new run, not %q",
			resumed.RunID, first.RunID)
	}
	if resumed.SPIFFEID == "" || resumed.RunToken == "" {
		t.Errorf("a resume returned no credential handle: %+v", resumed)
	}

	body := registeredBody(t, env, resumed.RunID)
	if got := body[event.FieldParentRunID]; got != first.RunID {
		t.Errorf("the resumed run records %s = %v, want the retired run %s",
			event.FieldParentRunID, got, first.RunID)
	}
	if n := env.countEvents(t, first.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the retired run has %d run_registered, want 1", n)
	}

	// The marker now names the new run, so a stop finds it.
	stopped := env.mustStop(t, osSessionID)
	if stopped.RunID != resumed.RunID || !stopped.Retired {
		t.Errorf("a stop after a resume answered %+v; it must retire the resumed run %s",
			stopped, resumed.RunID)
	}
	if n := env.countEvents(t, resumed.RunID, event.EventTypeRunRetired); n != 1 {
		t.Errorf("the resumed run has %d run_retired after its stop, want 1", n)
	}
}

// A replayed resume start registers nothing a second time.
func TestRM191AReplayedResumeDoesNotRegisterTwice(t *testing.T) {
	env := osSetup(t, nil)
	first := env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	resumed := env.mustStart(t, osSessionID)
	before := rm191RegisteredCount(t, env)

	again := env.mustStart(t, osSessionID)
	if again.RunID != resumed.RunID {
		t.Errorf("a replayed resume named run %q, the resume named %q", again.RunID, resumed.RunID)
	}
	if again.Registered {
		t.Error("a replayed resume reports registered=true")
	}
	if again.Retired {
		t.Errorf("a replayed resume answered retired: %+v", again)
	}
	if after := rm191RegisteredCount(t, env); after != before {
		t.Errorf("a replayed resume grew run_registered from %d to %d", before, after)
	}
	if again.RunID == first.RunID {
		t.Error("a replayed resume fell back to the retired run")
	}
}

// The key is a function of the retired run and the session, and nothing else.
// A resume whose marker could not be written the first time must replay the
// same registration from the still-retired marker.
func TestRM191TheResumeKeyIsDerivedFromTheRetiredRunAndTheSession(t *testing.T) {
	a := observeSessionResumeKey("run-a", osSessionID)
	if a != observeSessionResumeKey("run-a", osSessionID) {
		t.Error("the resume key is not deterministic")
	}
	if a == observeSessionResumeKey("run-b", osSessionID) {
		t.Error("two retired runs give one resume key")
	}
	if a == observeSessionResumeKey("run-a", osForeignSessionID) {
		t.Error("two sessions give one resume key")
	}
	if a == observeSessionKey(osSessionID) {
		t.Error("the resume key equals the session's first key; it would replay the retired run")
	}
}

func TestRM191AResumeWhoseMappingWasNotWrittenReplaysOnRetry(t *testing.T) {
	env := osSetup(t, nil)
	env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	osBlockTheMarkerWrite(t, env, osSessionID)
	if _, err := env.start(t, osSessionID); err == nil {
		t.Fatal("a resume that could not write its mapping succeeded")
	}
	before := rm191RegisteredCount(t, env)
	osUnblockTheMarkerWrite(t, env, osSessionID)

	resumed := env.mustStart(t, osSessionID)
	if after := rm191RegisteredCount(t, env); after != before {
		t.Errorf("the retry registered again: run_registered went from %d to %d", before, after)
	}
	if resumed.Retired || resumed.RunID == "" {
		t.Errorf("the retry answered %+v", resumed)
	}
}

// Control: a start on an ACTIVE marker is the duplicate start it always was.
func TestRM191AStartOnAnActiveMarkerIsUnchanged(t *testing.T) {
	env := osSetup(t, nil)
	first := env.mustStart(t, osSessionID)
	before := rm191RegisteredCount(t, env)

	again := env.mustStart(t, osSessionID)
	if again.RunID != first.RunID || again.Registered || again.Retired {
		t.Errorf("a start on an active marker answered %+v; want the same run %s, "+
			"registered=false", again, first.RunID)
	}
	if after := rm191RegisteredCount(t, env); after != before {
		t.Errorf("a start on an active marker grew run_registered from %d to %d", before, after)
	}
	if _, ok := registeredBody(t, env, first.RunID)[event.FieldParentRunID]; ok {
		t.Error("a run started with no parent records one")
	}
}

// Control: a first-ever start registers under the session key, with no parent.
func TestRM191AFirstStartIsUnchanged(t *testing.T) {
	env := osSetup(t, nil)
	first := env.mustStart(t, osSessionID)
	if !first.Registered || first.Retired || first.RunID == "" {
		t.Fatalf("a first start answered %+v", first)
	}
	body := registeredBody(t, env, first.RunID)
	if got := body[event.FieldIdempotencyKey]; got != observeSessionKey(osSessionID) {
		t.Errorf("a first start registered under key %v, want %q", got, observeSessionKey(osSessionID))
	}
	if _, ok := body[event.FieldParentRunID]; ok {
		t.Error("a first start with no parent records one")
	}
}

// The exemption is the resume path's alone. register_agent called directly —
// even with the very key and parent a resume would use — is still refused a
// retired parent (MCP-082), and nothing is appended.
func TestRM191RegisterAgentCalledDirectlyStillRefusesARetiredParent(t *testing.T) {
	env := osSetup(t, nil)
	retired := env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	before := len(env.chain(t))
	out, err := registerAgent(t.Context(), nil, registerAgentIn{
		AgentType:      observeSessionDefaultAgentType,
		TaskID:         osTask,
		IdempotencyKey: observeSessionResumeKey(retired.RunID, osSessionID),
		Repo:           osRepo,
		Branch:         osBranch,
		ParentRunID:    retired.RunID,
	})
	if err == nil {
		t.Fatalf("register_agent accepted a retired parent directly and returned %+v", out)
	}
	if got := osError(t, err).Class; got != ClassRunAlreadyRetired {
		t.Errorf("error_class = %s, want %s", got, ClassRunAlreadyRetired)
	}
	if after := len(env.chain(t)); after != before {
		t.Errorf("the chain grew from %d to %d on a refused registration", before, after)
	}
}

// And no caller of the tool can switch the exemption on: it is not a member
// of the arguments the transport decodes.
func TestRM191TheResumeExemptionCannotBeSentByACaller(t *testing.T) {
	var in registerAgentIn
	raw := []byte(`{"agent_type":"a","task_id":"t","idempotency_key":"k",` +
		`"parent_run_id":"run-x","resumesRetiredParent":true,"resumes_retired_parent":true}`)
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if in.resumesRetiredParent {
		t.Error("a caller's JSON set the resume exemption")
	}
}

// A resume carrying a different parent records the retired run, and says the
// caller's parent was not recorded: one member holds one parent.
func TestRM191AResumeNamingAnotherParentRecordsTheRetiredRunAndSaysSo(t *testing.T) {
	env := osSetup(t, nil)
	other := env.mustStart(t, "other-session")
	first := env.mustStart(t, osSessionID)
	env.mustStop(t, osSessionID)

	resumed, err := osStartWithParent(t, env, osSessionID, other.RunID)
	if err != nil {
		t.Fatalf("a resume carrying a parent was refused: %v", err)
	}
	if got := registeredBody(t, env, resumed.RunID)[event.FieldParentRunID]; got != first.RunID {
		t.Errorf("the resumed run records %s = %v, want the retired run %s",
			event.FieldParentRunID, got, first.RunID)
	}
	if !strings.Contains(resumed.Detail, other.RunID) {
		t.Errorf("the reply does not name the parent it dropped: %q", resumed.Detail)
	}
}
