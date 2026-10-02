// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// RM-314: harness agent-type names never refuse a subagent. The type is
// folded into doc 02 §5's grammar before register_agent; the harness's own
// string is kept in the mapping row, outside the chain.

// registerChild drives one subagent's first request through the fixture's
// guard. spawnType is the model's subagent_type (empty: no spawn type);
// hookType is the SubagentStart hook's agent_type (empty: none stated).
func registerChild(t *testing.T, spawnType, hookType string) (*identityFixture, Identification) {
	t.Helper()
	f := newIdentityFixture(t)
	if err := f.tree.RecordSpawn(t.Context(), PendingSpawn{
		ParentRunID: "run-parent", SessionID: "s1", Prompt: "plan the subtask", AgentType: spawnType,
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	child := Identification{SessionID: "s1", AgentID: "a0123456789abcdef"}
	if hookType != "" {
		f.sessionWorkspaces.RecordStated("s1", child.AgentID, StatedWorkspace{Cwd: fixtureDirectory, AgentType: hookType})
	}
	r2, refusal := f.guard.Check(identityRequest(t, child, "plan the subtask", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	_ = mustRunID(t, r2)
	return f, child
}

func mappingOf(t *testing.T, f *identityFixture, id Identification) RunMapping {
	t.Helper()
	m, found, err := f.mappings.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent: found=%v err=%v", found, err)
	}
	return m
}

// SER-021: a request from a `Plan` subagent registers a run with agent type
// plan, and the mapping row keeps "Plan".
func TestSER021APlanSubagentRegistersAsPlanAndTheMappingKeepsPlan(t *testing.T) {
	f, child := registerChild(t, "Plan", "")
	if got := f.registrar.lastSeen.AgentType; got != "plan" {
		t.Errorf("registered AgentType = %q, want plan", got)
	}
	if got := mappingOf(t, f, child).AgentTypeVerbatim; got != "Plan" {
		t.Errorf("mapping AgentTypeVerbatim = %q, want Plan", got)
	}
}

func TestSER021HarnessNamesFoldBeforeRegistration(t *testing.T) {
	for in, want := range map[string]string{
		"Explore":                       "explore",
		"general-purpose":               "general-purpose",
		"flutter-all:flutter-architect": "flutter-all-flutter-architect",
		"日本語":                           "unnamed",
		strings.Repeat("Long", 20):      strings.Repeat("long", 15) + "lon",
	} {
		f, child := registerChild(t, in, "")
		if got := f.registrar.lastSeen.AgentType; got != want {
			t.Errorf("%q registered as %q, want %q", in, got, want)
		}
		if got := mappingOf(t, f, child).AgentTypeVerbatim; got != in {
			t.Errorf("%q: mapping AgentTypeVerbatim = %q, want the harness string", in, got)
		}
	}
}

// The hook's agent_type is harness-asserted and wins; the model's
// subagent_type is a witness. A disagreement after folding is a finding.
func TestSER021TheHookAgentTypeWinsAndADisagreementIsAFinding(t *testing.T) {
	f, child := registerChild(t, "Plan", "Explore")
	if got := f.registrar.lastSeen.AgentType; got != "explore" {
		t.Errorf("registered AgentType = %q, want explore (the hook's)", got)
	}
	if got := mappingOf(t, f, child).AgentTypeVerbatim; got != "Explore" {
		t.Errorf("mapping AgentTypeVerbatim = %q, want Explore", got)
	}
	if len(f.witnessed) != 1 {
		t.Fatalf("findings = %+v, want one disagreement", f.witnessed)
	}
	want := AgentTypeFinding{SessionID: "s1", AgentID: child.AgentID, Hook: "Explore", Model: "Plan"}
	if f.witnessed[0] != want {
		t.Errorf("finding = %+v, want %+v", f.witnessed[0], want)
	}
}

func TestSER021AgreementAfterFoldingIsNoFinding(t *testing.T) {
	f, _ := registerChild(t, "plan", "Plan")
	if got := f.registrar.lastSeen.AgentType; got != "plan" {
		t.Errorf("registered AgentType = %q, want plan", got)
	}
	if len(f.witnessed) != 0 {
		t.Errorf("findings = %+v, want none: the two agree after folding", f.witnessed)
	}
}

func TestSER021TheHookAgentTypeAloneIsEnough(t *testing.T) {
	f, child := registerChild(t, "", "Explore")
	if got := f.registrar.lastSeen.AgentType; got != "explore" {
		t.Errorf("registered AgentType = %q, want explore", got)
	}
	if got := mappingOf(t, f, child).AgentTypeVerbatim; got != "Explore" {
		t.Errorf("mapping AgentTypeVerbatim = %q, want Explore", got)
	}
	if len(f.witnessed) != 0 {
		t.Errorf("findings = %+v, want none: there is no witness to disagree", f.witnessed)
	}
}

// Neither source: the stated default, and nothing verbatim to keep.
func TestSER021NoAgentTypeAtAllKeepsTheDefaultAndNoVerbatim(t *testing.T) {
	f, child := registerChild(t, "", "")
	if got := f.registrar.lastSeen.AgentType; got != defaultSubagentType {
		t.Errorf("registered AgentType = %q, want %q", got, defaultSubagentType)
	}
	if got := mappingOf(t, f, child).AgentTypeVerbatim; got != "" {
		t.Errorf("mapping AgentTypeVerbatim = %q, want empty", got)
	}
}

// The root's type stays the fixed "main", whatever the hook states.
func TestSER021TheRootStaysMain(t *testing.T) {
	f := newIdentityFixture(t)
	f.sessionWorkspaces.RecordStated("s1", "", StatedWorkspace{Cwd: fixtureDirectory, AgentType: "Plan"})
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if got := f.registrar.lastSeen.AgentType; got != mainAgentID {
		t.Errorf("root AgentType = %q, want %q", got, mainAgentID)
	}
}

// A subagent with no statement of its own falls back to the session's
// newest directory, never to another agent's type.
func TestSER021AnotherAgentsStatedTypeIsNeverBorrowed(t *testing.T) {
	ws := NewSessionWorkspaces(0)
	ws.RecordStated("s1", "agent-a", StatedWorkspace{Cwd: "/w", AgentType: "Explore"})
	st, ok := ws.LookupStated("s1", "agent-b")
	if !ok || st.Cwd != "/w" {
		t.Fatalf("LookupStated(agent-b) = %+v, %v; want the session's newest directory", st, ok)
	}
	if st.AgentType != "" {
		t.Errorf("agent-b borrowed agent-a's type %q", st.AgentType)
	}
	if own, _ := ws.LookupStated("s1", "agent-a"); own.AgentType != "Explore" {
		t.Errorf("agent-a's own type = %q, want Explore", own.AgentType)
	}
}

// The verbatim string is unauthenticated harness input bound for a database
// column: bounded, valid UTF-8, and never a NUL.
func TestSER021TheVerbatimAgentTypeIsBounded(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("é", 300),
		"bad\x00name",
		"\xff\xfeinvalid",
	} {
		got := verbatimAgentType(in)
		if len(got) > maxAgentTypeVerbatimBytes || !utf8.ValidString(got) || strings.ContainsRune(got, 0) {
			t.Errorf("verbatimAgentType(%q) = %q: not bounded, valid and NUL-free", in, got)
		}
		if got == "" {
			t.Errorf("verbatimAgentType(%q) is empty; something of the name should survive", in)
		}
	}
	if got := verbatimAgentType("Plan"); got != "Plan" {
		t.Errorf("verbatimAgentType(Plan) = %q", got)
	}
}
