// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/gateway"
)

// RM-314 (SER-021): the SubagentStart hook's agent_type travels with the
// statement -- to the endpoint, through the client service's cache, and in
// the header -- so the core records the harness's own name for the type.

// The hook input Claude Code sends on SubagentStart carries agent_type.
func TestSER021HookStatementCarriesAgentType(t *testing.T) {
	posts, post := capturePosts(nil)
	in := `{"session_id":"` + testSessionID + `","cwd":"/workspace/repo","hook_event_name":"SubagentStart",` +
		`"agent_id":"aa328d4891c7406b1","agent_type":"Plan"}`

	runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if len(*posts) != 1 || (*posts)[0].body["agent_type"] != "Plan" {
		t.Fatalf("posts = %+v, want one stating agent_type Plan", *posts)
	}
}

// An event with no agent_type states none.
func TestSER021HookStatementWithoutAgentTypeStatesNone(t *testing.T) {
	posts, post := capturePosts(nil)
	in := `{"session_id":"` + testSessionID + `","cwd":"/workspace/repo","hook_event_name":"UserPromptSubmit"}`

	runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if len(*posts) != 1 {
		t.Fatalf("posts = %+v, want one", *posts)
	}
	if v, ok := (*posts)[0].body["agent_type"]; ok {
		t.Errorf("agent_type = %q stated for an event that carried none", v)
	}
}

// The endpoint records the stated type with the agent's statement. Any
// harness string is accepted: the gateway folds it, never refuses it.
func TestSER021EndpointRecordsTheStatedAgentType(t *testing.T) {
	for _, at := range []string{"Plan", "flutter-all:flutter-architect", "日本語"} {
		h, ws := sessionWorkspaceTestHandler(t)
		rec := httptest.NewRecorder()
		body := `{"session_id":"` + testSessionID + `","agent_id":"` + shSubagent + `","cwd":"/client/repo","agent_type":"` + at + `"}`
		h(rec, sessionWorkspaceRequest(t, http.MethodPost, "127.0.0.1:40000", body))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%q: status = %d, want 204. body: %s", at, rec.Code, rec.Body.String())
		}
		got, ok := ws.LookupStated(testSessionID, shSubagent)
		if !ok || got.AgentType != at {
			t.Errorf("%q: LookupStated = %+v, %v; want the stated agent type", at, got, ok)
		}
	}
}

// The header carries the subagent's own statement, agent_type included.
func TestSER021HeaderStatementCarriesAgentType(t *testing.T) {
	r, id := shRequest(shHeader(`{"session_id":"`+testSessionID+`","agent_id":"`+shSubagent+
		`","cwd":"/w/sub","agent_type":"Explore"}`), shSubagent)
	agent, st, ok := (headerStatements{callers: localCallers{}}).Decode(r, id)
	if !ok || agent != shSubagent || st.AgentType != "Explore" {
		t.Fatalf("Decode = %q %+v %v; want the subagent's statement with agent_type Explore", agent, st, ok)
	}
}

// The finding sink logs a disagreement as one warning naming both strings.
func TestSER021AgentTypeDisagreementIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logAgentTypeWitness(newServeLog(&buf))(gateway.AgentTypeFinding{
		SessionID: testSessionID, AgentID: shSubagent, Hook: "Explore", Model: "Plan",
	})
	out := buf.String()
	for _, want := range []string{"finding", "Explore", "Plan", shSubagent} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not name %q", out, want)
		}
	}
}
