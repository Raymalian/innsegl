// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The harness states each session's working directory in its own hook
// input (session_id, agent_id, cwd), captured from Claude Code 2.1.287 on
// 2026-10-01. SessionWorkspaces is where the session hook records it and the
// identity guard reads it, so the directory never has to be read out of the
// conversation's prose.

func TestSessionWorkspacesAnswersTheNewestDirectoryOfTheMainAgent(t *testing.T) {
	s := NewSessionWorkspaces(0)
	s.Record("sess-1", "", "/workspace/repo")
	s.Record("sess-1", "", "/workspace/repo/web")

	if got, ok := s.Lookup("sess-1", mainAgentID); !ok || got != "/workspace/repo/web" {
		t.Fatalf("Lookup = %q, %v; want the newest directory", got, ok)
	}
}

func TestSessionWorkspacesPrefersASubagentsOwnDirectory(t *testing.T) {
	s := NewSessionWorkspaces(0)
	s.Record("sess-1", "", "/workspace/repo")
	s.Record("sess-1", "agent-a", "/workspace/other")

	if got, _ := s.Lookup("sess-1", "agent-a"); got != "/workspace/other" {
		t.Errorf("subagent Lookup = %q, want its own directory", got)
	}
	if got, _ := s.Lookup("sess-1", mainAgentID); got != "/workspace/other" {
		t.Errorf("main Lookup = %q, want the session's newest directory", got)
	}
}

// A subagent starts in its parent's directory (measured: SubagentStart's cwd
// equals the parent's). A subagent the hook never named falls back to the
// session's newest directory rather than being refused.
func TestSessionWorkspacesFallsBackToTheSessionForAnUnnamedSubagent(t *testing.T) {
	s := NewSessionWorkspaces(0)
	s.Record("sess-1", "", "/workspace/repo")

	if got, ok := s.Lookup("sess-1", "agent-unseen"); !ok || got != "/workspace/repo" {
		t.Fatalf("Lookup = %q, %v; want the session's directory", got, ok)
	}
}

func TestSessionWorkspacesKnowsNothingOfAnUnseenSession(t *testing.T) {
	s := NewSessionWorkspaces(0)
	if got, ok := s.Lookup("sess-unseen", mainAgentID); ok || got != "" {
		t.Fatalf("Lookup = %q, %v; want nothing", got, ok)
	}
}

func TestSessionWorkspacesIgnoresAnEmptyRecord(t *testing.T) {
	s := NewSessionWorkspaces(0)
	s.Record("", "", "/workspace/repo")
	s.Record("sess-1", "", "")
	if _, ok := s.Lookup("sess-1", mainAgentID); ok {
		t.Fatal("an empty directory was recorded")
	}
}

// Session ids are harness-asserted and never authenticated, so the table is
// bounded like SessionEndSignals: at capacity the oldest session goes.
func TestSessionWorkspacesEvictsTheOldestSessionAtCapacity(t *testing.T) {
	s := NewSessionWorkspaces(2)
	s.Record("sess-1", "", "/a")
	s.Record("sess-2", "", "/b")
	s.Record("sess-1", "agent-a", "/a2") // the same session again: no new slot
	s.Record("sess-3", "", "/c")

	if _, ok := s.Lookup("sess-1", mainAgentID); ok {
		t.Error("sess-1 survived; the oldest session should have been evicted")
	}
	for _, id := range []string{"sess-2", "sess-3"} {
		if _, ok := s.Lookup(id, mainAgentID); !ok {
			t.Errorf("%s was evicted", id)
		}
	}
}

// A session with many subagents cannot grow without bound either.
func TestSessionWorkspacesBoundsTheAgentsOfOneSession(t *testing.T) {
	s := NewSessionWorkspaces(0)
	for i := range maxAgentsPerSession + 10 {
		s.Record("sess-1", "agent-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "/w")
	}
	if n := s.agentCount("sess-1"); n > maxAgentsPerSession {
		t.Fatalf("one session holds %d agents, want at most %d", n, maxAgentsPerSession)
	}
}
