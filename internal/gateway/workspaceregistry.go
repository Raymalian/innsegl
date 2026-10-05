// SPDX-License-Identifier: Apache-2.0

package gateway

import "sync"

// SessionWorkspaces is where each session's working directory is known from:
// the harness's own hook input, which carries session_id, agent_id and cwd as
// structured fields on every event (captured from Claude Code 2.1.287,
// 2026-10-01). `innsegl hook session` posts them to the gateway's local
// session-workspace endpoint, and the identity guard reads them here.
//
// # Why not the conversation
//
// The directory used to be read out of the prompt's prose. That broke the
// moment the harness moved the statement: a session resumed after a summary
// states it only in later "Environment update" messages, and every request
// was refused. Hook input is the harness's structured channel for the same
// fact, so nothing here parses text.
//
// # What a forged record buys
//
// Nothing an agent could not already do. A record is harness-asserted and
// unauthenticated, the same class as the agent-id header (ADR-0058 decision
// 2). A record naming only a directory registers no run, because the core
// reads no client tree (ADR-0071); one naming a repository is bound to the
// installation's scope in hosted mode (ADR-0064).
//
// # Memory only
//
// The hooks re-state the directory before every user turn and every subagent,
// and a run that already has a mapping (Continue, Restore) needs no directory
// at all. In hosted mode the client service also attaches its cached
// statement to every request (StatementHeader, RM-313), which refills an
// empty table, so a restart costs nothing. Keeping it
// in memory also keeps host paths out of the database.
type SessionWorkspaces struct {
	mu       sync.Mutex
	max      int
	order    []string // session ids, oldest first
	sessions map[string]*sessionWorkspace
}

// StatedWorkspace is what a client states about where a session works: its
// working directory and, when the client could derive it, the repository,
// worktree, branch, task and head (internal/workspace). The repository fields
// are all empty for a client that stated only a directory.
type StatedWorkspace struct {
	Cwd                                string
	Repo, Worktree, Branch, Task, Head string
	// AgentType is the harness's own name for the agent's type, from the
	// SubagentStart hook's agent_type (RM-314), verbatim: "Plan",
	// "flutter-all:flutter-architect". Empty for a harness that sends none.
	// It belongs to the agent that stated it, so a lookup that falls back to
	// the session's newest statement drops it.
	AgentType string
}

// HasRepo reports whether the client derived the workspace itself, so the
// gateway needs no filesystem to know it.
func (s StatedWorkspace) HasRepo() bool { return s.Repo != "" }

// Workspace is the part the run is registered from.
func (s StatedWorkspace) Workspace() Workspace {
	return Workspace{Repo: s.Repo, Branch: s.Branch, Task: s.Task}
}

// sessionWorkspace is one session's newest statement, and each agent's own.
type sessionWorkspace struct {
	latest StatedWorkspace
	agents map[string]StatedWorkspace
	// lastRepo is the newest statement that named a repository (LastRepo).
	lastRepo StatedWorkspace
}

// DefaultMaxSessionWorkspaces bounds the table, the same reasoning
// DefaultMaxSessionEndSignals gives: an unauthenticated key must not be a way
// to exhaust memory.
const DefaultMaxSessionWorkspaces = 4096

// maxAgentsPerSession bounds one session's agent table for the same reason.
const maxAgentsPerSession = 256

// NewSessionWorkspaces builds an empty table. maxSessions bounds it; zero or
// less means DefaultMaxSessionWorkspaces.
func NewSessionWorkspaces(maxSessions int) *SessionWorkspaces {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessionWorkspaces
	}
	return &SessionWorkspaces{max: maxSessions, sessions: make(map[string]*sessionWorkspace)}
}

// Record notes that agentID of sessionID is in dir. An empty agentID, or
// mainAgentID, is the session's main agent. Either way dir becomes the
// session's newest directory. An empty session id or directory is ignored.
func (s *SessionWorkspaces) Record(sessionID, agentID, dir string) {
	s.RecordStated(sessionID, agentID, StatedWorkspace{Cwd: dir})
}

// RecordStated is Record for a statement that may carry the derived
// workspace. A statement replaces the agent's previous one whole: a newer
// directory-only statement does not keep an older repository.
func (s *SessionWorkspaces) RecordStated(sessionID, agentID string, st StatedWorkspace) {
	if sessionID == "" || st.Cwd == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.sessions[sessionID]
	if !ok {
		if len(s.order) >= s.max && len(s.order) > 0 {
			delete(s.sessions, s.order[0])
			s.order = s.order[1:]
		}
		w = &sessionWorkspace{agents: make(map[string]StatedWorkspace)}
		s.sessions[sessionID] = w
		s.order = append(s.order, sessionID)
	}
	w.latest = st
	if st.HasRepo() {
		w.lastRepo = st
	}
	if agentID == "" || agentID == mainAgentID {
		return
	}
	if _, known := w.agents[agentID]; !known && len(w.agents) >= maxAgentsPerSession {
		// Full: the subagent falls back to the session's newest directory,
		// which is where it started anyway.
		return
	}
	w.agents[agentID] = st
}

// Lookup answers agentID's directory in sessionID: the agent's own when the
// hook named it, otherwise the session's newest. A subagent starts in its
// parent's directory, so that fallback is the directory it is in.
func (s *SessionWorkspaces) Lookup(sessionID, agentID string) (string, bool) {
	st, ok := s.LookupStated(sessionID, agentID)
	return st.Cwd, ok
}

// LookupStated is Lookup for the whole statement.
func (s *SessionWorkspaces) LookupStated(sessionID, agentID string) (StatedWorkspace, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.sessions[sessionID]
	if !ok {
		return StatedWorkspace{}, false
	}
	if st, ok := w.agents[agentID]; ok {
		return st, true
	}
	// The session's newest directory is where the agent is; the type in that
	// statement belongs to whichever agent stated it, never this one (RM-314).
	st := w.latest
	st.AgentType = ""
	return st, true
}

// Knows reports whether agentID of sessionID has a statement of its own: the
// session's for the main agent ("" or mainAgentID), the agent's own for a
// subagent.
func (s *SessionWorkspaces) Knows(sessionID, agentID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	if agentID == "" || agentID == mainAgentID {
		return true
	}
	_, ok = w.agents[agentID]
	return ok
}

// LastRepo answers the newest statement in sessionID, by any of its agents,
// that named a repository. A later directory-only statement replaces the
// current one but not this: in hosted mode a session recorded in a
// repository stays recorded when it leaves it (ADR-0063, amended
// 2026-10-02).
func (s *SessionWorkspaces) LastRepo(sessionID string) (StatedWorkspace, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.sessions[sessionID]
	if !ok || !w.lastRepo.HasRepo() {
		return StatedWorkspace{}, false
	}
	return w.lastRepo, true
}

// agentCount is for tests: how many agents sessionID holds.
func (s *SessionWorkspaces) agentCount(sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.sessions[sessionID]; ok {
		return len(w.agents)
	}
	return 0
}
