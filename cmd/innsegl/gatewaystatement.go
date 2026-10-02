// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"regexp"
	"strings"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/gateway"
)

// Bounds on the fields of a stated workspace (RM-282, #458). A statement is
// unauthenticated input from the host, so each field is a bounded token, not a
// payload.
const (
	maxStatedBranchBytes   = 255
	maxStatedTaskBytes     = 63
	maxStatedWorktreeBytes = 4096
)

var (
	// statedHead is a full git object id: SHA-1 or SHA-256, lowercase hex.
	statedHead = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	// statedTask is doc 02 §5's identifier grammar.
	statedTask = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// sessionWorkspaceStatement is the body `innsegl hook session` posts. Only
// session_id and cwd are required; the rest is the client's own derivation.
type sessionWorkspaceStatement struct {
	SessionID string `json:"session_id"`
	AgentID   string `json:"agent_id"`
	Cwd       string `json:"cwd"`
	Repo      string `json:"repo"`
	Worktree  string `json:"worktree"`
	Branch    string `json:"branch"`
	Task      string `json:"task"`
	Head      string `json:"head"`
	// AgentType is the SubagentStart hook's agent_type, as the harness sent
	// it (RM-314). Never a reason to refuse: the gateway folds it into the
	// identifier grammar and bounds what it keeps.
	AgentType string `json:"agent_type"`
}

// valid reports whether the statement is well formed. A statement that names
// a repository must name its branch and task too, because a run cannot be
// registered without them; one that names no repository must name none of
// them, so a half-derived statement is refused rather than half-believed.
func (in sessionWorkspaceStatement) valid() bool {
	if !gateway.IsSessionID(in.SessionID) ||
		(in.AgentID != "" && !gateway.IsAgentID(in.AgentID)) ||
		len(in.Cwd) > maxWorkingDirectoryBytes || !filepath.IsAbs(in.Cwd) || filepath.Clean(in.Cwd) != in.Cwd {
		return false
	}
	if in.Repo == "" {
		return in.Worktree == "" && in.Branch == "" && in.Task == "" && in.Head == ""
	}
	if event.ValidateRepo(in.Repo) != nil ||
		in.Branch == "" || len(in.Branch) > maxStatedBranchBytes || strings.ContainsAny(in.Branch, "\x00\r\n") ||
		!statedTask.MatchString(in.Task) {
		return false
	}
	if in.Head != "" && !statedHead.MatchString(in.Head) {
		return false
	}
	if in.Worktree != "" && (len(in.Worktree) > maxStatedWorktreeBytes || filepath.IsAbs(in.Worktree) ||
		filepath.Clean(in.Worktree) != in.Worktree || strings.HasPrefix(in.Worktree, "..")) {
		return false
	}
	return true
}

// stated is the statement as the gateway's session table holds it.
func (in sessionWorkspaceStatement) stated() gateway.StatedWorkspace {
	return gateway.StatedWorkspace{
		Cwd: in.Cwd, Repo: in.Repo, Worktree: in.Worktree, Branch: in.Branch, Task: in.Task, Head: in.Head,
		AgentType: in.AgentType,
	}
}
