// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// describe_workspace and observe_session are DEPRECATED (ADR-0071).
//
// Both read a projects folder mounted into the core. The core mounts none: it
// reads repositories only from its mirror (ADR-0065), the client derives its
// own workspace (ADR-0064), and the session hook posts to the gateway. Neither
// tool has had a configuration in any shipped deployment since, so every call
// was already refused.
//
// The NAMES are a protected surface (VERSIONING.md surface 4): removing one is
// a major-release change, announced one minor ahead in CHANGELOG.md and in the
// tool descriptions. So both stay bound, with their argument and result
// shapes unchanged, and refuse every call with INVARIANT_VIOLATION — the class
// the hosted core already answered them with — and a message naming the ADR.
// The implementation behind them is gone. The names go at the next major.

func init() {
	RegisterTool(ToolDescribeWorkspace, bindDescribeWorkspace)
	RegisterTool(ToolObserveSession, bindObserveSession)
}

// deprecatedADR is the decision both refusals cite.
const deprecatedADR = "ADR-0071"

// deprecatedRefusal is the one answer a deprecated tool gives.
func deprecatedRefusal(tool ToolName) *Error {
	return Errorf(ClassInvariantViolation, "",
		"%s is deprecated and refuses every call (%s): the core reads repositories only "+
			"from its mirror and mounts no projects folder. The client states its workspace "+
			"and the session hook reports to the gateway. The name is removed at the next "+
			"major release", tool, deprecatedADR)
}

// describeWorkspaceIn is IP §4's argument list, kept so the advertised input
// schema does not change while the name is deprecated.
type describeWorkspaceIn struct {
	CWD string `json:"cwd"`
}

// describeWorkspaceOut is IP §4's result shape, kept for the same reason.
type describeWorkspaceOut struct {
	Repo             string `json:"repo"`
	Worktree         string `json:"worktree"`
	Branch           string `json:"branch"`
	Task             string `json:"task"`
	IsLinkedWorktree bool   `json:"is_linked_worktree"`
}

func bindDescribeWorkspace(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolDescribeWorkspace),
		Description: "Deprecated (" + deprecatedADR + "): refuses every call and is removed at " +
			"the next major release. It described a workspace from a projects folder mounted " +
			"into the core; the core mounts none, and the client states its own workspace.",
	}, describeWorkspace)
}

func describeWorkspace(context.Context, *sdk.CallToolRequest, describeWorkspaceIn) (describeWorkspaceOut, error) {
	return describeWorkspaceOut{}, deprecatedRefusal(ToolDescribeWorkspace)
}

// observeSessionIn is doc 01 §4's argument list, kept so the advertised input
// schema does not change while the name is deprecated.
type observeSessionIn struct {
	SessionID       string `json:"session_id"`
	Phase           string `json:"phase"`
	CWD             string `json:"cwd,omitempty"`
	AgentType       string `json:"agent_type,omitempty"`
	Task            string `json:"task,omitempty"`
	ParentRunID     string `json:"parent_run_id,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	EndsDescendants bool   `json:"ends_descendants,omitempty"`
}

// observeSessionOut is doc 01 §4's result shape, kept for the same reason.
type observeSessionOut struct {
	SessionID  string `json:"session_id"`
	Phase      string `json:"phase"`
	Known      bool   `json:"known"`
	Registered bool   `json:"registered"`
	Retired    bool   `json:"retired"`
	RunID      string `json:"run_id,omitempty"`
	SPIFFEID   string `json:"spiffe_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	RunToken   string `json:"run_token,omitempty"`
	AgentType  string `json:"agent_type,omitempty"`
	Task       string `json:"task,omitempty"`
	Repo       string `json:"repo,omitempty"`
	Worktree   string `json:"worktree,omitempty"`
	Branch     string `json:"branch,omitempty"`
	RetiredAt  string `json:"retired_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

func bindObserveSession(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolObserveSession),
		Description: "Deprecated (" + deprecatedADR + "): refuses every call and is removed at " +
			"the next major release. It began and ended a harness session against a projects " +
			"folder mounted into the core; the session hook now reports to the gateway.",
	}, observeSession)
}

func observeSession(context.Context, *sdk.CallToolRequest, observeSessionIn) (observeSessionOut, error) {
	return observeSessionOut{}, deprecatedRefusal(ToolObserveSession)
}
