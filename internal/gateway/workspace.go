// SPDX-License-Identifier: Apache-2.0

package gateway

// workspace.go — RM-231 (#376): the contract's WorkspaceResolver
// (lifecycle_contract.go), on top of describe_workspace's own configured
// resolver (internal/mcp/gateway.go's ResolveWorkspaceForGateway, itself
// DescribeWorkspaceConfig.describe, internal/mcp/workspace.go:232). No rule
// is duplicated here: an unset projects mount, a path outside it, or a
// directory that is not a git working tree is refused exactly as
// describe_workspace refuses it over the wire — never guessed, because a
// run cannot be registered without repo and branch (ADR-0045).

import (
	"context"

	"innsegl.dev/innsegl/internal/mcp"
)

// MCPWorkspaceResolver implements WorkspaceResolver by calling straight into
// internal/mcp's describe_workspace path, in process.
type MCPWorkspaceResolver struct{}

// NewMCPWorkspaceResolver returns the resolver every deployment wires by
// default. It holds no state of its own: internal/mcp already holds the
// configured projects mount (ConfigureDescribeWorkspace), and this type is
// only ever a caller of that.
func NewMCPWorkspaceResolver() MCPWorkspaceResolver { return MCPWorkspaceResolver{} }

var _ WorkspaceResolver = MCPWorkspaceResolver{}

// Resolve implements WorkspaceResolver.
func (MCPWorkspaceResolver) Resolve(ctx context.Context, workingDirectory string) (Workspace, error) {
	ws, err := mcp.ResolveWorkspaceForGateway(ctx, workingDirectory)
	if err != nil {
		return Workspace{}, err
	}
	return Workspace{Repo: ws.Repo, Branch: ws.Branch, Task: ws.Task}, nil
}
