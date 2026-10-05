// SPDX-License-Identifier: Apache-2.0

package gateway

// workspace.go — how a session's statement becomes a Workspace.
//
// The client derives its own workspace and states it (ADR-0064). The core
// reads repositories only from its mirror and mounts no projects folder
// (ADR-0065), so a statement that names only a directory has nothing to be
// resolved against: NoTreeResolver refuses it by name (ADR-0071). It replaced
// a resolver that called describe_workspace in process, which refused the
// same statement for the same reason, less plainly.

import (
	"context"
	"fmt"
)

// NoTreeResolver is the WorkspaceResolver every deployment wires: it refuses
// every directory, because the core reads no client tree.
type NoTreeResolver struct{}

var _ WorkspaceResolver = NoTreeResolver{}

// Resolve implements WorkspaceResolver.
func (NoTreeResolver) Resolve(_ context.Context, workingDirectory string) (Workspace, error) {
	return Workspace{}, fmt.Errorf("the session stated only its directory %q, and the core "+
		"reads no client tree (ADR-0071): `innsegl hook session` states the repository, "+
		"branch and task", workingDirectory)
}

// StatedWorkspaceResolver turns a session's statement into a Workspace. A
// statement that carries the client's own derivation is used as stated, with
// no filesystem access; one that carries only a directory goes to Fallback.
type StatedWorkspaceResolver struct {
	// Fallback resolves a directory-only statement.
	Fallback WorkspaceResolver
}

// ResolveStated refuses with errDirectoryNotStated when the statement names
// neither a repository nor a directory.
func (r StatedWorkspaceResolver) ResolveStated(ctx context.Context, st StatedWorkspace) (Workspace, error) {
	if st.HasRepo() {
		return st.Workspace(), nil
	}
	if st.Cwd == "" {
		return Workspace{}, errDirectoryNotStated
	}
	return r.Fallback.Resolve(ctx, st.Cwd)
}
