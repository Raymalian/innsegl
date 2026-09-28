// SPDX-License-Identifier: Apache-2.0

package gateway

// registrar.go — RM-231 (#376): the contract's Registrar
// (lifecycle_contract.go), implemented on top of internal/mcp's in-process
// wrapper (internal/mcp/gateway.go). ADR-0053 is unchanged by any of this:
// the MCP issues every identity, and every method below is a way of calling
// into it, never a second issuance path. ADR-0060: this stays inside the one
// innsegl process — MCPRegistrar holds no client, no socket and no state of
// its own, because internal/mcp already holds the configured SPIRE client,
// ledger and idempotency store.

import (
	"context"

	"innsegl.dev/innsegl/internal/mcp"
)

// MCPRegistrar implements Registrar by calling straight into
// internal/mcp's register_agent and retire_agent, in process.
type MCPRegistrar struct{}

// NewMCPRegistrar returns the Registrar every deployment wires by default.
func NewMCPRegistrar() MCPRegistrar { return MCPRegistrar{} }

var _ Registrar = MCPRegistrar{}

// Register implements Registrar: a new run, through register_agent's own
// mint path.
//
// in.ResumesRetiredParent is forwarded exactly as given, and this method
// neither sets it nor checks where it came from — see
// mcp.GatewayRegistration's own comment for the restriction that binds
// every caller of Register and Restore: it must be false unless a
// LifecyclePolicy has already decided DecisionAdopt (ADR-0058 decision 8).
func (MCPRegistrar) Register(ctx context.Context, in RegisterInput) (RegisteredRun, error) {
	return registerThrough(ctx, in)
}

// Restore implements Registrar: register_agent's own heal, reached by
// calling register_agent again with the idempotency key that produced
// prior.RunID. That replay is what restores a withdrawn SPIRE entry
// (ADR-0058 decision 6, restore-before-forward) — register_agent tells a
// replay from a first execution by itself, using nothing this method adds.
// What this method does add is the one check register_agent cannot make on
// its own behalf: the run that comes back must be the run being restored,
// never a different one, so a caller that mismatched a mapping row and an
// idempotency key is told so rather than handed the wrong identity.
func (MCPRegistrar) Restore(ctx context.Context, prior RunMapping, in RegisterInput) (RegisteredRun, error) {
	out, err := registerThrough(ctx, in)
	if err != nil {
		return RegisteredRun{}, err
	}
	if out.RunID != prior.RunID {
		return RegisteredRun{}, mcp.Errorf(mcp.ClassInvariantViolation, prior.RunID,
			"restoring run %q with idempotency_key %q named run %q instead; a replay of the "+
				"same key must name the same run, so the caller's mapping and its key have "+
				"come apart", prior.RunID, in.IdempotencyKey, out.RunID)
	}
	return out, nil
}

// Retire implements Registrar: retire_agent's own path.
func (MCPRegistrar) Retire(ctx context.Context, runID string) (string, error) {
	return mcp.RetireRunForGateway(ctx, runID)
}

// registerThrough is Register and Restore's one translation of
// RegisterInput into mcp.GatewayRegistration, so the two methods cannot
// drift into building it two different ways. in.Workspace supplies
// register_agent's required repo, branch and task_id (ADR-0045): the
// WorkspaceResolver (workspace.go) is what produces it, never this file.
func registerThrough(ctx context.Context, in RegisterInput) (RegisteredRun, error) {
	out, err := mcp.RegisterRunForGateway(ctx, mcp.GatewayRegistration{
		AgentType:            in.AgentType,
		TaskID:               in.Workspace.Task,
		IdempotencyKey:       in.IdempotencyKey,
		Repo:                 in.Workspace.Repo,
		Branch:               in.Workspace.Branch,
		ParentRunID:          in.ParentRunID,
		ResumesRetiredParent: in.ResumesRetiredParent,
	})
	if err != nil {
		return RegisteredRun{}, err
	}
	return RegisteredRun{
		SPIFFEID:  out.SPIFFEID,
		RunID:     out.RunID,
		ExpiresAt: out.ExpiresAt,
		RunToken:  out.RunToken,
	}, nil
}
