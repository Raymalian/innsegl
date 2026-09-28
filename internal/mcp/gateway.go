// SPDX-License-Identifier: Apache-2.0

package mcp

import "context"

// gateway.go — RM-231 (#376), E15 (#358): the in-process seam
// internal/gateway/registrar.go and internal/gateway/workspace.go reach
// through to register, restore, retire and resolve a workspace, without a
// second implementation of any of it (ADR-0053 unchanged: the MCP issues
// every identity; ADR-0060: the gateway is a companion of this same process,
// never a second service with a second path to one).
//
// Every function below is a thin translation over a tool this package
// already owns and already tests: register_agent (register_agent.go),
// retire_agent (retire_agent.go) and describe_workspace (workspace.go). No
// rule is re-decided here — not the idempotency claim, not the
// ledger-before-SPIRE append ordering (ADR-0018), not the parent checks, not
// the projects-mount refusal. internal/gateway cannot reach registerAgentIn,
// retireAgentIn or DescribeWorkspaceConfig.describe directly, because they
// are unexported; that is exactly why this file exists — one package
// boundary, one seam, crossed in exactly one place, so a rule enforced by
// the tool cannot be bypassed by calling around it.

// GatewayRegistration is register_agent's own argument shape, reached in
// process instead of over the wire. Every member but the last maps straight
// onto registerAgentIn's own exported members (register_agent.go).
//
// # ResumesRetiredParent — read this before setting it true
//
// This maps straight onto registerAgentIn's unexported resumesRetiredParent.
// That field is unexported in register_agent.go so that no JSON decoder and
// no caller outside this package can ever set it; the field on THIS struct
// is necessarily exported, because internal/gateway is outside this package
// and has no other way to reach it at all. That makes this struct the one
// place the restriction has to be re-stated rather than enforced by the
// compiler:
//
// It may be true only when a LifecyclePolicy has already decided
// DecisionAdopt (ADR-0058 decision 8). The contract's own
// RegisterInput.ResumesRetiredParent (internal/gateway/lifecycle_contract.go)
// carries the identical restriction in its own comment, for the identical
// reason. It must never be copied from RequestFacts, a harness header, or
// anything else a request itself carries: doing so would let a caller
// resurrect any retired run's parent edge simply by naming it — exactly what
// MCP-082 exists to refuse on every other path into register_agent. This
// function trusts its caller on this one member the same way
// register_agent.go trusts registerAgentIn's own unexported field: by
// construction, not by a check made here.
type GatewayRegistration struct {
	AgentType            string
	TaskID               string
	IdempotencyKey       string
	Repo                 string
	Branch               string
	ParentRunID          string
	ResumesRetiredParent bool

	// ForkedFromRunID names the run this one's fingerprint was linked from
	// (ADR-0058 decision 5). It maps straight onto registerAgentIn's
	// unexported forkedFromRunID for the identical reason ResumesRetiredParent
	// does: that field is unexported in register_agent.go so that no JSON
	// decoder and no caller outside this package can ever set it, and this
	// struct's member is necessarily exported because internal/gateway has no
	// other way to reach it. It may be set only once a LifecyclePolicy has
	// already decided Fork (ADR-0058 decision 5); the contract's own
	// RegisterInput.ForkedFromRunID (internal/gateway/lifecycle_contract.go)
	// carries the identical restriction in its own comment.
	ForkedFromRunID string
}

// GatewayRegisteredRun is what RegisterRunForGateway answers.
//
// RunToken is held in memory only (RunToken, runtoken.go:45): it is derived
// fresh from the deployment's identity secret on every call — register_agent
// recomputes it on the way out rather than reading it from the idempotency
// store's recorded reply (register_agent.go's register method) — so it is
// never written to the ledger, never written to the idempotency store, and
// never persisted anywhere by this wrapper either. Nothing in this file logs
// it. ADR-0058 decision 10 ("run tokens are held only by the gateway") is
// exactly this value, handed back in memory and nowhere else.
type GatewayRegisteredRun struct {
	SPIFFEID, RunID, ExpiresAt, RunToken string
}

// RegisterRunForGateway reaches register_agent's own configured mint path in
// process: the same idempotency claim (ADR-0017), the same
// ledger-before-SPIRE append ordering (ADR-0018), the same parent checks
// (register_agent.go's checkParent). It is register_agent's tool body,
// called directly — there is no sdk.CallToolRequest to build and no
// transport to cross, which is the whole point of calling it from inside
// this same process rather than back over the wire the gateway itself sits
// in front of.
//
// # How this also implements the contract's Restore
//
// Calling this twice with the arguments that name one run — the same
// agent_type, task_id and idempotency_key — is what register_agent's own
// heal already does for a replay: see register_agent.go's package
// comment and its heal method. The second call is answered from the
// idempotency store, and if the SPIRE entry has since been withdrawn (the
// run lapsed and the reaper took it), heal recreates it before the reply is
// returned. That single behaviour is how internal/gateway/registrar.go
// implements the lifecycle contract's Restore: it calls this same function
// again with the idempotency key that produced the run it wants restored.
// This wrapper needs no second code path for it, because register_agent
// does not have one either.
//
// A misconfigured deployment (register_agent bound but never wired with
// ConfigureRegisterAgent) is refused exactly as a wire caller would be
// refused — registerAgentConfigured's own INVARIANT_VIOLATION, never a
// panic reaching into the gateway's own request path.
//
// # Every error answered here carries one of IP §4's classes
//
// Served over the wire, an unclassified error from a tool body is given one
// by server.go's own dispatch loop — `return errorResult(Classify(err)),
// nil, nil` — before it ever reaches a caller. Calling cfg.register directly
// is calling that tool body WITHOUT that dispatch loop, so this function
// applies the identical Classify to whatever cfg.register returns. Without
// it, a failure register_agent's own layers leave unclassified (an ordinary
// *ledger.StoreError from a database outage, for instance) would reach
// internal/gateway as a plain error with no class at all — exactly the thing
// this issue's "errors keep the MCP's error classes" rules out.
// registerAgentConfigured's own refusal is already a classified *Error and
// Classify is a no-op on one (errors.go's Classify: "if errors.As(err,
// &classified) { return classified }").
func RegisterRunForGateway(ctx context.Context, in GatewayRegistration) (GatewayRegisteredRun, error) {
	cfg, err := registerAgentConfigured()
	if err != nil {
		return GatewayRegisteredRun{}, err
	}
	out, err := cfg.register(ctx, registerAgentIn{
		AgentType:            in.AgentType,
		TaskID:               in.TaskID,
		IdempotencyKey:       in.IdempotencyKey,
		Repo:                 in.Repo,
		Branch:               in.Branch,
		ParentRunID:          in.ParentRunID,
		resumesRetiredParent: in.ResumesRetiredParent,
		forkedFromRunID:      in.ForkedFromRunID,
	})
	if err != nil {
		return GatewayRegisteredRun{}, Classify(err)
	}
	// registerAgentOut and GatewayRegisteredRun have identical fields (same
	// names, same types, in the same order) precisely so this is a
	// conversion and not a second listing that could drift from the first.
	return GatewayRegisteredRun(out), nil
}

// RetireRunForGateway reaches retire_agent's own configured path in process:
// the same ledger-before-SPIRE-deletion ordering, the same idempotent
// replay (a second retirement of one run answers with the original
// instant), the same admin-scope check. It is retire_agent's tool body,
// called directly, exactly as RegisterRunForGateway is register_agent's —
// including the same Classify step on the way out; see
// RegisterRunForGateway's comment for why calling the tool body directly
// needs it here and would not over the wire.
func RetireRunForGateway(ctx context.Context, runID string) (string, error) {
	retireMu.RLock()
	svc := retireActive
	retireMu.RUnlock()
	if svc == nil {
		// The same refusal retireAgent itself gives a bound-but-unconfigured
		// call (retire_agent.go): an alert-level defect in the wiring, not a
		// class IP §4 has for "internal error".
		return "", Errorf(ClassInvariantViolation, runID,
			"retire_agent is bound but not configured; no run can be retired")
	}
	out, err := svc.retire(ctx, retireAgentIn{RunID: runID})
	if err != nil {
		return "", Classify(err)
	}
	return out.RetiredAt, nil
}

// GatewayWorkspace mirrors the lifecycle contract's gateway.Workspace: Repo,
// Branch and Task, and nothing else. This package does not import
// internal/gateway to reuse its type directly — internal/gateway already
// imports this package to reach these three functions, and a second import
// the other way would be a cycle. Restating the three fields here is the
// whole cost of avoiding it.
type GatewayWorkspace struct {
	Repo, Branch, Task string
}

// ResolveWorkspaceForGateway derives a workspace from a harness-reported
// working directory through describe_workspace's own configured resolver
// (DescribeWorkspaceConfig.describe, workspace.go:232) — no rule duplicated
// here. An unset projects mount, a path outside it, or a directory that is
// not a git working tree is refused by that same method, exactly as
// describe_workspace refuses it over the wire: never guessed, because the
// answer is on its way into a run registration (ADR-0045 — a run cannot be
// registered without repo and branch).
func ResolveWorkspaceForGateway(ctx context.Context, workingDirectory string) (GatewayWorkspace, error) {
	cfg := describeWorkspaceConfigured()
	out, err := cfg.describe(ctx, workingDirectory)
	if err != nil {
		return GatewayWorkspace{}, err
	}
	return GatewayWorkspace{Repo: out.Repo, Branch: out.Branch, Task: out.Task}, nil
}
