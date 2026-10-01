// SPDX-License-Identifier: Apache-2.0

package gateway

// The contract E15 (#358) builds against: an agent's identity lifecycle driven
// by its traffic (ADR-0058), placed in this process (ADR-0060). Declarations
// only — each implementation lives in its own issue's file, so #376–#379 can
// be built in parallel and #380 composes them into one Guard:
//
//	#376 Registrar          registrar.go (+ internal/mcp/gateway.go)
//	#377 TreeLinker         tree.go;   RequestFacts extraction: facts.go
//	#378 MappingStore       mapping_postgres.go (+ its migration)
//	#379 LifecyclePolicy    lifecycle.go
//	#380 the identity Guard identity.go, one line in Guards()
//
// Changing anything here after the wave starts changes it for every issue at
// once; do it as its own commit, never inside an issue's.

import (
	"context"
	"time"
)

// RequestFacts is what one model request says about its agent, read once from
// the request body (bounded, like sse.go's limits) and shared through the
// request context by every later guard and observer — the body is read here
// and nowhere else.
type RequestFacts struct {
	// Brief is the agent's first user text with harness reminders stripped:
	// for a subagent, byte for byte the prompt its parent's spawn carried
	// (ADR-0058 decision 3).
	Brief string

	// FirstAssistant is the conversation's first assistant turn, canonically
	// encoded; empty on an agent's very first request, which has none yet.
	FirstAssistant []byte

	// WorkingDirectory is where the agent works, as the session hook
	// reported it (a host path; workspaceregistry.go). Never read from the
	// request body: the identity guard sets it. Empty when unknown.
	WorkingDirectory string

	// Stated is the whole statement the session hook made for this agent: the
	// directory above and, when the client derived it, the workspace. Never
	// read from the request body: the identity guard sets it.
	Stated StatedWorkspace

	// ToolResultIDs are the tool_use ids whose results this request carries.
	ToolResultIDs []string
}

// Fingerprint identifies a conversation independent of its session
// (ADR-0058 decision 4). It is empty until the conversation has a first
// assistant turn, so a fingerprint reaches the mapping as a later row, never
// by updating one.
type Fingerprint string

// Workspace is the repository an agent works in, derived by the MCP's own
// workspace logic (internal/mcp/workspace.go) — never parsed a second way here.
type Workspace struct {
	Repo, Branch, Task string
}

// WorkspaceResolver turns a harness-reported working directory into a
// Workspace, or refuses: a run cannot be registered without repo and branch
// (ADR-0045).
type WorkspaceResolver interface {
	Resolve(ctx context.Context, workingDirectory string) (Workspace, error)
}

// RunMapping is one insert-only row of the gateway's run mapping (ADR-0060
// decision 3). It has no status: lifecycle state is always read from the
// chain (internal/ledger/runstate.go), never stored here. It never holds a run
// token.
type RunMapping struct {
	RunID            string
	SessionID        string
	AgentID          string // mainAgentID for the root agent
	Fingerprint      Fingerprint
	ParentRunID      string // the exact-brief spawn link; empty for a root
	ForkedFromRunID  string // set only by a fork (ADR-0058 decision 5)
	AdoptedFromRunID string // set only when a retired run is resumed (decision 8)
	RecordedAt       time.Time
}

// MappingStore is the insert-only mapping. Lookups answer the most recent row
// for their key; a later row (for example one that adds a fingerprint)
// supersedes an earlier one without changing it.
type MappingStore interface {
	Insert(ctx context.Context, m RunMapping) error
	BySessionAgent(ctx context.Context, sessionID, agentID string) (RunMapping, bool, error)
	ByFingerprint(ctx context.Context, fp Fingerprint) ([]RunMapping, error)
}

// RegisterInput is a registration through the MCP's own register_agent path.
type RegisterInput struct {
	AgentType      string
	IdempotencyKey string
	Workspace      Workspace
	ParentRunID    string
	// ResumesRetiredParent may be set only by the LifecyclePolicy's adopt
	// decision, never from anything a request carries (ADR-0058 decision 8).
	ResumesRetiredParent bool
	// ForkedFromRunID names the run this one's fingerprint was linked from.
	// It may be set only by the LifecyclePolicy's DecisionFork (ADR-0058
	// decision 5), never from anything a request carries — the same
	// restriction ResumesRetiredParent states above, for the same reason:
	// mcp.GatewayRegistration.ForkedFromRunID carries it across the one seam
	// into register_agent's own unexported forkedFromRunID.
	//
	// Added by #380 (RM-235), after this contract's own wave started: this is
	// its own commit, per this file's package comment.
	ForkedFromRunID string
}

// RegisteredRun is what registration answers. RunToken is held in memory
// only; it is derived from the identity secret (mcp.RunToken), so it is
// re-derived after a restart and never persisted.
type RegisteredRun struct {
	SPIFFEID, RunID, ExpiresAt, RunToken string
}

// Registrar reaches register_agent and retire_agent in process, through the
// exported wrapper in internal/mcp (ADR-0053 unchanged: the MCP issues every
// identity).
type Registrar interface {
	Register(ctx context.Context, in RegisterInput) (RegisteredRun, error)
	// Restore replays the prior registration with the same idempotency key:
	// register_agent's heal is ADR-0058 decision 6's restore-before-forward.
	Restore(ctx context.Context, prior RunMapping, in RegisterInput) (RegisteredRun, error)
	Retire(ctx context.Context, runID string) (retiredAt string, err error)
}

// PendingSpawn is a parent's spawning tool call, seen as its block closes.
type PendingSpawn struct {
	ParentRunID string
	SessionID   string
	Prompt      string // byte for byte the spawn's prompt input
	// AgentType is the spawn's own asked-for agent type -- the Agent/Task
	// tool call's own subagent_type input (RM-263, #416), never the
	// harness-asserted agent id. Empty when the spawning tool_use carried
	// no such field; a caller resolving this spawn decides what an empty
	// value falls back to (identity.go's agentTypeFor), not this contract.
	// ADR-0041's pseudonymisation is untouched: this is the same raw value
	// register_agent's own AgentType input already carries and already
	// pseudonymises into the SPIFFE ID while recording the real value on
	// run_registered unchanged.
	AgentType  string
	ObservedAt time.Time
}

// TreeLinker links a child to its parent by exact equality of the child's
// brief and a pending spawn's prompt, never containment (ADR-0058 decision 3).
// One spawn links exactly one child. ResolveParent answers the matched
// spawn's AgentType alongside its parent run id (RM-263, #416) -- empty when
// the matched spawn carried none -- so a caller can register the child with
// the type it was actually spawned as.
type TreeLinker interface {
	RecordSpawn(ctx context.Context, s PendingSpawn) error
	ResolveParent(ctx context.Context, sessionID, childBrief string) (parentRunID, agentType string, ok bool, err error)
}

// Decision is the lifecycle policy's answer for one request.
type Decision int

const (
	// DecisionRefuse is the zero value on purpose: an unset decision refuses.
	DecisionRefuse Decision = iota
	DecisionContinue
	DecisionRestore
	DecisionNew
	DecisionFork
	DecisionAdopt
)

// LifecycleInput is everything the policy decides on; it reads nothing else.
type LifecycleInput struct {
	ID          Identification
	Facts       RequestFacts
	Fingerprint Fingerprint
	ParentRunID string // resolved by the TreeLinker, or empty
	Prior       RunMapping
	Found       bool
	PriorState  string // the chain's state of Prior.RunID (ledger.Run* values)
	Now         time.Time
}

// LifecyclePolicy decides; it performs nothing.
type LifecyclePolicy interface {
	Decide(ctx context.Context, in LifecycleInput) (Decision, error)
}
