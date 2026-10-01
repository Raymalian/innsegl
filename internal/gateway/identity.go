// SPDX-License-Identifier: Apache-2.0

package gateway

// identity.go is #380 (RM-235): the identity Guard the contract
// (lifecycle_contract.go) describes -- ADR-0058 decision 11, "no identity,
// no request", wired into the request path guard.go's own Guards function
// builds. It composes, and performs nothing on its own: RequestFacts
// extraction (facts.go), the TreeLinker (tree.go), the MappingStore
// (mapping_postgres.go), the LifecyclePolicy (lifecycle.go) and the
// Registrar and WorkspaceResolver (registrar.go, workspace.go) are each
// #376-#379's own file; this file is only the seam that reads a request,
// asks each of those exactly the question the contract says it answers, and
// acts on what comes back.
//
// # The one new dependency the contract does not declare
//
// LifecycleInput.PriorState is "the chain's state of Prior.RunID
// (ledger.Run* values)" -- read fresh, never stored (ADR-0060 decision 3).
// The contract declares no interface for that read because none of #376-379
// needed one; this issue is the first caller, so RunStateReader is declared
// here rather than added to the frozen contract file. It reuses
// mcp.CredentialRun.State, which is itself ledger.RunStateOf -- the ONE rule
// (internal/ledger/runstate.go), never a second opinion computed here.
//
// # GID-012: refuse, never forward
//
// Any error, and DecisionRefuse itself, ends the request with 403 and a
// reason -- nothing is queued, nothing is forwarded provisionally (ADR-0058
// decision 11, IP §6.1).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

// ---------------------------------------------------------------------------
// RunStateReader: the one read the contract does not declare (see this
// file's own doc comment).
// ---------------------------------------------------------------------------

// RunStateReader answers a run's current lifecycle state, read from the
// chain -- one of ledger.RunStates -- never a stored status.
type RunStateReader interface {
	RunState(ctx context.Context, runID string) (string, error)
	// RunRegistration answers what the chain recorded when runID was
	// registered. Restoring a run replays that registration, so it needs
	// no working directory.
	RunRegistration(ctx context.Context, runID string) (RunRegistration, error)
}

// RunRegistration is what run_registered recorded: the agent type and task
// register_agent's idempotency claim is keyed on, and the repository.
type RunRegistration struct {
	AgentType, TaskID, Repo string
}

// credentialRunStates implements RunStateReader on top of mcp.CredentialRuns
// -- internal/rundir.Directory's own interface, read the same way
// register_agent, retire_agent and get_credential already do, never a
// second lookup invented here. Not found is refused: a mapping row pointing
// to a run the chain does not know is an internal inconsistency, never a
// state to guess at.
type credentialRunStates struct {
	runs    mcp.CredentialRuns
	horizon time.Duration
	now     func() time.Time
}

// NewCredentialRunStates builds a RunStateReader on runs -- in production,
// internal/rundir.Directory over the same ledger the mapping store's DSN
// names. horizon is ledger.DefaultRestoreHorizon's own meaning applied to
// this read: how long a withdrawn run may still be restored before it reads
// as abandoned. Zero or less means no horizon, matching
// mcp.CredentialRun.State's (and so ledger.RunStateOf's) own reading of it.
func NewCredentialRunStates(runs mcp.CredentialRuns, horizon time.Duration, now func() time.Time) RunStateReader {
	if now == nil {
		now = time.Now
	}
	return &credentialRunStates{runs: runs, horizon: horizon, now: now}
}

func (r *credentialRunStates) RunState(ctx context.Context, runID string) (string, error) {
	run, found, err := r.runs.CredentialRun(ctx, runID)
	if err != nil {
		return "", fmt.Errorf("read run %q's state from the chain: %w", runID, err)
	}
	if !found {
		return "", fmt.Errorf("run %q is in the gateway's own mapping but the chain does not "+
			"know it; refusing rather than guessing a state for a run that cannot be read", runID)
	}
	return run.State(r.now(), r.horizon), nil
}

func (r *credentialRunStates) RunRegistration(ctx context.Context, runID string) (RunRegistration, error) {
	run, found, err := r.runs.CredentialRun(ctx, runID)
	if err != nil {
		return RunRegistration{}, fmt.Errorf("read run %q's registration from the chain: %w", runID, err)
	}
	if !found {
		return RunRegistration{}, fmt.Errorf("run %q is in the gateway's own mapping but the chain does "+
			"not know it; refusing rather than restoring a run that cannot be read", runID)
	}
	return RunRegistration{AgentType: run.AgentType, TaskID: run.TaskID, Repo: run.Repo}, nil
}

// ---------------------------------------------------------------------------
// The run id, carried forward exactly as Identification and RequestFacts
// already are (harness.go, facts.go).
// ---------------------------------------------------------------------------

type runIDContextKey struct{}

// WithRunID returns a copy of ctx carrying runID, retrievable with
// RunIDFromContext. The identity guard calls this for every request it
// permits, so a later observer -- the tool-use spawn recorder (below) among
// them -- can read the run this request was resolved to without a second
// lookup.
func WithRunID(ctx context.Context, runID string) context.Context {
	return context.WithValue(ctx, runIDContextKey{}, runID)
}

// RunIDFromContext returns the run id the identity guard attached to ctx,
// and whether one was found. A request refused before the identity guard
// ran -- or one this build never wired an identity guard for at all --
// carries none.
func RunIDFromContext(ctx context.Context) (string, bool) {
	runID, ok := ctx.Value(runIDContextKey{}).(string)
	return runID, ok
}

// ---------------------------------------------------------------------------
// The Guard.
// ---------------------------------------------------------------------------

const (
	// DefaultIdentityCacheSize bounds the identity guard's own in-memory
	// cache of (session, agent) -> RunMapping, the same reasoning
	// tree.go's DefaultMaxPendingSpawns gives its own bounded table: a
	// harness-asserted key is not authenticated, so an unbounded cache is a
	// memory-exhaustion vector independent of anything the store itself
	// bounds.
	DefaultIdentityCacheSize = 8192

	identityGuardSource = "innsegl gateway: no identity could be issued for this agent; refusing to forward"
)

// IdentityGuardConfig is what an IdentityGuard runs on. Every dependency
// here is one of #376-#379's own declared interfaces, or RunStateReader
// (this file's own, see the package doc comment) -- nothing new is
// invented for this file to compose them.
type IdentityGuardConfig struct {
	// Mappings is the insert-only run mapping (mapping_postgres.go).
	// Required.
	Mappings MappingStore
	// Tree resolves a child's parent by exact-equality spawn matching
	// (tree.go). Required.
	Tree TreeLinker
	// Policy decides Continue/Restore/New/Fork/Adopt/Refuse (lifecycle.go).
	// Required.
	Policy LifecyclePolicy
	// Registrar reaches register_agent/retire_agent in process
	// (registrar.go). Required.
	Registrar Registrar
	// Workspaces resolves a harness-reported working directory
	// (workspace.go). Required.
	Workspaces WorkspaceResolver
	// RunStates reads a run's lifecycle state off the chain. Required.
	RunStates RunStateReader
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
	// CacheSize bounds the in-memory (session, agent) -> RunMapping cache in
	// front of Mappings. Zero or less means DefaultIdentityCacheSize.
	CacheSize int
	// SessionEndSignals, when set, is Cancel-ed for every request this
	// guard permits from a session's main agent (lifecycle.go's own doc
	// comment on the section: this is the half of the session-end redesign
	// that makes a forged signal against a session that is still genuinely
	// talking harmless). OPTIONAL: nil means this guard does not know about
	// session-end signals at all, which is every configuration before #380's
	// review fix and every test that has no reason to exercise it.
	SessionEndSignals *SessionEndSignals
	// SessionWorkspaces is where the session hook states each session's
	// working directory (workspaceregistry.go). Required: a new run is
	// registered from it and from nothing else.
	SessionWorkspaces *SessionWorkspaces
}

// IdentityGuard is ADR-0058 decision 11, wired into guard.go's chain: a
// request the guard cannot resolve to a live, restorable identity is
// refused with 403 before it reaches the upstream -- never queued, never
// forwarded provisionally (GID-012).
type IdentityGuard struct {
	mappings   MappingStore
	tree       TreeLinker
	policy     LifecyclePolicy
	registrar  Registrar
	workspaces StatedWorkspaceResolver
	runStates  RunStateReader
	now        func() time.Time

	cache             *identityCache
	sessionEndSignals *SessionEndSignals
	sessionWorkspaces *SessionWorkspaces
}

// NewIdentityGuard builds an IdentityGuard, or refuses -- the same
// "refuse rather than silently run half-wired" posture NewBackstop
// (lifecycle.go) and NewSessionRateLimiter (limit.go) already take.
func NewIdentityGuard(cfg IdentityGuardConfig) (*IdentityGuard, error) {
	switch {
	case cfg.Mappings == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no MappingStore")
	case cfg.Tree == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no TreeLinker")
	case cfg.Policy == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no LifecyclePolicy")
	case cfg.Registrar == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no Registrar")
	case cfg.Workspaces == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no WorkspaceResolver")
	case cfg.RunStates == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no RunStateReader")
	case cfg.SessionWorkspaces == nil:
		return nil, errors.New("innsegl gateway: identity guard configuration: no SessionWorkspaces")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	size := cfg.CacheSize
	if size <= 0 {
		size = DefaultIdentityCacheSize
	}
	return &IdentityGuard{
		mappings:          cfg.Mappings,
		tree:              cfg.Tree,
		policy:            cfg.Policy,
		registrar:         cfg.Registrar,
		workspaces:        StatedWorkspaceResolver{Fallback: cfg.Workspaces},
		runStates:         cfg.RunStates,
		now:               now,
		cache:             newIdentityCache(size),
		sessionEndSignals: cfg.SessionEndSignals,
		sessionWorkspaces: cfg.SessionWorkspaces,
	}, nil
}

var _ Guard = (*IdentityGuard)(nil)

// Check implements Guard.
func (g *IdentityGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	id, ok := IdentificationFromContext(r.Context())
	if !ok {
		// Guards() places the identity guard after the harness-shape guard
		// for exactly this reason: a request that reaches here without an
		// Identification never passed one. Refusing rather than guessing is
		// the same posture every other guard in this chain already takes.
		return nil, g.refuse("no harness identification was found on this request")
	}

	// Any request from this session's main agent falsifies its own
	// session-end signal, if one is standing: the harness that would have
	// sent that signal is plainly still driving this session (lifecycle.go's
	// own doc comment on why this is what makes a forged signal against a
	// live session harmless). Done before deciding anything else, and
	// regardless of what this request goes on to decide or whether it is
	// ultimately refused: RECEIVING it is the fact that matters here, not
	// what it turns out to mean.
	if g.sessionEndSignals != nil && id.AgentID == mainAgentID {
		g.sessionEndSignals.Cancel(id.SessionID)
	}

	facts := ExtractRequestFacts(r)
	// The working directory is what the session hook stated, never what the
	// conversation says (workspaceregistry.go). Attached to the facts so the
	// recorder snapshots the same directory the run was registered from.
	facts.Stated, _ = g.sessionWorkspaces.LookupStated(id.SessionID, id.AgentID)
	facts.WorkingDirectory = facts.Stated.Cwd
	ctx := WithRequestFacts(r.Context(), facts)
	fp := ComputeFingerprint(facts)

	prior, found, err := g.priorMapping(ctx, id, fp)
	if err != nil {
		return nil, g.refuseErr("looking up this agent's prior identity", err)
	}

	var priorState string
	if found {
		priorState, err = g.runStates.RunState(ctx, prior.RunID)
		if err != nil {
			return nil, g.refuseErr("reading run state from the chain", err)
		}
	}

	var parentRunID, spawnAgentType string
	if !found {
		if p, at, linked, rerr := g.tree.ResolveParent(ctx, id.SessionID, facts.Brief); rerr == nil && linked {
			parentRunID = p
			spawnAgentType = at
		}
	}

	decision, err := g.policy.Decide(ctx, LifecycleInput{
		ID: id, Facts: facts, Fingerprint: fp, ParentRunID: parentRunID,
		Prior: prior, Found: found, PriorState: priorState, Now: g.now(),
	})
	if err != nil {
		return nil, g.refuse("the lifecycle policy could not decide: " + err.Error())
	}

	runID, actErr := g.act(ctx, decision, id, facts, fp, parentRunID, spawnAgentType, prior)
	if errors.Is(actErr, errDirectoryNotStated) {
		return nil, &Refusal{
			Status:     http.StatusServiceUnavailable,
			Reason:     identityGuardSource + ": " + actErr.Error(),
			RetryAfter: directoryRetryAfter,
		}
	}
	if actErr != nil {
		return nil, g.refuseErr("", actErr)
	}

	return r.WithContext(WithRunID(ctx, runID)), nil
}

// errDirectoryNotStated is a run that must be registered for a session the
// session hook has not stated a directory for yet. It is answered 503 with
// Retry-After, not 403: the hook runs before every user turn and every
// subagent, so the same request succeeds once it has.
var errDirectoryNotStated = errors.New("the session hook has not stated this session's working " +
	"directory yet; `innsegl hook session` must run on SessionStart, UserPromptSubmit, SubagentStart " +
	"and CwdChanged (install.sh installs it)")

// directoryRetryAfter is how long a harness is asked to wait before retrying
// a request refused with errDirectoryNotStated.
const directoryRetryAfter = 2 * time.Second

// resolveWorkspace resolves the hook-stated directory, refusing with
// errDirectoryNotStated rather than asking the resolver about nothing.
func (g *IdentityGuard) resolveWorkspace(ctx context.Context, facts RequestFacts) (Workspace, error) {
	return g.workspaces.ResolveStated(ctx, facts.Stated)
}

// outageRetryAfter is how long a harness is asked to wait before retrying a
// request refused because a dependency is down.
const outageRetryAfter = 5 * time.Second

// refuseErr refuses for err, prefixed with the step that failed. A
// dependency outage -- an MCP error whose class is retryable (IP §4:
// IDENTITY_UNAVAILABLE, LEDGER_UNAVAILABLE, ...) or a connection that could
// not be made at all -- is answered 503 with Retry-After, naming the class,
// so the harness retries and the person reading it knows what is down. Any
// other failure refuses the request itself and stays 403. Nothing is ever
// forwarded either way (decision 11).
func (g *IdentityGuard) refuseErr(step string, err error) *Refusal {
	detail := err.Error()
	if step != "" {
		detail = step + ": " + detail
	}
	var mcpErr *mcp.Error
	var netErr net.Error
	switch {
	case errors.As(err, &mcpErr) && mcpErr.Retryable:
		return &Refusal{
			Status:     http.StatusServiceUnavailable,
			Reason:     identityGuardSource + ": " + string(mcpErr.Class) + " (a dependency is down; retrying): " + detail,
			RetryAfter: outageRetryAfter,
		}
	case errors.As(err, &netErr):
		return &Refusal{
			Status:     http.StatusServiceUnavailable,
			Reason:     identityGuardSource + ": a dependency could not be reached (retrying): " + detail,
			RetryAfter: outageRetryAfter,
		}
	}
	return g.refuse(detail)
}

func (g *IdentityGuard) refuse(detail string) *Refusal {
	return &Refusal{Status: http.StatusForbidden, Reason: identityGuardSource + ": " + detail}
}

// priorMapping answers this request's prior mapping row, the cache first
// (mapping_postgres.go stays the truth; the cache is only in front of it),
// then BySessionAgent, then -- only when that finds nothing and a
// fingerprint is known -- ByFingerprint for a fork or an adoption
// (lifecycle.go's own doc comment: a caller that falls back to
// ByFingerprint can only be filling Prior from a DIFFERENT session/agent).
func (g *IdentityGuard) priorMapping(ctx context.Context, id Identification, fp Fingerprint) (RunMapping, bool, error) {
	if m, ok := g.cache.get(id.SessionID, id.AgentID); ok {
		return m, true, nil
	}

	m, found, err := g.mappings.BySessionAgent(ctx, id.SessionID, id.AgentID)
	if err != nil {
		return RunMapping{}, false, err
	}
	if found {
		g.cache.put(id.SessionID, id.AgentID, m)
		return m, true, nil
	}
	if fp == "" {
		return RunMapping{}, false, nil
	}

	rows, err := g.mappings.ByFingerprint(ctx, fp)
	if err != nil {
		return RunMapping{}, false, err
	}
	if len(rows) == 0 {
		return RunMapping{}, false, nil
	}
	// Oldest first (the contract's own ordering); the newest row is this
	// fingerprint's most recently known continuation, which is what a fork
	// or an adoption should be measured against.
	return rows[len(rows)-1], true, nil
}

// act performs the one thing the decided Decision requires and answers the
// run id to attach to the request's context. Nothing here re-decides;
// Decide already did that. spawnAgentType is the agent type the TreeLinker
// resolved alongside parentRunID (empty when nothing was resolved) --
// RM-263 (#416): agentTypeFor turns it, plus id, into what actually reaches
// RegisterInput.AgentType.
func (g *IdentityGuard) act(
	ctx context.Context, decision Decision, id Identification, facts RequestFacts,
	fp Fingerprint, parentRunID, spawnAgentType string, prior RunMapping,
) (string, error) {
	switch decision {
	case DecisionContinue:
		g.recordFingerprintIfNewlyKnown(ctx, id, prior, fp)
		return prior.RunID, nil

	case DecisionRestore:
		// A replay of the run's own registration, from what the chain
		// recorded: register_agent's idempotency claim is keyed on agent
		// type and task, so those must be the recorded values, and no
		// working directory is needed at all.
		reg, err := g.runStates.RunRegistration(ctx, prior.RunID)
		if err != nil {
			return "", fmt.Errorf("read run %q's registration to restore it: %w", prior.RunID, err)
		}
		out, err := g.registrar.Restore(ctx, prior, RegisterInput{
			AgentType:      reg.AgentType,
			IdempotencyKey: idempotencyKeyFor(id),
			Workspace:      Workspace{Repo: reg.Repo, Task: reg.TaskID},
		})
		if err != nil {
			return "", fmt.Errorf("restore run %q: %w", prior.RunID, err)
		}
		g.recordFingerprintIfNewlyKnown(ctx, id, prior, fp)
		return out.RunID, nil

	case DecisionNew:
		ws, err := g.resolveWorkspace(ctx, facts)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a new run: %w", err)
		}
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:      agentTypeFor(id, spawnAgentType),
			IdempotencyKey: idempotencyKeyFor(id),
			Workspace:      ws,
			ParentRunID:    parentRunID,
		})
		if err != nil {
			return "", fmt.Errorf("register a new run: %w", err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, ParentRunID: parentRunID,
		})
		return out.RunID, nil

	case DecisionFork:
		ws, err := g.resolveWorkspace(ctx, facts)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a fork of run %q: %w", prior.RunID, err)
		}
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:       agentTypeFor(id, spawnAgentType),
			IdempotencyKey:  idempotencyKeyFor(id),
			Workspace:       ws,
			ForkedFromRunID: prior.RunID,
		})
		if err != nil {
			return "", fmt.Errorf("register a fork of run %q: %w", prior.RunID, err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, ForkedFromRunID: prior.RunID,
		})
		return out.RunID, nil

	case DecisionAdopt:
		ws, err := g.resolveWorkspace(ctx, facts)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a run adopting %q: %w", prior.RunID, err)
		}
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:      agentTypeFor(id, spawnAgentType),
			IdempotencyKey: idempotencyKeyFor(id),
			Workspace:      ws,
		})
		if err != nil {
			return "", fmt.Errorf("register a run adopting %q: %w", prior.RunID, err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, AdoptedFromRunID: prior.RunID,
		})
		return out.RunID, nil

	default: // DecisionRefuse, and any value this policy might one day add.
		return "", errors.New("the lifecycle policy refused this request")
	}
}

// insertAndCache inserts m and, only once the insert has actually
// succeeded, caches it -- a cached row the store never has is worse than a
// cache miss, since a miss merely repeats the lookup.
func (g *IdentityGuard) insertAndCache(ctx context.Context, id Identification, m RunMapping) {
	if err := g.mappings.Insert(ctx, m); err != nil {
		// Registration already succeeded and the run is real; a failure to
		// record the mapping row is logged nowhere in this package
		// (proxy.go's own doc comment: nothing here logs), but the row can
		// be recorded on this same (session, agent)'s next request, which
		// will find no prior row and try again. Not caching a row the
		// store does not have keeps the two from disagreeing.
		return
	}
	g.cache.put(id.SessionID, id.AgentID, m)
}

// recordFingerprintIfNewlyKnown inserts the "later row" the contract's own
// MappingStore doc comment describes -- fingerprint added later, found by
// fingerprint from then on -- exactly once per (session, agent): only when
// the cached/stored prior still carries none. A failure here does not
// refuse the request: the run this call is continuing or restoring is
// already resolved, and the fingerprint can be recorded again on a later
// request that finds the same gap.
func (g *IdentityGuard) recordFingerprintIfNewlyKnown(ctx context.Context, id Identification, prior RunMapping, fp Fingerprint) {
	if prior.Fingerprint != "" || fp == "" {
		return
	}
	updated := prior
	updated.Fingerprint = fp
	if err := g.mappings.Insert(ctx, updated); err != nil {
		return
	}
	g.cache.put(id.SessionID, id.AgentID, updated)
}

// defaultSubagentType is agentTypeFor's own fallback when a spawn resolved
// no AgentType at all -- no pending spawn matched, or one matched but its
// own tool_use carried no subagent type (an older harness, or a spawn shape
// this build does not yet recognise). A stated placeholder, RM-263 (#416):
// it must never be id.AgentID, which is an opaque per-run identifier (a
// UUID, harness.go's own isUUID), not a type, and recording it as one would
// repeat the exact bug this issue exists to close.
const defaultSubagentType = "subagent"

// agentTypeFor is what this build records as registerAgentIn.AgentType for
// a run the gateway registers from traffic alone (RM-263, #416). The root
// agent's type is the harness shape itself: Identification.AgentID is
// mainAgentID ("main") only for the root (harness.go's own recogniser never
// sets it to anything else), so that fixed value is what is recorded, never
// something read off a spawn. A subagent's real type is spawnAgentType --
// resolved by the TreeLinker's ResolveParent alongside the parent run id,
// itself read from the spawning Agent/Task tool call's own subagent_type
// input (identity.go's SpawnRecorder) -- never the harness-asserted agent
// id id.AgentID otherwise carries, which names a run, not a kind of agent.
// A subagent whose spawn resolved no type at all falls back to
// defaultSubagentType, a stated placeholder, rather than ever substituting
// the id.
func agentTypeFor(id Identification, spawnAgentType string) string {
	if id.AgentID == mainAgentID {
		return mainAgentID
	}
	if spawnAgentType != "" {
		return spawnAgentType
	}
	return defaultSubagentType
}

// idempotencyKeyFor is the SAME key on every request of one (session,
// agent) pair -- required so that a later Restore replays register_agent's
// own idempotency claim for the run this call first registered
// (registrar.go's own doc comment on Restore), rather than minting a
// second identity for a run that only went briefly quiet.
func idempotencyKeyFor(id Identification) string {
	return "gateway:" + id.Harness + ":" + id.Version + ":" + id.SessionID + ":" + id.AgentID
}

// ---------------------------------------------------------------------------
// The in-memory cache in front of MappingStore. The store stays the truth
// (a fresh process has an empty cache and asks the store again, which is
// exactly GID-009's own case); this only saves a lookup within one
// process's lifetime for a (session, agent) pair it has already resolved.
// ---------------------------------------------------------------------------

type identityCacheKey struct{ sessionID, agentID string }

type identityCache struct {
	mu    sync.Mutex
	max   int
	order []identityCacheKey // oldest first
	byKey map[identityCacheKey]RunMapping
}

func newIdentityCache(capacity int) *identityCache {
	return &identityCache{max: capacity, byKey: make(map[identityCacheKey]RunMapping)}
}

func (c *identityCache) get(sessionID, agentID string) (RunMapping, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.byKey[identityCacheKey{sessionID, agentID}]
	return m, ok
}

func (c *identityCache) put(sessionID, agentID string, m RunMapping) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := identityCacheKey{sessionID, agentID}
	if _, exists := c.byKey[key]; !exists {
		if len(c.order) >= c.max && len(c.order) > 0 {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.byKey, oldest)
		}
		c.order = append(c.order, key)
	}
	c.byKey[key] = m
}

// ---------------------------------------------------------------------------
// The tool-use spawn recorder: feeds TreeLinker.RecordSpawn from a
// spawning Agent/Task tool call, with the PARENT's run id (proxy.go's
// ContextToolUseObserver -- the parent's own run id is exactly what the
// identity guard already attached to the parent's request context while
// resolving the SAME request whose reply is now streaming this tool_use
// block).
// ---------------------------------------------------------------------------

// spawnToolNames are the tool_use names Claude Code uses to spawn a
// subagent (docs/decisions/model-gateway-spike.md: "the subagent prompt in
// the Agent tool_use"). Both names are recognised because the harness has
// used each across recorded versions; recognising an unrecognised third
// name is exactly the "loosen an existing recogniser" harness.go's own doc
// comment warns against, so a future name is a fixture and a name to add
// here, never a reason to guess.
var spawnToolNames = map[string]bool{"Agent": true, "Task": true}

// spawnToolInput is what this recorder reads out of a spawning tool_use's
// input: the subagent's own prompt, byte for byte what its first request's
// Brief will be (ADR-0058 decision 3), and the type it was asked to spawn
// as -- the Agent/Task tool's own subagent_type field (RM-263, #416; issue
// #416's own body names this field). Empty when the tool_use carried none;
// agentTypeFor (identity.go) decides what an empty value falls back to,
// never this struct.
type spawnToolInput struct {
	Prompt       string `json:"prompt"`
	SubagentType string `json:"subagent_type"`
}

// SpawnRecorder implements proxy.go's ContextToolUseObserver: every Agent or
// Task tool_use seen while a PARENT's own reply streams is recorded against
// tree (RecordSpawn), keyed by the parent's session id and carrying the
// parent's own run id -- read off the request's context, which the identity
// guard already attached earlier in this same request's handling.
type SpawnRecorder struct {
	tree TreeLinker
	now  func() time.Time
}

// NewSpawnRecorder builds a SpawnRecorder over tree. now is nil for
// time.Now.
func NewSpawnRecorder(tree TreeLinker, now func() time.Time) *SpawnRecorder {
	if now == nil {
		now = time.Now
	}
	return &SpawnRecorder{tree: tree, now: now}
}

var (
	_ ToolUseObserver        = (*SpawnRecorder)(nil)
	_ ContextToolUseObserver = (*SpawnRecorder)(nil)
)

// OnToolUse implements the plain ToolUseObserver interface. Without a
// request context there is no parent run id to record against, so this does
// nothing -- proxy.go's boundToolUseObserver always prefers
// OnToolUseContext when it is available, which in production is always,
// since Proxy.ToolUse is set to a SpawnRecorder exactly when this package
// wires one.
func (s *SpawnRecorder) OnToolUse(ToolUse) {}

// OnToolUseContext implements ContextToolUseObserver.
func (s *SpawnRecorder) OnToolUseContext(ctx context.Context, t ToolUse) {
	if !spawnToolNames[t.Name] || t.Truncated {
		return
	}
	var in spawnToolInput
	if err := json.Unmarshal(t.Input, &in); err != nil || in.Prompt == "" {
		return
	}
	id, ok := IdentificationFromContext(ctx)
	if !ok {
		return
	}
	parentRunID, ok := RunIDFromContext(ctx)
	if !ok || parentRunID == "" {
		return
	}
	discardSpawnError(s.tree.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: parentRunID,
		SessionID:   id.SessionID,
		Prompt:      in.Prompt,
		AgentType:   in.SubagentType,
		ObservedAt:  s.now(),
	}))
}

// discardSpawnError is RecordSpawn's named discard: this package's own doc
// comment (proxy.go) is that nothing here logs, and a validation refusal
// from RecordSpawn (an empty session, prompt or parent, none of which this
// call ever passes -- each is checked above) has no caller left to tell.
func discardSpawnError(error) {}
