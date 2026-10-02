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
// decision 11, IP §6.1). Two inputs the core cannot record are not errors
// (RM-313): a session with no statement at all, and a repository outside
// the installation's scope. Those are forwarded unrecorded and reported
// (statementheader.go), because a refusal there was a loop the harness
// retried into until it failed.

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
	// Pins, set in hosted mode only (RM-284, #460), pins each session to the
	// installation that first used it. With Pins set, a request that carries
	// no verified installation (InstallationFromContext) is refused: hosted
	// mode has no anonymous caller. Nil is single-host mode, unchanged.
	Pins *SessionPins
	// Scope, set with Pins, keeps a run from being registered for a
	// repository outside the installation's scope (ADR-0064 decision 3); such
	// a request is forwarded unrecorded and reported (RM-313). With it set, a
	// session that states no repository and was never recorded passes
	// through unrecorded, and a recorded session stays recorded (ADR-0063,
	// amended 2026-10-02).
	Scope ScopeChecker
	// HeaderStatements, when set, reads the statement the client service
	// attaches to a model request (StatementHeader). It is used only when
	// the registry has no statement for the agent (RM-313). Optional.
	HeaderStatements HeaderStatements
	// OnUnrecorded, when set, is told once per (session, agent, reason)
	// about a request forwarded without being recorded. Optional.
	OnUnrecorded func(UnrecordedFinding)
	// OnAgentTypeWitness, when set, is told when the hook's agent_type and
	// the model's subagent_type name different types after folding (RM-314).
	// The hook's wins; this is the finding. Optional.
	OnAgentTypeWitness func(AgentTypeFinding)
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
	pins              *SessionPins
	scope             ScopeChecker
	headerStatements  HeaderStatements
	onUnrecorded      func(UnrecordedFinding)
	onWitness         func(AgentTypeFinding)
	reported          *reportedFindings
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
	case (cfg.Pins == nil) != (cfg.Scope == nil):
		return nil, errors.New("innsegl gateway: identity guard configuration: hosted mode needs both Pins and Scope")
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
		pins:              cfg.Pins,
		scope:             cfg.Scope,
		headerStatements:  cfg.HeaderStatements,
		onUnrecorded:      cfg.OnUnrecorded,
		onWitness:         cfg.OnAgentTypeWitness,
		reported:          newReportedFindings(size),
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

	// Hosted mode (RM-284, #460): the client guard verified an installation,
	// and the session belongs to the first one that used it. Checked before
	// anything else, so a refused request cancels no signal and claims
	// nothing.
	if g.pins != nil {
		inst, ok := InstallationFromContext(r.Context())
		if !ok {
			return nil, clientRefusal()
		}
		// The run mapping is the durable half of the pin (#488): the
		// in-memory pins start empty after a restart, but the mapping
		// still says which installation made this session's runs. Checked
		// for this agent and for the session's main agent, before the
		// in-memory pin is taken, so a refused installation pins nothing.
		owner, err := g.sessionOwner(r.Context(), id)
		if err != nil {
			return nil, g.refuseErr("reading which installation owns this session", err)
		}
		if owner != "" && owner != inst {
			return nil, clientRefusal()
		}
		if !g.pins.Pin(id.SessionID, inst) {
			return nil, clientRefusal()
		}
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

	// RM-313: a core that restarted has an empty registry; the client
	// service's statement on the request refills it.
	g.adoptHeaderStatement(r, id)

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

	// Hosted mode (ADR-0063, amended 2026-10-02): a session that is not in a
	// git repository, and never was, passes through to the provider
	// unrecorded -- no run, no mapping row. A session that has been recorded
	// stays recorded wherever it goes next (sessionRecorded).
	if g.scope != nil && !found {
		recorded, rerr := g.sessionRecorded(ctx, id, facts.Stated)
		if rerr != nil {
			return nil, g.refuseErr("reading whether this session is recorded", rerr)
		}
		if !recorded {
			if facts.Stated.Cwd == "" {
				// No statement at all, from the hook or the header (RM-313):
				// forwarded unrecorded and reported, never a retry loop.
				g.unrecorded(ctx, id, UnrecordedNoStatement, "")
			}
			return r.WithContext(ctx), nil
		}
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
	// What the core cannot record is forwarded unrecorded and reported
	// (RM-313): no statement at all, or a repository the installation may
	// not record. Never a 503 the harness retries into the same answer.
	if errors.Is(actErr, errDirectoryNotStated) {
		g.unrecorded(ctx, id, UnrecordedNoStatement, "")
		return r.WithContext(ctx), nil
	}
	if errors.Is(actErr, errOutOfScope) {
		g.unrecorded(ctx, id, UnrecordedOutOfScope, facts.Stated.Repo)
		return r.WithContext(ctx), nil
	}
	if actErr != nil {
		return nil, g.refuseErr("", actErr)
	}

	return r.WithContext(WithRunID(ctx, runID)), nil
}

// adoptHeaderStatement records the statement r carries (StatementHeader)
// when the registry has none for this agent. A statement the installation
// may not record is kept as its directory alone, so the session is one
// outside any repository and the scope is not asked again on every request.
func (g *IdentityGuard) adoptHeaderStatement(r *http.Request, id Identification) {
	if g.headerStatements == nil || g.sessionWorkspaces.Knows(id.SessionID, id.AgentID) {
		return
	}
	agentID, st, ok := g.headerStatements.Decode(r, id)
	if !ok || g.sessionWorkspaces.Knows(id.SessionID, agentID) {
		return
	}
	verdict, err := g.headerStatements.Admit(r.Context(), id.SessionID, st)
	if err != nil {
		// The scope cannot be read now; the next request asks again.
		return
	}
	switch verdict {
	case StatementAdmitted:
		g.sessionWorkspaces.RecordStated(id.SessionID, agentID, st)
	case StatementOutOfScope:
		g.sessionWorkspaces.RecordStated(id.SessionID, agentID, StatedWorkspace{Cwd: st.Cwd})
		g.unrecorded(r.Context(), id, UnrecordedOutOfScope, st.Repo)
	case StatementRefused:
	}
}

// unrecorded reports, once per (session, agent, reason), a request
// forwarded without being recorded.
func (g *IdentityGuard) unrecorded(ctx context.Context, id Identification, reason UnrecordedReason, repo string) {
	if g.onUnrecorded == nil || !g.reported.first(findingKey{id.SessionID, id.AgentID, reason}) {
		return
	}
	inst, _ := InstallationFromContext(ctx)
	g.onUnrecorded(UnrecordedFinding{
		SessionID: id.SessionID, AgentID: id.AgentID, Installation: inst, Repo: repo, Reason: reason,
	})
}

// sessionRecorded reports, in hosted mode, whether a request with no prior
// mapping of its own belongs to a recorded session: one that states a
// repository now, stated one earlier (SessionWorkspaces.LastRepo), or whose
// main agent already has a run (the durable half, which outlives a restart).
// Recording is sticky: an agent does not escape it by leaving the repository.
func (g *IdentityGuard) sessionRecorded(ctx context.Context, id Identification, stated StatedWorkspace) (bool, error) {
	if stated.HasRepo() {
		return true, nil
	}
	if _, ok := g.sessionWorkspaces.LastRepo(id.SessionID); ok {
		return true, nil
	}
	runID, err := g.sessionMainRun(ctx, id.SessionID)
	return runID != "", err
}

// sessionMainRun answers the run of sessionID's main agent, the cache first;
// empty when it has none.
func (g *IdentityGuard) sessionMainRun(ctx context.Context, sessionID string) (string, error) {
	if m, ok := g.cache.get(sessionID, mainAgentID); ok {
		return m.RunID, nil
	}
	m, found, err := g.mappings.BySessionAgent(ctx, sessionID, mainAgentID)
	if err != nil || !found {
		return "", err
	}
	return m.RunID, nil
}

// errDirectoryNotStated is a run that must be registered for a session the
// session hook has not stated a directory for, and no header statement
// supplied. The request is forwarded unrecorded and reported (RM-313): a 503
// here was a loop the harness retried into until it gave up.
var errDirectoryNotStated = errors.New("the session hook has not stated this session's working " +
	"directory; `innsegl hook session` must run on SessionStart, UserPromptSubmit, SubagentStart " +
	"and CwdChanged")

// resolveWorkspace resolves the hook-stated directory, refusing with
// errDirectoryNotStated rather than asking the resolver about nothing.
//
// In hosted mode the workspace must be the client's own derivation (the core
// never reads a client's files, ADR-0064 decision 2) and its repository must
// be in the installation's scope; anything else is errOutOfScope. The
// installation's scope check is also where its organisation becomes the
// repository's holder on first use (ADR-0063, amended 2026-10-02).
func (g *IdentityGuard) resolveWorkspace(ctx context.Context, id Identification, facts RequestFacts, prior RunMapping) (Workspace, error) {
	if g.scope == nil {
		return g.workspaces.ResolveStated(ctx, facts.Stated)
	}
	inst, ok := InstallationFromContext(ctx)
	if !ok {
		return Workspace{}, errOutOfScope
	}
	ws, err := g.recordedWorkspace(ctx, id, facts.Stated, prior)
	if err != nil {
		return Workspace{}, err
	}
	if ws.Repo == "" {
		return Workspace{}, errOutOfScope
	}
	in, err := g.scope.InScope(ctx, inst, ws.Repo)
	if err != nil {
		return Workspace{}, fmt.Errorf("check the installation's scope: %w", err)
	}
	if !in {
		return Workspace{}, errOutOfScope
	}
	return ws, nil
}

// recordedWorkspace is where a hosted run is registered: the repository
// stated now; else the newest one this session stated; else -- a session
// that left its repository, seen by a core that restarted since -- the
// registration of the run this request continues from (prior) or of the
// session's main agent. Empty when none applies.
func (g *IdentityGuard) recordedWorkspace(ctx context.Context, id Identification, stated StatedWorkspace, prior RunMapping) (Workspace, error) {
	if stated.HasRepo() {
		return stated.Workspace(), nil
	}
	if last, ok := g.sessionWorkspaces.LastRepo(id.SessionID); ok {
		return last.Workspace(), nil
	}
	anchor := prior.RunID
	if anchor == "" {
		runID, err := g.sessionMainRun(ctx, id.SessionID)
		if err != nil {
			return Workspace{}, err
		}
		anchor = runID
	}
	if anchor == "" {
		return Workspace{}, nil
	}
	reg, err := g.runStates.RunRegistration(ctx, anchor)
	if err != nil {
		return Workspace{}, fmt.Errorf("read run %q's registration for the session's repository: %w", anchor, err)
	}
	return Workspace{Repo: reg.Repo, Task: reg.TaskID}, nil
}

// errOutOfScope is a run the installation may not register: no repository to
// register it under, or one outside its scope. The request is forwarded
// unrecorded and reported (RM-313), never refused.
var errOutOfScope = errors.New("the stated repository is outside the installation's scope")

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

// sessionOwner answers the installation recorded for this session's runs:
// this agent's latest mapping row, else the session's main agent's. Empty
// when neither row names one (a new session, or single-host rows).
func (g *IdentityGuard) sessionOwner(ctx context.Context, id Identification) (string, error) {
	for _, agent := range []string{id.AgentID, mainAgentID} {
		if m, ok := g.cache.get(id.SessionID, agent); ok && m.ClientID != "" {
			return m.ClientID, nil
		}
		m, found, err := g.mappings.BySessionAgent(ctx, id.SessionID, agent)
		if err != nil {
			return "", err
		}
		if found && m.ClientID != "" {
			return m.ClientID, nil
		}
	}
	return "", nil
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
// RM-263 (#416), RM-314: agentTypeFor turns it, the hook's own agent_type
// (facts.Stated.AgentType) and id into what actually reaches
// RegisterInput.AgentType, and the harness string the mapping row keeps.
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
		ws, err := g.resolveWorkspace(ctx, id, facts, prior)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a new run: %w", err)
		}
		agentType, verbatim := g.agentTypeFor(id, facts.Stated.AgentType, spawnAgentType)
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:      agentType,
			IdempotencyKey: idempotencyKeyFor(id),
			Workspace:      ws,
			ParentRunID:    parentRunID,
		})
		if err != nil {
			return "", fmt.Errorf("register a new run: %w", err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, ParentRunID: parentRunID, AgentTypeVerbatim: verbatim,
		})
		return out.RunID, nil

	case DecisionFork:
		ws, err := g.resolveWorkspace(ctx, id, facts, prior)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a fork of run %q: %w", prior.RunID, err)
		}
		agentType, verbatim := g.agentTypeFor(id, facts.Stated.AgentType, spawnAgentType)
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:       agentType,
			IdempotencyKey:  idempotencyKeyFor(id),
			Workspace:       ws,
			ForkedFromRunID: prior.RunID,
		})
		if err != nil {
			return "", fmt.Errorf("register a fork of run %q: %w", prior.RunID, err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, ForkedFromRunID: prior.RunID, AgentTypeVerbatim: verbatim,
		})
		return out.RunID, nil

	case DecisionAdopt:
		ws, err := g.resolveWorkspace(ctx, id, facts, prior)
		if err != nil {
			return "", fmt.Errorf("resolve the workspace to register a run adopting %q: %w", prior.RunID, err)
		}
		agentType, verbatim := g.agentTypeFor(id, facts.Stated.AgentType, spawnAgentType)
		out, err := g.registrar.Register(ctx, RegisterInput{
			AgentType:      agentType,
			IdempotencyKey: idempotencyKeyFor(id),
			Workspace:      ws,
		})
		if err != nil {
			return "", fmt.Errorf("register a run adopting %q: %w", prior.RunID, err)
		}
		g.insertAndCache(ctx, id, RunMapping{
			RunID: out.RunID, SessionID: id.SessionID, AgentID: id.AgentID,
			Fingerprint: fp, AdoptedFromRunID: prior.RunID, AgentTypeVerbatim: verbatim,
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
	if m.ClientID == "" {
		m.ClientID, _ = InstallationFromContext(ctx)
	}
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
