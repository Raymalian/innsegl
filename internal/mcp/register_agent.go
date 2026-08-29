// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// register_agent — RM-022 (#30), IP §4:
//
//	register_agent(agent_type, task_id, idempotency_key) →
//	    {spiffe_id, run_id, expires_at}.
//	Creates SPIRE entry + `run_registered` event atomically.
//	Same idempotency_key → same run, never a second identity.
//
// # The two systems, and the order they are written in
//
// A SPIRE entry and a ledger event live in different systems, so there is no
// transaction that spans them and "atomically" cannot mean what it means
// inside one database. What it can mean is that one order is chosen, its
// failure window is named, and the window is on the side that cannot break an
// invariant. ADR-0018 records the choice; it is:
//
//  1. append `run_registered`,
//  2. then create the SPIRE entry.
//
// A crash between them leaves a RECORD WITH NO IDENTITY. Nothing can be signed
// under that run — SPIRE holds no entry, so `get_credential` refuses — and the
// replay converges: the ledger's UNIQUE idempotency_key returns the original
// event rather than writing a second (LED-008), and the entry is then created.
//
// The other order leaves an IDENTITY WITH NO RECORD, which is I3 ("no action
// without a record") broken in the direction that lets attributed work happen
// off the books. RM-017's reaper faced the mirror of this and chose the same
// way: it records `run_expired` BEFORE deleting the entry. Read together the
// rule is one rule — the ledger is written before the identity changes state,
// in both directions — so the record may run ahead of SPIRE and can never fall
// behind it.
//
// # Why the run id is derived and not minted
//
// ADR-0017's idempotency store returns the recorded reply on a replay, but a
// claim whose lease has run out is TAKEN OVER and the tool runs a second time.
// That second execution must not mint a second identity, so the run id is a
// pure function of the arguments that name the run (see registerAgentRunID).
// Two executions of one call therefore ask SPIRE for the same entry, and SPIRE
// answers the second with DUPLICATE_REQUEST rather than a second identity —
// which is the inner idempotency ADR-0017 §5 relies on being there.

func init() { RegisterTool(ToolRegisterAgent, bindRegisterAgent) }

// registerAgentIn is IP §4's argument list, verbatim. The member names are
// part of the tool contract that MCP-001 pins.
type registerAgentIn struct {
	// AgentType is the {agent-type} component of the run's SPIFFE ID. It is
	// held to doc 02 §5's identifier grammar because that is where it ends up.
	AgentType string `json:"agent_type"`
	// TaskID is the caller's task reference. It is recorded verbatim as the
	// event's `task_ref` and lowercased into the SPIFFE ID's {task-id} — which
	// is exactly what golden fixture 01 shows: task_ref "JIRA-118" against
	// spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42.
	TaskID string `json:"task_id"`
	// IdempotencyKey makes the call repeatable (IP §6.6, ADR-0004).
	IdempotencyKey string `json:"idempotency_key"`
}

// registerAgentOut is IP §4's result shape, verbatim.
type registerAgentOut struct {
	SPIFFEID string `json:"spiffe_id"`
	RunID    string `json:"run_id"`
	// ExpiresAt is when the identity stops being usable: the instant the entry
	// was created plus the TTL SPIRE actually applied to it, in doc 02 §1's
	// timestamp form. It is read off the entry rather than off the request, so
	// it never promises a lifetime SPIRE did not grant.
	ExpiresAt string `json:"expires_at"`
}

// RegisterAgentIdentities is the SPIRE surface this tool needs — RM-015's
// admin client, as an interface so that the tool's error paths are testable
// without a SPIRE and so that this package holds no SPIRE client of its own.
// *spire.Client satisfies it.
type RegisterAgentIdentities interface {
	// TrustDomain is the trust domain the run's SPIFFE ID is built in.
	TrustDomain() string
	// RegisterRun creates exactly one entry per run, and reports a second
	// registration of one run as DUPLICATE_REQUEST.
	RegisterRun(ctx context.Context, reg spire.Registration) (spire.Entry, error)
	// LookupRun returns the run's entry, and whether SPIRE holds one.
	LookupRun(ctx context.Context, run spire.RunRef) (spire.Entry, bool, error)
}

// RegisterAgentLedger is the ledger surface this tool needs. *ledger.Store
// satisfies it.
type RegisterAgentLedger interface {
	// Append writes one event; an append whose idempotency_key has already
	// been used returns the original event and writes nothing (LED-008).
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// The production implementations must satisfy the two interfaces above, or the
// fakes the contract tests use would be free to drift from what this tool will
// actually be handed.
var (
	_ RegisterAgentIdentities = (*spire.Client)(nil)
	_ RegisterAgentLedger     = (*ledger.Store)(nil)
)

// RegisterAgentConfig is what register_agent runs on. Install it with
// ConfigureRegisterAgent before serving.
type RegisterAgentConfig struct {
	// Identities is the SPIRE admin client. Required.
	Identities RegisterAgentIdentities
	// Ledger is the append-only event store. Required.
	Ledger RegisterAgentLedger
	// Idempotency records the reply of each keyed call (ADR-0017). Required.
	Idempotency *IdempotencyStore
	// ParentID is the attested node every run entry hangs off. Required: an
	// entry with no reachable parent is an entry no workload can ever match.
	ParentID string
	// Selectors are what the workload must match for SPIRE to attest it (I1).
	// Nil means DefaultRegisterAgentSelectors.
	Selectors func(spire.RunRef) []spire.Selector
	// TTL is the identity lifetime asked for. Zero lets internal/spire apply
	// its own default; internal/spire refuses anything above spire.MaxRunTTL,
	// and this tool does not second-guess that (IP §6.2).
	TTL time.Duration
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// DefaultRegisterAgentSelectors binds a run's entry to the workload carrying
// that run's labels — the convention RM-015's SPIRE harness attests against
// and deploy/compose/spire/agent.conf documents.
//
// Three selectors and not one: SPIRE requires a workload to match all of them,
// so a container that carries only the run id but belongs to another task
// cannot pick up this identity. Selector strength is review surface, not
// something this package can judge (doc 04) — a deployment with a different
// attestor supplies its own function.
func DefaultRegisterAgentSelectors(run spire.RunRef) []spire.Selector {
	return []spire.Selector{
		{Type: "docker", Value: "label:dev.innsegl.run-id:" + run.RunID},
		{Type: "docker", Value: "label:dev.innsegl.agent-type:" + run.AgentType},
		{Type: "docker", Value: "label:dev.innsegl.task-id:" + run.TaskID},
	}
}

// registerAgentState holds the installed configuration.
//
// It is package state because ADR-0016 §5 fixes the seam: a tool file
// registers its own binder from its own init and the binder receives only the
// *Server, so there is nowhere else for a tool's dependencies to be handed in
// without a file every tool author would have to edit.
var registerAgentState struct {
	mu  sync.RWMutex
	cfg *RegisterAgentConfig
}

// ConfigureRegisterAgent installs the dependencies register_agent runs on and
// returns a function restoring whatever was installed before.
//
// A configuration missing a dependency is refused here rather than at the
// first call: an operator finds out at start-up, not when an agent does.
func ConfigureRegisterAgent(cfg RegisterAgentConfig) (func(), error) {
	if cfg.Identities == nil {
		return nil, registerAgentMisconfigured("no SPIRE client: register_agent cannot mint an identity (I1)")
	}
	if cfg.Ledger == nil {
		return nil, registerAgentMisconfigured("no ledger: register_agent cannot record the issuance (I3)")
	}
	if cfg.Idempotency == nil {
		return nil, registerAgentMisconfigured(
			"no idempotency store: a replay could mint a second identity (IP §6.6, ADR-0017)")
	}
	if cfg.ParentID == "" {
		return nil, registerAgentMisconfigured(
			"no parent id: an entry with no attested parent is one no workload can match (I1)")
	}
	if cfg.Selectors == nil {
		cfg.Selectors = DefaultRegisterAgentSelectors
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	registerAgentState.mu.Lock()
	defer registerAgentState.mu.Unlock()
	previous := registerAgentState.cfg
	registerAgentState.cfg = &cfg
	return func() {
		registerAgentState.mu.Lock()
		defer registerAgentState.mu.Unlock()
		registerAgentState.cfg = previous
	}, nil
}

// registerAgentMisconfigured names a dependency the tool cannot run without.
func registerAgentMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "register_agent configuration: %s", detail)
}

// registerAgentConfigured returns the installed configuration.
func registerAgentConfigured() (*RegisterAgentConfig, error) {
	registerAgentState.mu.RLock()
	defer registerAgentState.mu.RUnlock()
	if registerAgentState.cfg == nil {
		return nil, registerAgentMisconfigured(
			"the tool is advertised but not wired; it refuses rather than minting an unrecorded identity")
	}
	return registerAgentState.cfg, nil
}

func bindRegisterAgent(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolRegisterAgent),
		Description: "Register one agent run: record run_registered in the ledger and create the " +
			"run's SPIRE entry. The same idempotency_key always names the same run.",
	}, registerAgent)
}

func registerAgent(ctx context.Context, _ *sdk.CallToolRequest, in registerAgentIn) (registerAgentOut, error) {
	cfg, err := registerAgentConfigured()
	if err != nil {
		return registerAgentOut{}, err
	}
	return cfg.register(ctx, in)
}

// register is the tool, once its dependencies are known.
func (c *RegisterAgentConfig) register(ctx context.Context, in registerAgentIn) (registerAgentOut, error) {
	run, err := registerAgentRun(in)
	if err != nil {
		return registerAgentOut{}, err
	}
	spiffeID, err := run.SPIFFEID(c.Identities.TrustDomain())
	if err != nil {
		return registerAgentOut{}, err
	}

	// The key is validated by the store, which owns doc 02 §2's bound on it
	// and refuses a key naming a different request (ADR-0017 §3). Nothing has
	// happened yet at this point, so a refusal here costs nothing.
	outcome, err := c.Idempotency.Do(ctx, Call{
		Tool: string(ToolRegisterAgent),
		Key:  in.IdempotencyKey,
		// The arguments that make this request this request. The key itself is
		// not among them: it is what the fingerprint is looked up by.
		Params: map[string]any{"agent_type": in.AgentType, "task_id": in.TaskID},
	}, func(ctx context.Context) (any, error) {
		return c.mint(ctx, run, spiffeID, in)
	})
	if err != nil {
		return registerAgentOut{}, err
	}

	var out registerAgentOut
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return registerAgentOut{}, Errorf(ClassInvariantViolation, run.RunID,
			"the recorded reply for idempotency_key %q is not a register_agent result: %w",
			in.IdempotencyKey, err)
	}
	return out, nil
}

// mint records the issuance and then creates the identity, in that order.
//
// See the ordering note at the top of this file: the append comes first
// because a record with no identity is inert, and an identity with no record
// is I3 broken.
func (c *RegisterAgentConfig) mint(ctx context.Context, run spire.RunRef, spiffeID string, in registerAgentIn) (any, error) {
	if _, err := c.Ledger.Append(ctx, registerAgentEvent(run, spiffeID, in)); err != nil {
		return nil, registerAgentLedgerError(run.RunID, err)
	}
	entry, err := c.identity(ctx, run)
	if err != nil {
		return nil, err
	}
	// spiffeID rather than entry.SPIFFEID: the reply names the identity the
	// ledger recorded, so a reply and a record can never disagree. RegisterRun
	// already refuses an entry SPIRE created under a different ID.
	return registerAgentOut{
		SPIFFEID:  spiffeID,
		RunID:     run.RunID,
		ExpiresAt: event.NewTimestamp(c.Now().Add(entry.TTL)).String(),
	}, nil
}

// identity creates the run's SPIRE entry, or adopts the one already there.
//
// An entry for this run existing already is not an error and not a second
// identity: the run id is derived, so the only thing that can have created it
// is this same call, executed a second time after its claim's lease ran out
// (ADR-0017 §5). Adopting it is what makes that second execution harmless.
func (c *RegisterAgentConfig) identity(ctx context.Context, run spire.RunRef) (spire.Entry, error) {
	entry, err := c.Identities.RegisterRun(ctx, spire.Registration{
		Run:       run,
		ParentID:  c.ParentID,
		Selectors: c.Selectors(run),
		TTL:       c.TTL,
	})
	if err == nil {
		return entry, nil
	}
	if class, _ := spire.ClassOf(err); class != spire.ClassDuplicateRequest {
		// IP §6.1: spire-server down is IDENTITY_UNAVAILABLE and retryable,
		// an attestation refusal is ATTESTATION_FAILED and is not. Both are
		// internal/spire's to classify and neither is re-derived here. Nothing
		// is queued and no provisional identity is handed back.
		return spire.Entry{}, err
	}

	existing, found, err := c.Identities.LookupRun(ctx, run)
	if err != nil {
		return spire.Entry{}, err
	}
	if !found {
		// SPIRE said the entry exists and then said it does not. The only
		// things that delete a run's entry are retirement and the reaper, and
		// both mean the run is over — so this fails closed rather than
		// re-creating the entry and resurrecting a retired identity
		// (IP §6.2: retirement is effective immediately).
		return spire.Entry{}, Errorf(ClassRunAlreadyRetired, run.RunID,
			"SPIRE reported an existing entry for this run and then held none; "+
				"the run has been retired or expired and is not re-registered under the same key")
	}
	return existing, nil
}

// registerAgentEvent is the `run_registered` event of doc 02 §3.
//
// Every member name here is a protected string. `source` is `mcp` because an
// MCP tool call appended it, and `idempotency_key` is present because
// ADR-0004 requires it on exactly the events whose originating tool accepts
// one. event_id, ts, chain_position, prev_event_hash and event_hash are the
// ledger's to assign and are deliberately absent.
func registerAgentEvent(run spire.RunRef, spiffeID string, in registerAgentIn) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: in.IdempotencyKey,
		event.FieldAgentType:      run.AgentType,
		// The caller's reference, verbatim. doc 02 §3's `task_ref` is an
		// external reference and deliberately not the SPIFFE ID's {task-id}.
		event.FieldTaskRef: in.TaskID,
	}
}

// registerAgentRunPrefix and registerAgentRunIDHexDigits shape the derived run
// id. The prefix makes a run id legible in a SPIFFE ID and in a log line
// (golden fixture 01's is "run-42"); 32 hex digits is 128 bits of the digest,
// which is what fits doc 02 §5's 63-character identifier with room to spare.
const (
	registerAgentRunPrefix      = "run-"
	registerAgentRunIDHexDigits = 32
)

// registerAgentRunID derives the run id from the three arguments that name the
// run: the same call always names the same run, on any replica, after any
// crash, with nothing shared between them.
//
// This is what makes a second EXECUTION of one call harmless. ADR-0017 takes
// over a claim whose lease ran out and runs the tool again; a minted run id
// would give that second execution a different identity to create, and MCP-007
// would fail in the one interleaving nobody watches. A derived one gives it
// the identity that already exists.
//
// The preimage is the three values quoted, so no run of concatenations can
// spell another triple: strconv-style quoting escapes the quotes it adds.
// Truncating to 128 bits leaves a collision — two different keys naming one
// run — at a birthday bound far beyond the number of runs a deployment can
// hold, and the idempotency store refuses a key naming a different request
// before the run id is ever consulted.
func registerAgentRunID(in registerAgentIn) string {
	preimage := strconv.Quote(in.AgentType) + strconv.Quote(in.TaskID) + strconv.Quote(in.IdempotencyKey)
	digest := strings.TrimPrefix(event.Digest([]byte(preimage)), event.HashPrefix)
	return registerAgentRunPrefix + digest[:registerAgentRunIDHexDigits]
}

// registerAgentRun turns IP §4's arguments into the run they name.
//
// agent_type is used as given: doc 02 §3 holds it to the identifier grammar
// because it is a component of the SPIFFE ID, and silently rewriting it would
// make the recorded agent_type differ from the one the caller believes it
// registered. task_id is lowercased for the SPIFFE ID's {task-id} and kept
// verbatim for the event's task_ref, which is the split golden fixture 01
// shows.
func registerAgentRun(in registerAgentIn) (spire.RunRef, error) {
	if err := event.ValidateIdentifier(in.AgentType); err != nil {
		return spire.RunRef{}, Errorf(ClassInvariantViolation, "",
			"agent_type is not a run identity component (doc 02 §5): %w", err)
	}
	taskID := strings.ToLower(in.TaskID)
	if err := event.ValidateIdentifier(taskID); err != nil {
		return spire.RunRef{}, Errorf(ClassInvariantViolation, "",
			"task_id %q is not a run identity component once lowercased (doc 02 §5): %w",
			in.TaskID, err)
	}
	return spire.RunRef{
		AgentType: in.AgentType,
		TaskID:    taskID,
		RunID:     registerAgentRunID(in),
	}, nil
}

// registerAgentLedgerSource names this layer in a classified error.
const registerAgentLedgerSource = "internal/ledger, through register_agent"

// registerAgentLedgerError carries a ledger failure into IP §4's vocabulary.
//
// internal/ledger keeps the same eleven spellings but does not implement
// Classified, so it is mapped across by string identity here — the same move
// Classify makes for *spire.Error, and for the same reason: one vocabulary,
// so a rename in either package fails the mapping loudly rather than inventing
// a class. classifyAs ANDs the flag with the class default (ADR-0016), so this
// layer can narrow `retryable` and cannot widen it.
//
// A failure the ledger did not classify is returned untouched, and Classify
// reports it as INVARIANT_VIOLATION: an unnamed failure inside the MCP is a
// defect, and IP §4 has no class for one.
func registerAgentLedgerError(runID string, err error) error {
	var stored *ledger.StoreError
	if !errors.As(err, &stored) {
		return err
	}
	return classifyAs(Class(stored.Class), runID, stored.Error(), stored.Retryable,
		registerAgentLedgerSource, err)
}
