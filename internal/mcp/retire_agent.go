// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// retire_agent — RM-025 (#33). IP §4:
//
//	retire_agent(run_id) → {retired_at}. Deletes SPIRE entry, appends
//	`run_retired`. Idempotent: retiring a retired run returns success with the
//	original timestamp.
//
// # The order the two systems are written in
//
// A SPIRE entry and a ledger event live in different systems, so no
// transaction spans them; what can be chosen is the order, and which side the
// failure window falls on. ADR-0018 settled it for both directions and named
// this tool explicitly: **the ledger may describe an identity that does not
// exist; SPIRE must never hold an identity the ledger does not describe.**
// Registration appends `run_registered` and then creates the entry; RM-017's
// reaper appends `run_expired` and then deletes; retirement appends
// `run_retired` and then deletes.
//
//  1. append `run_retired`,
//  2. then delete the SPIRE entry.
//
// THE NAMED FAILURE MODE: a crash — or a ledger success followed by a SPIRE
// refusal — leaves a run the ledger describes as retired whose registration
// entry still exists. The call reports the SPIRE failure with SPIRE's own
// class, so the caller knows the retirement is incomplete, and a retry
// converges: the record is already there, no second event is appended, and the
// entry is deleted. Nothing can be done under the run in the meantime, because
// every MCP path resolves a run through the ledger-backed run directory first
// and refuses a retired one (MCP-009). A caller that never retries leaves the
// entry for RM-017's reaper, which deletes it at its deadline.
//
// The other order is worse in the way that matters. Deleting first and
// crashing leaves an identity destroyed with nothing anywhere recording that
// it existed or why it went — I3 ("no action without a record") broken, and
// permanently, because nothing afterwards can reconstruct the instant. It also
// misreports the run in the window: with the entry gone and no `run_retired`,
// `get_credential` refuses at its SPIRE gate with RUN_NOT_FOUND, which says
// the run never existed rather than that it was retired.
//
// Retirement is the one direction where ledger-first is not merely the safer
// window but the *effective* one: writing the record is precisely what makes
// retirement take effect through the MCP, so doing it first shortens, rather
// than lengthens, the interval in which a retired run is still credentialable.
//
// # Where the original timestamp comes from
//
// `retired_at` is the `ts` the ledger assigned to `run_retired`, read back off
// the append and, on every later call, out of the run directory — which reads
// the chain. This tool reads no clock. The ledger is the only durable record
// of when a retirement happened (I4 keeps it; the SPIRE entry is deleted), so
// answering from anywhere else would let the reply and the record of one
// retirement disagree, and disagree permanently.
//
// # Idempotency, and why there is no key
//
// ADR-0004: `retire_agent` accepts no `idempotency_key` and `run_retired`
// carries none. "A run retires once. A separate key would invent a way for two
// retirements of one run to disagree, which is a contradiction the ledger
// would then have to record." Idempotency is intrinsic to `run_id`: the
// question "has this run been retired?" has one durable answer, and this tool
// asks it rather than dedupes against a key. The MCP idempotency store
// (ADR-0017) is therefore not used here either — it is keyed by a
// caller-supplied key this tool does not have, and synthesising one would put
// retirement at the mercy of a caller that happened to use the same string for
// something else.
//
// The cost is that the check and the append are two steps rather than one, and
// the mechanism that would fuse them is the one ADR-0004 forbids. Two
// genuinely concurrent FIRST retirements of one run can therefore both find no
// record and both append, leaving two `run_retired` events. Both callers are
// still told the same instant, because the directory answers with the
// earliest; at most one deletion finds an entry, and the other is the success
// with nothing deleted that IP §4 already requires; and every later call is
// answered from the earliest record. What the window cannot produce is a
// retirement that is not recorded, or an entry deleted without a record.
//
// # Immediacy is this layer's obligation
//
// IP §6.2: retirement is effective immediately, with no cached-credential
// grace path through the MCP. SPIRE's own convergence is not immediate —
// RM-014 measured 3–7 seconds for a deleted entry to fall out of the server's
// cache and then the agent's — so immediacy cannot be inherited from it. It is
// discharged server-side: this tool caches nothing, and the record it writes
// is authoritative the instant it commits, which is before the entry is even
// deleted.

// retireAgentIn is IP §4's parameter list, exactly: one run_id, and — ADR-0004
// — no idempotency_key, now or ever.
type retireAgentIn struct {
	RunID string `json:"run_id"`
}

// retireAgentOut is IP §4's result shape, exactly: {retired_at}.
//
// The instant is spelled the way doc 02 §1 spells one — RFC 3339 UTC at
// millisecond precision — which is the same string the `run_retired` event
// carries in `ts`, so the reply and the record cannot disagree by format.
type retireAgentOut struct {
	RetiredAt string `json:"retired_at"`
}

// RetireAgentEntries is the SPIRE surface this tool needs: RM-015's admin
// client, as an interface so the error paths are testable without a container.
// *spire.Client satisfies it.
//
// RetireRun deletes the run's registration entry and nothing else. It never
// touches ledger content (I4), and it is itself idempotent: a run SPIRE holds
// no entry for is a success with nothing deleted.
type RetireAgentEntries interface {
	RetireRun(ctx context.Context, run spire.RunRef) (spire.Retirement, error)
}

// RetireAgentLedger is the ledger surface this tool needs. *ledger.Store
// satisfies it.
type RetireAgentLedger interface {
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// The production implementations must satisfy the interfaces above, or the
// doubles the contract tests use would be free to drift from what this tool is
// actually handed.
var (
	_ RetireAgentEntries = (*spire.Client)(nil)
	_ RetireAgentLedger  = (*ledger.Store)(nil)
)

// RetireAgentConfig is what retire_agent runs on. Install it with
// ConfigureRetireAgent before serving.
type RetireAgentConfig struct {
	// Runs resolves run_id to the run it names, and reports when that run was
	// retired. Required.
	//
	// It is get_credential's directory interface and deliberately not a second
	// one: doc 07 MCP-009 is about every tool agreeing that a run is retired,
	// and two definitions of "what is a run" are two things that can disagree
	// about exactly that. Its RetiredAt must be the EARLIEST `run_retired` for
	// the run — the original, which IP §4 requires every later call to be
	// answered with.
	Runs CredentialRuns
	// Entries is the SPIRE admin client. Required: a retirement that cannot
	// delete the entry has not retired the identity (IP §1).
	Entries RetireAgentEntries
	// Ledger is the append-only event store. Required — I3 admits no action
	// without a record, and deleting an identity is an action.
	Ledger RetireAgentLedger
}

// retireService is the configured tool.
//
// There is no clock here, and that is deliberate: every instant this tool
// reports comes from the ledger.
type retireService struct {
	runs    CredentialRuns
	entries RetireAgentEntries
	ledger  RetireAgentLedger
}

// retireActive holds the installed configuration.
//
// It is package state because ADR-0016 §5 fixes the seam: a tool file
// registers its own binder from its own init and the binder receives only the
// *Server, so there is nowhere else for a tool's dependencies to be handed in
// without a file every tool author would have to edit.
var (
	retireMu     sync.RWMutex
	retireActive *retireService
)

// ConfigureRetireAgent installs the dependencies retire_agent runs on and
// returns a function restoring whatever was installed before.
//
// A configuration missing a dependency is refused here rather than at the
// first call: an operator finds out at start-up, not when an agent tries to
// retire a run and cannot.
func ConfigureRetireAgent(cfg RetireAgentConfig) (func(), error) {
	switch {
	case cfg.Runs == nil:
		return nil, retireAgentMisconfigured(
			"no run directory: nothing knows what a run_id names, or whether it is already retired")
	case cfg.Entries == nil:
		return nil, retireAgentMisconfigured(
			"no SPIRE client: retire_agent cannot delete the run's entry, and the identity would outlive the run")
	case cfg.Ledger == nil:
		return nil, retireAgentMisconfigured(
			"no ledger: retire_agent cannot record the retirement (I3), and the instant would be unrecoverable")
	}
	svc := &retireService{runs: cfg.Runs, entries: cfg.Entries, ledger: cfg.Ledger}

	retireMu.Lock()
	defer retireMu.Unlock()
	previous := retireActive
	retireActive = svc
	return func() {
		retireMu.Lock()
		defer retireMu.Unlock()
		retireActive = previous
	}, nil
}

// retireAgentMisconfigured names a dependency the tool cannot run without.
func retireAgentMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "retire_agent configuration: %s", detail)
}

func init() { RegisterTool(ToolRetireAgent, bindRetireAgent) }

func bindRetireAgent(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolRetireAgent),
		Description: "Retire one agent run: record run_retired in the ledger and delete the run's " +
			"SPIRE entry. Effective immediately, and idempotent — retiring a retired run " +
			"succeeds with the instant it was originally retired. No ledger event is ever removed.",
	}, retireAgent)
}

func retireAgent(ctx context.Context, _ *sdk.CallToolRequest, in retireAgentIn) (retireAgentOut, error) {
	retireMu.RLock()
	svc := retireActive
	retireMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return retireAgentOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"retire_agent is bound but not configured; no run can be retired")
	}
	return svc.retire(ctx, in)
}

// retire is the three gates, the record, and the deletion — in that order.
func (s *retireService) retire(ctx context.Context, in retireAgentIn) (retireAgentOut, error) {
	// Gate 1 — a run id that cannot name a run names no run. Checked before
	// any dependency is consulted, so a malformed id costs nothing and reaches
	// neither the ledger nor SPIRE.
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return retireAgentOut{}, Errorf(ClassRunNotFound, "",
			"%q is not a run id: %v", in.RunID, err)
	}

	// Gate 2 — the run exists, and the ledger says whether it is already
	// retired. This one read is both the idempotency check and the source of
	// the original instant.
	run, found, err := s.runs.CredentialRun(ctx, in.RunID)
	if err != nil {
		return retireAgentOut{}, credentialLedgerError(in.RunID, err)
	}
	if !found {
		return retireAgentOut{}, Errorf(ClassRunNotFound, in.RunID, "no run %q", in.RunID)
	}

	// Gate 3 — the directory answered about the run that was asked for, and
	// the identity it named is that run's own, inside the /agent/ subtree.
	// get_credential makes this check before asking SPIRE to MINT; the same
	// check is made here before asking SPIRE to DELETE, because a directory
	// that answered with another run's identity would otherwise be a way to
	// delete an entry that is not this run's. It is deliberately the same
	// function and not a second copy of the rule.
	spiffeID, err := credentialRunIdentity(in.RunID, run)
	if err != nil {
		return retireAgentOut{}, err
	}

	retiredAt := event.NewTimestamp(run.RetiredAt)
	if !run.Retired() {
		// Ledger first. See the ordering note at the top of this file.
		if retiredAt, err = s.record(ctx, run, spiffeID); err != nil {
			return retireAgentOut{}, err
		}
	}

	// SPIRE second — and on the already-retired path too, not only the first
	// time. A retirement whose deletion failed left the entry behind, and this
	// is what converges it; RetireRun is idempotent, so a run whose entry is
	// already gone costs one lookup and deletes nothing.
	//
	// A failure here is reported with internal/spire's own class (IP §6.1:
	// SPIRE unreachable is IDENTITY_UNAVAILABLE and retryable). The record
	// stands regardless — I4 — so the retry is a convergence, not a repeat.
	ref, err := run.Ref()
	if err != nil {
		return retireAgentOut{}, err
	}
	if _, err := s.entries.RetireRun(ctx, ref); err != nil {
		return retireAgentOut{}, err
	}

	return retireAgentOut{RetiredAt: retiredAt.String()}, nil
}

// record appends the `run_retired` event of doc 02 §3 and returns the instant
// the ledger stamped on it.
//
// Every member name here is a protected string. `source` is `mcp` because an
// MCP tool call appended it. There is no `idempotency_key` — ADR-0004 forbids
// one on this event type, whatever the source, and the ledger enforces the
// absence — and no type-specific members: doc 02 §3 gives `run_retired` none,
// because the fact being recorded is the retirement itself and nothing about
// it needs a payload (E4). event_id, ts, chain_position, prev_event_hash and
// event_hash are the ledger's to assign and are deliberately absent.
func (s *retireService) record(ctx context.Context, run CredentialRun, spiffeID string) (event.Timestamp, error) {
	record, err := s.ledger.Append(ctx, event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     event.EventTypeRunRetired,
		event.FieldSource:        event.SourceMCP,
		event.FieldRunID:         run.RunID,
		event.FieldSpiffeID:      spiffeID,
	})
	if err != nil {
		return event.Timestamp{}, credentialLedgerError(run.RunID, err)
	}
	return retireAgentInstant(run.RunID, record)
}

// retireAgentInstant reads the `ts` the ledger assigned to the retirement.
//
// The ledger's answer is checked rather than trusted, for the same reason the
// run directory's is: the entire content of this tool's reply is one instant,
// and an empty or unreadable one would be handed to a caller as though the
// retirement had no time. Refusing is the only safe answer — the record itself
// stands (I4), so a caller that retries reaches this code again with whatever
// the ledger holds, and an operator sees an alert rather than a blank field.
func retireAgentInstant(runID string, record event.Fields) (event.Timestamp, error) {
	raw, ok := record[event.FieldTS].(string)
	if !ok {
		return event.Timestamp{}, Errorf(ClassInvariantViolation, runID,
			"the ledger recorded the retirement of %q with no %s; there is no instant to answer with",
			runID, event.FieldTS)
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		return event.Timestamp{}, Errorf(ClassInvariantViolation, runID,
			"the ledger recorded the retirement of %q at %q, which is not a doc 02 §1 instant: %w",
			runID, raw, err)
	}
	return ts, nil
}
