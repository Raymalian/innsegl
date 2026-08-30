// SPDX-License-Identifier: Apache-2.0

// Package rundir is the shipped run directory: the ledger-backed answer to
// "does this run exist, what is its identity, and has it been retired?".
//
// # Why this package exists at all, and why here
//
// `mcp.CredentialRuns` is the seam three of the five IP §4 tools begin at.
// RM-023 declared it and deliberately shipped no implementation, writing that
// "the run directory is shared with the other four tools, and a second
// definition of what is a run is a second thing that can disagree about
// retirement". Until this package there was no first definition either: every
// implementation in the repository was a test double, so a deployment could
// wire `get_credential`, `record_event` and `retire_agent` to nothing.
//
// It is its own package because it is the only component that has to know both
// halves and neither half may know it:
//
//   - `internal/ledger` cannot hold it. That package's own documentation states
//     the boundary — "The chain is type-agnostic. It does not know what an
//     event means: no event_type enum, no per-type required members" — and this
//     reader is nothing but event_type and per-type members. It would also have
//     to import `internal/mcp`, which imports `internal/ledger`: an import
//     cycle, not a style question.
//   - `internal/mcp` cannot hold it. IP §1 makes that package the transport,
//     the tool surface and the admin credential; a Postgres query per run in it
//     would put a storage layout inside the component whose whole contract is
//     the wire. It is also a closed, protected surface.
//
// So the directory sits above both, imports both, and is imported by the entry
// point that wires them together.
//
// # It believes nothing it did not read on the chain
//
// Every value here comes out of a `run_registered` event: the identity, the
// agent type and the task. Nothing is derived from anything else — in
// particular `agent_type` and `task_ref` are READ from the event rather than
// parsed back out of `spiffe_id`. That is what makes `mcp.credentialRunIdentity`
// a real check: it requires `spiffe_id` to end in
// `/agent/{agent_type}/{task_id}/{run_id}`, and a directory that had split the
// SPIFFE ID to obtain those three components would satisfy that check by
// construction, whatever the ledger actually held.
package rundir

import (
	"context"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
)

// RunEvents is the run-scoped ledger read this directory is built on: every
// event carrying one run_id, in chain order. *ledger.Store implements it.
//
// It is an interface so that the reader's refusals — every one of which is a
// chain this package must never guess about — are testable exhaustively
// without a database per case, and so that this package holds no pool of its
// own.
type RunEvents interface {
	EventsForRun(ctx context.Context, runID string) ([]event.Fields, error)
}

var _ RunEvents = (*ledger.Store)(nil)

// Config is what a Directory needs.
type Config struct {
	// Events is the run-scoped ledger read. Required.
	Events RunEvents
}

// Directory answers mcp.CredentialRuns out of the hash chain.
type Directory struct{ events RunEvents }

var _ mcp.CredentialRuns = (*Directory)(nil)

// New builds a Directory, or refuses.
//
// A directory with nothing to read would report every run unknown, which is
// indistinguishable from a fresh deployment: `get_credential` would answer
// RUN_NOT_FOUND for a run that exists, and `retire_agent` would refuse to
// retire an identity that is live. It is refused at construction so an
// operator finds out at start-up rather than when an agent does.
func New(cfg Config) (*Directory, error) {
	if cfg.Events == nil {
		return nil, mcp.Errorf(mcp.ClassInvariantViolation, "",
			"rundir: no ledger to read; a run directory with no chain reports every run unknown")
	}
	return &Directory{events: cfg.Events}, nil
}

// CredentialRun returns the run named by runID, and whether the chain knows
// one.
//
// An unknown run is not an error: it is RUN_NOT_FOUND, which the tools
// classify. A run the chain describes in a way this reader cannot read IS an
// error, and an alert-level one — three tools mint, append and delete against
// this answer, so a member that cannot be read is never a zero value.
//
// The ledger's own failure is returned verbatim, so that a ledger outage
// reaches the caller as LEDGER_UNAVAILABLE and retryable rather than as a
// defect inside the MCP. `mcp.credentialLedgerError` performs that mapping at
// every call site.
//
// An empty runID is not special-cased. `internal/ledger` refuses it — `run_id`
// is nullable, and the events that carry no run must never be matched by an
// empty string — and one refusal in one place is the point of the seam.
func (d *Directory) CredentialRun(ctx context.Context, runID string) (mcp.CredentialRun, bool, error) {
	records, err := d.events.EventsForRun(ctx, runID)
	if err != nil {
		return mcp.CredentialRun{}, false, err
	}

	var (
		run        mcp.CredentialRun
		registered bool
	)
	for _, rec := range records {
		if err := checkScope(rec, runID); err != nil {
			return mcp.CredentialRun{}, false, err
		}
		kind, ok := rec[event.FieldEventType].(string)
		if !ok {
			return mcp.CredentialRun{}, false, malformed(runID,
				"an event for run %q carries no readable event_type", runID)
		}

		switch kind {
		case event.EventTypeRunRegistered:
			if registered {
				// The run id is derived from the caller's arguments and the
				// ledger's idempotency_key is UNIQUE, so one run registers
				// once. Two registrations would describe one run with two
				// identities, and choosing between them is a guess about which
				// identity a credential should be minted for (I2).
				return mcp.CredentialRun{}, false, malformed(runID,
					"run %q is registered twice on the chain, with %q and with %q",
					runID, run.SPIFFEID, rec[event.FieldSpiffeID])
			}
			identity, err := runIdentity(rec, runID)
			if err != nil {
				return mcp.CredentialRun{}, false, err
			}
			run.RunID = runID
			run.SPIFFEID = identity.spiffeID
			run.AgentType = identity.agentType
			run.TaskID = identity.taskRef
			registered = true

		case event.EventTypeRunRetired:
			at, err := retiredAt(rec, runID)
			if err != nil {
				return mcp.CredentialRun{}, false, err
			}
			// ADR-0020 §5. A check-then-append leaves a window in which two
			// genuinely concurrent FIRST retirements of one run both find no
			// record and both append, and I4 makes both permanent. What keeps
			// that survivable is precisely this line: every caller, then and
			// forever after, is told the ORIGINAL instant, so two retirements
			// of one run cannot be reported as two different retirements.
			//
			// Earliest by INSTANT, not first in chain order. They agree on
			// every chain a single ledger writes, because `ts` is read inside
			// the serialized append — which is exactly why relying on the
			// agreement would be untested code the day it stopped holding
			// (two writers, a restored backup, a clock stepped backwards
			// inside IP §6.8's bound).
			if run.RetiredAt.IsZero() || at.Before(run.RetiredAt) {
				run.RetiredAt = at
			}
		}
	}

	if !registered {
		// Events for a run the chain never registered are not a run. Answering
		// "found" would hand the tools a CredentialRun with no identity, and
		// `credentialRunIdentity` would then report an INVARIANT_VIOLATION for
		// what is really an unknown run.
		return mcp.CredentialRun{}, false, nil
	}
	return run, true, nil
}

// checkScope refuses a record that is not this run's.
//
// The read is run-scoped in SQL, so this can only fire on a defect — in the
// query, in a test double, or in a caller that filtered wrongly. It is checked
// anyway because the cost is one comparison and the failure it catches is a
// tool acting on another run's identity, which is I2.
func checkScope(rec event.Fields, runID string) error {
	id, ok := rec[event.FieldRunID].(string)
	if !ok {
		return malformed(runID,
			"the run-scoped read for %q returned an event carrying no run_id", runID)
	}
	if id != runID {
		return malformed(runID,
			"the run-scoped read for %q returned an event for run %q", runID, id)
	}
	return nil
}

// identity is the three components a `run_registered` event records.
type identity struct{ spiffeID, agentType, taskRef string }

// runIdentity reads them, refusing rather than defaulting any one of them.
func runIdentity(rec event.Fields, runID string) (identity, error) {
	var out identity
	for _, member := range []struct {
		name string
		into *string
	}{
		{event.FieldSpiffeID, &out.spiffeID},
		{event.FieldAgentType, &out.agentType},
		{event.FieldTaskRef, &out.taskRef},
	} {
		value, ok := rec[member.name].(string)
		if !ok {
			return identity{}, malformed(runID,
				"run_registered for %q carries no readable %s", runID, member.name)
		}
		*member.into = value
	}
	return out, nil
}

// retiredAt reads the instant a `run_retired` event records.
//
// ADR-0020 §2: "A record the ledger returns without a readable `ts` is
// INVARIANT_VIOLATION, not an empty `retired_at`. The reply's entire content
// is one instant, and a blank one is exactly the shape a vacuously-passing
// idempotency test takes."
func retiredAt(rec event.Fields, runID string) (time.Time, error) {
	raw, ok := rec[event.FieldTS].(string)
	if !ok {
		return time.Time{}, malformed(runID, "run_retired for %q carries no readable ts", runID)
	}
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		return time.Time{}, malformed(runID, "run_retired for %q carries the unreadable ts %q: %v",
			runID, raw, err)
	}
	return ts.Time(), nil
}

// malformed is this package's one refusal.
//
// Every case is a chain that does not describe the run it claims to, which is
// either a defect in what wrote it or something writing events this deployment
// did not write. IP §4 has one class for that and it is alert-level.
func malformed(runID, format string, args ...any) error {
	return mcp.Errorf(mcp.ClassInvariantViolation, runID, format, args...)
}
