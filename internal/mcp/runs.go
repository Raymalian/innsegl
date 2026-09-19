// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// CredentialRuns resolves a run_id to the run it names.
//
// IP §4 gives get_credential a run_id and nothing else, so something has to
// hold the mapping from run_id to identity. That something is whatever
// appended `run_registered` — register_agent (RM-022, #30) — and it is
// deliberately an interface here rather than a query this file invents: the
// run directory is shared with the other four tools, and a second definition
// of "what is a run" is a second thing that can disagree about retirement.
type CredentialRuns interface {
	// CredentialRun returns the run, and whether one is known by that id. An
	// unknown run is not an error: it is RUN_NOT_FOUND, which this file
	// classifies.
	CredentialRun(ctx context.Context, runID string) (CredentialRun, bool, error)
}

// CredentialRun is what the MCP knows about one run: what the run REALLY was,
// its identity, and whether it has been retired.
//
// The SPIFFE ID is held rather than rebuilt from a trust domain this package
// would then have to be told, so that exactly one component — whatever created
// the run — decides what a run's identity is, and this one checks that answer
// rather than inventing a second way to compute it.
//
// # AgentType and TaskID are the RECORD, not the identity (RM-079, #116)
//
// They are the ledger's own `agent_type` and `task_ref`: the caller's values,
// verbatim, with the caller's casing. Under identity mode `pseudonymous` — the
// default — the SPIFFE ID's {agent_type} and {task_id} segments are KEYED
// PSEUDONYMS of them and the two are not equal, and cannot be compared without
// the deployment secret. Anything that needs the segments (SPIRE holds nothing
// else) reads them off SPIFFEID with spire.RunRefOf; see Ref.
type CredentialRun struct {
	RunID string
	// AgentType and TaskID are `agent_type` and `task_ref` as the ledger
	// recorded them. They are what a human resolves a pseudonymous identity
	// back to; they are NOT the SPIFFE ID's segments.
	AgentType string
	TaskID    string
	SPIFFEID  string
	// Repo is `run_registered`'s own `repo`: doc 02 §5's host/org/name, as the
	// registration recorded it (ADR-0045).
	//
	// It is held because it is what an admin credential is scoped to (#264):
	// the three tools that take a run id answer a caller whose credential is
	// for another repository exactly as they answer a run that does not exist,
	// and they need the run's repository to make that comparison.
	//
	// EMPTY IS POSSIBLE AND IS NOT AN ERROR. `repo` became required at append
	// under ADR-0045; a run registered before that has none on the chain, and
	// refusing to read such a run would make history unreadable to close a
	// gap that is about new calls. It is empty, and adminScopeAdmits refuses
	// it under any credential — a run that cannot be shown to be in this
	// credential's repository is not in it.
	Repo string
	// RetiredAt is the instant `run_retired` was appended, zero for a live
	// run. I4: retirement removes the identity, never the record.
	RetiredAt time.Time
	// ExpiredAt is the NEWEST `run_expired`, zero if the reaper never took this
	// run's authorisation.
	//
	// It is not retirement and must never be read as it: expiry withdraws a
	// credential from a run that went quiet, and a quiet agent is often one
	// waiting on a usage limit or a human. That is why a resumed run can have
	// its entry restored at all.
	//
	// It is kept because that restoration cannot be unbounded. A run whose
	// process was killed fires no retirement hook, so nothing ever ends it, and
	// without a horizon its identity stays mintable forever. This is the
	// instant that horizon is measured from.
	//
	// # Newest, where RetiredAt is earliest (RM-152, #255)
	//
	// The difference is not an inconsistency, it is the difference between the
	// two facts. Two concurrent retirements of one run are two reports of ONE
	// ending, so every caller is told the original instant for ever (ADR-0020
	// §5). A run's expiries are not reports of one fact: it has one per quiet
	// spell, the reaper keys each to the lapse it records, and the only one a
	// restore horizon can be measured from is the lapse being restored FROM.
	// Measured from the earliest, a run that lapsed on day one, resumed, and
	// worked for longer than the horizon is refused restore on its next lapse
	// however recently it was alive — doc 07 MCP-078.
	ExpiredAt time.Time
	// LastActivityAt is the newest event on this run that the REAPER DID NOT
	// WRITE, zero for a run whose entire record is the reaper's.
	//
	// It is the member that makes ExpiredAt answerable. A withdrawal on its own
	// says only that the run was quiet at some instant; whether that is still
	// true is decided by whether anything the run did is newer. Without this
	// the MCP could tell a lapse from a retirement but not a lapse from a
	// RESTORED lapse, which is the distinction #258 exists for.
	LastActivityAt time.Time
}

// State is the run's lifecycle state — active, lapsed, abandoned or retired —
// by the one rule, at the given instant and restore horizon.
//
// # Why the MCP asks rather than answers
//
// Three components used to decide independently whether a run was closed and
// they disagreed: the reconciler read a withdrawal as final, the read API read
// it as reversible, and an operator was shown both about the same run (RM-155,
// #258). The rule is internal/ledger's now, in one place, and this method is
// the MCP's way of consulting it rather than a fourth opinion.
//
// The facts are exactly what CredentialRun already holds, read off this run's
// own events by the run directory (internal/rundir): a retirement, a newest
// withdrawal, and the newest thing the run itself did.
//
// horizon is `innsegl serve`'s `--abandon-after`. Zero or less means the
// deployment set none, and a withdrawn run then stays Lapsed until something
// ends it — the same reading get_credential's fourth gate gives a zero.
func (r CredentialRun) State(now time.Time, horizon time.Duration) string {
	return ledger.RunStateOf(ledger.RunFacts{
		Retired:        r.Retired(),
		RetiredAt:      r.RetiredAt,
		WithdrawnAt:    r.ExpiredAt,
		LastActivityAt: r.LastActivityAt,
	}, now, horizon)
}

// credentialRunIdentity returns the SPIFFE ID to mint for AND the run
// reference SPIRE is addressed by, having checked that the run directory
// answered about the run that was asked for and that the identity it named is
// that run's own, inside the /agent/ subtree.
//
// Both come out of ONE parse of one string. An earlier revision of RM-079
// validated the identity here and parsed it a second time at each call site,
// which left the second parse's error branch unreachable — a dead error path is
// exactly what IP §2's 100%-branch floor exists to find, and it found it.
//
// # What this check can still see, and what RM-079 took away from it
//
// Before RM-079 it required the identity to end in
// `/agent/{agent_type}/{task_id}/{run_id}` from the directory's own three
// values. That comparison is not available any more: under `pseudonymous` the
// first two segments are HMACs of the recorded values, so reproducing them
// would mean holding the DEPLOYMENT SECRET ON A READ PATH — and then a rotated
// or lost secret would stop every live run getting a credential and stop it
// being retired, which is precisely the failure the ledger-row mapping exists
// to avoid. Weakening the check is the smaller cost, and it is stated here
// rather than left to be discovered.
//
// What survives is the half the check was for: a directory that answered with
// ANOTHER RUN'S identity is still refused, because the identity must be a
// well-formed SPIFFE ID in the /agent/ subtree whose {run_id} is this run's.
// That is what stops a directory being a second route to AB-10.
func credentialRunIdentity(runID string, run CredentialRun) (string, spire.RunRef, error) {
	if run.RunID != runID {
		return "", spire.RunRef{}, Errorf(ClassInvariantViolation, runID,
			"the run directory answered for run %q", run.RunID)
	}
	// The grammar of doc 01 §1 / doc 02 §5, from the one definition of it in
	// this repository, applied ONCE. It already requires the /agent/ subtree
	// and four components; the comparison below requires the last of them to
	// be THIS run's.
	ref, err := run.Ref()
	if err != nil {
		return "", spire.RunRef{}, err
	}
	if ref.RunID != run.RunID {
		return "", spire.RunRef{}, Errorf(ClassInvariantViolation, runID,
			"identity %q does not name run %q", run.SPIFFEID, run.RunID)
	}
	return run.SPIFFEID, ref, nil
}

// credentialLedgerError carries the ledger's own classification across.
//
// internal/ledger predates mcp.Classified (ADR-0016) and raises *StoreError
// with the same eleven spellings; mapping it by string identity here means a
// rename in either package fails the mapping loudly rather than inventing a
// class. Anything the ledger did not classify is INVARIANT_VIOLATION: IP §4's
// vocabulary is closed, and an unnameable failure inside the MCP is a defect.
func credentialLedgerError(runID string, err error) error {
	var stored *ledger.StoreError
	if errors.As(err, &stored) {
		return classifyAs(Class(stored.Class), runID, stored.Error(), stored.Retryable, "internal/ledger", err)
	}
	return classifyAs(ClassInvariantViolation, runID, err.Error(), false, "the ledger", err)
}
