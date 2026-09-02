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
	// RetiredAt is the instant `run_retired` was appended, zero for a live
	// run. I4: retirement removes the identity, never the record.
	RetiredAt time.Time
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
