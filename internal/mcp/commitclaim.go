// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/signing"
)

// commitclaim.go — RM-240 (#385), ADR-0059 decision 2: the claim
// prepare-commit-msg asks the core for, built from a run id alone.
//
// It is sign_commit's own claim-building (sign_commit.go: `claim :=
// signing.Claim{Identity: spiffeID, Run: run.RunID, Task: claimedTask}`),
// reached in process the way gateway.go reaches register_agent and
// retire_agent — one seam, crossed once, so this file does not re-decide a
// rule sign_commit already enforces: the same run directory, the same
// pseudonymiser, the same task-rendering rule (RM-079, #116).
//
// # Why a run that is merely not-retired is not enough here
//
// sign_commit's own resolveRun checks only Retired(): a lapsed or abandoned
// run still resolves there, because get_credential's gate 4 is the thing
// that actually stops it later, against SPIRE (get_credential.go). This
// function has no SPIRE gate downstream of it — a prepare-commit-msg call
// answered for a run nothing is coming back to sign would hand an operator a
// message carrying a claim that can never be honoured, discovered only when
// the signing endpoint refuses it. So CommitClaimForRun asks the ledger's own
// question — CredentialRun.State, the one rule three components used to
// answer differently until RM-155 (#258) put it in one place — and refuses a
// run that is retired, lapsed or unknown exactly alike: a run that is not
// working cannot claim a commit's trailers.
type CommitClaimConfig struct {
	// Runs resolves run_id. Required, and get_credential's and sign_commit's
	// own interface rather than a second one: a second definition of "what is
	// a run" is a second thing that can disagree about retirement.
	Runs CredentialRuns
	// Pseudonyms renders the run's OWN task reference into the Agent-Task
	// trailer the way register_agent rendered it into the SPIFFE ID's
	// {task_id}. Required, and it MUST be the same one sign_commit holds
	// (RM-079, #116): a claim whose task segment disagrees with the identity
	// is one nothing downstream can honour.
	Pseudonyms *identity.Pseudonymiser
	// AbandonAfter bounds how long a withdrawn run's lapse still reads as
	// merely lapsed rather than abandoned (CredentialRun.State). Zero means
	// the deployment set no horizon — see that method's own comment.
	AbandonAfter time.Duration
	// Now is the clock a run's state is read at. Nil means time.Now.
	Now func() time.Time
}

// commitClaimService is the configured claim builder.
type commitClaimService struct {
	runs         CredentialRuns
	pseudonyms   *identity.Pseudonymiser
	abandonAfter time.Duration
	now          func() time.Time
}

// newCommitClaimService checks the configuration and returns the claim
// builder. Every dependency is required for the same reason sign_commit's
// own newSignCommitService gives (sign_commit.go): a missing gate is an open
// door rather than a degraded mode.
func newCommitClaimService(cfg CommitClaimConfig) (*commitClaimService, error) {
	refuse := func(detail string) (*commitClaimService, error) {
		return nil, Errorf(ClassInvariantViolation, "", "commit claim configuration: %s", detail)
	}
	switch {
	case cfg.Runs == nil:
		return refuse("no run directory: a commit's trailers cannot be attributed to an " +
			"identity nothing can resolve (I2)")
	case cfg.Pseudonyms == nil:
		return refuse("no pseudonymiser: nothing would render the Agent-Task trailer the way " +
			"register_agent rendered the identity's {task_id}, so every claim would be refused " +
			"as inconsistent (RM-079, #116)")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &commitClaimService{
		runs:         cfg.Runs,
		pseudonyms:   cfg.Pseudonyms,
		abandonAfter: cfg.AbandonAfter,
		now:          now,
	}, nil
}

// claim is CommitClaimForRun's configured half.
func (c *commitClaimService) claim(ctx context.Context, runID string) (signing.Claim, error) {
	// A run id the grammar will never carry cannot be on the chain (doc 02
	// §5), so refusing here is the same answer the ledger would give for one
	// it has never heard of — and it is cheaper: nothing is asked of the
	// ledger for a shape that could never be a run.
	if err := event.ValidateIdentifier(runID); err != nil {
		return signing.Claim{}, Errorf(ClassRunNotFound, runID, "%q is not a run id: %v", runID, err)
	}

	run, found, err := c.runs.CredentialRun(ctx, runID)
	if err != nil {
		return signing.Claim{}, credentialLedgerError(runID, err)
	}
	if !found {
		return signing.Claim{}, Errorf(ClassRunNotFound, runID, "no run %q", runID)
	}

	// Retirement keeps its own class — the same one get_credential and
	// sign_commit both use — because it is a settled, permanent fact and not
	// merely "not active right now" the way a lapse is.
	if run.Retired() {
		return signing.Claim{}, Errorf(ClassRunAlreadyRetired, runID,
			"run %q was retired at %s; a retired run cannot claim a commit's trailers (IP §6.2)",
			runID, event.NewTimestamp(run.RetiredAt))
	}

	// A run that is merely not-retired is not enough here — see this file's
	// own package comment for why this gate is stricter than sign_commit's
	// own resolveRun. get_credential's own gate 4 answers a lapsed or
	// abandoned run's SPIRE lookup with RUN_NOT_FOUND once no restore is
	// possible (get_credential.go); this reads the same as that, directly
	// off the ledger's own rule (CredentialRun.State), rather than waiting to
	// discover it the expensive way against SPIRE.
	if state := run.State(c.now(), c.abandonAfter); state != ledger.RunActive {
		return signing.Claim{}, Errorf(ClassRunNotFound, runID,
			"run %q is %s, not active; a run that is not working cannot claim a commit's trailers",
			runID, state)
	}

	// The directory's answer is checked, not trusted — the same defensive
	// read get_credential.go and sign_commit.go both perform before minting
	// or signing anything against it.
	spiffeID, _, err := credentialRunIdentity(runID, run)
	if err != nil {
		return signing.Claim{}, err
	}

	// The run's OWN task_ref, read off the ledger the way sign_commit reads
	// the caller's — but there is no caller-supplied task_ref here, so the
	// only value that can possibly be consistent with this run's identity is
	// the one register_agent recorded for it (RM-079, #116).
	claimedTask, err := c.pseudonyms.ClaimedTask(run.TaskID)
	if err != nil {
		return signing.Claim{}, Errorf(ClassInvariantViolation, runID,
			"run %q's own task_ref %q is not a run identity component (doc 02 §6): %v",
			runID, run.TaskID, err)
	}

	claim := signing.Claim{Identity: spiffeID, Run: run.RunID, Task: claimedTask}
	if _, err := claim.Trailers(); err != nil {
		return signing.Claim{}, Errorf(ClassInvariantViolation, runID,
			"the commit's trailers cannot be claimed for run %q: %v", runID, err)
	}
	return claim, nil
}

var (
	commitClaimMu     sync.RWMutex
	commitClaimActive *commitClaimService
)

// ConfigureCommitClaim installs the dependencies CommitClaimForRun runs on
// and returns a function restoring whatever was installed before — the same
// shape as ConfigureSignCommit (sign_commit.go), so wiring this follows one
// convention across the package.
func ConfigureCommitClaim(cfg CommitClaimConfig) (func(), error) {
	svc, err := newCommitClaimService(cfg)
	if err != nil {
		return nil, err
	}
	commitClaimMu.Lock()
	defer commitClaimMu.Unlock()
	previous := commitClaimActive
	commitClaimActive = svc
	return func() {
		commitClaimMu.Lock()
		defer commitClaimMu.Unlock()
		commitClaimActive = previous
	}, nil
}

// CommitClaimForRun is ADR-0059 decision 2's claim: what
// cmd/innsegl/committrailers.go asks for on every prepare-commit-msg call,
// and what the signing agent (#386) will receive by injection. See this
// file's own doc comment for what it refuses and why.
func CommitClaimForRun(ctx context.Context, runID string) (signing.Claim, error) {
	commitClaimMu.RLock()
	svc := commitClaimActive
	commitClaimMu.RUnlock()
	if svc == nil {
		return signing.Claim{}, Errorf(ClassInvariantViolation, runID,
			"commit claim is bound but not configured; no claim is built rather than one "+
				"built for an unconfigured signer")
	}
	return svc.claim(ctx, runID)
}
