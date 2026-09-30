// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/signing"
)

// Test catalog IDs this file drives toward: CMT-004 and CMT-005 are
// committrailers_test.go's (the handler that calls this in process) and
// githook_test.go's (the real-git end of the same path); this file is the
// claim CommitClaimForRun builds before either of those is reached.

// ---------------------------------------------------------------------------
// Test double.
// ---------------------------------------------------------------------------

// ccRuns is CredentialRuns, held in memory exactly the way raRuns
// (register_agent_test.go) and retireRuns (retire_agent_test.go) hold it for
// this package's other tools: a directory that answers from what the test put
// in it, so a case can say "this run is retired" without a second ledger.
type ccRuns struct {
	mu    sync.Mutex
	runs  map[string]CredentialRun
	calls int
	err   error
}

func newCCRuns() *ccRuns { return &ccRuns{runs: map[string]CredentialRun{}} }

func (r *ccRuns) put(run CredentialRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs[run.RunID] = run
}

// putAs files run under queryID even when run.RunID names something else —
// the one way this fake can answer the way a directory bug would: naming
// another run's identity for the run that was asked about.
func (r *ccRuns) putAs(queryID string, run CredentialRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs[queryID] = run
}

func (r *ccRuns) CredentialRun(_ context.Context, runID string) (CredentialRun, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return CredentialRun{}, false, r.err
	}
	run, ok := r.runs[runID]
	return run, ok, nil
}

// ccWiring builds a valid CommitClaimConfig against a fresh ccRuns and a
// literal pseudonymiser (task_ref carried verbatim — easiest to assert
// against; TestCommitClaimRendersThePseudonymousTaskTheSameWaySignCommitDoes
// covers the default mode separately), and installs it, restoring whatever
// was there before when the test ends.
func ccWiring(t *testing.T, mutate func(*CommitClaimConfig)) *ccRuns {
	t.Helper()
	runs := newCCRuns()
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	cfg := CommitClaimConfig{Runs: runs, Pseudonyms: literal}
	if mutate != nil {
		mutate(&cfg)
	}
	restore, err := ConfigureCommitClaim(cfg)
	if err != nil {
		t.Fatalf("ConfigureCommitClaim: %v", err)
	}
	t.Cleanup(restore)
	return runs
}

const ccIdentity = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"

// ccActiveRun is a run CredentialRun.State reads as active: not retired, no
// withdrawal recorded.
func ccActiveRun(runID string) CredentialRun {
	return CredentialRun{RunID: runID, SPIFFEID: ccIdentity, AgentType: "fix-ci", TaskID: "JIRA-118"}
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

func TestConfigureCommitClaimRefusesAnIncompleteConfiguration(t *testing.T) {
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	cases := []struct {
		name string
		cfg  CommitClaimConfig
	}{
		{"nothing configured", CommitClaimConfig{}},
		{"no run directory", CommitClaimConfig{Pseudonyms: literal}},
		{"no pseudonymiser", CommitClaimConfig{Runs: newCCRuns()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ConfigureCommitClaim(tc.cfg); err == nil {
				t.Fatal("ConfigureCommitClaim admitted an incomplete configuration")
			} else {
				requireClass(t, err, ClassInvariantViolation)
			}
		})
	}
}

func TestCommitClaimIsNotServedUntilItIsConfigured(t *testing.T) {
	// Force the unconfigured state directly, whatever another test in this
	// file happens to have left active, and restore it afterward.
	commitClaimMu.Lock()
	previous := commitClaimActive
	commitClaimActive = nil
	commitClaimMu.Unlock()
	t.Cleanup(func() {
		commitClaimMu.Lock()
		commitClaimActive = previous
		commitClaimMu.Unlock()
	})

	_, err := CommitClaimForRun(t.Context(), "run-42")
	requireClass(t, err, ClassInvariantViolation)
}

func TestConfigureCommitClaimRefusesTheIncompleteAndRestoresThePrevious(t *testing.T) {
	runs := ccWiring(t, nil)
	runs.put(ccActiveRun("run-42"))

	if _, err := ConfigureCommitClaim(CommitClaimConfig{Runs: runs}); err == nil {
		t.Fatal("ConfigureCommitClaim admitted a configuration with no pseudonymiser")
	}

	// The valid configuration ccWiring installed is still active.
	claim, err := CommitClaimForRun(t.Context(), "run-42")
	if err != nil {
		t.Fatalf("CommitClaimForRun after a refused reconfiguration: %v", err)
	}
	if claim.Run != "run-42" {
		t.Errorf("claim.Run = %q, want run-42", claim.Run)
	}
}

// ---------------------------------------------------------------------------
// A run that is not active: retired, lapsed, abandoned, unknown.
// ---------------------------------------------------------------------------

func TestCommitClaimRefusesARunThatIsNotActive(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	const abandonAfter = 24 * time.Hour

	cases := []struct {
		name string
		run  *CredentialRun // nil means unknown
		want Class
	}{
		{
			name: "unknown run",
			run:  nil,
			want: ClassRunNotFound,
		},
		{
			name: "retired",
			run: func() *CredentialRun {
				r := ccActiveRun("run-42")
				r.RetiredAt = now.Add(-time.Hour)
				return &r
			}(),
			want: ClassRunAlreadyRetired,
		},
		{
			name: "lapsed (withdrawn, inside the horizon)",
			run: func() *CredentialRun {
				r := ccActiveRun("run-42")
				r.ExpiredAt = now.Add(-time.Minute)
				return &r
			}(),
			want: ClassRunNotFound,
		},
		{
			name: "abandoned (withdrawn, past the horizon)",
			run: func() *CredentialRun {
				r := ccActiveRun("run-42")
				r.ExpiredAt = now.Add(-abandonAfter - time.Minute)
				return &r
			}(),
			want: ClassRunNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runs := ccWiring(t, func(cfg *CommitClaimConfig) {
				cfg.AbandonAfter = abandonAfter
				cfg.Now = func() time.Time { return now }
			})
			if tc.run != nil {
				runs.put(*tc.run)
			}
			claim, err := CommitClaimForRun(t.Context(), "run-42")
			if err == nil {
				t.Fatalf("CommitClaimForRun admitted a %s run, returning %+v", tc.name, claim)
			}
			requireClass(t, err, tc.want)
			if claim != (signing.Claim{}) {
				t.Errorf("a refusal returned a non-zero claim: %+v", claim)
			}
		})
	}
}

// TestCommitClaimRefusesAMalformedRunIDBeforeTouchingTheLedger pins that a
// run id the grammar (doc 02 §5) will not carry is refused cheaply, the same
// class as one the ledger has never heard of — a caller learns nothing about
// which run ids exist by the shape of the refusal.
func TestCommitClaimRefusesAMalformedRunIDBeforeTouchingTheLedger(t *testing.T) {
	runs := ccWiring(t, nil)
	_, err := CommitClaimForRun(t.Context(), "Not A Valid Run Id!!")
	requireClass(t, err, ClassRunNotFound)
	if runs.calls != 0 {
		t.Errorf("the ledger was consulted %d times for a run id refused by grammar alone", runs.calls)
	}
}

// ---------------------------------------------------------------------------
// The ledger's own failure, and a directory that misbehaves.
// ---------------------------------------------------------------------------

func TestCommitClaimPropagatesALedgerFailureClassified(t *testing.T) {
	runs := ccWiring(t, nil)
	runs.err = errors.New("connection refused")
	_, err := CommitClaimForRun(t.Context(), "run-42")
	// credentialLedgerError's own fallback: an error the ledger did not
	// classify itself is INVARIANT_VIOLATION (runs.go's own comment).
	requireClass(t, err, ClassInvariantViolation)
}

// TestCommitClaimRefusesADirectoryThatNamesAnotherRun pins the same defensive
// check get_credential and sign_commit both run: a directory that answers
// with another run's identity for the run that was asked about is refused
// rather than trusted, guarding against a second route to AB-10.
func TestCommitClaimRefusesADirectoryThatNamesAnotherRun(t *testing.T) {
	runs := ccWiring(t, nil)
	runs.putAs("run-42", CredentialRun{
		RunID:    "run-42",
		SPIFFEID: "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-9", // names run-9, not run-42
		TaskID:   "JIRA-118",
	})
	_, err := CommitClaimForRun(t.Context(), "run-42")
	requireClass(t, err, ClassInvariantViolation)
}

// ---------------------------------------------------------------------------
// The claim itself.
// ---------------------------------------------------------------------------

func TestCommitClaimRefusesATaskThatIsNotARunIdentityComponent(t *testing.T) {
	runs := ccWiring(t, nil)
	run := ccActiveRun("run-42")
	run.TaskID = "" // fails event.ValidateIdentifier once lowercased
	runs.put(run)
	_, err := CommitClaimForRun(t.Context(), "run-42")
	requireClass(t, err, ClassInvariantViolation)
}

// TestCommitClaimRefusesAnIncoherentClaim pins that ADR-0018 §6's consistency
// rule -- Agent-Task must lowercase to the SPIFFE ID's own task segment -- is
// still checked here, even though this function never touches a certificate.
// A directory that recorded task_ref inconsistently with the identity it
// minted is a defect this function refuses rather than claims trailers for.
func TestCommitClaimRefusesAnIncoherentClaim(t *testing.T) {
	runs := ccWiring(t, nil)
	runs.put(CredentialRun{
		RunID:    "run-42",
		SPIFFEID: ccIdentity, // task segment "jira-118"
		TaskID:   "SOMETHING-ELSE",
	})
	_, err := CommitClaimForRun(t.Context(), "run-42")
	requireClass(t, err, ClassInvariantViolation)
}

func TestCommitClaimForAnActiveRunReturnsTheClaimSignCommitWouldBuild(t *testing.T) {
	runs := ccWiring(t, nil)
	runs.put(ccActiveRun("run-42"))

	claim, err := CommitClaimForRun(t.Context(), "run-42")
	if err != nil {
		t.Fatalf("CommitClaimForRun: %v", err)
	}
	want := signing.Claim{Identity: ccIdentity, Run: "run-42", Task: "JIRA-118"}
	if claim != want {
		t.Errorf("CommitClaimForRun = %+v, want %+v", claim, want)
	}
	// The claim sign_commit itself would render for the identical run
	// (sign_commit.go: `claim := signing.Claim{Identity: spiffeID, Run:
	// run.RunID, Task: claimedTask}`) renders without error too — the two are
	// the same claim, built the same way.
	if _, err := claim.Trailers(); err != nil {
		t.Errorf("the returned claim does not render: %v", err)
	}
}

// TestCommitClaimRendersThePseudonymousTaskTheSameWaySignCommitDoes pins that
// this function is not special-cased to `literal` mode: under the default
// `pseudonymous` mode the Agent-Task trailer is the SAME keyed pseudonym
// register_agent would have minted into the identity's own {task_id} segment
// (RM-079, #116) — not the caller's task_ref read back verbatim.
func TestCommitClaimRendersThePseudonymousTaskTheSameWaySignCommitDoes(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	pseudo, err := identity.New(identity.ModePseudonymous, secret)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	taskID, err := pseudo.TaskID("JIRA-118")
	if err != nil {
		t.Fatalf("pseudo.TaskID: %v", err)
	}
	spiffeID := "spiffe://innsegl.dev/agent/fix-ci/" + taskID + "/run-42"

	runs := ccWiring(t, func(cfg *CommitClaimConfig) { cfg.Pseudonyms = pseudo })
	runs.put(CredentialRun{RunID: "run-42", SPIFFEID: spiffeID, TaskID: "JIRA-118"})

	claim, err := CommitClaimForRun(t.Context(), "run-42")
	if err != nil {
		t.Fatalf("CommitClaimForRun: %v", err)
	}
	if claim.Task == "JIRA-118" {
		t.Fatalf("test setup: the pseudonymised task equals the caller's own value")
	}
	claimedTask, err := pseudo.ClaimedTask("JIRA-118")
	if err != nil {
		t.Fatalf("pseudo.ClaimedTask: %v", err)
	}
	if claim.Task != claimedTask {
		t.Errorf("claim.Task = %q, want %q (pseudo.ClaimedTask's own answer)", claim.Task, claimedTask)
	}
	if _, err := claim.Trailers(); err != nil {
		t.Errorf("the returned claim does not render: %v", err)
	}
}

// TestCommitClaimForRunUsesTheConfiguredClock pins that AbandonAfter's
// horizon is measured from the configured Now, not time.Now — the same
// determinism CredentialRun.State's own comment requires of every caller.
func TestCommitClaimForRunUsesTheConfiguredClock(t *testing.T) {
	frozen := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	runs := ccWiring(t, func(cfg *CommitClaimConfig) {
		cfg.AbandonAfter = time.Hour
		cfg.Now = func() time.Time { return frozen }
	})
	run := ccActiveRun("run-42")
	run.ExpiredAt = frozen.Add(-time.Minute) // lapsed as of the frozen clock
	runs.put(run)

	if _, err := CommitClaimForRun(t.Context(), "run-42"); err == nil {
		t.Fatal("a lapsed run (by the configured clock) claimed trailers")
	} else {
		requireClass(t, err, ClassRunNotFound)
	}
}
