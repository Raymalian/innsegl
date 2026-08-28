// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"testing"
	"time"
)

// SPI-002 (doc 07, layer I)
//
//	Workload with wrong selectors requests credential
//	→ Refused; ATTESTATION_FAILED at MCP layer
//	→ proves I1 and IP §6.1, and covers abuse case AB-01
//
// # How this case is kept from passing vacuously
//
// "The thing was refused" is a test that passes when nothing was attempted, and
// this one has three separate ways to be hollow. Each is closed by an assertion
// rather than by a comment:
//
//  1. NOTHING WAS REGISTERED, so of course nothing was issued. Closed by
//     registering the run first and, in the same test, watching a workload with
//     the RIGHT selectors receive the SVID before the wrong one is tried. If
//     the positive control never gets an identity the test fails there.
//
//  2. THE ENTRY HAD NOT PROPAGATED YET. Registration reaches the agent through
//     a cache, so a wrong-selector probe run immediately after a create would
//     be refused for the wrong reason and look identical. Closed by the same
//     positive control: it polls until the identity is actually being issued,
//     so by the time the wrong-selector probe runs the entry is demonstrably
//     live on this agent.
//
//  3. THE PROBE NEVER REACHED SPIRE — a missing socket, an unstartable
//     container, a binary that exited before dialling — would also produce
//     "no identity". Closed by asserting the class the client derived from what
//     the Workload API actually returned: an unreachable Workload API is
//     IDENTITY_UNAVAILABLE, retryable, and a refusal is ATTESTATION_FAILED, not
//     retryable. The final subtest exercises the unreachable case explicitly so
//     that the two are known to be distinguishable rather than assumed to be.
func TestSPI002WorkloadWithWrongSelectorsIsRefused(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	run := newRun(t, "demo", "rm-015")

	want, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("RunRef.SPIFFEID: %v", err)
	}
	registerForTest(t, c, s, run)

	// (1) and (2): the positive control. The identity exists and is being
	// issued on this agent, right now, to a workload that matches.
	issued := s.probeUntilIssued(t, run, 90*time.Second)
	if issued.Outcome.SPIFFEID != want {
		t.Fatalf("positive control fetched %q, want %q", issued.Outcome.SPIFFEID, want)
	}

	// Each case below changes exactly one selector's worth of truth about the
	// workload while it asks for the same run's identity.
	for _, tc := range []struct {
		name string
		is   RunRef
	}{
		{
			name: "wrong run id",
			is:   RunRef{AgentType: run.AgentType, TaskID: run.TaskID, RunID: run.RunID + "-imposter"},
		},
		{
			name: "wrong agent type",
			is:   RunRef{AgentType: "other", TaskID: run.TaskID, RunID: run.RunID},
		},
		{
			name: "wrong task id",
			is:   RunRef{AgentType: run.AgentType, TaskID: "rm-999", RunID: run.RunID},
		},
		{
			name: "no labels at all",
			is:   RunRef{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.runProbe(t, tc.is, run)

			if got.ExitCode == 0 {
				t.Fatalf("a workload labelled %+v was issued %q while asking for %q: "+
					"selectors are not being enforced", tc.is, got.Outcome.SPIFFEID, want)
			}
			if got.Outcome.SPIFFEID != "" {
				t.Errorf("refused fetch still carried a SPIFFE ID: %q", got.Outcome.SPIFFEID)
			}
			// (3): the class is derived from what SPIRE returned, and it is the
			// one IP §6.1 names.
			if got.Outcome.Class != ClassAttestationFailed {
				t.Errorf("class = %q, want %s (raw probe output: %s)",
					got.Outcome.Class, ClassAttestationFailed, got.Raw)
			}
			if got.Outcome.Retryable {
				t.Error("ATTESTATION_FAILED was marked retryable; " +
					"IP §6.1 says not retryable, and retrying cannot make a workload " +
					"be something else")
			}
			t.Logf("refused: %s", got.Outcome.Message)
		})
	}

	// (3), stated as its own case: a Workload API that cannot be reached is a
	// different class from one that refuses. Without this, every assertion
	// above would also pass if the probe had never managed to dial anything.
	t.Run("an unreachable Workload API is a different class", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		_, err := FetchRunSVID(ctx, "unix:///nonexistent/innsegl-no-such-agent.sock", testTrustDomain, run)
		if err == nil {
			t.Fatal("fetching from a socket that does not exist succeeded")
		}
		class, ok := ClassOf(err)
		if !ok || class != ClassIdentityUnavailable {
			t.Errorf("class = %q (ok=%v), want %s: %v", class, ok, ClassIdentityUnavailable, err)
		}
		if !IsRetryable(err) {
			t.Error("IDENTITY_UNAVAILABLE from an unreachable agent must be retryable (IP §6.1)")
		}
		if class == ClassAttestationFailed {
			t.Error("an unreachable agent was reported as an attestation failure; " +
				"SPI-002 would then be unable to tell a refusal from an outage")
		}
	})
}

// TestFetchRunSVIDRefusesAnotherRunsIdentity is the other half of I1 at the
// client: a workload that somehow holds a valid SVID for run A must not be able
// to present it as run B. IP §6.2 calls cross-run use an INVARIANT_VIOLATION.
//
// It runs a probe container carrying run A's selectors while asking for run B's
// identity: SPIRE issues A's SVID, and the client refuses to call it B's.
func TestFetchRunSVIDRefusesAnotherRunsIdentity(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)

	runA := newRun(t, "demo", "rm-015")
	runB := newRun(t, "demo", "rm-015")

	registerForTest(t, c, s, runA)
	s.probeUntilIssued(t, runA, 90*time.Second)

	got := s.runProbe(t, runA, runB)

	if got.ExitCode == 0 {
		t.Fatalf("run %s's workload was accepted as run %s", runA.RunID, runB.RunID)
	}
	if got.Outcome.Class != ClassInvariantViolation {
		t.Errorf("class = %q, want %s (raw probe output: %s)",
			got.Outcome.Class, ClassInvariantViolation, got.Raw)
	}
	if got.Outcome.Retryable {
		t.Error("INVARIANT_VIOLATION was marked retryable")
	}
}
