// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/spire"
)

// OPS-003 — "kill -9 fuzz campaign: random process kills across all components
// for a bounded soak, then full verification sweep" (doc 07, layer F; IP §6.6,
// §6.7).
//
// Doc 07 gives the expected result in one line:
//
//	Chain verifies end-to-end; reconciler converges; no orphan identities past TTL
//
// and issue #61 adds the fourth: no invariant violation survives the sweep.
//
// # The two ways this test could be worthless, and what is done about each
//
// A soak that kills processes and then asserts "nothing broke" passes when
// nothing was happening, and a verification sweep nobody has watched fail
// proves only that it compiles. Both failure modes are gated here rather than
// hoped away.
//
//  1. EVERY KILL LANDS ON WORK IN FLIGHT, AND THE PROOF IS DURABLE. The killer
//     never sleeps and then fires. It polls Postgres and fires the instant the
//     idempotency table holds an `in_progress` row — a claim taken by a tool
//     call that has not recorded its reply. That row is durable evidence,
//     written by the shipped server, that the process about to die is between
//     the start and the end of a tool call. After the soak the campaign counts
//     the keys whose `claim_count` reached 2 or more: ADR-0017 §5 makes a
//     second claim the trace of a replica that was killed holding the first
//     one, and the campaign FAILS if that count is zero. "The test called kill"
//     and "a kill interrupted a write" are different claims and only the
//     second is OPS-003's.
//
//  2. THE SWEEP IS SHOWN TO FAIL. Every check below is a named function over
//     gathered state, and the last subtest runs those same functions over
//     state with a violation planted in it — a flipped byte in a chain link, a
//     removed event, a second identity for one run, a backwards timestamp, an
//     entry past its deadline, an entry for a run the chain never registered —
//     and fails if the sweep stays quiet. Two of the plants are not simulated
//     at all: a real registration entry with a one-second TTL is created in the
//     real SPIRE, and a fabricated `commit_recorded` is appended to the real
//     chain. This project has already shipped an assertion that could not fail
//     (RM-035 measured five integration cases skipping while CI stayed green);
//     a sweep with no self-test would be the same mistake in a new place.
//
// # Reproducing a run
//
// The seed is printed at the head of every campaign and again with every
// failure. INNSEGL_CHAOS_SEED=<seed> replays the identical sequence of kill
// targets, worker choices and delays.
//
// # What runs in CI and what is opt-in
//
// The whole of this file runs in CI, including both anti-vacuity gates and
// every planted violation. What CI does NOT do is soak for long: the kill
// budget defaults to k9KillsDefault, which is enough for the gates below to
// have something to measure and small enough to keep the case inside a few
// minutes. INNSEGL_CHAOS_KILLS and INNSEGL_CHAOS_WORKERS raise it for an
// operator who wants a long campaign; nothing is skipped when they are unset,
// and no assertion is weakened. A soak that only ran behind an env var would
// be a soak nobody runs.
func TestOPS003KillNineFuzzSoakAcrossEveryComponent(t *testing.T) {
	c := requireK9Campaign(t)

	c.soak(t)
	c.restoreEverything(t)

	// IP §6.7's resolution step, run by the shipped reaper rather than
	// reimplemented here. It is part of the sweep and not part of the
	// assertion: "no orphan identities past TTL" is a claim about the state a
	// deployment converges to, and the reaper is how a deployment converges.
	expired := c.reapUntilQuiet(t)
	state := c.gather(t)

	t.Run("the soak interrupted work that was genuinely in flight", func(t *testing.T) {
		ev := c.evidence(t)
		t.Logf("seed %d: %d kills across %v; %d calls dispatched, %d interrupted "+
			"mid-call; innsegl.idempotency holds %d key(s), %d reclaimed after a "+
			"holder died (deepest %d claims), %d still stranded in flight",
			c.seed, ev.kills, ev.byTarget, ev.dispatched, ev.interrupted,
			ev.claims.rows, ev.claims.takeovers, ev.claims.maxClaims, ev.claims.stranded)

		if ev.kills == 0 {
			t.Fatalf("the soak landed no kills at all (seed %d). OPS-003 is a claim about "+
				"what SIGKILL leaves behind; with no kill there is nothing to leave "+
				"anything behind and every assertion below is vacuous.", c.seed)
		}
		for target, n := range ev.byTarget {
			if n == 0 {
				t.Errorf("no kill landed on %s (seed %d); doc 07 OPS-003 says "+
					"\"across all components\"", target, c.seed)
			}
		}
		if ev.idleKills != 0 {
			t.Errorf("%d of %d kills were fired with nothing in flight (seed %d). The "+
				"killer is supposed to park on an in_progress idempotency row and fire "+
				"on it; a kill that landed on an idle process measures nothing.",
				ev.idleKills, ev.kills, c.seed)
		}
		if ev.interrupted == 0 {
			t.Errorf("no dispatched call was ever interrupted (seed %d): every one of "+
				"%d calls returned normally. Either the kills missed or the workload "+
				"was not calling anything.", c.seed, ev.dispatched)
		}
		// The durable half. ADR-0017 §5: claim_count above 1 means a lease ran
		// out and another caller took the claim over, which is what a SIGKILLed
		// replica leaves. Read out of Postgres, not inferred from timing.
		if ev.claims.takeovers+ev.claims.stranded == 0 {
			t.Errorf("not one claim in innsegl.idempotency was reclaimed or stranded "+
				"(seed %d): every one of %d keys has claim_count = 1 and a recorded "+
				"reply. No kill provably landed between a claim and its reply, so the "+
				"soak may have killed only processes that were waiting rather than "+
				"writing, and every assertion below would be about an undisturbed "+
				"system.", c.seed, ev.claims.rows)
		}
		if ev.invariantViolations != 0 {
			t.Errorf("the server answered INVARIANT_VIOLATION %d time(s) during the soak "+
				"(seed %d); IP §6.2 makes that alert-level and it is a defect, not "+
				"degradation: %s", ev.invariantViolations, c.seed, ev.firstInvariant)
		}
	})

	t.Run("the chain verifies end to end", func(t *testing.T) {
		t.Logf("seed %d: %d events on the chain, tip at position %d",
			c.seed, len(state.records), state.tip.Position)
		if len(state.records) == 0 {
			t.Fatalf("the chain is empty after the soak (seed %d). Every tool the "+
				"workload calls appends (I3), so an empty chain means the workload "+
				"never ran and the sweep below would verify nothing.", c.seed)
		}
		c.requireNoViolations(t, "the chain", k9SweepChain(state))
	})

	t.Run("no orphan identity outlives its TTL", func(t *testing.T) {
		t.Logf("seed %d: the reaper expired %d run(s); %d entries remain live, "+
			"%d were unclassifiable", c.seed, expired, len(state.live), len(state.skipped))
		if expired == 0 {
			t.Errorf("the reaper expired nothing (seed %d). The workload abandons one "+
				"run in three without retiring it, exactly as IP §6.7 describes, so a "+
				"sweep that found no orphan means either no run was abandoned or the "+
				"reaper is not looking.", c.seed)
		}
		c.requireNoViolations(t, "the identity plane", k9SweepIdentities(state))
	})

	t.Run("the reconciler converges", func(t *testing.T) {
		// First over the state the soak actually left. Nothing here signs, so
		// the chain holds no `commit_intent` and this cycle is expected to be
		// quiet — which is worth asserting and is NOT what makes the subtest
		// non-vacuous. The two cycles below are.
		clean := c.reconcile(t, time.Now())
		if !clean.Drift.Enabled {
			t.Fatalf("drift detection is off (seed %d); a reconciler that is not "+
				"watching the log reports agreement it never checked (IP §6.10)", c.seed)
		}
		if n := len(clean.Appended); n != 0 {
			t.Errorf("a cycle over the post-soak chain appended %d event(s) (seed %d): %v",
				n, c.seed, clean.Appended)
		}
		if clean.Unresolved != 0 || clean.Ambiguous != 0 || clean.Drift.Unresolved != 0 {
			t.Errorf("the cycle could not rule on everything it looked at (seed %d): "+
				"%d unresolved, %d ambiguous, %d unresolved drift", c.seed,
				clean.Unresolved, clean.Ambiguous, clean.Drift.Unresolved)
		}

		// Now something to converge ON. A `commit_intent` with no signature is
		// the durable residue of IP §6.5's A → B crash, and it is appended here
		// through the shipped ledger rather than produced by `sign_commit`
		// because ADR-0033 gate 7 probes Sigstore BEFORE Phase A: with no
		// Fulcio in this stack the tool refuses before it writes anything, so
		// the window cannot be reached from the outside. The residue is
		// identical, and REC-002 in internal/reconciler is where a real crashed
		// `sign_commit` is measured against a real Fulcio and a real Rekor.
		runID, spiffeID := c.aRegisteredRun(t, state)
		intent := c.plantIntent(t, runID, spiffeID, "ops-003/converge")
		t.Logf("seed %d: planted commit_intent %s for run %s", c.seed,
			member(t, intent, event.FieldEventID), runID)

		// An hour on, so the intent is past DefaultExpireAfter. Config.Now is
		// the reconciler's own seam for this; the ledger's clock is untouched.
		first := c.reconcile(t, time.Now().Add(time.Hour))
		if first.Expired != 1 || len(first.Appended) != 1 {
			t.Fatalf("the reconciler did not close the dangling intent (seed %d): "+
				"expired=%d appended=%v findings=%+v", c.seed, first.Expired,
				first.Appended, first.Findings)
		}
		c.requireEventType(t, first.Appended[0], event.EventTypeCommitIntentExpired)

		// Convergence is the second cycle, not the first: a repair that ran
		// again would be a repair nobody could run twice (REC-005).
		second := c.reconcile(t, time.Now().Add(2*time.Hour))
		if len(second.Appended) != 0 {
			t.Errorf("a second cycle over the repaired chain appended %v (seed %d); the "+
				"reconciler has not converged if running it again changes the ledger",
				second.Appended, c.seed)
		}
		if second.Open != 0 {
			t.Errorf("%d intent(s) are still open after the repair (seed %d)",
				second.Open, c.seed)
		}
	})

	// ---------------------------------------------------------------------
	// The sweep, shown to fail.
	// ---------------------------------------------------------------------

	t.Run("the sweep catches a planted broken chain link", func(t *testing.T) {
		bad := k9Clone(state)
		i := len(bad.records) / 2
		bad.records[i][event.FieldPrevEventHash] = k9FlipDigest(
			member(t, bad.records[i], event.FieldPrevEventHash))
		c.requireViolation(t, k9CheckChainLinks, k9SweepChain(bad),
			fmt.Sprintf("position %d", i+1))
	})

	t.Run("the sweep catches a planted removed event", func(t *testing.T) {
		bad := k9Clone(state)
		i := len(bad.records) / 2
		bad.records = append(bad.records[:i], bad.records[i+1:]...)
		// A removed event shows up as the walk arriving at a record that
		// carries the position after the one it expected.
		c.requireViolation(t, k9CheckChainLinks, k9SweepChain(bad),
			fmt.Sprintf("expected %d here and the record is at %d", i+1, i+2))
	})

	t.Run("the sweep catches a planted truncation", func(t *testing.T) {
		bad := k9Clone(state)
		bad.records = bad.records[:len(bad.records)-1]
		c.requireViolation(t, k9CheckChainTip, k9SweepChain(bad))
	})

	t.Run("the sweep catches a planted second identity", func(t *testing.T) {
		bad := k9Clone(state)
		reg := k9FindEvent(t, bad.records, event.EventTypeRunRegistered)
		bad.records = append(bad.records, k9CloneFields(reg))
		c.requireViolation(t, k9CheckOneIdentityPerRun, k9SweepChain(bad),
			member(t, reg, event.FieldRunID))
	})

	t.Run("the sweep catches a planted backwards timestamp", func(t *testing.T) {
		bad := k9Clone(state)
		i := len(bad.records) - 1
		bad.records[i][event.FieldTS] = "2000-01-01T00:00:00.000000Z"
		c.requireViolation(t, k9CheckMonotonicTS, k9SweepChain(bad))
	})

	t.Run("the sweep catches an entry for a run the chain never registered", func(t *testing.T) {
		bad := k9Clone(state)
		ghost := spire.Candidate{
			Run: spire.RunRef{
				AgentType: k9AgentType,
				TaskID:    k9TaskID,
				RunID:     fmt.Sprintf("run-%d-ghost", c.seed%1_000_000),
			},
			CreatedAt: bad.now,
			Deadline:  bad.now.Add(time.Hour),
		}
		ghost.Entry = spire.Entry{
			ID:       "ghost-entry",
			SPIFFEID: k9SPIFFEIDFor(t, ghost.Run),
			TTL:      time.Hour,
		}
		bad.live = append(bad.live, ghost)
		c.requireViolation(t, k9CheckEntryIsRecorded, k9SweepIdentities(bad), ghost.Run.RunID)
	})

	t.Run("the sweep catches a real orphan planted in the real SPIRE", func(t *testing.T) {
		// Not a tampered snapshot: a registration entry created through the
		// shipped admin client, with a one-second identity lifetime, that
		// nobody retires. IP §6.7's agent that crashed.
		run, cand := c.plantOrphan(t)
		orphaned := c.awaitOrphaned(t, state, cand)
		c.requireViolation(t, k9CheckNoOrphanPastTTL, k9SweepIdentities(orphaned), run.RunID)

		// And then the shipped reaper resolves it, which is the other half of
		// IP §6.7: the expiry is recorded, distinctly from a retirement.
		report := c.sweepOnce(t)
		expiry, found := report.FindExpired(run.RunID)
		if !found {
			t.Fatalf("the reaper did not expire the planted orphan %s (seed %d); "+
				"report: %s", run.RunID, c.seed, report)
		}
		if !expiry.Deleted {
			t.Errorf("the planted orphan's entry was not deleted (seed %d)", c.seed)
		}
		c.requireEventType(t, expiry.EventID, event.EventTypeRunExpired)
		c.requireNoViolations(t, "the identity plane after reaping the planted orphan",
			k9SweepIdentities(c.gather(t)))
	})

	t.Run("the sweep catches a fabricated commit record", func(t *testing.T) {
		// IP §6.10, in as many words: "inject a fabricated `commit_recorded`
		// with no Rekor entry, assert drift detection fires". Appended to the
		// REAL chain and asked of the REAL Rekor, which genuinely holds no such
		// entry. This is the plant that proves the cross-check half of the
		// sweep is capable of convicting the ledger it reads.
		runID, spiffeID := c.aRegisteredRun(t, state)
		intent := c.plantIntent(t, runID, spiffeID, "ops-003/fabricated")
		fake := c.plantFabricatedRecord(t, intent)

		result := c.reconcile(t, time.Now().Add(3*time.Hour))
		if result.Drift.Fabricated != 1 {
			t.Fatalf("drift detection did not convict the fabricated commit_recorded "+
				"(seed %d): %d fabricated, %d unattributed, %d unresolved, findings %+v",
				c.seed, result.Drift.Fabricated, result.Drift.Unattributed,
				result.Drift.Unresolved, result.Drift.Findings)
		}
		var subject string
		for _, f := range result.Drift.Findings {
			if f.Kind == reconciler.DriftFabricatedRecord {
				subject = f.SubjectEventID
			}
		}
		if want := member(t, fake, event.FieldEventID); subject != want {
			t.Errorf("the finding names subject %q, the fabricated event is %q (seed %d)",
				subject, want, c.seed)
		}
		if len(result.Drift.Appended) != 1 {
			t.Errorf("the cross-check appended %v (seed %d); IP §6.10 requires the "+
				"detection to be loud, which means recorded", result.Drift.Appended, c.seed)
		}

		// Still converges: a second cycle re-detects nothing, because the alert
		// is deduplicated by the subject's event id.
		again := c.reconcile(t, time.Now().Add(4*time.Hour))
		if len(again.Drift.Appended) != 0 {
			t.Errorf("a second cross-check appended %v (seed %d)", again.Drift.Appended, c.seed)
		}
	})

	t.Run("the chain still verifies after everything the sweep appended", func(t *testing.T) {
		// I4: every repair, every alert and every expiry above is a new event,
		// never an edit. If any of them had rewritten history this is where it
		// shows.
		c.requireNoViolations(t, "the chain, after the sweep", k9SweepChain(c.gather(t)))
	})
}

// TestOPS003ADependencyThatIsAbsentIsNotAStackThatFailed is issue #101's
// distinction, tested rather than commented.
//
// Eight harnesses in this repository report a failed dependency as a skip, so
// `go test` exits zero while nothing ran. internal/verify/verifyharness_test.go
// carries the corrected shape and this file adopts it: absent Docker is the
// only condition under which OPS-003 may skip, and everything else that can go
// wrong while standing the stack up — a network that cannot be created, a port
// that cannot be bound, a container that never becomes healthy — is a FAILURE.
//
// Both branches are exercised here, and this case never skips: it needs no
// Docker, because what it tests is the classification and not the stack.
func TestOPS003ADependencyThatIsAbsentIsNotAStackThatFailed(t *testing.T) {
	absent := fmt.Errorf("no reachable docker daemon: %w", errK9DependencyAbsent)
	skip, fail := k9Classify(absent)
	if skip == "" {
		t.Errorf("an absent Docker daemon must be a skip; got skip=%q fail=%q", skip, fail)
	}
	if fail != "" {
		t.Errorf("an absent Docker daemon must not be a failure; got fail=%q", fail)
	}

	broken := errors.New("compose up: Error response from daemon: " +
		"all predefined address pools have been fully subnetted")
	skip, fail = k9Classify(broken)
	if fail == "" {
		t.Errorf("a stack that did not come up on a machine that has Docker must be a "+
			"failure; got skip=%q fail=%q", skip, fail)
	}
	if skip != "" {
		t.Errorf("a stack that did not come up must not be a skip; got skip=%q", skip)
	}
	if !strings.Contains(fail, "address pools") {
		t.Errorf("the failure must carry the cause an operator acts on; got %q", fail)
	}

	// And the branch that matters most: errors.Is must not be fooled by an
	// error that merely mentions the words.
	lookalike := errors.New("a required dependency is absent")
	if _, fail = k9Classify(lookalike); fail == "" {
		t.Error("an error that only spells the sentinel's text must still be a failure; " +
			"the classification is errors.Is, not a substring match")
	}
}

// TestOPS003TheSeedIsReproducible pins the generator down.
//
// A campaign that finds a defect once and cannot be re-run is a rumour, so the
// seed has to reproduce the sequence exactly — including across Go releases,
// which is why the generator is written out here rather than taken from
// math/rand. This case never skips and needs nothing but the generator.
func TestOPS003TheSeedIsReproducible(t *testing.T) {
	draw := func(seed uint64) []int {
		r := newK9RNG(seed)
		out := make([]int, 0, 32)
		for range 16 {
			out = append(out, r.intn(len(k9Targets)))
			out = append(out, int(r.duration(0, time.Second)))
		}
		return out
	}
	a, b := draw(0xC0FFEE), draw(0xC0FFEE)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("draw %d differs between two generators seeded alike: %d vs %d",
				i, a[i], b[i])
		}
	}
	if c := draw(0xC0FFEF); fmt.Sprint(c) == fmt.Sprint(a) {
		t.Fatal("two different seeds produced the same sequence; the seed is not the input")
	}
}
