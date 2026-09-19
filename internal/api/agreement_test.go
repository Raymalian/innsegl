// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// REC-018 (proposed for doc 07; doc 07 is not modified here).
//
//	One chain holding every combination of withdrawal, activity and
//	retirement, read by the SPIRE entry reconciler and by the query API
//	→ the same state for the same run, from both, under every horizon
//	→ I3, IP §6.10, AB-11
//
// # Why this case is the point of #258 rather than a corollary of it
//
// Three components used to decide independently whether a run was closed. The
// reconciler read a run as closed from its first `run_expired` for ever and
// reported the entry the restore path legitimately re-created as one that
// should have been deleted; the query API, taught the right rule in #256, said
// the same run was active. Both answers were shown to the same operator about
// the same run, and an operator shown two answers learns to believe neither.
//
// Making REC-017 green only proves the reconciler stopped being wrong about ONE
// shape. What stops the two drifting apart again is that their answers are
// compared — so this case reads both, over a chain built to contain every
// combination the rule can be asked about, and fails on the first word they do
// not share.
//
// # Why it lives in this package
//
// It needs a real Postgres (the SQL rendering of the rule is half of what is
// being compared, and a rendering nothing executes proves nothing), the
// read-only role the query API refuses to start without, and the reconciler.
// This package's harness already stands up the first two. internal/spire is
// imported for the third; it does not import this package, so nothing here is
// a cycle.
//
// # How it is kept from passing vacuously
//
//  1. THE FIXTURE HAS TO CONTAIN ALL FOUR STATES. Asserted before anything is
//     compared: two components that agree on a chain holding only active runs
//     have agreed about nothing.
//  2. THE RECONCILER HAS TO HAVE READ THE CHAIN. Its answer must name every
//     run the read API names — a reconciler that read nothing agrees with
//     everything.
//  3. BOTH HORIZONS ARE EXERCISED. Lapsed and Abandoned differ by one
//     comparison against one number, and a case run at a single horizon cannot
//     see the two components reading that number differently.

// The fixture's runs, and what each one's record is.
//
// Every combination of the three facts, including the orders that only look
// redundant: a retirement before a withdrawal and a retirement after one are
// different chains, and the rule's first clause — retirement wins
// unconditionally — is the only thing that makes them the same answer.
var agreementRuns = []struct {
	id    string
	steps []struct{ typ, src string }
}{
	// No withdrawal.
	{"agree-registered", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP))},
	{"agree-working", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeToolCall, event.SourceMCP))},
	// Withdrawal, nothing since.
	{"agree-quiet", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper))},
	// Withdrawal, and the run spoke again: the restored run REC-017 is about.
	{"agree-resumed", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper),
		step(event.EventTypeToolCall, event.SourceMCP))},
	// Two withdrawals with work between them: the newest is the one that
	// stands, and it stands.
	{"agree-relapsed", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper),
		step(event.EventTypeToolCall, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper))},
	// Retirement, in every position relative to the other two facts.
	{"agree-ended", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunRetired, event.SourceMCP))},
	{"agree-ended-then-noise", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunRetired, event.SourceMCP),
		step(event.EventTypeToolCall, event.SourceMCP))},
	{"agree-withdrawn-then-ended", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper),
		step(event.EventTypeRunRetired, event.SourceMCP))},
	{"agree-ended-then-withdrawn", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunRetired, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper))},
	{"agree-resumed-then-ended", steps(
		step(event.EventTypeRunRegistered, event.SourceMCP),
		step(event.EventTypeRunExpired, event.SourceReaper),
		step(event.EventTypeToolCall, event.SourceMCP),
		step(event.EventTypeRunRetired, event.SourceMCP))},
}

type agreementStep struct{ typ, src string }

func step(typ, src string) agreementStep { return agreementStep{typ, src} }

func steps(in ...agreementStep) []struct{ typ, src string } {
	out := make([]struct{ typ, src string }, 0, len(in))
	for _, s := range in {
		out = append(out, struct{ typ, src string }{s.typ, s.src})
	}
	return out
}

// agreementSPIFFEID is the identity the fixture gives a run. The reconciler is
// keyed by SPIFFE ID and the query API by run id, so the two have to be
// relatable: this is the one place the fixture states how.
func agreementSPIFFEID(runID string) string {
	return "spiffe://innsegl.dev/agent/fix-ci/jira-1/" + runID
}

// agreementFixture writes the chain and returns the owner store (the
// reconciler's ledger) beside the read-only store (the query API's).
func agreementFixture(t *testing.T) (*ledger.Store, string) {
	t.Helper()
	owner, _, readerDSN := migrated(t)
	ctx := t.Context()

	for _, run := range agreementRuns {
		for i, s := range run.steps {
			body := event.Fields{
				event.FieldEventType: s.typ,
				event.FieldRunID:     run.id,
				event.FieldSpiffeID:  agreementSPIFFEID(run.id),
				event.FieldSource:    s.src,
			}
			switch s.typ {
			case event.EventTypeRunRegistered:
				// ADR-0004: only the registration carries a key here.
				// run_retired and run_expired are refused outright if given
				// one, and two run_expired events for one run is exactly what
				// RM-152 (#255) made possible.
				body[event.FieldIdempotencyKey] = run.id + "-register"
				body[event.FieldAgentType] = "fix-ci"
				body[event.FieldTaskRef] = "JIRA-1"
				body[event.FieldRepo] = "github.com/innsegl/one"
				body[event.FieldBranch] = "main"
			case event.EventTypeToolCall:
				body[event.FieldToolName] = "observe_tool_call"
				body[event.FieldIdempotencyKey] = fmt.Sprintf("%s-call-%d", run.id, i)
			}
			appendOrFail(ctx, t, owner, body)
		}
	}
	return owner, readerDSN
}

// noEntries is SPIRE holding nothing.
//
// The comparison below is about what the two components CONCLUDE from the
// chain, and SPIRE's entry list is not an input to that: the reconciler derives
// a run's state from the ledger alone and only then asks whether the entries
// match it. Holding the entry list empty keeps the fixture's chain still —
// every drift this reconciler could raise is appended as a
// `ledger_drift_detected` carrying the run's own id, which would itself become
// the run's newest non-reaper fact and move the very states being compared.
// TestREC018TheTwoAgreeAboutWhichEntriesShouldBeGone uses a fixture of its own
// for exactly that reason.
type noEntries struct{}

func (noEntries) TrustDomain() string { return "innsegl.dev" }

func (noEntries) ListAgentEntries(context.Context) ([]spire.Entry, error) {
	return nil, nil
}

// heldEntries is SPIRE holding one entry for every run named.
type heldEntries struct{ spiffeIDs []string }

func (heldEntries) TrustDomain() string { return "innsegl.dev" }

func (e heldEntries) ListAgentEntries(context.Context) ([]spire.Entry, error) {
	out := make([]spire.Entry, 0, len(e.spiffeIDs))
	for i, id := range e.spiffeIDs {
		out = append(out, spire.Entry{ID: fmt.Sprintf("entry-%d", i), SPIFFEID: id})
	}
	return out, nil
}

// reconcilerStates runs one cycle and returns the state it derived per run.
//
// minAge is enormous on purpose in the agreement case: the two age-gated drift
// kinds are then out of reach, the cycle appends nothing, and the chain the
// query API reads a moment later is the chain the reconciler read.
func reconcilerStates(t *testing.T, owner *ledger.Store, entries spire.EntrySource,
	minAge time.Duration,
) spire.Result {
	t.Helper()
	rec, err := spire.NewReconciler(spire.ReconcilerConfig{
		Entries:  entries,
		Ledger:   owner,
		Appender: owner,
		MinAge:   minAge,
		Alert:    func(context.Context, spire.Drift) {},
		Observe:  func(spire.Result, error) {},
	})
	if err != nil {
		t.Fatalf("spire.NewReconciler: %v", err)
	}
	result, err := rec.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result
}

// TestREC018TheReconcilerAndTheReadAPIAgreeAboutEveryRun.
func TestREC018TheReconcilerAndTheReadAPIAgreeAboutEveryRun(t *testing.T) {
	for _, horizon := range []struct {
		name string
		set  string
	}{
		// Longer than anything in the fixture is old: every standing
		// withdrawal is inside it, and Lapsed is the withdrawn answer.
		{name: "inside the restore horizon", set: "720h"},
		// Shorter than the age of any event already appended, so every
		// standing withdrawal is outside it and Abandoned is.
		{name: "past the restore horizon", set: "1ns"},
		// The third arm: a deployment that set none. Nothing is ever
		// abandoned, in either component.
		{name: "with no horizon at all", set: "0"},
	} {
		t.Run(horizon.name, func(t *testing.T) {
			// ONE VARIABLE, READ BY BOTH. The reconciler resolves it in
			// NewReconciler and the query API in Open, from the same function
			// (ledger.RestoreHorizonFromEnv), so this line is also the
			// assertion that there is one number rather than two that happen
			// to match today.
			t.Setenv(ledger.EnvRestoreHorizon, horizon.set)

			owner, readerDSN := agreementFixture(t)
			result := reconcilerStates(t, owner, noEntries{}, 100*time.Hour)
			if len(result.Appended) != 0 {
				t.Fatalf("the agreement cycle appended %d alert(s): %v. Those carry the "+
					"run's own id, so they become its newest fact and move the states "+
					"being compared — the comparison below would be measuring itself",
					len(result.Appended), result.Appended)
			}

			s, _ := readStore(t, readerDSN)
			page, err := s.ListRuns(t.Context(), RunFilter{Limit: MaxPageSize})
			if err != nil {
				t.Fatalf("ListRuns: %v", err)
			}
			if len(page.Runs) != len(agreementRuns) {
				t.Fatalf("the read API returned %d runs, want %d: the fixture and the "+
					"comparison are not looking at the same chain",
					len(page.Runs), len(agreementRuns))
			}

			// (1) The fixture really does exercise the rule.
			seen := map[string]bool{}
			for _, r := range page.Runs {
				seen[r.Status] = true
			}
			wantStates := []string{StatusActive, StatusRetired}
			if horizon.set == "1ns" {
				wantStates = append(wantStates, StatusAbandoned)
			} else {
				wantStates = append(wantStates, StatusLapsed)
			}
			for _, want := range wantStates {
				if !seen[want] {
					t.Fatalf("no run in the fixture reads %q under horizon %q; agreement "+
						"over a chain that never reaches a state says nothing about it",
						want, horizon.set)
				}
			}

			// (2) and (3) — the comparison itself.
			for _, r := range page.Runs {
				got, known := result.RunStates[r.RunID]
				if !known {
					t.Errorf("the reconciler derived no state for %s, which the read API "+
						"calls %q. A control that has not read a run cannot be said to "+
						"agree about it", r.RunID, r.Status)
					continue
				}
				if got != r.Status {
					t.Errorf("%s: the reconciler says %q and the read API says %q.\n"+
						"Two components deciding a run's state on different grounds is the "+
						"defect #258 closes: the one shown to an operator as an integrity "+
						"alert and the one shown on the dashboard have to be the same word",
						r.RunID, got, r.Status)
				}
			}

			// And the detail view, which is a second statement of the same
			// thing and has been wrong on its own before.
			for _, r := range page.Runs {
				detail, derr := s.Run(t.Context(), r.RunID)
				if derr != nil {
					t.Fatalf("Run(%s): %v", r.RunID, derr)
				}
				if detail.Status != r.Status {
					t.Errorf("%s: the runs table says %q and the run detail says %q",
						r.RunID, r.Status, detail.Status)
				}
			}

			// The overview counts the same four states, and a count that
			// disagrees with the rows it summarises is the shape #256 already
			// caught once.
			overview, oerr := s.Overview(t.Context())
			if oerr != nil {
				t.Fatalf("Overview: %v", oerr)
			}
			counts := map[string]int{
				StatusActive:    overview.ActiveRuns,
				StatusLapsed:    overview.LapsedRuns,
				StatusAbandoned: overview.AbandonedRuns,
				StatusRetired:   overview.RetiredRuns,
			}
			for _, state := range RunStatuses {
				want := 0
				for _, r := range page.Runs {
					if r.Status == state {
						want++
					}
				}
				if counts[state] != want {
					t.Errorf("the overview counts %d %s runs and the table lists %d",
						counts[state], state, want)
				}
			}
		})
	}
}

// TestREC018TheTwoAgreeAboutWhichEntriesShouldBeGone: agreement about a word is
// worth having because of what the word DECIDES.
//
// The reconciler's whole output is an accusation — "the ledger says this entry
// was deleted and SPIRE still holds it" — and the run it makes that accusation
// about must be exactly a run the read API does not call active. A restored run
// raises nothing (REC-017); a retired one whose entry came back raises
// `spire_entry_not_deleted` and must keep doing so, because retirement is final
// and an entry that comes back after one is AB-11.
func TestREC018TheTwoAgreeAboutWhichEntriesShouldBeGone(t *testing.T) {
	t.Setenv(ledger.EnvRestoreHorizon, "720h")

	owner, readerDSN := agreementFixture(t)

	// THE READ API IS ASKED FIRST, AND THAT ORDER IS LOAD-BEARING.
	//
	// An alert is an append. `ledger_drift_detected` carries the run's own
	// `run_id` and `spiffe_id` (doc 02 §2 omits the two only for an alert that
	// references no run) and its `source` is `reconciler`, which is not the
	// reaper — so by the rule both components read, the alert itself becomes
	// the run's newest non-reaper fact and a withdrawn run reads active from
	// the moment it is raised. Reading the API after the cycle would compare
	// the reconciler's answer against a chain the cycle had changed.
	//
	// That interaction is REPORTED, NOT PAPERED OVER: it is a property of the
	// rule #256 shipped and #258 extracted, not of this test, and it is written
	// up at ledger.RunFacts.LastActivityAt. Both halves of it — a standing
	// finding that stops being reported, and a dashboard that calls the run
	// active — are for a human to rule on, and neither is this issue's to
	// change unilaterally.
	s, _ := readStore(t, readerDSN)
	page, err := s.ListRuns(t.Context(), RunFilter{Limit: MaxPageSize})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}

	// SPIRE holds an entry for every run in the fixture.
	held := heldEntries{}
	for _, run := range agreementRuns {
		held.spiffeIDs = append(held.spiffeIDs, agreementSPIFFEID(run.id))
	}
	// MinAge a nanosecond: the fixture's state is already fully formed, and
	// waiting out DefaultMinAge would only re-test #108's in-flight window.
	// A nanosecond rather than zero, because zero is read as "use the default"
	// — the one value ReconcilerConfig.MinAge does not honour literally.
	result := reconcilerStates(t, owner, held, time.Nanosecond)

	accused := map[string]bool{}
	for _, d := range result.Drifts {
		if d.Kind == spire.DriftEntryNotDeleted {
			accused[d.RunID] = true
		}
		if d.Kind == spire.DriftEntryUnattributed {
			t.Errorf("the reconciler could not attribute %s to any run in a fixture that "+
				"registered every one of them: %+v", d.SPIFFEID, d)
		}
	}
	for _, r := range page.Runs {
		shouldBeGone := r.Status != StatusActive
		if accused[r.RunID] != shouldBeGone {
			t.Errorf("%s reads %q and the reconciler %s its surviving entry.\n"+
				"An entry is expected exactly while the run is active: reporting one for "+
				"a run the dashboard calls active teaches an operator to ignore %s, and "+
				"NOT reporting one for a run it calls retired is AB-11 going unseen",
				r.RunID, r.Status,
				map[bool]string{true: "reported", false: "did not report"}[accused[r.RunID]],
				spire.DriftEntryNotDeleted)
		}
	}

	// And the vacuous pass this is shaped against: a reconciler that accused
	// everything, or nothing, would satisfy a loop that never ran.
	if len(accused) == 0 {
		t.Fatal("no run was accused at all; a fixture in which nothing should have been " +
			"deleted cannot show that the two components agree about which runs should")
	}
	if len(accused) == len(page.Runs) {
		t.Fatal("every run was accused; the fixture holds active runs whose entry is " +
			"exactly where it belongs")
	}
	if !slices.ContainsFunc(page.Runs, func(r RunSummary) bool {
		return r.RunID == "agree-resumed" && r.Status == StatusActive
	}) {
		t.Fatal("agree-resumed is not active; REC-017's shape is missing from this fixture")
	}
}
