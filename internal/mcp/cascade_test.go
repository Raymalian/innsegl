// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// MCP-083 … MCP-085 — a harness that ends a session ends what it started
// (RM-157, #260).
//
// # What was measured
//
// Five subagent runs sat Active for between three and nine hours after the
// processes behind them were gone, and an operator closed them by hand.
// Nothing had ended them and nothing could have: a killed process fires no
// SubagentStop, and the reaper's grace is twelve hours by policy. The one
// party that KNEW those subagents were over — the session that started them —
// said nothing on its way out.
//
// # The line these cases exist to hold
//
// This is an ASSERTION, not an inference. The cascade runs when, and only
// when, a stop carries `ends_descendants`; nothing anywhere reads a parent's
// retirement and concludes anything about a child's. That would be IP §3 E7,
// and E7 is about what the code DOES rather than about what it is called — so
// the negative cases below are the load-bearing ones:
//
//   - a start that carries the flag ends nothing (the session is running),
//   - a stop that does NOT carry it ends only its own run (default off),
//   - a repeat ends nothing a second time.
//
// # What is real here
//
// The ledger is a real Postgres and the parentage lookup is the shipped
// ledger.Store.ChildRuns over the shipped migration 0005 index, because "every
// descendant" is a claim about the edges the chain actually holds. The
// retirement is the shipped retire_agent, in process, so "no second event" is
// migrations/0004's partial unique index rather than a stand-in's bookkeeping.
// SPIRE is the same fake the rest of this package's session cases use.

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

// osStopEnding is a stop that asserts it ends what it started.
func osStopEnding(t *testing.T, sessionID string) (observeSessionOut, error) {
	t.Helper()
	return observeSession(t.Context(), nil, observeSessionIn{
		SessionID:       sessionID,
		Phase:           ObserveSessionPhaseStop,
		EndsDescendants: true,
	})
}

// osMustStopEnding fails the test on a refusal. A stop never blocks, whatever
// else it could not finish, so a helper never tolerates one.
func osMustStopEnding(t *testing.T, sessionID string) observeSessionOut {
	t.Helper()
	out, err := osStopEnding(t, sessionID)
	if err != nil {
		t.Fatalf("a stop that ends what it started refused with %v.\n"+
			"A stop never blocks (IP §4): a retry storm was measured at nine deep when "+
			"one did, and a cascade is the last thing that should introduce one", err)
	}
	return out
}

// osFamily is a session, a subagent it started, and a subagent that subagent
// started — three generations, because "descendants" is not "children" and a
// walk that stopped at the first generation would pass every one-level case.
type osFamily struct {
	session    observeSessionOut
	child      observeSessionOut
	grandchild observeSessionOut
}

const (
	osFamilySession    = "orchestrator-session"
	osFamilyChild      = "worker-agent"
	osFamilyGrandchild = "worker-of-the-worker"
)

func osStartFamily(t *testing.T, e *osEnv) osFamily {
	t.Helper()
	fam := osFamily{session: e.mustStart(t, osFamilySession)}

	child, err := osStartWithParentSession(t, e, osFamilyChild, osFamilySession)
	if err != nil {
		t.Fatalf("starting a subagent under the session: %v", err)
	}
	fam.child = child

	grandchild, err := osStartWithParentSession(t, e, osFamilyGrandchild, osFamilyChild)
	if err != nil {
		t.Fatalf("starting a subagent under the subagent: %v", err)
	}
	fam.grandchild = grandchild

	// The edges are the whole premise. A fixture whose runs were unrelated
	// would make every assertion below vacuous.
	for _, rel := range []struct{ child, parent observeSessionOut }{
		{fam.child, fam.session}, {fam.grandchild, fam.child},
	} {
		if got := registeredBody(t, e, rel.child.RunID)[event.FieldParentRunID]; got != rel.parent.RunID {
			t.Fatalf("%s of %s = %v, want %s; the fixture has no family to cascade over",
				event.FieldParentRunID, rel.child.RunID, got, rel.parent.RunID)
		}
	}
	return fam
}

// retirements counts the `run_retired` events for one run, off the chain.
func (e *osEnv) retirements(t *testing.T, runID string) int {
	t.Helper()
	return e.countEvents(t, runID, event.EventTypeRunRetired)
}

// ---------------------------------------------------------------------------
// MCP-083 — the descendants are ended.
// ---------------------------------------------------------------------------

// MCP-083: a stop that asserts it ends what it started ends every still-open
// descendant, to every depth, and records each ending.
func TestMCP083AStopThatEndsWhatItStartedEndsEveryOpenDescendant(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	for _, run := range []observeSessionOut{fam.session, fam.child, fam.grandchild} {
		if n := env.retirements(t, run.RunID); n != 0 {
			t.Fatalf("%s is already retired %d time(s) before the stop", run.RunID, n)
		}
	}

	stopped := osMustStopEnding(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("the session's own stop did not retire it: %+v", stopped)
	}

	for what, run := range map[string]observeSessionOut{
		"the session":    fam.session,
		"its subagent":   fam.child,
		"its grandchild": fam.grandchild,
	} {
		if n := env.retirements(t, run.RunID); n != 1 {
			t.Errorf("%s (%s) has %d run_retired, want exactly 1.\n"+
				"The session that started it said so on its way out; a run nothing ends "+
				"stays Active until the reaper's grace runs out hours later",
				what, run.RunID, n)
		}
	}
}

// A cascaded ending is BYTE-IDENTICAL to any other, which is the constraint
// that keeps this out of a major release: doc 02 §3 gains no member for "this
// one was cascaded", and `source` stays `mcp` because an MCP tool call
// appended it.
func TestACascadedEndingIsIndistinguishableFromAnyOther(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)
	osMustStopEnding(t, osFamilySession)

	own := osRetirementOf(t, env, fam.session.RunID)
	cascaded := osRetirementOf(t, env, fam.child.RunID)

	// Same members, name for name. A reader of the chain cannot tell which of
	// these two endings was asked for directly and which followed.
	ownNames, cascadedNames := osMemberNames(own), osMemberNames(cascaded)
	if strings.Join(ownNames, ",") != strings.Join(cascadedNames, ",") {
		t.Fatalf("a cascaded run_retired carries %v and an ordinary one carries %v.\n"+
			"They must be the same event: a new member here is a major release (doc 08 §3)",
			cascadedNames, ownNames)
	}
	if got := cascaded[event.FieldSource]; got != event.SourceMCP {
		t.Errorf("a cascaded run_retired has source %v, want %q; the enum gains nothing",
			got, event.SourceMCP)
	}
	if got := cascaded[event.FieldEventType]; got != event.EventTypeRunRetired {
		t.Errorf("a cascaded ending was recorded as %v, want %q", got, event.EventTypeRunRetired)
	}
	if _, present := cascaded[event.FieldIdempotencyKey]; present {
		t.Errorf("a cascaded run_retired carries an %s; ADR-0004 forbids one on this "+
			"event type, and the partial unique index is what keeps it to one per run",
			event.FieldIdempotencyKey)
	}
}

// A LAPSED descendant is still open, and is ended. Silence is not an ending
// (#258): a run the reaper withdrew authorisation from is an agent that went
// quiet, not one that finished, and the session that started it is the only
// party entitled to say it is over.
func TestALapsedDescendantIsStillOpenAndIsEnded(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	if _, err := env.ledger.Append(t.Context(), event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     event.EventTypeRunExpired,
		event.FieldSource:        event.SourceReaper,
		event.FieldRunID:         fam.child.RunID,
		event.FieldSpiffeID:      fam.child.SPIFFEID,
	}); err != nil {
		t.Fatalf("appending a lapse for the subagent: %v", err)
	}

	osMustStopEnding(t, osFamilySession)

	if n := env.retirements(t, fam.child.RunID); n != 1 {
		t.Errorf("a LAPSED descendant has %d run_retired, want 1. A withdrawal is not an "+
			"ending, so the run was still open and the session said it was over", n)
	}
	if n := env.retirements(t, fam.grandchild.RunID); n != 1 {
		t.Errorf("the lapsed run's own child has %d run_retired, want 1; the walk must "+
			"not stop at a run that went quiet", n)
	}
}

// ---------------------------------------------------------------------------
// MCP-084 — a repeat is a no-op.
// ---------------------------------------------------------------------------

// MCP-084: repeating the stop ends nothing a second time.
//
// `run_retired` takes no idempotency key (ADR-0004), so this is not a dedupe
// against a caller's string: it is the run directory's answer plus
// migrations/0004's partial unique index, reached through the shipped
// retire_agent. A second `run_retired` for one run is IP §6.6's "never a
// second event" broken, permanently.
func TestMCP084RepeatingTheStopEndsNothingASecondTime(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	osMustStopEnding(t, osFamilySession)
	before := len(env.chain(t))

	second := osMustStopEnding(t, osFamilySession)
	third := osMustStopEnding(t, osFamilySession)

	if after := len(env.chain(t)); after != before {
		t.Errorf("two more stops appended %d event(s); a repeat is a no-op", after-before)
	}
	for _, run := range []observeSessionOut{fam.session, fam.child, fam.grandchild} {
		if n := env.retirements(t, run.RunID); n != 1 {
			t.Errorf("%s has %d run_retired after three stops, want 1", run.RunID, n)
		}
	}
	// And every repeat is answered with the ORIGINAL instant, never a clock
	// read now (IP §4).
	if second.RetiredAt == "" || second.RetiredAt != third.RetiredAt {
		t.Errorf("repeated stops answered %q then %q; both must be the first retirement",
			second.RetiredAt, third.RetiredAt)
	}
}

// ---------------------------------------------------------------------------
// MCP-085 — a partial failure is reported, and is not fatal.
// ---------------------------------------------------------------------------

// MCP-085: one descendant that cannot be ended is reported in `detail` and
// costs neither the stop nor the other descendants.
func TestMCP085APartialFailureIsReportedAndDoesNotFailTheStop(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	// SPIRE refuses to delete exactly one run's entry. retire_agent appends
	// the record first and then deletes (ADR-0018), so this is the window that
	// leaves a retirement incomplete — and it is reported with SPIRE's own
	// class rather than with a class this file invented.
	env.spire.failRun(fam.child.RunID, errors.New("the SPIRE server is not answering"))

	stopped := osMustStopEnding(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("one descendant's failure cost the session its own retirement: %+v", stopped)
	}
	if !strings.Contains(stopped.Detail, fam.child.RunID) {
		t.Errorf("detail does not name the descendant that could not be ended.\n"+
			"got: %q\nwant it to name %s", stopped.Detail, fam.child.RunID)
	}

	// THE OTHERS STILL ENDED. A cascade that stopped at its first failure
	// would leave the rest of a killed session's subagents Active, which is
	// the whole defect.
	if n := env.retirements(t, fam.grandchild.RunID); n != 1 {
		t.Errorf("the grandchild has %d run_retired, want 1; one failure must not "+
			"abandon the rest of the walk", n)
	}
	if n := env.retirements(t, fam.session.RunID); n != 1 {
		t.Errorf("the session itself has %d run_retired, want 1", n)
	}
}

// A SECOND failure does not displace the first, and does not lengthen the
// reply.
//
// The summary names ONE descendant — "the first being …" — and a walk over a
// killed session can meet any number. IP §2 puts the branch that keeps it at
// one on the 100% floor, so this is the case where it is taken: two
// descendants, both unable to be ended, and a reply that is still the same
// shape as the reply for one.
//
// Which one is named is not arbitrary either. It is the first in walk order,
// which is breadth-first from the stopping run, so two operators reading two
// copies of this reply are reading about the same run.
func TestASecondFailureDoesNotDisplaceTheFirstOneNamed(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	// BOTH descendants, so the walk meets a failure with a failure already
	// recorded. SPIRE refuses each deletion; retire_agent appends the record
	// first and deletes after (ADR-0018), so this is the window that leaves a
	// retirement incomplete rather than a stand-in's bookkeeping.
	env.spire.failRun(fam.child.RunID, errors.New("the SPIRE server is not answering"))
	env.spire.failRun(fam.grandchild.RunID, errors.New("the SPIRE server is not answering"))

	stopped := osMustStopEnding(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("two descendants' failures cost the session its own retirement: %+v", stopped)
	}

	// THE FIRST IN WALK ORDER, AND ONLY IT. Naming the second as well would
	// make the reply grow with the outage, which is how a stop's detail
	// becomes a page nobody reads.
	if !strings.Contains(stopped.Detail, fam.child.RunID) {
		t.Errorf("detail does not name the first descendant that could not be ended.\n"+
			"got: %q\nwant it to name %s", stopped.Detail, fam.child.RunID)
	}
	if strings.Contains(stopped.Detail, fam.grandchild.RunID) {
		t.Errorf("detail names the second failure as well as the first.\n"+
			"got: %q\nit must not name %s", stopped.Detail, fam.grandchild.RunID)
	}
	// AND BOTH ARE COUNTED. One exemplar is not one attempt: an operator who
	// read "the first being X" and concluded X was the only casualty would be
	// wrong about the rest of the session.
	if !strings.Contains(stopped.Detail, "0 of 2") || !strings.Contains(stopped.Detail, "2 could not be ended") {
		t.Errorf("detail does not count both failures.\ngot: %q\nwant it to say 0 of 2 "+
			"ended and 2 could not be", stopped.Detail)
	}

	// THE WALK CONTINUED PAST THE FIRST FAILURE. The second descendant's
	// retirement was attempted, which is what the record shows: retire_agent
	// appends before it deletes, so the event is there even though SPIRE
	// refused.
	if n := env.retirements(t, fam.grandchild.RunID); n != 1 {
		t.Errorf("the grandchild has %d run_retired, want 1; the walk stopped at the "+
			"first failure and left the rest of the session open", n)
	}
	if n := env.retirements(t, fam.session.RunID); n != 1 {
		t.Errorf("the session itself has %d run_retired, want 1", n)
	}
}

// A parentage lookup that fails is the same shape of news: reported, and not a
// refusal.
func TestADescendantLookupFailureIsReportedAndDoesNotFailTheStop(t *testing.T) {
	env := osSetup(t, func(cfg *ObserveSessionConfig) {
		cfg.Descendants = osFailingDescendants{errors.New("the ledger is not answering")}
	})
	fam := osStartFamily(t, env)

	stopped := osMustStopEnding(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("a failed lookup cost the session its own retirement: %+v", stopped)
	}
	if stopped.Detail == "" {
		t.Error("a failed parentage lookup was silent; a stop that cannot say what it " +
			"did not finish is a stop an operator finds out about hours later")
	}
	if n := env.retirements(t, fam.child.RunID); n != 0 {
		t.Errorf("a descendant was ended though the lookup failed (%d run_retired); "+
			"nothing may be ended on a guess", n)
	}
}

// A deployment that has not wired a parentage lookup at all says so, and still
// stops. Absent, the flag is inert rather than fatal.
func TestADeploymentWithNoParentageLookupStillStops(t *testing.T) {
	env := osSetup(t, func(cfg *ObserveSessionConfig) { cfg.Descendants = nil })
	fam := osStartFamily(t, env)

	stopped := osMustStopEnding(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("an unwired lookup cost the session its own retirement: %+v", stopped)
	}
	if stopped.Detail == "" {
		t.Error("a deployment that cannot resolve descendants answered a cascade with " +
			"silence; the harness asserted something this replica could not act on")
	}
	if n := env.retirements(t, fam.child.RunID); n != 0 {
		t.Errorf("a descendant was ended with no lookup wired (%d run_retired)", n)
	}
}

// ---------------------------------------------------------------------------
// The negatives. These are what separate an assertion from a sweep.
// ---------------------------------------------------------------------------

// DEFAULT OFF: a harness that does not set the flag changes no behaviour at
// all. The subagents of a session stopped without it stay exactly as they were.
func TestEndsDescendantsDefaultsOffAndChangesNothing(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	stopped := env.mustStop(t, osFamilySession)
	if !stopped.Retired {
		t.Fatalf("the ordinary stop did not retire the session: %+v", stopped)
	}
	if n := env.retirements(t, fam.session.RunID); n != 1 {
		t.Errorf("the session has %d run_retired, want 1", n)
	}
	for _, run := range []observeSessionOut{fam.child, fam.grandchild} {
		if n := env.retirements(t, run.RunID); n != 0 {
			t.Errorf("%s was ended by a stop that asserted nothing (%d run_retired).\n"+
				"Ending a run because its parent ended is the inference IP §3 E7 forbids; "+
				"only the harness saying so AT THE TIME counts", run.RunID, n)
		}
	}
}

// NOTHING IS ENDED WHILE THE SESSION IS STILL RUNNING. The flag is read on a
// stop and nowhere else: a start that carries it — a duplicate start, say,
// from a harness that sets it everywhere — ends nothing, because the session
// that would be asserting it has not ended.
func TestNothingIsEndedWhileTheSessionIsStillRunning(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	again, err := observeSession(t.Context(), nil, observeSessionIn{
		SessionID:       osFamilySession,
		Phase:           ObserveSessionPhaseStart,
		CWD:             env.tree.repo,
		EndsDescendants: true,
	})
	if err != nil {
		t.Fatalf("a duplicate start carrying the flag was refused: %v", err)
	}
	if again.RunID != fam.session.RunID {
		t.Fatalf("the duplicate start returned %s, want the session's own run %s",
			again.RunID, fam.session.RunID)
	}

	for _, run := range []observeSessionOut{fam.session, fam.child, fam.grandchild} {
		if n := env.retirements(t, run.RunID); n != 0 {
			t.Errorf("%s was ended by a START (%d run_retired). The session is still "+
				"running; there is nothing for anyone to have asserted yet", run.RunID, n)
		}
	}
}

// A subagent that itself started others ends them, and ends nothing above it.
// The flag is about what THIS run started, never about what started it.
func TestACascadeNeverReachesUpwards(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	osMustStopEnding(t, osFamilyChild)

	if n := env.retirements(t, fam.grandchild.RunID); n != 1 {
		t.Errorf("the subagent's own subagent has %d run_retired, want 1", n)
	}
	if n := env.retirements(t, fam.session.RunID); n != 0 {
		t.Errorf("the session that started the subagent was ended by the subagent's "+
			"stop (%d run_retired). A cascade runs downwards only: the session is "+
			"still working", n)
	}
}

// THE WIRE SHAPE. The flag is a boolean in the tool's schema, so a harness that
// sends the STRING "true" is refused — and the refusal arrives as a stop that
// silently did not happen, because a stop never blocks and a harness has no way
// to tell a refused argument from a deployment that is down.
//
// The reference shim sends a JSON boolean (scripts/hooks/subagent-identity.sh,
// OPS-056 in the self-test); this is the half of that contract the MCP owns.
func TestEndsDescendantsIsABooleanOnTheWire(t *testing.T) {
	var asBool observeSessionIn
	if err := json.Unmarshal([]byte(`{"phase":"stop","ends_descendants":true}`), &asBool); err != nil {
		t.Fatalf("a JSON boolean was refused: %v", err)
	}
	if !asBool.EndsDescendants {
		t.Error("a JSON boolean decoded to false")
	}

	var asString observeSessionIn
	if err := json.Unmarshal([]byte(`{"phase":"stop","ends_descendants":"true"}`), &asString); err == nil {
		t.Error(`the string "true" was accepted. It is not accepted, and a harness that ` +
			"sends it gets a stop that silently did nothing — which is why the reference " +
			"shim sends a boolean and its self-test asserts the shape on the wire")
	}

	// AND ABSENT IS OFF. The zero value is the whole of the default, so a
	// harness that has never heard of this field changes nothing.
	var absent observeSessionIn
	if err := json.Unmarshal([]byte(`{"phase":"stop"}`), &absent); err != nil {
		t.Fatalf("a stop with no flag was refused: %v", err)
	}
	if absent.EndsDescendants {
		t.Error("a stop that said nothing asserted something")
	}
}

// A run that started nothing says nothing extra. Every leaf subagent is this
// case, and a line of stderr per stop about a family of none is noise an
// operator learns to skip past — which is how the line that matters gets
// skipped too.
func TestARunThatStartedNothingReportsNothing(t *testing.T) {
	env := osSetup(t, nil)
	fam := osStartFamily(t, env)

	stopped := osMustStopEnding(t, osFamilyGrandchild)
	if !stopped.Retired {
		t.Fatalf("the leaf's stop did not retire it: %+v", stopped)
	}
	if stopped.Detail != "" {
		t.Errorf("a leaf run's stop said %q; it started nothing and there is nothing "+
			"to report", stopped.Detail)
	}
	if n := env.retirements(t, fam.session.RunID); n != 0 {
		t.Errorf("the leaf's stop ended something above it (%d run_retired)", n)
	}
}

// ---------------------------------------------------------------------------
// The walk itself, and the three things it has to say.
//
// Driven directly, because the two branches below need a shape a real
// deployment would take a thousand registrations to reach and a malformed
// chain to reach at all — and a branch that can only be driven by a thousand
// registrations is a branch nothing drives.
// ---------------------------------------------------------------------------

// osTree is a parentage lookup over a literal map.
type osTree map[string][]string

func (t osTree) ChildRuns(_ context.Context, runID string) ([]string, error) {
	return t[runID], nil
}

// The walk stops at its bound and says so. A stop must never block, and an
// unbounded walk of an append-only chain is a way for one to.
func TestTheWalkStopsAtItsBoundAndSaysSo(t *testing.T) {
	tree := osTree{
		"run-root": {"run-a", "run-b"},
		"run-a":    {"run-c"},
		"run-b":    {"run-d"},
	}
	found, truncated, err := observeSessionDescendantsOf(t.Context(), tree, "run-root", 3)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if !truncated {
		t.Errorf("a walk bounded at 3 over a tree of 4 did not report truncation")
	}
	if len(found) != 3 {
		t.Errorf("the walk returned %d runs, want its bound of 3: %v", len(found), found)
	}
	if detail := observeSessionCascadeTruncated(truncated, len(found)); detail == "" {
		t.Error("a truncated walk was silent; a stop that ended some of a family and " +
			"stopped must say which half an operator is looking at")
	}
	// AND WHAT IT FOUND IS BREADTH-FIRST: both children before either
	// grandchild, so a truncated walk ends the runs nearest the one that
	// asserted rather than one deep branch of them.
	if found[0] != "run-a" || found[1] != "run-b" {
		t.Errorf("the walk went %v, want the root's own children first", found)
	}
}

// A cycle terminates. register_agent cannot create one — it refuses a run
// naming itself and admits only a parent that already exists — but a walk over
// an append-only record must not be able to loop whatever is written on it.
func TestTheWalkTerminatesOnACycle(t *testing.T) {
	tree := osTree{
		"run-root": {"run-a"},
		"run-a":    {"run-b"},
		"run-b":    {"run-root", "run-a"},
	}
	found, truncated, err := observeSessionDescendantsOf(t.Context(), tree, "run-root", observeSessionMaxCascade)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if truncated {
		t.Error("a three-run cycle reported truncation; it terminated on `seen`, not on the bound")
	}
	if got := strings.Join(found, ","); got != "run-a,run-b" {
		t.Errorf("the walk found %q, want each run once and never the root itself", got)
	}
}

// A lookup that fails part-way returns what it already named. Those runs are
// named correctly, and dropping them would trade a partial answer for none.
func TestAPartialWalkKeepsWhatItAlreadyFound(t *testing.T) {
	failAfterRoot := osPartialTree{
		children: map[string][]string{"run-root": {"run-a"}},
		err:      errors.New("the ledger stopped answering"),
	}
	found, _, err := observeSessionDescendantsOf(t.Context(), failAfterRoot, "run-root", observeSessionMaxCascade)
	if err == nil {
		t.Fatal("a failing lookup reported success")
	}
	if len(found) != 1 || found[0] != "run-a" {
		t.Errorf("the walk returned %v; the runs it had already named are named correctly", found)
	}
	if detail := observeSessionCascadeLookupFailed(err); !strings.Contains(detail, "stopped answering") {
		t.Errorf("the failure was not carried through verbatim: %q", detail)
	}
}

// The three things a cascade can have to say, and the one case where it says
// nothing. `detail` is the only channel a stop has — it never refuses — so a
// wording that dropped the failure would make a partial cascade silent.
func TestTheCascadeSaysWhatItDidAndWhatItDidNot(t *testing.T) {
	if got := observeSessionCascadeSummary(0, 0, 0, ""); got != "" {
		t.Errorf("a run with no descendants reported %q", got)
	}
	if got := observeSessionCascadeSummary(2, 2, 0, ""); !strings.Contains(got, "2 run(s)") {
		t.Errorf("a clean cascade did not say how many it ended: %q", got)
	}
	partial := observeSessionCascadeSummary(3, 2, 1, "run-x — LEDGER_UNAVAILABLE: down")
	for _, want := range []string{"2 of 3", "run-x", "LEDGER_UNAVAILABLE"} {
		if !strings.Contains(partial, want) {
			t.Errorf("a partial cascade did not mention %q: %q", want, partial)
		}
	}
	if got := observeSessionCascadeLookupFailed(nil); got != "" {
		t.Errorf("a lookup that succeeded reported %q", got)
	}
	if got := observeSessionCascadeTruncated(false, 0); got != "" {
		t.Errorf("a walk that finished reported %q", got)
	}
	// AND EVERY PIECE OF NEWS SURVIVES THE JOIN. A stop can have more than one
	// thing to say — its own retirement failed AND the cascade could not
	// resolve — and reporting only the first hides the half being looked for.
	joined := observeSessionDetails("", "first", "", "second")
	if joined != "first second" {
		t.Errorf("observeSessionDetails = %q, want both parts and no empty ones", joined)
	}
	if observeSessionDetails("", "") != "" {
		t.Error("a reply with nothing to say said something")
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func osRetirementOf(t *testing.T, e *osEnv, runID string) event.Fields {
	t.Helper()
	for _, body := range e.chain(t) {
		if body[event.FieldEventType] == event.EventTypeRunRetired &&
			body[event.FieldRunID] == runID {
			return body
		}
	}
	t.Fatalf("no run_retired for %s", runID)
	return nil
}

func osMemberNames(body event.Fields) []string {
	names := make([]string, 0, len(body))
	for name := range body {
		names = append(names, name)
	}
	// sort.Strings without the import: the set is tiny and this file already
	// compares them as one joined string.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// osPartialTree answers for the runs it knows and fails for the rest, which is
// the shape a lookup takes when a database goes away mid-walk.
type osPartialTree struct {
	children map[string][]string
	err      error
}

func (p osPartialTree) ChildRuns(_ context.Context, runID string) ([]string, error) {
	if kids, known := p.children[runID]; known {
		return kids, nil
	}
	return nil, p.err
}

// osFailingDescendants is a parentage lookup that is reachable and answers
// with an outage. It is not a stand-in for the shipped one — every positive
// case above uses the real ledger.Store — it exists only to drive the branch a
// real outage would.
type osFailingDescendants struct{ err error }

func (f osFailingDescendants) ChildRuns(_ context.Context, _ string) ([]string, error) {
	return nil, f.err
}
