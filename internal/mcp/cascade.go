// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"

	"innsegl.dev/innsegl/internal/ledger"
)

// A harness that ends a session ends what it started — RM-157 (#260), E9.
//
// # What was measured, and by whom it was not said
//
// Five subagent runs sat Active for between three and nine hours after the
// processes behind them were gone, and an operator closed them by hand.
// Nothing had ended them and nothing could have. A killed process fires no
// SubagentStop, so the subagent's own harness event never happens; the
// reaper's grace is twelve hours by policy, and shortening it is what E9
// exists to say is the wrong answer — an agent waiting on a provider limit,
// running a long build, or on a sleeping machine is silent and alive, and
// tuning the window only chooses which error to make.
//
// The party that KNEW is the session that started them. It said nothing on its
// way out. This is what it says.
//
// # THE CONTRACT, AND IT IS ADDRESSED TO WHOEVER WRITES THE SECOND HARNESS
//
// `ends_descendants` is an ASSERTION, made by the harness, under the identity
// the harness is acting as. It means, in full:
//
//	"The processes behind the runs this run started are gone. I know that
//	 because I am the thing that started them and I am now ending."
//
// It does NOT mean "probably finished", "idle", "quiet for a while" or "I am
// tidying up". A harness that sets it on a run whose children are still
// working has ended live agents, and the endings are on an append-only chain
// under its own name: `run_retired` is terminal (IP §6.2, I4), it is not
// reversible, and nothing afterwards can distinguish it from a truthful one.
// Set it on a session end and on a subagent stop for a subagent that itself
// spawned others. Set it nowhere else.
//
// DEFAULT OFF, and that is load-bearing. A harness that does not send this
// field gets exactly the behaviour it had before: its stop ends its own run
// and touches nothing else. Nothing about an existing deployment changes until
// a harness chooses to speak.
//
// # This is an assertion, not an inference (IP §3 E7)
//
// Nothing in this server reads a parent's retirement and concludes anything
// about a child's. There is no sweep, no reaper hook, no reconciliation pass
// that walks the parent edge; the only thing that ends a descendant is a stop
// call that carried the flag, at the moment it carried it. That distinction is
// the whole of E7 and it is about what this code DOES — passing
// scripts/exemptions.sh, which greps for `backfill|import-history|reattribute|
// infer…Attribution`, proves nothing about it either way.
//
// The negative cases are where it is held: a START carrying the flag ends
// nothing, a stop without it ends nothing but its own run, and a repeat ends
// nothing a second time (cascade_test.go).
//
// # Nothing new is recorded
//
// A cascaded ending is BYTE-IDENTICAL to any other `run_retired`. No event
// type, field, enum or source changes — doc 02 §3 gains no member saying "this
// one followed from its parent", and `source` stays `mcp` because an MCP tool
// call appended it. That is what keeps this a minor release (doc 08 §3), and
// it is also the honest record: the fact being recorded is that the run ended,
// which is the same fact either way.
//
// It follows that this file writes no event of its own. It calls the SHIPPED
// retire_agent, in process, exactly as observe_session already does for the
// session's own retirement — one retirement path, one gate, one `run_retired`.
//
// # Idempotency, without a key
//
// ADR-0004 gives `run_retired` no idempotency_key and this adds none. Repeating
// a stop re-walks the parentage and calls retire_agent again for each run it
// finds; retire_agent reads the run directory, sees the run already retired,
// appends nothing and answers with the original instant, and migrations/0004's
// partial unique index is what makes that hold under a race rather than under
// a check. So a repeat costs reads and writes nothing, which is what "safe to
// repeat" has to mean for a record that cannot be amended.
//
// # What this does NOT do to a marker, stated rather than discovered
//
// A descendant is found by run id and ended by run id. Its own session marker
// — if it has one; a run registered on first sight by observe_tool_call has
// none — still reads live afterwards, because nothing here can map a run back
// to the session id its marker is filed under without scanning the volume.
//
// The consequences are bounded and both self-heal. A later stop for that
// session calls retire_agent on an already-retired run, is answered with the
// original instant, appends nothing and writes the marker straight. A start
// for that session id meets register_agent's refusal rather than this file's,
// which is the same limit observe_session already states for a run retired out
// from under it by a direct retire_agent call. #213 owns that class.
//
// # A stop never blocks, and a cascade is the last place to start
//
// Every failure here is a REPLY carrying bad news, never a refusal: the lookup
// being unreachable, one descendant's retirement failing, this deployment
// having no parentage lookup wired at all. A blocked stop was measured
// producing nine repeated invocations — a retry storm, not a fix — and the
// convergence story is better than a retry anyway: the runs that were not
// ended are still open, a later stop ends them, and the reaper's withdrawal
// stands behind that (IP §6.7).

// ObserveSessionDescendants resolves which runs a run started.
//
// ONE METHOD, and it is the ledger's own: `ChildRuns` reads the runs whose
// `run_registered` CARRIES this run as its `parent_run_id`, in chain order,
// off migration 0005's index. *ledger.Store satisfies it.
//
// The interface exists rather than the concrete type so that a deployment that
// has not wired one is a nil this file can report, and so that an outage is
// drivable in a test without taking a database down. It deliberately cannot
// express anything except "which runs named this one as their parent" — a
// lookup that could also answer "which runs were running at the time" is the
// shape of the inference E7 forbids, and an interface that cannot say it is
// one fewer thing to keep out later.
type ObserveSessionDescendants interface {
	ChildRuns(ctx context.Context, runID string) ([]string, error)
}

// The production implementation must satisfy it, or the lookup this tool is
// handed would be free to drift from the one its cases drive.
var _ ObserveSessionDescendants = (*ledger.Store)(nil)

// observeSessionMaxCascade bounds how many runs one stop will walk.
//
// A STOP MUST NEVER BLOCK, and an unbounded walk of an append-only chain is a
// way for one to take minutes. The bound is far above anything observed — the
// deepest delegation this project has recorded is a session, its subagents and
// their subagents, tens of runs — and a stop that reaches it says so and ends
// what it found. The rest are not lost: they are still open, and the next stop
// re-walks (the walk is idempotent) or the reaper withdraws their authorisation
// at its deadline.
const observeSessionMaxCascade = 1024

// endsWhatItStarted ends every still-open run this one started, and returns
// what to tell the caller. The empty string means there is nothing to say.
//
// # Order
//
// Breadth-first from the stopping run: its own children in chain order, then
// theirs, and so on. Chain order is registration order, so the endings are
// recorded in the order the delegation happened, which is the order a reader
// walking the chain meets the runs in. Nothing depends on the order for
// correctness — a retirement neither needs its parent retired nor its children
// still live — so the one that reads well is the one to pick.
//
// A run is visited once. A cycle cannot be created through register_agent,
// which refuses a run naming itself and can only accept a parent that already
// exists, but a walk over an append-only record must not be able to loop
// whatever is on it.
//
// # Which runs are skipped
//
// Only a run that is already retired, and retire_agent is what decides that —
// not this file, and not a second reading of the chain. A LAPSED or ABANDONED
// descendant is still OPEN: silence is not an ending at any threshold (#258),
// and a run whose authorisation the reaper withdrew is an agent that went
// quiet, not one that finished. Those are ended here, which is the point —
// they are exactly the runs a killed session leaves behind.
func (c *observeSessionService) endsWhatItStarted(ctx context.Context, runID string) string {
	if c.descendants == nil {
		// Not a refusal, and not silence either. The harness asserted
		// something this replica cannot act on, and an operator who reads
		// "retired <run>" and assumes the subagents went with it is back to
		// discovering otherwise hours later.
		return "this stop asserted that it ends the runs it started, and this deployment " +
			"has no parentage lookup wired, so none was resolved and none was ended. " +
			"Those runs stay Active until they are stopped or the reaper withdraws " +
			"their authorisation (IP §6.7)"
	}

	found, truncated, lookupErr := observeSessionDescendantsOf(
		ctx, c.descendants, runID, observeSessionMaxCascade)

	// WHAT WAS FOUND IS STILL ENDED. A lookup that failed part-way has already
	// told the truth about the runs it did name, and dropping them would trade
	// a partial answer for none.
	var (
		ended  int
		failed int
		first  string
	)
	for _, descendant := range found {
		// retire_agent, in process: the SHIPPED tool, the same one the
		// session's own retirement goes through. A second retirement path
		// here would be a second thing that can disagree about what a run is,
		// whether it is already retired, and which instant it ended at.
		if _, err := retireAgent(ctx, nil, retireAgentIn{RunID: descendant}); err != nil {
			failed++
			if first == "" {
				classified := Classify(err)
				first = fmt.Sprintf("%s — %s: %s", descendant, classified.Class, classified.Message)
			}
			// AND THE WALK CONTINUES. A cascade that stopped at its first
			// failure would leave the rest of a killed session's subagents
			// open, which is the defect this exists to close.
			continue
		}
		ended++
	}

	return observeSessionDetails(
		observeSessionCascadeSummary(len(found), ended, failed, first),
		observeSessionCascadeLookupFailed(lookupErr),
		observeSessionCascadeTruncated(truncated, len(found)),
	)
}

// observeSessionDescendantsOf walks the parent edge downwards and returns
// every run below this one, breadth-first, whether it reached the end, and
// what stopped it if it did not.
//
// An error is returned WITH whatever was found rather than instead of it: the
// runs already named are named correctly, and a stop that ends none of them
// because the last read failed has made the outage worse.
// The bound is a parameter rather than the constant read in place, so the
// truncation it causes is drivable without a thousand registrations. There is
// one production caller and it passes observeSessionMaxCascade.
func observeSessionDescendantsOf(ctx context.Context, lookup ObserveSessionDescendants, root string, limit int) ([]string, bool, error) {
	seen := map[string]bool{root: true}
	queue := []string{root}
	var order []string

	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]

		children, err := lookup.ChildRuns(ctx, parent)
		if err != nil {
			return order, false, err
		}
		for _, child := range children {
			if seen[child] {
				continue
			}
			seen[child] = true
			order = append(order, child)
			if len(order) >= limit {
				return order, true, nil
			}
			queue = append(queue, child)
		}
	}
	return order, false, nil
}

// observeSessionCascadeSummary says what the cascade did, or nothing when
// there was nothing below this run.
//
// A run with no descendants is the ordinary case — every leaf subagent, and
// every session that delegated nothing — and it is not worth a line of a
// harness's stderr on every stop.
func observeSessionCascadeSummary(found, ended, failed int, first string) string {
	switch {
	case found == 0:
		return ""
	case failed == 0:
		return fmt.Sprintf(
			"this stop ends what it started: %d run(s) below this one are recorded as ended",
			ended)
	default:
		return fmt.Sprintf(
			"this stop ends what it started: %d of %d run(s) below this one are recorded as "+
				"ended and %d could not be ended, the first being %s. The stop did not refuse "+
				"— a stop that blocks is answered by a harness with a retry storm, not with a "+
				"fix — so those runs are still open: a later stop ends them, and the reaper "+
				"withdraws their authorisation if nothing does (IP §6.7)",
			ended, found, failed, first)
	}
}

// observeSessionCascadeLookupFailed reports a parentage lookup that could not
// finish. The class and message are the ledger's own, carried verbatim, for
// observeSessionStopFailed's reason: a second wording for one failure sends a
// reader to the wrong file.
func observeSessionCascadeLookupFailed(err error) string {
	if err == nil {
		return ""
	}
	classified := Classify(err)
	return fmt.Sprintf(
		"the runs this one started could not be resolved — %s: %s. Any not named above are "+
			"still open; a later stop resolves them, because ending a run twice appends "+
			"nothing (ADR-0004)",
		classified.Class, classified.Message)
}

// observeSessionCascadeTruncated reports a walk that hit its bound.
func observeSessionCascadeTruncated(truncated bool, found int) string {
	if !truncated {
		return ""
	}
	return fmt.Sprintf(
		"the walk stopped at %d runs, which is this deployment's bound on one stop: a stop "+
			"must never block, and an unbounded walk is a way for one to. Anything below "+
			"those is still open and a later stop reaches it",
		found)
}

// observeSessionDetails joins the things one reply has to say, skipping the
// ones with nothing to report.
//
// A stop can have more than one piece of news — its own retirement failed AND
// the cascade could not resolve, say — and reporting only the first would hide
// exactly the half an operator is looking for.
func observeSessionDetails(parts ...string) string {
	joined := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if joined != "" {
			joined += " "
		}
		joined += part
	}
	return joined
}
