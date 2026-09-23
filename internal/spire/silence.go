// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"fmt"
	"time"
)

// Silence, not age (RM-125, #180).
//
// # The measurement
//
// reaper.go's own header states the assumption this file corrects: "an entry
// that has outlived the identity lifetime it was registered with, plus a
// configured grace, is orphaned by definition, because a run that was still
// working would have been retired or re-registered."
//
// The last clause is false of the agents this system serves. A subagent works
// for hours on one registration and re-registers never, so the reaper's first
// production sweep expired two runs that were mid-task:
//
//	reap at 2026-09-08T13:15:52Z: 2 entries in the agent subtree, 0 live, 2 expired
//
// Between them they had made 313 recorded tool calls, the last of them in the
// second the reaper deleted their entries. Neither could obtain a credential
// afterwards, so neither could sign anything for the rest of its work. The
// reaper has been off ever since, which leaves IP §6.7 unenforced — a run that
// dies without a clean stop stays Active forever, one measured at 13 hours.
//
// # Where the liveness signal actually is
//
// The header is right that SPIRE holds none. A registration entry records when
// the server created it and what TTL it issues, and nothing else; there is no
// "the workload is still running" bit and no callback when one stops.
//
// The LEDGER holds one. `record_event` appends a `tool_call` for every observed
// call (#171), so the chain knows when a run last did something — and a busy
// run therefore renews itself simply by working, which is what the grace period
// was always reaching for. So the reaper stops asking how old an entry is and
// asks how long the run has been quiet.
//
// # Additive, so no deployment changes underneath its operator
//
// ActivitySource is optional. Unconfigured, every decision is the deadline it
// was before, byte for byte. That is not timidity: a deployment whose ledger
// records nothing for a run must still be able to reap that run's orphans, and
// a reaper that refused to act without a signal it may never receive would leak
// every entry forever instead of two.

// ActivitySource reports when a run was last observed doing something.
//
// `known` is false for a run the source has nothing about, which is a different
// answer from "silent since the epoch": the first falls back to the deadline,
// and the second would reap instantly. *ledger.Store implements it.
type ActivitySource interface {
	LastActivity(ctx context.Context, runID string) (time.Time, bool, error)
}

// orphaned is the whole of the reaper's decision.
//
// Two gates, in this order, and the order matters:
//
//  1. Inside its own deadline, an entry is live whatever the ledger says. A run
//     that has recorded nothing yet has not thereby run out of time.
//  2. Past it, silence decides — but only when there is something to be silent
//     against. With no activity known, the deadline is the only evidence there
//     is, and it is the evidence every deployment used before this.
//
// Grace means the same thing in both readings: how long the reaper waits past
// the end of something before calling the run gone. It was slack on a lifetime;
// it is now slack on a heartbeat.
func orphaned(now, deadline, last time.Time, known bool, grace time.Duration) bool {
	if !now.After(deadline) {
		return false
	}
	if !known {
		return true
	}
	return now.After(last.Add(grace))
}

// orphanedNow decides one candidate, consulting the ledger if there is one.
//
// It returns a *Skipped rather than a verdict when the ledger cannot answer.
// An entry the reaper cannot judge is one it has no basis to delete — the same
// rule classify already applies to an entry it cannot date — and the operator
// needs to see that the reaper has stopped judging, which a silent "live"
// would not show.
//
// The ledger is asked ONLY about entries already past their deadline. That is
// not an optimization detail worth hiding: it means a sweep over a healthy
// deployment, where every entry is inside its TTL, makes no ledger queries at
// all, and the cost of this file scales with the number of suspected orphans
// rather than with the number of live agents.
func (r *Reaper) orphanedNow(ctx context.Context, now time.Time, cand *Candidate) (bool, *Skipped) {
	if !now.After(cand.Deadline) {
		return false, nil
	}
	if r.activity == nil {
		return true, nil
	}

	last, known, err := r.activity.LastActivity(ctx, cand.Run.RunID)
	if err != nil {
		return false, &Skipped{
			EntryID:  cand.Entry.ID,
			SPIFFEID: cand.Entry.SPIFFEID,
			Reason: fmt.Sprintf("the ledger could not say when run %s was last active, "+
				"so whether it is orphaned is unknown: %v", cand.Run.RunID, err),
		}
	}
	if known {
		cand.LastActivity = last
	}
	return orphaned(now, cand.Deadline, last, known, r.grace), nil
}

// orphanedUnentried decides one candidate the LEDGER supplied — a run it calls
// active that SPIRE holds no entry for (RM-181, #289).
//
// # It is the same predicate, over the same grace, and that is the point
//
// The reaper's verdict was checked and is not at fault; only the set it was
// given was. So this routes through `orphaned` rather than restating it, with
// the deadline set to the end of the grace measured from the run's last
// recorded activity. Both of `orphaned`'s gates then ask the identical
// question — has the silence outlasted the grace — and there is exactly one
// duration in the decision, the one the operator configured. Nothing here is a
// new threshold and nothing here is more eager than the entried path: a run
// that worked a second ago is live on both.
//
// # Why "nothing known" refuses, where the entried path falls back
//
// orphanedNow treats an unknown activity as orphaned, and is right to: the
// entry's own deadline is real evidence that has already elapsed, and it is the
// evidence every deployment used before #180. THERE IS NO SUCH EVIDENCE HERE.
// A run with no entry has no TTL, no creation time and no deadline; strip the
// activity as well and the reaper is left holding nothing at all. Withdrawing
// on nothing at all is what classify's skip branch already refuses for an entry
// it cannot date, and the same refusal belongs here.
//
// It should also be unreachable in a shipped deployment, and it is checked
// anyway: a run only reaches this population by having a readable
// `run_registered`, whose source is the MCP's, so the ledger has at least that
// one event to date it by. A future RunSource that answered from somewhere else
// gets a skip rather than a deletion.
func (r *Reaper) orphanedUnentried(ctx context.Context, now time.Time, cand *Candidate) (bool, *Skipped) {
	last, known, err := r.activity.LastActivity(ctx, cand.Run.RunID)
	if err != nil {
		return false, &Skipped{
			SPIFFEID: cand.Entry.SPIFFEID,
			Reason: fmt.Sprintf("the ledger could not say when run %s was last active, "+
				"so whether the run it calls active is gone is unknown: %v", cand.Run.RunID, err),
		}
	}
	if !known {
		return false, &Skipped{
			SPIFFEID: cand.Entry.SPIFFEID,
			Reason: fmt.Sprintf("the ledger calls run %s active and records nothing it "+
				"ever did, and it has no SPIRE entry to date it by either, so there is "+
				"nothing for its silence to be measured against", cand.Run.RunID),
		}
	}
	cand.LastActivity = last
	cand.Deadline = last.Add(r.grace)
	return orphaned(now, cand.Deadline, last, true, r.grace), nil
}
