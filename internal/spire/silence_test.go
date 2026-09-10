// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// SPI-011 (proposed for doc 07; doc 07 is not modified here).
//
// A run that is still working is not orphaned, whatever its TTL says.
//
// # What this corrects
//
// This file's own header states the assumption that failed:
//
//	an entry that has outlived the identity lifetime it was registered with,
//	plus a configured grace, is orphaned by definition, because a run that was
//	still working would have been retired or re-registered.
//
// The last clause is not true of the agents this system serves. A subagent
// works for hours without re-registering, so on 2026-09-08 the reaper's first
// pass expired two that were alive — 183 and 130 recorded tool calls, last
// activity in the same second it killed them:
//
//	reap at 13:15:52Z: 2 entries in the agent subtree, 0 live, 2 expired
//
// Their SPIRE entries were deleted, so neither could obtain a credential or
// sign anything for the rest of its task. The reaper has been switched off
// since, which leaves IP §6.7 unenforced: a run that dies without a clean stop
// stays Active forever, one measured at 13 hours.
//
// # Why the ledger and not SPIRE
//
// The header is right that SPIRE holds no liveness signal — an entry records
// when it was created and what TTL it issues, and nothing else. But the LEDGER
// holds one: `record_event` appends a `tool_call` for every observed call
// (#171), so the chain knows when a run last did something.
//
// So age is the wrong question and silence is the right one. A busy run renews
// itself simply by working; a dead one goes quiet immediately, which is what
// the grace period was always trying to detect.
func TestSPI011ARunThatIsStillWorkingIsNotOrphaned(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	past := now.Add(-2 * time.Hour) // long past its deadline
	grace := 5 * time.Minute

	for _, tc := range []struct {
		name     string
		last     time.Time
		known    bool
		orphaned bool
	}{
		{"working seconds ago", now.Add(-3 * time.Second), true, false},
		{"working just inside the grace", now.Add(-4 * time.Minute), true, false},
		{"silent just past the grace", now.Add(-6 * time.Minute), true, true},
		{"silent for hours", now.Add(-13 * time.Hour), true, true},
		// No activity recorded at all: fall back to the deadline, which is the
		// behaviour every deployment had before this. A reaper that refused to
		// act without a ledger signal would leak every orphan on a deployment
		// that records none.
		{"nothing known about the run", time.Time{}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := orphaned(now, past, tc.last, tc.known, grace)
			if got != tc.orphaned {
				t.Errorf("orphaned = %v, want %v", got, tc.orphaned)
			}
		})
	}

	t.Run("a live deadline is never orphaned, however quiet", func(t *testing.T) {
		future := now.Add(time.Hour)
		if orphaned(now, future, time.Time{}, false, grace) {
			t.Error("an entry inside its own TTL was called orphaned; silence cannot " +
				"expire a run the deadline has not reached")
		}
	})
}

// activityStub is a ledger that answers whatever the case under test needs, and
// counts what it was asked.
type activityStub struct {
	last  time.Time
	known bool
	err   error
	asked []string
}

func (a *activityStub) LastActivity(_ context.Context, runID string) (time.Time, bool, error) {
	a.asked = append(a.asked, runID)
	if a.err != nil {
		return time.Time{}, false, a.err
	}
	return a.last, a.known, nil
}

// SPI-012 (proposed for doc 07; doc 07 is not modified here).
//
// The reaper asks the ledger before it deletes, and the answers it can get from
// a ledger are three, not two: still working, silent, and "I could not tell
// you". Only the second is an orphan.
func TestSPI012TheSweepConsultsTheLedgerBeforeDeleting(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	expired := Candidate{
		Entry:    Entry{ID: "e1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/t/r1"},
		Run:      RunRef{RunID: "r1"},
		Deadline: now.Add(-2 * time.Hour),
	}

	t.Run("with no ledger to ask, the deadline still decides", func(t *testing.T) {
		r := &Reaper{grace: 5 * time.Minute}
		cand := expired
		reap, skip := r.orphanedNow(t.Context(), now, &cand)
		if !reap || skip != nil {
			t.Errorf("reap=%v skip=%v; an unconfigured activity source must leave "+
				"every deployment's behaviour exactly as it was", reap, skip)
		}
	})

	t.Run("a run that worked seconds ago survives its own deadline", func(t *testing.T) {
		stub := &activityStub{last: now.Add(-3 * time.Second), known: true}
		r := &Reaper{grace: 5 * time.Minute, activity: stub}
		cand := expired
		reap, skip := r.orphanedNow(t.Context(), now, &cand)
		if reap {
			t.Fatal("a run with activity three seconds ago was reaped; this is the " +
				"2026-09-08 failure, where two agents mid-task lost their identities")
		}
		if skip != nil {
			t.Fatalf("reported as skipped (%s); it was judged, and judged live", skip.Reason)
		}
		if !cand.LastActivity.Equal(stub.last) {
			t.Errorf("LastActivity = %v, want %v recorded on the candidate so the "+
				"report can say WHY the entry survived", cand.LastActivity, stub.last)
		}
	})

	t.Run("a run silent past the grace is still reaped", func(t *testing.T) {
		stub := &activityStub{last: now.Add(-6 * time.Minute), known: true}
		r := &Reaper{grace: 5 * time.Minute, activity: stub}
		cand := expired
		reap, skip := r.orphanedNow(t.Context(), now, &cand)
		if !reap || skip != nil {
			t.Errorf("reap=%v skip=%v; silence past the grace is what IP §6.7 exists "+
				"to clean up, and a reaper that never reaps is the bug it replaces",
				reap, skip)
		}
	})

	t.Run("a ledger that cannot answer stops the deletion", func(t *testing.T) {
		stub := &activityStub{err: errors.New("connection refused")}
		r := &Reaper{grace: 5 * time.Minute, activity: stub}
		cand := expired
		reap, skip := r.orphanedNow(t.Context(), now, &cand)
		if reap {
			t.Fatal("an entry was deleted on an unreadable ledger; the reaper had no " +
				"basis to call it orphaned, and deleting on no basis is what classify's " +
				"skip branch already refuses to do")
		}
		if skip == nil {
			t.Fatal("left silently live; an operator cannot see a reaper that has " +
				"stopped judging unless the report says so")
		}
		if !strings.Contains(skip.Reason, "connection refused") {
			t.Errorf("reason %q does not carry the ledger's own error", skip.Reason)
		}
	})

	t.Run("a live entry is not looked up at all", func(t *testing.T) {
		stub := &activityStub{}
		r := &Reaper{grace: 5 * time.Minute, activity: stub}
		cand := expired
		cand.Deadline = now.Add(time.Hour)
		reap, skip := r.orphanedNow(t.Context(), now, &cand)
		if reap || skip != nil {
			t.Errorf("reap=%v skip=%v for an entry inside its own TTL", reap, skip)
		}
		if len(stub.asked) != 0 {
			t.Errorf("asked the ledger %v; a sweep costs one query per ENTRY PAST ITS "+
				"DEADLINE, not one per entry", stub.asked)
		}
	})
}
