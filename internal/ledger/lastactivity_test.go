// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// LED-034 (proposed for doc 07; doc 07 is not modified here).
//
// The reaper's liveness question, answered by the only component that holds a
// liveness signal at all (#180, and see internal/spire/silence.go for the
// measurement that made it necessary).
func TestLastActivityIsTheRunsMostRecentEvent(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	before := time.Now().UTC().Add(-time.Second)
	for i := range 3 {
		if _, err := s.Append(ctx, runScopedBody("run-a", event.EventTypeToolCall, i)); err != nil {
			t.Fatalf("append run-a #%d: %v", i, err)
		}
		// A second run appended after each of run-a's events. A read that
		// answered with the chain's latest event rather than this RUN's would
		// pass on a single-run chain and report every idle run as busy.
		if _, err := s.Append(ctx, runScopedBody("run-b", event.EventTypeToolCall, i)); err != nil {
			t.Fatalf("append run-b #%d: %v", i, err)
		}
	}
	after := time.Now().UTC().Add(time.Second)

	last, known, err := s.LastActivity(ctx, "run-a")
	if err != nil {
		t.Fatalf("LastActivity: %v", err)
	}
	if !known {
		t.Fatal("a run with three events reported no activity; the reaper would " +
			"fall back to the deadline and delete a working agent's identity")
	}
	if last.Before(before) || last.After(after) {
		t.Errorf("LastActivity = %s, outside the window [%s, %s] the events were written in",
			last, before, after)
	}

	// The chain-order guarantee: the answer is run-a's LAST event, and run-a's
	// last event precedes run-b's, so an answer taken from the wrong run would
	// be later than this one.
	lastB, _, err := s.LastActivity(ctx, "run-b")
	if err != nil {
		t.Fatalf("LastActivity for run-b: %v", err)
	}
	if !lastB.After(last) && !lastB.Equal(last) {
		t.Errorf("run-b's last activity %s precedes run-a's %s, but run-b was appended after",
			lastB, last)
	}
}

// TestLastActivityIgnoresTheReapersOwnEvents. `run_expired` carries the run id
// and lands in the same chain, so a naive read would see the reaper's own
// record of the expiry as fresh activity BY the run. A sweep whose delete
// failed would then find the orphan "busy" on its next pass and never retry —
// the reaper would have talked itself out of its own job.
func TestLastActivityIgnoresTheReapersOwnEvents(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	if _, err := s.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldRunID:          "run-gone",
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-gone",
		event.FieldSource:         event.SourceReaper,
		event.FieldIdempotencyKey: "reaper:run_expired:run-gone",
	}); err != nil {
		t.Fatalf("append run_expired: %v", err)
	}

	_, known, err := s.LastActivity(ctx, "run-gone")
	if err != nil {
		t.Fatalf("LastActivity: %v", err)
	}
	if known {
		t.Error("the reaper's own run_expired counted as the run being active; " +
			"an orphan whose deletion failed would then be spared forever")
	}
}

// TestLastActivityIsUnknownForAnUnknownRun: not an error, and not a zero time
// passed off as an answer. The reaper's two cases are "still working" and "I
// have nothing", and they lead to opposite decisions.
func TestLastActivityIsUnknownForAnUnknownRun(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	if _, err := s.Append(ctx, runScopedBody("run-a", event.EventTypeToolCall, 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	last, known, err := s.LastActivity(ctx, "run-nobody")
	if err != nil {
		t.Fatalf("LastActivity for an unknown run: %v", err)
	}
	if known || !last.IsZero() {
		t.Errorf("LastActivity = (%s, %v) for an unknown run, want (zero, false)", last, known)
	}
}

// TestLastActivityRefusesAnEmptyRunID, for EventsForRun's reason: run_id is
// nullable, and an empty argument must not be read as "the events with no run".
func TestLastActivityRefusesAnEmptyRunID(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	if _, _, err := s.LastActivity(ctx, ""); err == nil {
		t.Fatal("an empty run id was accepted; it names no run")
	}
}
