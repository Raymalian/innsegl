// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// LED-035 (proposed for doc 07; doc 07 is not modified here).
//
// The reaper's withdrawal is recorded once per LAPSE (RM-152, #255), and a
// lapse is named by the chain position of the last thing the run did before it.
// That number is what this read exists to supply, and the two properties it has
// to have are the ones asserted here: it is THIS run's own newest event, and it
// is the same event LastActivity reports the instant of.
//
// The reaper's own `run_expired` is excluded for the reason LastActivity states
// — a sweep must not read its own record as evidence that the run it declared
// dead is working — and that exclusion is load-bearing twice over here: counted,
// the position would advance on every sweep, and every retry of one failed lapse
// would be named a different lapse and recorded again.
func TestLastActivityAtIsThePositionOfThatSameEvent(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	// Interleaved with another run, so that a read answering with the CHAIN's
	// tip rather than this run's would be caught.
	var wantPosition int64
	for i := range 3 {
		rec, err := s.Append(ctx, runScopedBody("run-a", event.EventTypeToolCall, i))
		if err != nil {
			t.Fatalf("append run-a #%d: %v", i, err)
		}
		wantPosition = positionOf(t, rec)
		if _, err := s.Append(ctx, runScopedBody("run-b", event.EventTypeToolCall, i)); err != nil {
			t.Fatalf("append run-b #%d: %v", i, err)
		}
	}

	at, position, known, err := s.LastActivityAt(ctx, "run-a")
	if err != nil {
		t.Fatalf("LastActivityAt: %v", err)
	}
	if !known {
		t.Fatal("a run with three events reported no activity")
	}
	if position != wantPosition {
		t.Errorf("LastActivityAt position = %d, want %d — run-a's own newest event, "+
			"not the chain's tip", position, wantPosition)
	}

	// The instant and the position are the same event's, so the two reads
	// cannot name two different lapses.
	instant, alsoKnown, err := s.LastActivity(ctx, "run-a")
	if err != nil || !alsoKnown {
		t.Fatalf("LastActivity: known=%v err=%v", alsoKnown, err)
	}
	if !instant.Equal(at) {
		t.Errorf("LastActivity = %s and LastActivityAt = %s; they must read one row", instant, at)
	}
}

// The reaper's own events do not move the position, so a sweep that failed its
// delete and retried would compute the same key and record nothing twice.
func TestLastActivityAtIgnoresTheReapersOwnEvents(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	work, err := s.Append(ctx, runScopedBody("run-quiet", event.EventTypeToolCall, 0))
	if err != nil {
		t.Fatalf("append the run's work: %v", err)
	}
	if _, werr := s.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldRunID:          "run-quiet",
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-quiet",
		event.FieldSource:         event.SourceReaper,
		event.FieldIdempotencyKey: "reaper:run_expired:run-quiet@1",
	}); werr != nil {
		t.Fatalf("append the withdrawal: %v", werr)
	}

	_, position, known, err := s.LastActivityAt(ctx, "run-quiet")
	if err != nil || !known {
		t.Fatalf("LastActivityAt: known=%v err=%v", known, err)
	}
	if want := positionOf(t, work); position != want {
		t.Errorf("LastActivityAt position = %d after a run_expired was appended, want %d — "+
			"the reaper reading its own record would rename the lapse it just recorded, "+
			"and record the same silence again on its next sweep", position, want)
	}
}

// An unknown run has no position, and the zero is not one: see LastActivity.
func TestLastActivityAtIsUnknownForAnUnknownRun(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	at, position, known, err := s.LastActivityAt(ctx, "run-nobody")
	if err != nil {
		t.Fatalf("LastActivityAt for an unknown run: %v", err)
	}
	if known || position != 0 || !at.IsZero() {
		t.Errorf("LastActivityAt = (%s, %d, %v) for an unknown run, want (zero, 0, false)",
			at, position, known)
	}
	if _, _, _, err := s.LastActivityAt(ctx, ""); err == nil {
		t.Error("an empty run id was read as a run; events with no run carry a NULL run_id")
	}
}

func positionOf(t *testing.T, rec event.Fields) int64 {
	t.Helper()
	position, ok := rec[event.FieldChainPosition].(int64)
	if !ok {
		t.Fatalf("the appended record's %s is %T, want an integer",
			event.FieldChainPosition, rec[event.FieldChainPosition])
	}
	return position
}
