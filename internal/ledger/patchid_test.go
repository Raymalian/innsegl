// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// LED-038 (proposed for doc 07; doc 07 is not modified here) — RM-121, #193.
//
// The read behind ADR-0047's content check: which runs recorded this change?
//
// Keyed on the CHANGE and never on the run, because a lookup keyed on the
// caller's own claim would let the claim choose the evidence it is checked
// against. The verifier compares the run itself.
func TestLED038RunsForPatchIDFindsWhoRecordedAChange(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	const patch = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
	other := strings.Repeat("b", 40)

	if _, err := s.Append(ctx, commitRecordedBody("run-a", patch, "1")); err != nil {
		t.Fatalf("append run-a: %v", err)
	}
	// A second run recording a DIFFERENT change, so a read that ignored the
	// patch id would pass on a single-record chain and fail nobody.
	if _, err := s.Append(ctx, commitRecordedBody("run-b", other, "2")); err != nil {
		t.Fatalf("append run-b: %v", err)
	}

	got, err := s.RunsForPatchID(ctx, patch)
	if err != nil {
		t.Fatalf("RunsForPatchID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("RunsForPatchID returned %d records, want 1: %+v", len(got), got)
	}
	if got[0].RunID != "run-a" || got[0].PatchID != patch {
		t.Errorf("got %+v, want run-a and the patch id asked for", got[0])
	}
	if got[0].CommitSHA == "" || got[0].EventID == "" {
		t.Errorf("got %+v; a reader needs the commit the ledger holds and the event "+
			"that says so, or the answer cannot be checked", got[0])
	}

	t.Run("a change nobody recorded returns nothing, and no error", func(t *testing.T) {
		got, err := s.RunsForPatchID(ctx, strings.Repeat("c", 40))
		if err != nil {
			t.Fatalf("RunsForPatchID for an unknown change: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("returned %d records for a change nobody recorded", len(got))
		}
	})

	t.Run("the same change by two runs returns both", func(t *testing.T) {
		// A patch id identifies a change and not a maker, so two agents making
		// the same change produce one id. The read must return both and let
		// the verifier decide, rather than picking one and calling it the
		// author.
		if _, err := s.Append(ctx, commitRecordedBody("run-c", patch, "3")); err != nil {
			t.Fatalf("append run-c: %v", err)
		}
		got, err := s.RunsForPatchID(ctx, patch)
		if err != nil {
			t.Fatalf("RunsForPatchID: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("returned %d records for a change two runs made, want 2", len(got))
		}
	})

	t.Run("an empty patch id is refused, not matched", func(t *testing.T) {
		if _, err := s.RunsForPatchID(ctx, ""); err == nil {
			t.Error("an empty patch id was accepted; it names no change, and matching " +
				"every event that carries none would answer a question nobody asked")
		}
	})
}

// commitRecordedBody is a `commit_recorded` for one run and one change.
func commitRecordedBody(runID, patchID, n string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/" + runID,
		event.FieldIdempotencyKey: "recorded-" + runID + "-" + n,
		event.FieldRepo:           "github.com/acme/api",
		event.FieldTreeHash:       strings.Repeat("a", 40),
		event.FieldPatchID:        patchID,
		event.FieldCommitSHA:      strings.Repeat(n, 40),
		event.FieldIntentEventID:  "01a047a5-cc41-7c45-86fd-a88c8c2b532" + n,
		event.FieldRekorEntryUUID: strings.Repeat("d", 64),
		event.FieldRekorLogIndex:  int64(1),
	}
}

// TestLED039HoldsAnyPatchIDSeparatesAnOldChainFromAChangedOne.
//
// The two states a content check must never confuse: a chain that recorded no
// change identities at all (an older deployment) and a chain that recorded some
// and does not hold this one (the content changed). The first is a fact about
// the deployment; the second is a finding about a commit.
func TestLED039HoldsAnyPatchIDSeparatesAnOldChainFromAChangedOne(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	recorded, err := HoldsAnyPatchID(ctx, s.pool)
	if err != nil {
		t.Fatalf("HoldsAnyPatchID on an empty chain: %v", err)
	}
	if recorded {
		t.Fatal("an empty chain reported holding a patch id")
	}

	// THE THIRD STATE CANNOT BE SYNTHESIZED HERE, and that is itself the
	// point. A chain holding `commit_recorded` without a patch id is one
	// written before the cutover: the append path refuses schema 1 outright
	// (SER-026) and schema 2 requires the member, so only real history
	// produces it. The evidence for that case is a measurement rather than a
	// fixture — on this project's own deployment on 2026-09-10, 126
	// `commit_recorded` events and zero patch ids, which is exactly the state
	// this function exists to report before a gate accuses all 126 of them.
	//
	// What is testable is the boundary either side of it, and both are below.

	if _, aerr := s.Append(ctx, commitRecordedBody("run-new", strings.Repeat("e", 40), "4")); aerr != nil {
		t.Fatalf("append a schema 2 commit_recorded: %v", aerr)
	}
	recorded, err = HoldsAnyPatchID(ctx, s.pool)
	if err != nil {
		t.Fatalf("HoldsAnyPatchID: %v", err)
	}
	if !recorded {
		t.Error("a chain holding a patch id reported none, so a content check would " +
			"stand down on a deployment that can answer it")
	}
}
