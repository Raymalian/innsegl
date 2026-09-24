// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// ADP-011 — the content lookup names the adoption, ADR-0051 decision 5, #298.
//
// A verifier asking "who recorded this change?" of an adopting commit has to
// be told which dead run the change was adopted from, or it cannot hold the
// commit's Agent-Adopted-Run trailer to anything. The link is on the chain:
// the intent's adoption_event_id names the run_adopted event, and that event
// names the dead run.
func TestADP011RunsForPatchIDNamesTheRunAChangeWasAdoptedFrom(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	const adoptedPatch = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
	plainPatch := strings.Repeat("b", 40)

	adopted, err := s.Append(ctx, event.Fields{
		event.FieldSchemaVersion:   event.SchemaVersion,
		event.FieldEventType:       event.EventTypeRunAdopted,
		event.FieldSource:          event.SourceMCP,
		event.FieldRunID:           "run-live",
		event.FieldSpiffeID:        "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-live",
		event.FieldIdempotencyKey:  "adopted-1",
		event.FieldAdoptedRunID:    "run-dead",
		event.FieldAdoptedRunState: "retired",
		event.FieldPayloadDigest:   "sha256:" + strings.Repeat("e", 64),
	})
	if err != nil {
		t.Fatalf("append run_adopted: %v", err)
	}
	intent := event.Fields{
		event.FieldSchemaVersion:   event.SchemaVersion,
		event.FieldEventType:       event.EventTypeCommitIntent,
		event.FieldSource:          event.SourceMCP,
		event.FieldRunID:           "run-live",
		event.FieldSpiffeID:        "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-live",
		event.FieldIdempotencyKey:  "intent-1",
		event.FieldRepo:            "github.com/acme/api",
		event.FieldTreeHash:        strings.Repeat("a", 40),
		event.FieldPatchID:         adoptedPatch,
		event.FieldAdoptionEventID: adopted[event.FieldEventID],
	}
	if _, err = s.Append(ctx, intent); err != nil {
		t.Fatalf("append intent: %v", err)
	}
	if _, err = s.Append(ctx, commitRecordedBody("run-live", adoptedPatch, "1")); err != nil {
		t.Fatalf("append recorded: %v", err)
	}
	// The control: a plain change by the same run names no adoption.
	if _, err = s.Append(ctx, commitRecordedBody("run-live", plainPatch, "2")); err != nil {
		t.Fatalf("append plain: %v", err)
	}

	got, err := s.RunsForPatchID(ctx, adoptedPatch)
	if err != nil || len(got) != 1 {
		t.Fatalf("RunsForPatchID = %+v, %v; want one record", got, err)
	}
	if got[0].AdoptedRun != "run-dead" || got[0].CommitSHA == "" {
		t.Errorf("got %+v; want the change attributed to run-live, adopted from run-dead, "+
			"with the commit it became", got[0])
	}

	plain, err := s.RunsForPatchID(ctx, plainPatch)
	if err != nil || len(plain) != 1 || plain[0].AdoptedRun != "" {
		t.Errorf("a plain change = %+v, %v; want one record adopting nothing", plain, err)
	}
}

// ADP-013 — an adoption is spent by its commit, ADR-0051 decision 6.
//
// The read behind it: every adoption of one dead run, by any run, and whether
// the commit it was for was recorded. An adoption whose commit never landed is
// not spent; it failed, and the work is still there to adopt.
func TestADP013AdoptionsOfARunSaysWhichWereCommitted(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	adopt := func(n, dead string) event.Fields {
		t.Helper()
		rec, err := s.Append(ctx, event.Fields{
			event.FieldSchemaVersion:   event.SchemaVersion,
			event.FieldEventType:       event.EventTypeRunAdopted,
			event.FieldSource:          event.SourceMCP,
			event.FieldRunID:           "run-live",
			event.FieldSpiffeID:        "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-live",
			event.FieldIdempotencyKey:  "adopted-" + n,
			event.FieldAdoptedRunID:    dead,
			event.FieldAdoptedRunState: "retired",
			event.FieldPayloadDigest:   "sha256:" + strings.Repeat(n, 64),
		})
		if err != nil {
			t.Fatalf("append run_adopted %s: %v", n, err)
		}
		return rec
	}
	intentFor := func(n string, adoption event.Fields) event.Fields {
		t.Helper()
		rec, err := s.Append(ctx, event.Fields{
			event.FieldSchemaVersion:   event.SchemaVersion,
			event.FieldEventType:       event.EventTypeCommitIntent,
			event.FieldSource:          event.SourceMCP,
			event.FieldRunID:           "run-live",
			event.FieldSpiffeID:        "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-live",
			event.FieldIdempotencyKey:  "intent-" + n,
			event.FieldRepo:            "github.com/acme/api",
			event.FieldTreeHash:        strings.Repeat("a", 40),
			event.FieldPatchID:         strings.Repeat(n, 40),
			event.FieldAdoptionEventID: adoption[event.FieldEventID],
		})
		if err != nil {
			t.Fatalf("append intent %s: %v", n, err)
		}
		return rec
	}

	committed := adopt("1", "run-dead")
	intent := intentFor("1", committed)
	recorded := commitRecordedBody("run-live", strings.Repeat("1", 40), "1")
	recorded[event.FieldIntentEventID] = intent[event.FieldEventID]
	if _, err := s.Append(ctx, recorded); err != nil {
		t.Fatalf("append recorded: %v", err)
	}
	failed := adopt("2", "run-dead")
	intentFor("2", failed) // signed never: no commit_recorded follows
	adopt("3", "run-other")

	got, err := s.AdoptionsOf(ctx, "run-dead")
	if err != nil {
		t.Fatalf("AdoptionsOf: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("AdoptionsOf = %+v, want the two adoptions of run-dead and not run-other's", got)
	}
	byID := map[string]Adoption{}
	for _, a := range got {
		byID[a.EventID] = a
	}
	committedID, _ := committed[event.FieldEventID].(string) //nolint:errcheck // an appended event's id is a string
	failedID, _ := failed[event.FieldEventID].(string)       //nolint:errcheck // same
	if a := byID[committedID]; !a.Committed || a.RunID != "run-live" ||
		a.PayloadDigest != "sha256:"+strings.Repeat("1", 64) {
		t.Errorf("the committed adoption = %+v", a)
	}
	if a := byID[failedID]; a.Committed {
		t.Errorf("an adoption whose commit never landed reads as committed: %+v", a)
	}
}
