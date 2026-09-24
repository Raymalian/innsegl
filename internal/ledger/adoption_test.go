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
