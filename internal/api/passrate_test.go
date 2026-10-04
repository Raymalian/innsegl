// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// The overview's verification pass rate is measured live: the ledger only
// names which commits are the most recent, and each verdict comes from the
// three checks against git, Fulcio and Rekor (IP §6.11, FD P2). With the
// upstreams up the commit counts as verified; with them down the same
// commit, still recorded in the ledger, counts as could not be checked.
func TestTheRecentPassRateIsMeasuredLiveNeverReadFromTheLedger(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	owner, _, readerDSN := migrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The ledger knows this commit and says it was signed.
	base := func(eventType string) event.Fields {
		return event.Fields{
			event.FieldEventType: eventType,
			event.FieldRunID:     "run-1",
			event.FieldSpiffeID:  fixtureIdentity,
			event.FieldSource:    event.SourceMCP,
		}
	}
	reg := base(event.EventTypeRunRegistered)
	reg[event.FieldAgentType] = "fix-ci"
	reg[event.FieldTaskRef] = "rm-040"
	// ADR-0045, required under schema 2.
	reg[event.FieldRepo] = fixtureRepo
	reg[event.FieldBranch] = "main"
	reg[event.FieldIdempotencyKey] = "run-1-register"
	appendOrFail(ctx, t, owner, reg)

	intent := base(event.EventTypeCommitIntent)
	intent[event.FieldRepo] = fixtureRepo
	intent[event.FieldTreeHash] = strings.Repeat("a", 40)
	intent[event.FieldPatchID] = strings.Repeat("c", 40)
	intent[event.FieldIdempotencyKey] = "run-1-intent"
	rec := appendOrFail(ctx, t, owner, intent)

	done := base(event.EventTypeCommitRecorded)
	done[event.FieldRepo] = fixtureRepo
	done[event.FieldTreeHash] = strings.Repeat("a", 40)
	done[event.FieldPatchID] = strings.Repeat("c", 40)
	done[event.FieldCommitSHA] = s.commit
	done[event.FieldIntentEventID] = rec[event.FieldEventID]
	done[event.FieldRekorEntryUUID] = strings.Repeat("b", 64)
	done[event.FieldRekorLogIndex] = int64(1)
	done[event.FieldIdempotencyKey] = "run-1-recorded"
	appendOrFail(ctx, t, owner, done)

	store, _ := readStore(t, readerDSN)
	prover := s.prover(t)

	live, err := MeasureRecent(ctx, store, prover, 20)
	if err != nil {
		t.Fatalf("MeasureRecent: %v", err)
	}
	if live.Checked != 1 || live.Verified != 1 || live.Failed != 0 || live.Unavailable != 0 {
		t.Fatalf("with the upstreams up: %+v, want one verified", live)
	}
	if len(live.Commits) != 1 || live.Commits[0].CommitSHA != s.commit || live.MeasuredAt.IsZero() {
		t.Fatalf("commits %+v, measured at %v", live.Commits, live.MeasuredAt)
	}

	s.fulcio.stop()
	s.log.stop()
	down, err := MeasureRecent(ctx, store, prover, 20)
	if err != nil {
		t.Fatalf("MeasureRecent: %v", err)
	}
	if down.Checked != 1 || down.Unavailable != 1 || down.Verified != 0 {
		t.Fatalf("with the upstreams down: %+v, want one could-not-check, never a ledger answer", down)
	}
}
