// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"fmt"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// runScopedBody is an event body for one named run.
func runScopedBody(runID, eventType string, n int) event.Fields {
	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      eventType,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/" + runID,
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("run-scoped-%s-%d", runID, n),
	}
	switch eventType {
	case event.EventTypeToolCall:
		body[event.FieldToolName] = "record_event"
		body[event.FieldPayloadDigest] = "sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000000"
	case event.EventTypeRunRegistered:
		body[event.FieldAgentType] = "fix-ci"
		body[event.FieldTaskRef] = "jira-118"
	case event.EventTypeRunRetired:
		// run_retired carries no idempotency_key at all (ADR-0004).
		delete(body, event.FieldIdempotencyKey)
	}
	return body
}

// TestEventsForRunReturnsOnlyThatRunInChainOrder is the run-scoped read the
// MCP's run directory needs: three tools ask "does this run exist, and is it
// retired?", and until now the only way to answer was to read the whole chain.
func TestEventsForRunReturnsOnlyThatRunInChainOrder(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	// Interleaved deliberately: a reader that returned a contiguous slice of
	// the chain would pass against two runs appended in blocks.
	want := []string{}
	for i := range 4 {
		if _, err := s.Append(ctx, runScopedBody("run-a", event.EventTypeToolCall, i)); err != nil {
			t.Fatalf("append run-a #%d: %v", i, err)
		}
		want = append(want, fmt.Sprintf("run-a-%d", i))
		if _, err := s.Append(ctx, runScopedBody("run-b", event.EventTypeToolCall, i)); err != nil {
			t.Fatalf("append run-b #%d: %v", i, err)
		}
	}

	got, err := s.EventsForRun(ctx, "run-a")
	if err != nil {
		t.Fatalf("EventsForRun: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("EventsForRun returned %d events for run-a, want %d", len(got), len(want))
	}

	var last int64
	for i, rec := range got {
		if id, ok := rec[event.FieldRunID].(string); !ok || id != "run-a" {
			t.Errorf("event %d carries run_id %q, want run-a; the read is not run-scoped", i, id)
		}
		pos, ok := rec[event.FieldChainPosition].(int64)
		if !ok {
			t.Fatalf("event %d carries no int64 chain_position: %#v", i, rec[event.FieldChainPosition])
		}
		if pos <= last {
			t.Errorf("event %d is at chain_position %d, not after %d; the read is not in chain order",
				i, pos, last)
		}
		last = pos
	}
}

// TestEventsForRunIsEmptyForAnUnknownRun: no such run is not an error. The run
// directory turns it into RUN_NOT_FOUND, which is the MCP's word and not the
// ledger's.
func TestEventsForRunIsEmptyForAnUnknownRun(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	if _, err := s.Append(ctx, runScopedBody("run-a", event.EventTypeToolCall, 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := s.EventsForRun(ctx, "run-nobody")
	if err != nil {
		t.Fatalf("EventsForRun for an unknown run: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("EventsForRun returned %d events for an unknown run, want none", len(got))
	}
}

// TestEventsForRunRefusesAnEmptyRunID: the events table holds a NULL run_id
// for every event that is not scoped to a run (a sealed segment, a drift
// alert). An empty argument must not be read as "match those".
func TestEventsForRunRefusesAnEmptyRunID(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	_, err := s.EventsForRun(ctx, "")
	if err == nil {
		t.Fatal("EventsForRun(\"\") returned no error; an empty run id names no run")
	}
	se := storeError(t, err)
	if se.Class != ClassInvariantViolation {
		t.Errorf("EventsForRun(\"\") is %s, want %s", se.Class, ClassInvariantViolation)
	}
}
