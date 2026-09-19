// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// childBody is a `run_registered` for one run, optionally naming its parent.
//
// Written here rather than folded into runScopedBody because the parent is the
// whole subject of this file: a helper that took it as one more positional
// argument would make every call site say `""` about a thing these tests are
// about.
func childBody(runID, parentRunID string, n int) event.Fields {
	body := runScopedBody(runID, event.EventTypeRunRegistered, n)
	// Required of a `run_registered` under schema 2 (ADR-0045): a run says
	// WHERE it works from the moment it exists.
	body[event.FieldRepo] = "example.test/org/name"
	body[event.FieldBranch] = "dev/e9"
	if parentRunID != "" {
		body[event.FieldParentRunID] = parentRunID
	}
	return body
}

// LED-040 — the children of a run, read off the chain.
//
// # Why the read exists
//
// `parent_run_id` has been a member of `run_registered` since ADR-0045 and
// nothing could ask the question it answers. "Which runs did this one start?"
// is what an orchestrator's page is, and it is the other half of "its parent
// ended while it is still open" — the strongest signal that a run is stranded.
//
// # Nothing here is derived
//
// A child is a run whose OWN registration named this run as its parent. There
// is no second rule, no inference from timing, and no inference from a shared
// working directory: a run that recorded no parent has none, permanently
// (IP §3, E7).
func TestLED040ChildRunsAreTheRunsThatNamedThisOne(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	// One parent, two children, and two runs that are nobody's children:
	// a root run, and a run whose parent is the OTHER root. A read that
	// answered with "every run registered after this one" passes on a chain
	// holding only a parent and its children, and fails here.
	for _, b := range []event.Fields{
		childBody("run-parent", "", 0),
		childBody("run-other-root", "", 1),
		childBody("run-child-a", "run-parent", 2),
		childBody("run-elsewhere", "run-other-root", 3),
		childBody("run-child-b", "run-parent", 4),
	} {
		if _, err := s.Append(ctx, b); err != nil {
			t.Fatalf("append %v: %v", b[event.FieldRunID], err)
		}
	}
	// A tool call by a child, so the read cannot be answering off run_id alone.
	if _, err := s.Append(ctx, runScopedBody("run-child-a", event.EventTypeToolCall, 5)); err != nil {
		t.Fatalf("append tool_call: %v", err)
	}

	got, err := s.ChildRuns(ctx, "run-parent")
	if err != nil {
		t.Fatalf("ChildRuns: %v", err)
	}
	want := []string{"run-child-a", "run-child-b"}
	if len(got) != len(want) {
		t.Fatalf("ChildRuns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("child %d = %q, want %q (chain order)", i, got[i], want[i])
		}
	}

	// A run nobody named is childless, and that is an empty answer rather than
	// an error: a leaf run is the ordinary case, not a failure.
	leaf, err := s.ChildRuns(ctx, "run-child-a")
	if err != nil {
		t.Fatalf("ChildRuns for a leaf: %v", err)
	}
	if len(leaf) != 0 {
		t.Errorf("ChildRuns(run-child-a) = %v, want none", leaf)
	}

	// A run this ledger has never held is childless too, and is likewise not
	// an error: the question "what did it start" has an answer for any string
	// that could name a run, and the answer is "nothing observed".
	none, err := s.ChildRuns(ctx, "run-never-existed")
	if err != nil {
		t.Fatalf("ChildRuns for an unknown run: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("ChildRuns(run-never-existed) = %v, want none", none)
	}
}

// An empty run id is refused rather than matched, for EventsForRun's reason:
// it names no run, and reading it as "the events with no run" would answer a
// question nobody asked.
func TestChildRunsRefusesAnEmptyRunID(t *testing.T) {
	s, _ := newStore(t)

	got, err := s.ChildRuns(testCtx(t, 30*time.Second), "")
	if err == nil {
		t.Fatalf("an empty run id was accepted and answered %v", got)
	}
	var stored *StoreError
	if !errors.As(err, &stored) || stored.Class != ClassInvariantViolation {
		t.Errorf("err = %v, want a %s StoreError", err, ClassInvariantViolation)
	}
}

// LED-040, second half: the read is one the planner can serve from the index
// migration 0005 adds.
//
// # Why this is asserted with sequential scans disabled
//
// The failure this guards against is not "the planner chose a scan on a small
// table" — it will, and it is right to. It is an index whose expression does
// not MATCH the query's, which is a silent defect: the index is created, the
// query works, and every children-of read is a full scan of a table doc 05 §4
// sizes at 20 GB a year. Disabling sequential scans asks the planner the only
// question worth asking here — CAN this index serve this query — and a
// mismatched expression answers no however large the table is.
func TestLED040ChildRunsIsServedByTheIndex(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	for i, b := range []event.Fields{
		childBody("run-parent", "", 0),
		childBody("run-child-a", "run-parent", 1),
	} {
		if _, err := s.Append(ctx, b); err != nil {
			t.Fatalf("append #%d: %v", i, err)
		}
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, execErr := conn.Exec(ctx, "SET enable_seqscan = off"); execErr != nil {
		t.Fatalf("disable sequential scans: %v", execErr)
	}

	rows, err := conn.Query(ctx, "EXPLAIN "+childRunsQuery, "run-parent")
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	if !strings.Contains(plan.String(), childRunsIndex) {
		t.Errorf("the children-of read is not served by %s:\n%s\n"+
			"An index whose expression does not match the query's is an index the "+
			"planner can never use, and every children-of read is then a full scan.",
			childRunsIndex, plan.String())
	}
}
