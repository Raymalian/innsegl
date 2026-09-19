// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// childRunsIndex names the index migration 0005 adds, so the read below and
// the test that proves the planner can use it agree about which index that is
// without either of them spelling it a second time.
const childRunsIndex = "events_parent_run_id_idx"

// childRunsQuery is the read itself, held as a constant for the same reason:
// the plan assertion must EXPLAIN the statement this method runs, not a
// paraphrase of it. An expression that drifted from the index's by one cast
// would be a silent full scan.
const childRunsQuery = `
	SELECT run_id FROM innsegl.events
	 WHERE event_type = '` + event.EventTypeRunRegistered + `'
	   AND (innsegl.event_body(canonical) ->> '` + event.FieldParentRunID + `') = $1
	 ORDER BY chain_position`

// ChildRuns returns the runs whose own registration named runID as their
// parent, in chain order.
//
// # What a child is, and what it is not
//
// A child is a run whose `run_registered` CARRIES `parent_run_id` equal to
// this run. That is the whole rule. Nothing here reads a timestamp, a working
// directory, an agent type or an idempotency key, and nothing here may grow to
// — a run that recorded no parent has none, permanently, and inferring one
// from what happened to be running at the time is exactly the inference IP §3
// E7 forbids. A wrong edge in an append-only record cannot be taken back.
//
// # Why it answers with run ids rather than with events
//
// The question is "which runs did this one start", and the answer is a list of
// runs. A caller that wants a child's own registration has EventsForRun for
// it, and returning the bodies here would make every caller decode a canonical
// record to read one member out of it.
//
// # An empty answer is not an error
//
// A leaf run has no children and so does a run this ledger has never held.
// Both are ordinary, and the caller that has to tell them apart asks whether
// the run exists — which is what the run directory is for. An empty run id is
// refused for EventsForRun's reason: it names no run, and matching it would
// answer a question nobody asked.
//
// # Cost
//
// One index-order read of migration 0005's partial expression index, which
// covers both the filter and the ordering. The result is unpaged, and bounded
// by what one run delegates: an orchestrator that spawned a thousand subagents
// returns a thousand ids, which is a list of identifiers and not a chain read.
func (s *Store) ChildRuns(ctx context.Context, runID string) ([]string, error) {
	if runID == "" {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "child_runs", Retryable: false,
			Err: fmt.Errorf("an empty run id names no run, so nothing can be its child"),
		}
	}

	rows, err := s.pool.Query(ctx, childRunsQuery, runID)
	if err != nil {
		return nil, classify("child_runs", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var child string
		if err := rows.Scan(&child); err != nil {
			return nil, classify("child_runs", err)
		}
		out = append(out, child)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("child_runs", err)
	}
	return out, nil
}
