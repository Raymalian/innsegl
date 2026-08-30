// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// EventsForRun returns every event carrying run_id, in chain order, exactly as
// each was written.
//
// # Why this read exists
//
// Three of the five MCP tools begin with the same question: does this run
// exist, and has it been retired? The answer is in the chain — `run_registered`
// and `run_retired` — and until this method there was no way to ask it that did
// not read the whole chain and filter in Go. That is the read a run directory
// makes on every single tool call, so it is O(chain) per call on a table that
// only grows, and doc 05 §4 sizes the chain at 20 GB a year.
//
// The index for it already exists: migration 0001 carries
// `events_run_id_idx (run_id, chain_position) WHERE run_id IS NOT NULL`,
// written for exactly this question. ADR-0018 and ADR-0020 both flagged the
// missing reader, and ADR-0020's earliest-`run_retired` contract cannot be
// honoured by anything else.
//
// # An empty run id is refused, not matched
//
// `run_id` is nullable: an event that is not scoped to a run — a sealed
// segment, a drift alert — carries none. An empty string is not that, and
// reading it as "the events with no run" would answer a question no caller
// asked. It is INVARIANT_VIOLATION, which is what a caller that built a run id
// out of nothing has.
//
// # No bound, and why that is safe here
//
// The result is every event for one run, unpaged. A run's event count is
// bounded by what one agent run does — doc 05 §4 sizes it at ~20 events — and
// a run directory that read a prefix could not see a `run_retired` that fell
// outside it, which is I4's guarantee turned into a bug. A pathological run is
// still bounded by LED-011's 1 KB per event.
func (s *Store) EventsForRun(ctx context.Context, runID string) ([]event.Fields, error) {
	if runID == "" {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "events_for_run", Retryable: false,
			Err: fmt.Errorf("an empty run id names no run; events with no run carry a NULL run_id"),
		}
	}

	rows, err := s.pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE run_id = $1
		  ORDER BY chain_position`, runID)
	if err != nil {
		return nil, classify("events_for_run", err)
	}
	defer rows.Close()

	var out []event.Fields
	for rows.Next() {
		var canonical []byte
		if err := rows.Scan(&canonical); err != nil {
			return nil, classify("events_for_run", err)
		}
		record, err := decode(canonical)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("events_for_run", err)
	}
	return out, nil
}
