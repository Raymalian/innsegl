// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// deadRunsQuery is DeadRunsForRepo's read. The runs come from their own
// registrations (events_event_type_idx), their facts from their own events
// (events_run_id_idx), and their state from RunStateSQL, the one rule every
// other reader uses. abandoned_before is NULL: lapsed and abandoned are both
// ended here, and which of the two a run is decides nothing.
const deadRunsQuery = `
	WITH reg AS (
	    SELECT DISTINCT run_id FROM innsegl.events
	     WHERE event_type = '` + event.EventTypeRunRegistered + `'
	       AND innsegl.resolve_alias(innsegl.event_body(canonical) ->> '` + event.FieldRepo + `') = $1),
	facts AS (
	    SELECT e.run_id,
	           bool_or(e.event_type = '` + event.EventTypeRunRetired + `') AS retired,
	           max(e.ts) FILTER (WHERE e.event_type = '` + event.EventTypeRunExpired + `') AS withdrawn_at,
	           max(e.ts) FILTER (WHERE ` + ActivitySQL + `) AS last_activity_at,
	           NULL::timestamptz AS abandoned_before
	      FROM innsegl.events e JOIN reg USING (run_id)
	     GROUP BY e.run_id)
	SELECT run_id FROM facts
	 WHERE (` + RunStateSQL + `) <> '` + RunActive + `'
	   AND last_activity_at >= $2
	 ORDER BY last_activity_at DESC, run_id
	 LIMIT $3`

// DeadRunsForRepo returns the runs registered for repo that the ledger does
// not call active and that were last active at or after since, most recent
// first, at most limit of them: the runs a commit in repo may adopt from
// (ADR-0079 decision 3).
//
// It is a prefilter, not a verdict. A caller asks each run's state again the
// way every tool asks it before it proves anything against the run.
//
// # Cost
//
// One pass over the `run_registered` events, which number one per run, then
// each candidate's own events through events_run_id_idx. `since` and `limit`
// bound what a caller does with the answer, not this read.
func (s *Store) DeadRunsForRepo(ctx context.Context, repo string, since time.Time, limit int) ([]string, error) {
	switch {
	case repo == "":
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "dead_runs_for_repo", Retryable: false,
			Err: fmt.Errorf("an empty repository names no repository a run was registered for"),
		}
	case limit < 1:
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "dead_runs_for_repo", Retryable: false,
			Err: fmt.Errorf("a cap of %d returns nothing a caller could have asked for", limit),
		}
	}
	rows, err := s.pool.Query(ctx, deadRunsQuery, repo, since, limit)
	if err != nil {
		return nil, classify("dead_runs_for_repo", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			return nil, classify("dead_runs_for_repo", err)
		}
		out = append(out, runID)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("dead_runs_for_repo", err)
	}
	return out, nil
}
