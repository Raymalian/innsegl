// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

// TestRunIndexRollupIsComputedOnce. Postgres estimates one row for the
// filtered `registered` side, picks a nested loop, and re-runs the inlined
// `rollup` aggregate once per run. Measured on a 47k-event ledger with 687
// runs in a 30-day window: 4.7 s for one page of the repository view, and
// 0.17 s with the rollup materialized and hash-joined.
func TestRunIndexRollupIsComputedOnce(t *testing.T) {
	for _, order := range []string{OrderDesc, OrderAsc} {
		if !contains(runsQuery(order), "rollup AS MATERIALIZED (") {
			t.Errorf("the %s runs query inlines `rollup`; the planner re-aggregates every event per run", order)
		}
	}
	if !contains(runSQL, "rollup AS MATERIALIZED (") {
		t.Error("the run query inlines `rollup`")
	}
}
