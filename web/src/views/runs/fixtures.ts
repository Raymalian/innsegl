// SPDX-License-Identifier: Apache-2.0

/*
 * Runs-table fixtures — the shape `internal/api` actually serves.
 *
 * Field for field, spelling for spelling, from `internal/api/query.go`'s
 * RunSummary and RunPage: snake_case JSON names, `repos` as an array because
 * a run touches more than one, `next_cursor` absent rather than empty at the
 * end of the set, `data_as_of` on every page. A table tested against an
 * invented shape is a table nobody has tested.
 *
 * Everything here is static. Nothing calls `Date.now()`, so two renders of the
 * same fixture are byte-identical — which is what FE-010 compares, without
 * stripping anything a reader can perceive.
 */

import type { RunPage, RunSummary } from "./api";

export const TRUST_DOMAIN = "spiffe://innsegl.dev";

export function runSummary(overrides: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: "run-7f3a2c",
    spiffe_id: `${TRUST_DOMAIN}/agent/fix-ci/task-1481/run-7f3a2c`,
    agent_type: "fix-ci",
    task_ref: "task-1481",
    status: "active",
    repos: ["innsegl.dev/core"],
    commits: 2,
    chain_position: 4181,
    registered_at: "2026-08-30T11:02:41Z",
    last_event_at: "2026-08-30T11:12:04Z",
    ...overrides,
  };
}

/** Three runs, one of each status, in the descending chain order the API
 * serves them in. */
export function threeRuns(): readonly RunSummary[] {
  return [
    runSummary(),
    runSummary({
      run_id: "run-0e91bd",
      spiffe_id: `${TRUST_DOMAIN}/agent/release-notes/task-902/run-0e91bd`,
      agent_type: "release-notes",
      task_ref: "task-902",
      status: "retired",
      repos: ["innsegl.dev/core", "innsegl.dev/docs"],
      commits: 1,
      chain_position: 4177,
    }),
    runSummary({
      run_id: "run-b52a10",
      spiffe_id: `${TRUST_DOMAIN}/agent/fix-ci/task-1477/run-b52a10`,
      agent_type: "fix-ci",
      task_ref: "task-1477",
      status: "expired",
      repos: [],
      commits: 0,
      chain_position: 4102,
    }),
  ];
}

export function runPage(overrides: Partial<RunPage> = {}): RunPage {
  return {
    runs: threeRuns(),
    total: 3,
    limit: 50,
    data_as_of: "2026-08-31T09:14:02Z",
    ...overrides,
  };
}

/** An empty page, for the "no runs match these filters" state. */
export function emptyPage(): RunPage {
  return runPage({ runs: [], total: 0 });
}
