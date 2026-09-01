// SPDX-License-Identifier: Apache-2.0

/*
 * The query-API responses the six real views need to render real content —
 * RM-049 (#57). Every shape below is drawn from `internal/api`'s own response
 * types, by reusing the fixture builders web/src's own component and view
 * suites already validated against those types (components/verification's
 * `fixtures.ts`, views/run-detail's `fixtures.ts`) rather than inventing a
 * second, unverified shape. Where no existing fixture covers a response (the
 * overview, the runs table, the repo/agent-type windows), the shape is typed
 * against the same view's own TypeScript interfaces so a field this build
 * does not expect is a compile error here, not a silent 404 in a browser.
 */

import { verifiedProof, COMMIT_SHA } from "../../src/components/verification/fixtures";
import type { Proof } from "../../src/components/verification/types";
import {
  runDetail,
  RUN_ID,
  SPIFFE_ID,
} from "../../src/views/run-detail/fixtures";
import type { RunDetail } from "../../src/views/run-detail/types";
import type { AnchorHeartbeat, OverviewData } from "../../src/views/overview/types";
import type { RunPage, RunSummary } from "../../src/views/runs/api";

/** The repo and agent type every fixture below agrees on, so a link followed
 * from one real view lands on a fixture the next view also recognises. */
export const REPO = "innsegl";
export const AGENT_TYPE = "fix-ci";

/** internal/api/query.go's AnchorHeartbeat: a segment sealed and anchored a
 * few minutes ago — the calm state doc 06 P3 says is what is left after the
 * alarm is designed. */
export function anchor(): AnchorHeartbeat {
  return {
    present: true,
    segment_id: "sha256:8f1c2d3e4b5a69708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f",
    first_position: 1,
    last_position: 46,
    sealed_at: "2026-08-31T11:52:00.000Z",
    anchored: true,
    rekor_log_index: 82900,
  };
}

export function overview(): OverviewData {
  return {
    active_runs: 3,
    retired_runs: 41,
    expired_runs: 1,
    commits_recorded: 12,
    open_alerts: 0,
    anchor: anchor(),
    data_as_of: "2026-08-31T12:00:00.000Z",
  };
}

function runSummary(overrides: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: RUN_ID,
    spiffe_id: SPIFFE_ID,
    agent_type: AGENT_TYPE,
    task_ref: "JIRA-118",
    status: "retired",
    repos: [REPO],
    commits: 1,
    chain_position: 46,
    registered_at: "2026-08-31T11:41:00.000Z",
    last_event_at: "2026-08-31T11:46:00.000Z",
    ...overrides,
  };
}

/** One page of the runs table: the retired run every other fixture agrees
 * with, plus an active one — so both StatusBadge treatments are on screen for
 * the a11y and green-audit walkthroughs, not just one. */
export function runPage(overrides: Partial<RunPage> = {}): RunPage {
  const runs = [
    runSummary(),
    runSummary({
      run_id: "run-a1b2c3",
      spiffe_id: "spiffe://innsegl.dev/agent/doc-writer/task-1502/run-a1b2c3",
      agent_type: "doc-writer",
      task_ref: "JIRA-121",
      status: "active",
      commits: 0,
      registered_at: "2026-08-31T11:55:00.000Z",
      last_event_at: "2026-08-31T11:55:00.000Z",
    }),
  ];
  return {
    runs,
    total: runs.length,
    limit: 200,
    data_as_of: "2026-08-31T12:00:00.000Z",
    ...overrides,
  };
}

/** internal/api/query.go's RunPage for a `limit=1` count-only read (the
 * overview's "runs today" card and the agent-type view's bucket counts). */
export function windowedCount(total: number): RunPage {
  return { runs: [], total, limit: 1, data_as_of: "2026-08-31T12:00:00.000Z" };
}

/** `GET /api/v1/runs/{run_id}` — the run this suite's run-detail fixtures
 * name (RUN_ID, "run-7f3a2c"), reused verbatim rather than re-specified. */
export function detail(): RunDetail {
  return runDetail();
}

/** `GET /api/v1/proof/{commit_sha}` — every check verified, the only proof
 * entitled to a green (doc 06 §5.3). RUN_ID's one commit and this proof name
 * the same SHA, so opening "Verify this commit" on the real run-detail page
 * renders the real, live VerificationPanel — not only the harness's copy of
 * it — which is what FE-013's green audit needs to see at least once. */
export function proof(): Proof {
  return verifiedProof();
}

export { COMMIT_SHA, RUN_ID, SPIFFE_ID };
