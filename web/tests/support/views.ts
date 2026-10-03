// SPDX-License-Identifier: Apache-2.0

// doc 06 §3's six views, addressed the way a reader actually reaches them —
// through src/app/routes.ts's own path grammar — and the document title each
// one produces (src/app/strings.ts's `documentTitle`), which is the cheapest
// real signal that the view which rendered is the one the address named and
// not doc 06 §4.6's placeholder or an unmocked-request error state.

import { AGENT_TYPE, ALERT_ID, COMMIT_SHA, REPO, RUN_ID } from "./api-fixtures";

export interface ViewCase {
  readonly name: string;
  readonly path: string;
  readonly title: string;
}

const TITLE_SUFFIX = " · Innsegl";

export const VIEWS: readonly ViewCase[] = [
  { name: "overview", path: "/", title: `Overview${TITLE_SUFFIX}` },
  { name: "runs", path: "/runs", title: `Runs${TITLE_SUFFIX}` },
  { name: "repos", path: "/repos", title: `Repositories${TITLE_SUFFIX}` },
  // E19 (#395-397): `/runs/:runId` is now the run PAGE (doc 06 §3.3's
  // replacement), not this hash-chain timeline — the timeline moved to
  // `/runs/:runId/chain` and stayed reachable there, so this suite's own
  // run-detail-specific assertions (the "Verify this commit" disclosure,
  // the credential-history table) still exercise the view they were written
  // against. The run PAGE itself is E19's own suite: web/src/views/run-page's
  // vitest tests and tests/visual/run-page.pw.ts.
  { name: "run", path: `/runs/${RUN_ID}/chain`, title: `Run detail${TITLE_SUFFIX}` },
  { name: "repo", path: `/repos/${REPO}`, title: `Repository${TITLE_SUFFIX}` },
  {
    name: "agentType",
    path: `/agent-types/${AGENT_TYPE}`,
    title: `Agent types${TITLE_SUFFIX}`,
  },
  {
    name: "verify",
    path: `/verify?commit=${COMMIT_SHA}&repo=${REPO}`,
    title: `Verify a commit${TITLE_SUFFIX}`,
  },
  // RM-330's alerts page: every alert, grouped by what raised it.
  { name: "alerts", path: "/alerts?kind=all", title: `Alerts${TITLE_SUFFIX}` },
  // ADR-0054's alert detail, reached from the alerts page or the header's
  // notification menu.
  { name: "alert", path: `/alerts/${ALERT_ID}`, title: `Alert${TITLE_SUFFIX}` },
];
