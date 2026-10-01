// SPDX-License-Identifier: Apache-2.0

/*
 * Query-API mocking for the six real views — RM-049 (#57).
 *
 * Every view in web/src talks to the query API with a plain `fetch` at a
 * same-origin path (doc 06 §7: "read-only API consumer"); none of them takes
 * an injected client this suite could swap out without editing web/src,
 * which this issue does not own. `page.route` intercepts at the network
 * layer instead — the real router, the real components and the real fetch
 * calls all run; only the server on the other end is a fixture.
 *
 * One handler, not one per view: a keyboard walkthrough (FE-009) navigates
 * BETWEEN views by clicking real links, so the mock has to answer whichever
 * request the view in front of it happens to make, not only the one the test
 * expected to be looking at.
 */

import type { Page, Route } from "@playwright/test";

import {
  RUN_ID,
  alertsPage,
  detail,
  overview,
  proof,
  runPage,
  windowedCount,
} from "./api-fixtures";

function json(route: Route, body: unknown, status = 200): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

/**
 * Wire every `/api/v1/*` request the six views can make to a fixture. Install
 * once per test/page — it lasts for the page's lifetime, so following a real
 * link from one view to another keeps working.
 */
export async function installApiMocks(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    const q = url.searchParams;

    // RM-260/RM-261 (ADR-0062) and #445: AuthGate reads session + setup
    // status on every mount, before any of the six views' own routes below
    // are ever requested. Answered as an already-signed-in operator by
    // default, so this suite's existing axe/keyboard coverage keeps
    // exercising the real views rather than the sign-in page — a
    // deliberately UNauthenticated scan of the gate itself lives in
    // tests/a11y/auth.pw.ts instead.
    if (p === "/api/v1/auth/session") {
      await json(route, { authenticated: true, display_name: "Test Operator" });
      return;
    }
    if (p === "/api/v1/auth/setup") {
      await json(route, { needed: false });
      return;
    }
    if (p === "/api/v1/health") {
      await json(route, { database: {}, auth: { enrolled: true, cannot_write_ledger: {} } });
      return;
    }

    if (p === "/api/v1/overview") {
      await json(route, overview());
      return;
    }

    if (p === `/api/v1/runs/${RUN_ID}`) {
      await json(route, detail());
      return;
    }

    if (p.startsWith("/api/v1/runs/")) {
      // A run id this suite did not fixture. Answered as internal/api answers
      // an unknown run: 404, so RunNotFound's own branch is what renders.
      await json(route, { error: { code: "not_found", message: "no such run" } }, 404);
      return;
    }

    // The header's notification menu reads this on every view (ADR-0054),
    // and the alert detail view pages it to find one event ID.
    if (p === "/api/v1/alerts") {
      await json(route, alertsPage());
      return;
    }

    if (p.startsWith("/api/v1/proof/")) {
      await json(route, proof());
      return;
    }

    if (p === "/api/v1/runs") {
      // The overview's "runs today" and "recent runs" reads both name a
      // limit; a filtered runs/repo/agent-type read does not name `limit=1`.
      if (q.get("limit") === "1") {
        await json(route, windowedCount(7));
        return;
      }
      await json(route, runPage());
      return;
    }

    // Anything else is a request this suite did not anticipate. Answering it
    // with a 500 rather than falling through to the real network makes an
    // unmocked request a loud test failure instead of a silent one — a view
    // rendering its error state would otherwise look, to axe, like a page
    // with very little content and no violations, which proves nothing.
    await json(
      route,
      { error: { code: "unmocked", message: `no fixture for ${p}${url.search}` } },
      500,
    );
  });
}
