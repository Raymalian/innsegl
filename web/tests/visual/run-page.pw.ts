// SPDX-License-Identifier: Apache-2.0

/*
 * The run page (#443, RM-278, and E19 #395-397 before it): a visual
 * regression of the page at 1440px, built from the approved boards' own
 * fixtures, in light and dark.
 *
 * This file owns its own API mock rather than extending
 * tests/support/mock-routes.ts (RM-049's own path, not this issue's), so it
 * intercepts the run page's three reads directly: the record, whichever step
 * diffs the fixture actually shows, and the commit's proof
 * (components/verification's own `verifiedProof` fixture — the real rollup,
 * not an invented shape).
 */

import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

import { verifiedProof } from "../../src/components/verification/fixtures";
import {
  record,
  stepOneDiff,
  statesRecord,
  statesDiff,
  agentRecord,
  sessionRecord,
  NOW,
  RUN_ID,
  STATES_NOW,
  STATES_RUN_ID,
  AGENT_NOW,
  AGENT_RUN_ID,
  SESSION_NOW,
  SESSION_RUN_ID,
} from "../../src/views/run-page/fixtures";
import type { RunRecord, StepDiff } from "../../src/views/run-page/types";

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

/** One run's worth of mocks: its own record, and whichever step diffs it
 * actually shows (an opened row's own `showDiff` rule — never every step). */
async function installRunPageMocks(
  page: Page,
  runId: string,
  getRecord: () => RunRecord,
  diffs: Readonly<Record<number, () => StepDiff>>,
): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;

    // ADR-0062's gate reads these on every mount; this page is shown to a
    // signed-in operator, as tests/support/mock-routes.ts answers them.
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

    if (p === `/api/v1/runs/${runId}/record`) {
      await json(route, getRecord());
      return;
    }
    const diffMatch = /^\/api\/v1\/runs\/([^/]+)\/steps\/(\d+)\/diff$/.exec(p);
    if (diffMatch !== null && diffMatch[1] === runId) {
      const step = Number(diffMatch[2]);
      const getDiff = diffs[step];
      if (getDiff !== undefined) {
        await json(route, getDiff());
        return;
      }
    }
    if (p.startsWith("/api/v1/proof/")) {
      await json(route, verifiedProof());
      return;
    }
    // Answered loudly rather than left to hang, so an unexpected request
    // fails the test instead of the page silently showing its error state.
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

for (const mode of ["light", "dark"] as const) {
  test.describe(`run page at 1440px (${mode})`, () => {
    test.use({ colorScheme: mode, viewport: { width: 1440, height: 1800 } });

    test(`renders the subagent page from agent-record.json, matching Agent.dc.html (${mode})`, async ({ page }) => {
      await page.clock.install({ time: AGENT_NOW });
      await installRunPageMocks(page, AGENT_RUN_ID, agentRecord, {});
      await page.goto(`/runs/${AGENT_RUN_ID}`);

      await expect(page.getByRole("heading", { level: 1, name: "RM-189 health stops naming repos" })).toBeVisible();
      await expect(page.getByText("Witnesses")).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`run-page-agent-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`renders the session page from session-record.json, matching Session.dc.html (${mode})`, async ({ page }) => {
      await page.clock.install({ time: SESSION_NOW });
      await installRunPageMocks(page, SESSION_RUN_ID, sessionRecord, {});
      await page.goto(`/runs/${SESSION_RUN_ID}`);

      await expect(page.getByRole("heading", { level: 1, name: "Session on Raymalian/innsegl" })).toBeVisible();
      await expect(page.getByText("Agents it started")).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`run-page-session-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`renders a plain root run (record.json) through the session layout (${mode})`, async ({ page }) => {
      await page.clock.install({ time: NOW });
      await installRunPageMocks(page, RUN_ID, record, { 1: stepOneDiff });
      await page.goto(`/runs/${RUN_ID}`);

      await expect(page.getByRole("heading", { level: 1, name: "Session on innsegl-test/gateway-livetest" })).toBeVisible();
      await expect(page.getByText("Valid")).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`run-page-main-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`renders side by side from the URL, doc 06 §7 (${mode})`, async ({ page }) => {
      await page.clock.install({ time: NOW });
      await installRunPageMocks(page, RUN_ID, record, { 1: stepOneDiff });
      await page.goto(`/runs/${RUN_ID}?diff=side`);

      await expect(page.getByRole("button", { name: "Side by side" }).first()).toHaveAttribute("aria-pressed", "true");
      await expect(page.getByText("Valid")).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`run-page-main-side-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`renders the disagreement and not-landed states (states-record.json) through the session layout (${mode})`, async ({
      page,
    }) => {
      // Steps 3 and 5 also changed the snapshot (writing, then reverting,
      // scratch/probe.sh) and so also show a diff — small synthetic ones
      // here rather than a fourth fixture file, since only this visual
      // check's own completeness needs them.
      const probeAdded = (): StepDiff => ({
        files: [
          {
            path: "scratch/probe.sh",
            old_path: "",
            status: "A",
            binary: false,
            truncated: false,
            hunks: [
              {
                old_start: 0,
                old_lines: 0,
                new_start: 1,
                new_lines: 2,
                lines: [
                  { kind: "add", old_no: 0, new_no: 1, text: "#!/bin/sh" },
                  { kind: "add", old_no: 0, new_no: 2, text: "for i in 1 2 3; do curl -s localhost/health; done" },
                ],
              },
            ],
          },
        ],
      });
      const probeRemoved = (): StepDiff => ({
        files: [
          {
            path: "scratch/probe.sh",
            old_path: "",
            status: "D",
            binary: false,
            truncated: false,
            hunks: [
              {
                old_start: 1,
                old_lines: 2,
                new_start: 0,
                new_lines: 0,
                lines: [
                  { kind: "del", old_no: 1, new_no: 0, text: "#!/bin/sh" },
                  { kind: "del", old_no: 2, new_no: 0, text: "for i in 1 2 3; do curl -s localhost/health; done" },
                ],
              },
            ],
          },
        ],
      });
      await page.clock.install({ time: STATES_NOW });
      await installRunPageMocks(page, STATES_RUN_ID, statesRecord, {
        3: probeAdded,
        5: probeRemoved,
        7: statesDiff,
      });
      await page.goto(`/runs/${STATES_RUN_ID}`);

      await expect(page.getByRole("alert")).toContainText("Witnesses disagree on step 7");
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`run-page-states-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });
  });
}
