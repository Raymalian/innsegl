// SPDX-License-Identifier: Apache-2.0

/*
 * The run page's own axe pass and keyboard walkthrough (#443, RM-278, and
 * E19 #395-397 before it), in a real Chromium (mirrors this directory's own
 * views.pw.ts: jsdom resolves neither `light-dark()` nor an accessible
 * name, so a real browser is what actually proves doc 06 §6.4 rather than
 * what the source merely claims).
 *
 * Self-contained mocks rather than tests/support/mock-routes.ts (RM-049's
 * own path) or the visual suite's private helper — the same three reads,
 * inline, so this file has no dependency on another test file's internals.
 * Run against both boards' own fixtures: a subagent (agent-record.json) and
 * a session (session-record.json), since the two render different controls.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

import { verifiedProof } from "../../src/components/verification/fixtures";
import {
  agentRecord,
  record,
  sessionRecord,
  stepOneDiff,
  AGENT_NOW,
  AGENT_RUN_ID,
  NOW,
  RUN_ID,
  SESSION_NOW,
  SESSION_RUN_ID,
} from "../../src/views/run-page/fixtures";
import type { RunRecord } from "../../src/views/run-page/types";

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installMocks(page: Page, runId: string, getRecord: () => RunRecord): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    // ADR-0062's gate reads these on every mount; this page is shown to a
    // signed-in operator, as tests/support/mock-routes.ts answers them.
    if (p === "/api/v1/auth/session") return json(route, { authenticated: true, display_name: "Test Operator" });
    if (p === "/api/v1/auth/setup") return json(route, { needed: false });
    if (p === "/api/v1/health") return json(route, { database: {}, auth: { enrolled: true, cannot_write_ledger: {} } });
    if (p === `/api/v1/runs/${runId}/record`) return json(route, getRecord());
    if (p.startsWith(`/api/v1/runs/${runId}/steps/`) && p.endsWith("/diff")) return json(route, stepOneDiff());
    if (p.startsWith("/api/v1/proof/")) return json(route, verifiedProof());
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

test("RM-278: the subagent page has no WCAG 2.1 AA violations", async ({ page }) => {
  await page.clock.install({ time: AGENT_NOW });
  await installMocks(page, AGENT_RUN_ID, agentRecord);
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.goto(`/runs/${AGENT_RUN_ID}`);
  await expect(page.getByText("Witnesses")).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  expect(
    results.violations,
    results.violations
      .map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`)
      .join("\n"),
  ).toEqual([]);
});

test("RM-278: the session page has no WCAG 2.1 AA violations", async ({ page }) => {
  await page.clock.install({ time: SESSION_NOW });
  await installMocks(page, SESSION_RUN_ID, sessionRecord);
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.goto(`/runs/${SESSION_RUN_ID}`);
  await expect(page.getByText("Agents it started")).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  expect(
    results.violations,
    results.violations
      .map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`)
      .join("\n"),
  ).toEqual([]);
});

test("RM-278: the lineage nav, agents table, step rows and toggles are all keyboard-reachable with a visible focus ring", async ({
  page,
}) => {
  await page.clock.install({ time: SESSION_NOW });
  await installMocks(page, SESSION_RUN_ID, sessionRecord);
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.goto(`/runs/${SESSION_RUN_ID}`);
  await expect(page.getByText("Agents it started")).toBeVisible();

  const targets = [
    page.getByRole("link", { name: "Baseline snapshot before first step" }).first(),
    page.getByRole("button", { name: "All" }),
    page.getByRole("button", { name: "Agents started" }),
    page.getByRole("searchbox", { name: "Find an agent by task" }),
  ];

  for (const target of targets) {
    await target.focus();
    await expect(target).toBeFocused();
    const outline = await target.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline, `${await target.textContent()} painted no visible outline`).not.toBe("none");
  }

  // The diff layout toggle shows only where a step has a diff (#443): a
  // gateway run's page.
  await page.clock.install({ time: NOW });
  await installMocks(page, RUN_ID, record);
  await page.goto(`/runs/${RUN_ID}`);
  for (const name of ["Unified", "Side by side"]) {
    const toggle = page.getByRole("button", { name });
    await toggle.focus();
    await expect(toggle).toBeFocused();
    expect(await toggle.evaluate((el) => getComputedStyle(el).outlineStyle)).not.toBe("none");
  }
});

test("RM-278: every diff line carries a +/- marker, not colour alone", async ({ page }) => {
  await page.clock.install({ time: NOW });
  await installMocks(page, RUN_ID, record);
  await page.goto(`/runs/${RUN_ID}`);
  // record.json's step 1 (a Write whose snapshot changed) opens by default
  // and shows the diff Main.dc.html specifies reusing inside an opened row.
  const diffFile = page.locator("[data-diff-file]").first();
  await expect(diffFile).toBeVisible();

  const markers = await diffFile.locator("[aria-hidden='true']").allTextContents();
  expect(markers.some((m) => m === "+" || m === "−")).toBe(true);
});
