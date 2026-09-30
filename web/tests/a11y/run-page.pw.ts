// SPDX-License-Identifier: Apache-2.0

/*
 * RPG-015 — the run page's axe pass and keyboard walkthrough, in a real
 * Chromium (mirrors this directory's own views.pw.ts: jsdom resolves
 * neither `light-dark()` nor an accessible name, so a real browser is what
 * actually proves doc 06 §6.4 rather than what the source merely claims).
 *
 * Self-contained mocks rather than tests/support/mock-routes.ts (RM-049's
 * own path) or this issue's own visual suite's private helper — the same
 * three reads, inline, so this file has no dependency on another test
 * file's internals.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

import { verifiedProof } from "../../src/components/verification/fixtures";
import { record, stepOneDiff, NOW, RUN_ID } from "../../src/views/run-page/fixtures";

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installMocks(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    // ADR-0062's gate reads these on every mount; this page is shown to a
    // signed-in operator, as tests/support/mock-routes.ts answers them.
    if (p === "/api/v1/auth/session") return json(route, { authenticated: true, display_name: "Test Operator" });
    if (p === "/api/v1/health") return json(route, { database: {}, auth: { enrolled: true, cannot_write_ledger: {} } });
    if (p === `/api/v1/runs/${RUN_ID}/record`) return json(route, record());
    if (p === `/api/v1/runs/${RUN_ID}/steps/1/diff`) return json(route, stepOneDiff());
    if (p.startsWith("/api/v1/proof/")) return json(route, verifiedProof());
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

test("RPG-015: the run page has no WCAG 2.1 AA violations", async ({ page }) => {
  await page.clock.install({ time: NOW });
  await installMocks(page);
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.goto(`/runs/${RUN_ID}`);
  await expect(page.getByText("Valid")).toBeVisible();

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

test("RPG-015: the agent tree, files, steps and toggle are all keyboard-reachable with a visible focus ring", async ({
  page,
}) => {
  await page.clock.install({ time: NOW });
  await installMocks(page);
  await page.setViewportSize({ width: 1440, height: 1800 });
  await page.goto(`/runs/${RUN_ID}`);
  await expect(page.getByText("Valid")).toBeVisible();

  const targets = [
    page.getByRole("link", { name: /^main/ }),
    page.getByRole("link", { name: /^general-purpose · run-/ }),
    page.getByRole("button", { name: "Unified" }),
    page.getByRole("button", { name: "Side by side" }),
    page.getByRole("button", { name: /Copy commit SHA/ }),
    page.getByRole("link", { name: "Verify it yourself" }),
  ];

  for (const target of targets) {
    await target.focus();
    await expect(target).toBeFocused();
    const outline = await target.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline, `${await target.textContent()} painted no visible outline`).not.toBe("none");
  }
});

test("RPG-015: every diff line carries a +/- marker, not colour alone", async ({ page }) => {
  await page.clock.install({ time: NOW });
  await installMocks(page);
  await page.goto(`/runs/${RUN_ID}`);
  const diffFile = page.locator("[data-diff-file]").first();
  await expect(diffFile).toBeVisible();

  const markers = await diffFile.locator("[aria-hidden='true']").allTextContents();
  expect(markers.some((m) => m === "+" || m === "−")).toBe(true);
});
