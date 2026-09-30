// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) — the gated shell's own screens: sign-in and
 * first-enrolment. doc 07's FE-009 pattern (axe pass + keyboard-only walk),
 * applied to the two pages every other view now sits behind.
 *
 * installApiMocks answers /api/v1/auth/session as an already-signed-in
 * operator by default (see that file's own comment), so these two states —
 * "nobody has ever enrolled" and "a user exists but this browser has no
 * session" — are wired here instead, by overriding just the two routes
 * AuthGate itself reads.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { installApiMocks } from "../support/mock-routes";

async function asUnauthenticated(page: Page, enrolled: boolean): Promise<void> {
  await installApiMocks(page);
  await page.route("**/api/v1/auth/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ authenticated: false }),
    });
  });
  await page.route("**/api/v1/health", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ database: {}, auth: { enrolled, cannot_write_ledger: {} } }),
    });
  });
}

function formatViolations(violations: readonly import("axe-core").Result[]): string {
  if (violations.length === 0) return "";
  return violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    ${n.target.join(" ")}: ${n.failureSummary ?? ""}`);
      return `${v.id} (${v.impact ?? "unknown"}): ${v.help}\n${nodes.join("\n")}`;
    })
    .join("\n\n");
}

test.describe("RM-260/RM-261: the sign-in page", () => {
  test("has no WCAG 2.1 AA violations", async ({ page }) => {
    await asUnauthenticated(page, true);
    await page.goto("/");
    await expect(page.getByRole("button", { name: /sign in with a passkey/i })).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("the passkey button is reachable by keyboard and carries a visible focus ring", async ({
    page,
  }) => {
    await asUnauthenticated(page, true);
    await page.goto("/");
    const button = page.getByRole("button", { name: /sign in with a passkey/i });
    await expect(button).toBeVisible();

    await page.keyboard.press("Tab");
    await expect(button).toBeFocused();
    const outline = await button.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).not.toBe("none");
  });

  test("renders no other view's content — nothing of the dashboard leaks", async ({ page }) => {
    await asUnauthenticated(page, true);
    await page.goto("/runs");
    await expect(page.getByRole("button", { name: /sign in with a passkey/i })).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("navigation")).toHaveCount(0);
  });
});

test.describe("RM-260/RM-261: the first-enrolment page", () => {
  test("has no WCAG 2.1 AA violations", async ({ page }) => {
    await asUnauthenticated(page, false);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /set up the first passkey/i })).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("both fields and the submit button are reachable by keyboard, in order", async ({
    page,
  }) => {
    await asUnauthenticated(page, false);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /set up the first passkey/i })).toBeVisible();

    await page.keyboard.press("Tab");
    await expect(page.getByLabel(/display name/i)).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByLabel(/one-time code/i)).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /create a passkey/i })).toBeFocused();
  });
});
