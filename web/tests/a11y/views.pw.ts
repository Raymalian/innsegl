// SPDX-License-Identifier: Apache-2.0

/*
 * FE-009 — doc 07: "axe pass + keyboard-only walkthrough of all six views."
 * Expected: "No violations; every interactive element reachable and
 * operable." Proves doc 06 §6.4.
 *
 * Two things every agent before this one explicitly declined to claim,
 * because no browser existed to claim them in: an axe pass against the
 * REAL, mocked-network-but-otherwise-unmodified six views (not a jsdom
 * stand-in, which resolves neither the cascade nor a real accessibility
 * tree), and a keyboard walkthrough that presses actual Tab/Enter/Space keys
 * and reads back actual focus and actual outline colour.
 *
 * "Accessibility is gating, not aspirational" (#57's brief): every `expect`
 * below fails the job, not just the individual test.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { RUN_ID } from "../support/api-fixtures";
import { installApiMocks } from "../support/mock-routes";
import { walkTabOrder } from "../support/keyboard";
import { VIEWS } from "../support/views";

test.describe("FE-009: axe pass, all six views", () => {
  for (const view of VIEWS) {
    test(`${view.name} has no WCAG 2.1 AA violations`, async ({ page }) => {
      await installApiMocks(page);
      await page.goto(view.path);
      await expect(page).toHaveTitle(view.title);

      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();

      expect(
        results.violations,
        formatViolations(results.violations),
      ).toEqual([]);
    });
  }
});

test.describe("FE-009: keyboard-only walkthrough, all six views", () => {
  for (const view of VIEWS) {
    test(`${view.name}: every interactive element is reachable and shows a visible focus state`, async ({
      page,
    }) => {
      await installApiMocks(page);
      await page.goto(view.path);
      await expect(page).toHaveTitle(view.title);

      const stops = await walkTabOrder(page);

      // A page with no keyboard-reachable content at all is not a page doc
      // 06 §6.4 has been satisfied on — the skip link and the nav rail alone
      // are three stops before any view-specific content.
      expect(stops.length, "no element was reachable by keyboard at all").toBeGreaterThan(0);

      // doc 06 §6.4: "Visible focus states." Checked on every stop, not a
      // sample: a component that forgets the shared `focusRing` utility is
      // exactly the thing this loop exists to catch.
      const invisible = stops.filter((stop) => !stop.outlineVisible);
      expect(
        invisible,
        `${invisible.length} of ${stops.length} keyboard stops painted no visible outline:\n` +
          invisible.map((s) => `  ${s.tag}[role=${s.role}] "${s.accessibleName}"`).join("\n"),
      ).toEqual([]);

      // The first stop on every view is the shell's own skip link — doc 06's
      // App.tsx renders it before the header, and FE-009 is exactly the test
      // that should notice if a view ever intercepted focus ahead of it.
      const first = stops[0];
      expect(first?.accessibleName ?? "").toMatch(/skip to main content/i);
    });
  }

  test("skip link moves focus into the main landmark", async ({ page }) => {
    await installApiMocks(page);
    await page.goto("/");
    await page.keyboard.press("Tab");
    await expect(page.getByText("Skip to main content")).toBeFocused();
    await page.keyboard.press("Enter");
    const main = page.locator("#main");
    await expect(main).toBeFocused();
  });

  test("the nav rail is keyboard-operable and moves between views", async ({ page }) => {
    await installApiMocks(page);
    await page.goto("/");
    const runsLink = page.getByRole("link", { name: "Runs", exact: true });
    await runsLink.focus();
    await expect(runsLink).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/runs$/);
    await expect(page).toHaveTitle("Runs · Innsegl");
  });

  test("the theme toggle is a keyboard-operable radio group", async ({ page }) => {
    await installApiMocks(page);
    await page.goto("/");
    const dark = page.getByRole("radio", { name: "Dark" });
    await dark.focus();
    await page.keyboard.press(" ");
    await expect(dark).toBeChecked();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });

  test("run detail: the verification disclosure opens on Enter and its content is reachable", async ({
    page,
  }) => {
    await installApiMocks(page);
    await page.goto(`/runs/${RUN_ID}`);
    const disclosure = page.getByRole("button", { name: "Verify this commit" });
    await disclosure.focus();
    await expect(disclosure).toHaveAttribute("aria-expanded", "false");
    await page.keyboard.press("Enter");
    await expect(disclosure).toHaveAttribute("aria-expanded", "true");
    // The panel's own heading (doc 06 §4.1) becomes reachable once open —
    // proof the disclosure did not merely toggle a state nobody can see.
    await expect(page.getByRole("heading", { name: "Verification" })).toBeVisible();
  });
});

function formatViolations(violations: readonly import("axe-core").Result[]): string {
  if (violations.length === 0) return "";
  return violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    ${n.target.join(" ")}: ${n.failureSummary ?? ""}`);
      return `${v.id} (${v.impact ?? "unknown"}): ${v.help}\n${nodes.join("\n")}`;
    })
    .join("\n\n");
}
