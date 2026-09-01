// SPDX-License-Identifier: Apache-2.0

/*
 * FE-001 — doc 07: "Visual regression: three-check panel in verified / failed
 * / unavailable. Expected: Three distinct renders (color+icon+label);
 * snapshots committed." Proves FD P2, §4.1.
 *
 * #57's brief adds the alert banner to this test's scope ("Visual regression
 * snapshots for verified, failed and verification-unavailable, plus the alert
 * banner"), and doc 06 §7 names both explicitly: "visual regression tests for
 * verified/failed/unavailable and the alert banner."
 *
 * Every scenario renders through web/tests/harness — the real components
 * (VerificationPanel, AlertBanner), the real compiled tailwind-theme.css, in
 * a real Chromium, so `light-dark()` and every cascade rule actually resolve
 * (issue #104's whole point). Nothing here is a jsdom class-name assertion.
 *
 * ── THE HAZARD THIS SUITE IS WRITTEN AGAINST ────────────────────────────────
 *
 * A prior agent in this project proved two states differed by stripping
 * `class` and `style` from markup while leaving a `data-*` attribute in
 * place, which made the assertion unfalsifiable. A snapshot suite has the
 * same hazard in a worse form: a screenshot that has never been observed to
 * fail proves nothing about what it would catch. The PR/commit history for
 * this change records three deliberate-break runs — one per tri-state — each
 * mutating the harness fixture to render the WRONG state and confirming
 * `toHaveScreenshot` actually fails before the mutation is reverted. See the
 * issue report for the exact commands and their output.
 */

import { expect, test } from "@playwright/test";

const SCENARIOS = [
  { name: "panel-verified", label: "three-check panel: verified" },
  { name: "panel-failed", label: "three-check panel: failed" },
  { name: "panel-unavailable", label: "three-check panel: verification unavailable" },
  { name: "panel-mismatch", label: "three-check panel: forged-trailer mismatch (FE-004 fixture)" },
  { name: "alert-integrity", label: "alert banner: integrity (chain verification failed)" },
  { name: "alert-degraded", label: "alert banner: degraded (anchoring lag)" },
] as const;

for (const mode of ["light", "dark"] as const) {
  test.describe(`FE-001: tri-state and alert-banner snapshots (${mode})`, () => {
    test.use({ colorScheme: mode });

    for (const scenario of SCENARIOS) {
      test(scenario.label, async ({ page }) => {
        await page.goto(`/tests/harness/index.html?scenario=${scenario.name}`);
        // The harness renders exactly one scenario; wait for it rather than
        // for a fixed delay, so a slow first paint cannot pass a suite that
        // was actually racing.
        await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);
        await expect(page.locator("[data-harness-root] > *")).toBeVisible();
        await expect(page).toHaveScreenshot(`${scenario.name}-${mode}.png`, {
          // The full harness body, not the viewport: a panel taller than the
          // viewport must not silently crop out of the comparison.
          fullPage: true,
        });
      });
    }
  });
}

test.describe("FE-001: the three tri-states are visually distinct from one another", () => {
  // The catalogue's own wording: "Three distinct renders." A trio of
  // snapshots that all happen to look identical would still pass a
  // per-scenario `toHaveScreenshot` on its first run — this test is the one
  // that actually enforces "distinct" as a same-run comparison, not merely
  // "matches its own committed baseline".
  test("verified, failed and unavailable render three different screenshots", async ({
    page,
  }) => {
    const shots: Buffer[] = [];
    for (const scenario of ["panel-verified", "panel-failed", "panel-unavailable"] as const) {
      await page.goto(`/tests/harness/index.html?scenario=${scenario}`);
      await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);
      shots.push(await page.screenshot({ fullPage: true }));
    }
    const [verified, failed, unavailable] = shots;
    expect(verified?.equals(failed ?? Buffer.alloc(0))).toBe(false);
    expect(verified?.equals(unavailable ?? Buffer.alloc(0))).toBe(false);
    expect(failed?.equals(unavailable ?? Buffer.alloc(0))).toBe(false);
  });
});
