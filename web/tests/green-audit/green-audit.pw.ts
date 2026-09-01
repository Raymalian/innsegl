// SPDX-License-Identifier: Apache-2.0

/*
 * FE-013 — doc 07: "Green audit: scan rendered views for green tokens.
 * Expected: Green appears only on cryptographic-verification states." Proves
 * FD §5.3.
 *
 * doc 06 §5.3: "Green = cryptographic verification passed. Nothing else is
 * ever green." ADR-0038 enforces that structurally in the token sheet — no
 * token may be named for a hue, the verification palette family is reachable
 * only from the `proof-verified` semantic group — but its own Consequences
 * section names the hole on purpose: Tailwind's arbitrary-value syntax,
 * `bg-[#00ff00]`, still compiles, "because it is greppable ... doc 07's
 * FE-013 ... [is] where it gets hunted." Static analysis of the sheet cannot
 * find that hole, because the hole is precisely a colour that never touches
 * the sheet. Only rendered output can — support/browser-scan.ts's
 * `scanGreenLeaks` reads the actual painted `color`, `background-color`,
 * every `border-*-color`, `outline-color`, and SVG `fill`/`stroke` off every
 * element, in a real Chromium, and permits a green only where it is nested
 * under the app's own `data-verdict="verified"` or
 * `data-check-result="verified"` marker (see that file's doc comment for
 * the exact scoping rule and why it matches how VerificationPanel actually
 * marks state).
 */

import { expect, test } from "@playwright/test";

import { scanGreenLeaks } from "../support/browser-scan";
import { RUN_ID } from "../support/api-fixtures";
import { installApiMocks } from "../support/mock-routes";
import { VIEWS } from "../support/views";

function formatLeaks(leaks: readonly ReturnType<typeof scanGreenLeaks>[number][]): string {
  return leaks
    .map(
      (l) =>
        `${l.selector} ${l.property}=${l.value} (hsl ${l.hue}°,${l.saturation}%,${l.lightness}%) nearest marker: ${l.nearestMarker}`,
    )
    .join("\n");
}

test.describe("FE-013: green audit, all six real views", () => {
  for (const view of VIEWS) {
    test(`${view.name}: no green outside a verified state`, async ({ page }) => {
      await installApiMocks(page);
      await page.goto(view.path);
      await expect(page).toHaveTitle(view.title);

      if (view.name === "run") {
        // Open the live verification so a genuine, real (not harness-only)
        // verified panel is on the page for this scan — the scan should
        // find the badge's own green and correctly permit it.
        await page.getByRole("button", { name: "Verify this commit" }).click();
        await expect(page.getByRole("heading", { name: "Verification" })).toBeVisible();
      }

      const leaks = await page.evaluate(scanGreenLeaks, { rootSelector: "body" });
      expect(leaks, formatLeaks(leaks)).toEqual([]);
    });
  }

  test("the run-detail scan is not vacuous: a verified badge is actually on the page while it passes", async ({
    page,
  }) => {
    await installApiMocks(page);
    await page.goto(`/runs/${RUN_ID}`);
    await page.getByRole("button", { name: "Verify this commit" }).click();
    await expect(page.getByRole("heading", { name: "Verification" })).toBeVisible();

    const verifiedBadges = await page.locator('[data-verdict="verified"]').count();
    expect(
      verifiedBadges,
      "no [data-verdict=verified] element rendered — the green-audit pass above would be " +
        "vacuously true rather than actually exercised",
    ).toBeGreaterThan(0);

    // Cross-check scanGreenLeaks's own detection capability against an
    // independent, much smaller read of the same element: the badge's text
    // colour really does measure as green, using nothing scanGreenLeaks
    // itself defines. If this failed while the audit above passed, the audit
    // would be passing by finding nothing rather than by finding the green
    // and correctly permitting it.
    const badgeIsGreen = await page.evaluate(() => {
      const badge = document.querySelector('[data-verdict="verified"]');
      if (badge === null) return false;
      const m = /^rgb\((\d+)[,\s]+(\d+)[,\s]+(\d+)\)$/.exec(getComputedStyle(badge).color);
      if (m === null) return false;
      const [r, g, b] = [Number(m[1]), Number(m[2]), Number(m[3])];
      return g > r && g > b; // green channel dominant — a coarse, independent check
    });
    expect(badgeIsGreen).toBe(true);
  });
});
