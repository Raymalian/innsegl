// SPDX-License-Identifier: Apache-2.0

/*
 * FE-101 (proposed; doc 07 has no id for this — see the PR/issue report) —
 * "Truncated identifiers expose their full value to assistive tech" (doc 06
 * §6.4, §4.3, P4).
 *
 * jsdom can read `aria-hidden`, `sr-only` text and `title` off a component
 * tree, and web/src/components/common/IdentifierChip.test.tsx already does —
 * but it cannot compute an ACCESSIBLE NAME, which is what a screen reader
 * actually announces and is a browser algorithm (the Accessible Name and
 * Description Computation spec), not a DOM read. This suite is the first
 * thing in the repository that asks a real browser what a truncated
 * identifier's accessible name actually is, via Playwright's
 * `getByRole(..., { name })`, which itself resolves ANDC rather than a
 * substring match.
 */

import { expect, test } from "@playwright/test";

const LONG_SPIFFE_ID = "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c9d8e1b4a6f";

test.describe("FE-101: identifier chip — full value reaches assistive technology", () => {
  test("the glyphs on screen are truncated, but the accessible name carries the full value", async ({
    page,
  }) => {
    await page.goto("/tests/harness/index.html?scenario=identifier-chip");

    const glyphs = page.locator("[data-identifier-display]");
    await expect(glyphs).toBeVisible();
    const shown = (await glyphs.textContent()) ?? "";
    expect(shown, "the harness fixture must actually be long enough to truncate").not.toBe(
      LONG_SPIFFE_ID,
    );
    expect(shown).toContain("…");

    // doc 06 §4.3: "middle-truncation preserving trust domain and final
    // segment" — both survive in what a SIGHTED reader sees too.
    expect(shown.startsWith("spiffe://innsegl.dev")).toBe(true);
    expect(shown.endsWith("run-7f3a2c9d8e1b4a6f")).toBe(true);

    // The truncated glyphs are aria-hidden, so a screen reader never receives
    // the abbreviated form at all — asserted directly rather than inferred
    // from the accessible name matching, since an element can carry the
    // right accessible name AND still expose the wrong text to AT if a
    // future edit dropped aria-hidden from the glyph span.
    await expect(glyphs).toHaveAttribute("aria-hidden", "true");

    // The button's accessible name — computed by the browser's own ANDC
    // implementation, not read out of the DOM by this test — must carry the
    // full, untruncated identifier. This is the assertion FE-101 exists for:
    // a screen-reader user hears the whole SPIFFE ID, never the ellipsis.
    const button = page.getByRole("button", { name: new RegExp(escapeRegExp(LONG_SPIFFE_ID)) });
    await expect(button).toBeVisible();
    await expect(button).toHaveCount(1);
  });

  test("the full value is copied to the clipboard, not the truncated glyphs", async ({
    page,
    context,
  }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/tests/harness/index.html?scenario=identifier-chip");
    await page.getByRole("button", { name: new RegExp(escapeRegExp(LONG_SPIFFE_ID)) }).click();
    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboard).toBe(LONG_SPIFFE_ID);
  });

  test("focus (not only hover) reveals the full value in a visible tooltip", async ({ page }) => {
    await page.goto("/tests/harness/index.html?scenario=identifier-chip");
    const button = page.getByRole("button", { name: new RegExp(escapeRegExp(LONG_SPIFFE_ID)) });
    await button.focus();
    const tooltip = page.getByRole("tooltip");
    await expect(tooltip).toBeVisible();
    await expect(tooltip).toHaveText(LONG_SPIFFE_ID);
  });

  test("a narrower chip still exposes the full value, unabbreviated, to assistive tech", async ({
    page,
  }) => {
    await page.goto("/tests/harness/index.html?scenario=identifier-chip-narrow");
    const button = page.getByRole("button", { name: new RegExp(escapeRegExp(LONG_SPIFFE_ID)) });
    await expect(button).toBeVisible();
    const glyphs = page.locator("[data-identifier-display]");
    expect((await glyphs.textContent())?.length ?? 0).toBeLessThan(LONG_SPIFFE_ID.length);
  });
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
