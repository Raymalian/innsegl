// SPDX-License-Identifier: Apache-2.0

/*
 * FE-128 — doc 07's new row, verbatim:
 *
 *   A | No view overflows sideways with real identifiers in it | Loading each
 *     of the six views in a real browser with full-length values — a whole
 *     SPIFFE ID, a 32-character run id, a 64-character digest — produces no
 *     horizontal page scroll and no element wider than the box holding it,
 *     except where that box declares `overflow-x` for itself |
 *     FD §5.4, P4, §8
 *
 * ── THE FAILURE THIS EXISTS FOR ────────────────────────────────────────────
 *
 * The whole browser suite was green while the verify page was visibly broken.
 * MEASURED in a browser: a Rekor artifact digest ran straight through the card
 * it was in, across the neighbouring one, and the labels beneath it collided
 * with the values above. Nothing caught it, and there were two reasons, both of
 * which this file answers.
 *
 *   The fixtures were short. `run-7f3a2c` fits anywhere, so no committed
 *   baseline had ever rendered an identifier at the width the product actually
 *   issues. web/src/views/run-detail/fixtures.ts now carries full-length
 *   values, which is what makes the assertion below capable of failing.
 *
 *   Nothing measured LAYOUT. contrast, axe and the tri-state baselines between
 *   them check colour, semantics and a fixed set of component renders; not one
 *   of them asks whether the page fits in its own window. doc 06 §5.4 sets a
 *   "fixed max content width for readability" and P4 puts identifiers on every
 *   view — an identifier is the one kind of text with no spaces in it, so it is
 *   the one kind that cannot wrap unless it is told to, and it is therefore the
 *   thing that breaks a layout first.
 *
 * ── WHAT COUNTS AS AN EXCEPTION ────────────────────────────────────────────
 *
 * An element that DECLARES `overflow-x: auto` or `scroll` is scrolling on
 * purpose — the table shell doc 06 §5.4 asks for ("tables full-width within
 * it", scrolling inside their own shell rather than pushing the page sideways),
 * and the `<pre>` that holds an event's canonical members. Those are allowed to
 * be wider than their box, and so is everything inside them. Everything else is
 * not: content wider than the box holding it is content a reader cannot reach.
 */

import { expect, test } from "@playwright/test";

import { installApiMocks } from "../support/mock-routes";
import { VIEWS } from "../support/views";

/** One element whose content is wider than the box it is in. */
interface Overflow {
  readonly selector: string;
  readonly text: string;
  readonly scrollWidth: number;
  readonly clientWidth: number;
}

/**
 * Every element under `root` whose own content overflows it horizontally,
 * skipping any subtree that declares its own horizontal scrolling.
 *
 * SELF-CONTAINED, for the reason browser-scan.ts gives at length: Playwright
 * serializes this function by its own source text, so it may reference nothing
 * from this module's scope.
 */
function scanOverflow(tolerancePx: number): Overflow[] {
  const found: Overflow[] = [];

  const describe = (element: Element): string => {
    const id = element.id === "" ? "" : `#${element.id}`;
    const classes =
      typeof element.className === "string" && element.className !== ""
        ? `.${element.className.trim().split(/\s+/).slice(0, 3).join(".")}`
        : "";
    return `${element.tagName.toLowerCase()}${id}${classes}`;
  };

  const walk = (element: Element): void => {
    const style = getComputedStyle(element);
    // An element with no box cannot overflow anything.
    if (style.display === "none" || style.visibility === "hidden") return;
    // Anything but `visible` means the element has DECLARED what happens to
    // content wider than itself: `auto`/`scroll` for the table shell and the
    // canonical-members block, `hidden`/`clip` for a truncated cell and for
    // every `sr-only` span (a 1x1 clipped box whose content is a whole
    // sentence). The defect this scan is for is the opposite — content
    // escaping a box that never said it could, which is what pushes a
    // neighbouring card sideways.
    if (style.overflowX !== "visible") return;

    if (element.scrollWidth > element.clientWidth + tolerancePx) {
      found.push({
        selector: describe(element),
        text: (element.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 120),
        scrollWidth: element.scrollWidth,
        clientWidth: element.clientWidth,
      });
    }

    for (const child of Array.from(element.children)) walk(child);
  };

  walk(document.body);
  return found;
}

function format(found: readonly Overflow[]): string {
  return found
    .map(
      (o) =>
        `${o.selector} — content ${o.scrollWidth}px in a ${o.clientWidth}px box: "${o.text}"`,
    )
    .join("\n");
}

/* Narrow enough that an unbreakable identifier has nowhere to hide, and a real
 * width a reader uses: a laptop with a browser sidebar open, or a tablet. The
 * default desktop viewport is wide enough to absorb a 64-character digest by
 * accident, which is most of how the original defect survived review. */
const WIDTHS = [
  { name: "desktop", width: 1280, height: 900 },
  { name: "narrow", width: 720, height: 900 },
] as const;

for (const size of WIDTHS) {
  test.describe(`FE-128: nothing overflows sideways at ${size.name} (${size.width}px)`, () => {
    for (const view of VIEWS) {
      test(`${view.name} fits in its own window`, async ({ page }) => {
        await page.setViewportSize({ width: size.width, height: size.height });
        await installApiMocks(page);
        await page.goto(view.path);
        await expect(page).toHaveTitle(view.title);

        if (view.name === "run") {
          // The three-check panel is where the longest values on this page
          // live — the certificate identity and the Rekor entry UUID — and it
          // is behind a disclosure, so a scan of the closed page would miss
          // exactly the elements that broke.
          await page.getByRole("button", { name: "Verify this commit" }).click();
          await expect(page.getByRole("heading", { name: "Verification" })).toBeVisible();
        }

        // The page itself first. A body wider than its window is the defect a
        // reader sees as a horizontal scrollbar under everything.
        const page1 = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          clientWidth: document.documentElement.clientWidth,
        }));
        expect(
          page1.scrollWidth,
          `the page scrolls sideways: ${page1.scrollWidth}px of content in a ${page1.clientWidth}px window`,
        ).toBeLessThanOrEqual(page1.clientWidth + 1);

        // Then every box inside it. `1` rather than `0`: sub-pixel layout
        // rounding puts a 1px difference on elements that are visually exact,
        // and a gate that cried wolf on those would be turned off.
        const found = await page.evaluate(scanOverflow, 1);
        expect(found, format(found)).toEqual([]);
      });
    }
  });
}
