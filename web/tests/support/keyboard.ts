// SPDX-License-Identifier: Apache-2.0

/*
 * The keyboard-only walkthrough FE-009 needs — doc 06 §6.4: "Full keyboard
 * operability: tables, filters, copy actions, expandable panels. Visible
 * focus states."
 *
 * Unlike browser-scan.ts, these helpers run entirely on the Node side of the
 * Playwright/browser boundary: each step is its own `page.keyboard.press`
 * and `page.evaluate` round trip, so there is no reason to make them
 * self-contained the way a single `page.evaluate` callback has to be.
 */

import type { Page } from "@playwright/test";

export interface FocusStop {
  readonly tag: string;
  readonly role: string;
  readonly accessibleName: string;
  /** Whether the element the browser just focused paints a visible outline —
   * doc 06 §6.4's "Visible focus states", read off the real cascade rather
   * than assumed from the `:focus-visible` rule in index.css existing. */
  readonly outlineVisible: boolean;
}

async function describeActiveElement(page: Page): Promise<FocusStop | null> {
  return page.evaluate(() => {
    const el = document.activeElement;
    if (el === null || el === document.body) return null;
    const cs = getComputedStyle(el);
    const outlineVisible =
      cs.outlineStyle !== "none" &&
      cs.outlineWidth !== "0px" &&
      Number.parseFloat(cs.outlineWidth) > 0;
    // A minimal, dependency-free accessible-name approximation: aria-label,
    // then the element's own text, then its value/placeholder. Good enough to
    // tell two focus stops apart in a failure message; the real accessible-
    // name computation is axe's job (FE-009's other half) and Playwright's
    // getByRole locators, not this diagnostic.
    const name =
      el.getAttribute("aria-label") ??
      (el.textContent ?? "").trim().slice(0, 60) ??
      (el as HTMLInputElement).value ??
      "";
    return {
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute("role") ?? el.tagName.toLowerCase(),
      accessibleName: name,
      outlineVisible,
    };
  });
}

/**
 * Press Tab up to `maxPresses` times from wherever focus currently is (a
 * fresh navigation starts with no element focused, which is where every call
 * site below begins), recording each stop. Stops early if focus leaves the
 * document (a keyboard user would have tabbed into browser chrome) or
 * revisits the very first stop (the tab order has cycled — a real end, not a
 * trap, PROVIDED it took more than one press to get there; cycling back on
 * press one is the actual trap and is left in the result for the caller to
 * see).
 */
export async function walkTabOrder(page: Page, maxPresses = 80): Promise<FocusStop[]> {
  const stops: FocusStop[] = [];
  let first: FocusStop | null = null;
  for (let i = 0; i < maxPresses; i++) {
    await page.keyboard.press("Tab");
    const stop = await describeActiveElement(page);
    if (stop === null) break; // focus left the document
    if (first === null) {
      first = stop;
    } else if (
      i > 0 &&
      stop.tag === first.tag &&
      stop.accessibleName === first.accessibleName &&
      stop.role === first.role
    ) {
      break; // cycled back to the start of the tab order
    }
    stops.push(stop);
  }
  return stops;
}
