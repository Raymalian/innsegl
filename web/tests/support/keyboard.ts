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
 *
 * ── WHY A FOCUS STOP IS NOT SIMPLY `document.activeElement` (FE-107) ────────
 *
 * The first version of this file assumed the two were the same thing and
 * asserted a visible outline on whatever `document.activeElement` returned.
 * That reported the runs view's two `<input type="date">` filters as painting
 * no focus ring, which looked like a product defect and is not one. Measured
 * in the shipped Chromium, tabbing from the start of one date filter:
 *
 *   press 0  activeElement=runs-filter-from  :focus=true   outline solid 2px
 *   press 1  activeElement=runs-filter-from  :focus=true   outline solid 2px
 *   press 2  activeElement=runs-filter-from  :focus=true   outline solid 2px
 *   press 3  activeElement=runs-filter-from  :focus=FALSE  outline none
 *            :focus-within=true
 *   press 4  activeElement=runs-filter-to    :focus=true   outline solid 2px
 *
 * Presses 0–2 are the day/month/year segments: the host input really is the
 * focused element, `:focus-visible` matches, and index.css's one focus rule
 * paints the app's own 2px ring. Press 3 is the calendar-picker indicator,
 * which is a separate focusable node inside Chromium's own UA shadow tree.
 * `document.activeElement` retargets to the host (that is what it is
 * specified to do for a node in a shadow tree), but the host is only
 * `:focus-within`, not `:focus` — so no author rule can match it, and no
 * author rule can reach the indicator either, because a page cannot style
 * another origin's UA shadow tree.
 *
 * So the assertion, not the product, was wrong: it read a focus state off an
 * element that was not focused. `describeActiveElement` now distinguishes the
 * two cases, and `views.pw.ts` asserts the app's ring on every stop the app
 * can actually style while measuring — not assuming — that the UA paints its
 * own indication on the stop it cannot (FE-107). An exemption nobody measures
 * is how a real defect gets waved through, which is the failure mode this
 * whole issue exists to close.
 */

import type { Page } from "@playwright/test";

/**
 * `element` — the focused node is the element itself; author CSS applies and
 * a visible focus ring is this project's own responsibility (doc 06 §6.4).
 *
 * `uaShadow` — the focused node lives inside a **user-agent** shadow tree of a
 * built-in control, and `document.activeElement` has retargeted to its host.
 * No author rule can match the focused node or the host's `:focus`. The
 * project cannot paint this ring and the browser must; FE-107 measures that
 * it does rather than taking it on trust.
 */
export type FocusStopKind = "element" | "uaShadow";

export interface FocusStop {
  readonly tag: string;
  /** `type` for an `<input>`, otherwise the empty string — the single most
   * useful field for telling two otherwise identical focus stops apart. */
  readonly type: string;
  readonly id: string;
  readonly role: string;
  readonly accessibleName: string;
  readonly kind: FocusStopKind;
  /** Whether the element the browser focused paints a visible outline —
   * doc 06 §6.4's "Visible focus states", read off the real cascade rather
   * than assumed from the `:focus-visible` rule in index.css existing. */
  readonly outlineVisible: boolean;
}

/**
 * Describe whatever currently holds focus, or null if nothing in the document
 * does.
 *
 * SELF-CONTAINED: the callback is serialized by `Function.toString()` and
 * re-evaluated in the browser, so it may reference nothing from this module.
 */
async function describeActiveElement(page: Page): Promise<FocusStop | null> {
  return page.evaluate(() => {
    const el = document.activeElement;
    if (el === null || el === document.body) return null;

    /* The built-in controls that own a UA shadow tree with its own focusable
     * parts. A custom element's name always contains a hyphen, so this list
     * cannot be widened by authoring one; and an element with an OPEN shadow
     * root is one whose author can style its inside, so it is deliberately
     * not here either — it gets the ordinary assertion and fails if it has no
     * ring. The exemption is for what the page provably cannot reach. */
    const UA_SHADOW_HOSTS: Record<string, readonly string[] | "*" | undefined> = {
      input: ["date", "time", "datetime-local", "month", "week", "color", "file", "range"],
      video: "*",
      audio: "*",
    };

    const tag = el.tagName.toLowerCase();
    const type = el instanceof HTMLInputElement ? el.type : "";

    const focused = el.matches(":focus");
    const focusWithin = el.matches(":focus-within");
    const allowedTypes = UA_SHADOW_HOSTS[tag];
    const isUaShadowHost =
      !tag.includes("-") &&
      el.shadowRoot === null && // an open (author) shadow root is the author's to style
      allowedTypes !== undefined &&
      (allowedTypes === "*" || allowedTypes.includes(type));

    const kind: "element" | "uaShadow" =
      !focused && focusWithin && isUaShadowHost ? "uaShadow" : "element";

    const cs = getComputedStyle(el);
    const outlineVisible =
      cs.outlineStyle !== "none" &&
      cs.outlineWidth !== "0px" &&
      Number.parseFloat(cs.outlineWidth) > 0;

    /* A minimal, dependency-free accessible-name approximation, good enough to
     * tell two focus stops apart in a failure message. The real accessible-
     * name computation is axe's job (FE-009's other half) and Playwright's
     * getByRole locators, not this diagnostic — but a stop reported with an
     * empty name is a failure message nobody can act on, which is what the
     * first version produced for every `<input>` on the runs view. */
    const labelledBy = el.getAttribute("aria-labelledby");
    const candidates: string[] = [
      el.getAttribute("aria-label") ?? "",
      labelledBy === null ? "" : (document.getElementById(labelledBy)?.textContent ?? ""),
      el.id === ""
        ? ""
        : (document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent ?? ""),
      el.textContent ?? "",
      el instanceof HTMLInputElement ? el.placeholder : "",
      el instanceof HTMLInputElement ? el.value : "",
    ];
    const name = (candidates.find((c) => c.trim() !== "") ?? "").trim().slice(0, 60);

    return {
      tag,
      type,
      id: el.id,
      role: el.getAttribute("role") ?? tag,
      accessibleName: name,
      kind,
      outlineVisible,
    };
  });
}

/** One line of diagnostics for a failure message. */
export function describeStop(stop: FocusStop): string {
  const type = stop.type === "" ? "" : `[type=${stop.type}]`;
  const id = stop.id === "" ? "" : `#${stop.id}`;
  return `${stop.tag}${type}${id} [role=${stop.role}] "${stop.accessibleName}" (${stop.kind})`;
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
      stop.id === first.id &&
      stop.accessibleName === first.accessibleName &&
      stop.role === first.role
    ) {
      break; // cycled back to the start of the tab order
    }
    stops.push(stop);
  }
  return stops;
}
