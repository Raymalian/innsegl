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
import { describeStop, walkTabOrder } from "../support/keyboard";
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

      // doc 06 §6.4: "Visible focus states." Checked on every stop the app can
      // actually style, not a sample: a component that forgets the shared
      // `focusRing` utility is exactly the thing this loop exists to catch.
      //
      // `uaShadow` stops are excluded and are NOT waved through — the focused
      // node is inside a built-in control's user-agent shadow tree, where no
      // author rule can reach and `document.activeElement` has retargeted to
      // the host (see support/keyboard.ts's header for the measured trace).
      // FE-107 below measures that the browser paints its own indication
      // there, so the exclusion rests on a measurement rather than on this
      // comment. `support/keyboard.ts` will only classify a built-in control
      // this way, so a component cannot buy the exemption by growing a
      // shadow root.
      const authorStyleable = stops.filter((stop) => stop.kind === "element");
      const invisible = authorStyleable.filter((stop) => !stop.outlineVisible);
      expect(
        invisible.map(describeStop),
        `${invisible.length} of ${authorStyleable.length} author-styleable keyboard stops ` +
          `painted no visible outline`,
      ).toEqual([]);

      // A view where every stop was classed `uaShadow` would pass the line
      // above by asserting nothing at all.
      expect(
        authorStyleable.length,
        `every keyboard stop on this view was classified uaShadow, so the focus-ring ` +
          `assertion above checked nothing: ${stops.map(describeStop).join(", ")}`,
      ).toBeGreaterThan(0);

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

/*
 * FE-107 (proposed; doc 07 has no id for this — see the report for #57).
 *
 * The one keyboard stop on the six views that the app cannot paint a focus
 * ring on, held to a measurement instead of to an exemption.
 *
 * The runs view's `from`/`to` filters are `<input type="date">`. Tabbing
 * through one produces four stops in Chromium: three date segments, on which
 * the host input really is `:focus` and index.css's rule paints the app's own
 * 2px ring, and then the calendar-picker indicator — a focusable node inside
 * Chromium's own UA shadow tree. `document.activeElement` retargets to the
 * host (as it is specified to), but the host matches only `:focus-within`, so
 * no author rule matches it and the page cannot reach the indicator either.
 *
 * The first version of this suite read `document.activeElement` alone and
 * reported those two stops as painting no focus ring, which read as a product
 * defect. It is not one — but "it is not one" is exactly the sentence that
 * should not be taken on trust, so this test measures both halves: that the
 * segments carry the app's ring, and that the stop the app cannot style is
 * visibly different from the same control unfocused, i.e. that the browser
 * really does indicate it. If a future Chromium stopped indicating it, this
 * goes red and the finding becomes a real accessibility defect to report.
 */
test.describe("FE-107: the date filter's UA-shadow focus stop, measured", () => {
  const FIELD = "#runs-filter-from";

  test("the three date segments carry the app's own focus ring", async ({ page }) => {
    await installApiMocks(page);
    await page.goto("/runs");
    await expect(page).toHaveTitle("Runs · Innsegl");
    await page.locator(FIELD).focus();

    for (let segment = 0; segment < 3; segment++) {
      const state = await page.locator(FIELD).evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          focus: el.matches(":focus"),
          focusVisible: el.matches(":focus-visible"),
          outline: `${cs.outlineStyle} ${cs.outlineWidth}`,
        };
      });
      expect(state.focus, `segment ${segment}: the host input is not :focus`).toBe(true);
      expect(state.focusVisible, `segment ${segment}: not :focus-visible`).toBe(true);
      expect(state.outline, `segment ${segment}: no ring`).toBe("solid 2px");
      await page.keyboard.press("Tab");
    }
  });

  test("the calendar-picker stop is a UA shadow node, and the browser indicates it", async ({
    page,
  }) => {
    await installApiMocks(page);
    await page.goto("/runs");
    await expect(page).toHaveTitle("Runs · Innsegl");
    const field = page.locator(FIELD);

    // State A: the control, unfocused. The baseline this comparison is
    // against — taken first so nothing about the later focus can leak into it.
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    const unfocused = await field.screenshot();

    // State B: four Tab presses from the field's start — past the three date
    // segments and onto the picker indicator.
    await field.focus();
    for (let i = 0; i < 3; i++) await page.keyboard.press("Tab");

    const state = await field.evaluate((el) => ({
      isActiveElement: document.activeElement === el,
      focus: el.matches(":focus"),
      focusWithin: el.matches(":focus-within"),
      outlineStyle: getComputedStyle(el).outlineStyle,
      hasAuthorShadowRoot: el.shadowRoot !== null,
    }));

    // The exact situation support/keyboard.ts classifies as `uaShadow`. If any
    // of these stopped holding, the classification would be resting on a
    // browser behaviour that no longer exists.
    expect(state.isActiveElement, "document.activeElement is no longer the date input").toBe(true);
    expect(state.focus, "the host matched :focus — this is not a UA-shadow stop at all").toBe(
      false,
    );
    expect(state.focusWithin, "the host is not even :focus-within").toBe(true);
    expect(state.hasAuthorShadowRoot, "the shadow root is author-open, so the app CAN style it").toBe(
      false,
    );
    expect(state.outlineStyle, "the app's ring is painted after all").toBe("none");

    const pickerFocused = await field.screenshot();
    expect(
      pickerFocused.equals(unfocused),
      "the date input renders identically whether or not its calendar-picker indicator holds " +
        "focus — the browser paints no focus indication there and the page cannot paint one, " +
        "so this IS an accessibility defect (doc 06 §6.4, 'Visible focus states') and the " +
        "uaShadow exemption in support/keyboard.ts must not stand",
    ).toBe(false);
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
