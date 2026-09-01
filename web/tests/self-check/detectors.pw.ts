// SPDX-License-Identifier: Apache-2.0

/*
 * FE-102 … FE-105 (proposed; doc 07 has no id for these — see the report for
 * #57) — the negative controls for every gate in this directory.
 *
 * ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
 *
 * Every other spec here asserts that something is absent: no axe violation, no
 * contrast pair below AA, no green outside a verified state, no focus stop
 * without a ring. An assertion of absence passes trivially if the detector
 * behind it is broken, mis-scoped, or looking at an empty page — and it passes
 * *quietly*, which is worse. This project has already shipped one assertion
 * that could not fail: a test that proved two states differed by stripping
 * `class` and `style` from markup while leaving a `data-*` attribute in place.
 * It was caught by mutation, not by review.
 *
 * So each detector is pointed at a deliberately defective scenario
 * (`harness/Harness.tsx`'s `PROBES`) and required to report the planted
 * defect. If a refactor ever makes a scan blind, these go red on the same
 * commit rather than the gating specs going quietly, permanently green.
 *
 * The one gate this file cannot cover is the committed screenshot baseline:
 * a negative control for `toHaveScreenshot` would be a second committed
 * baseline that must not match, which is a snapshot of a snapshot. That gate
 * is proved by deliberate mutation instead — three tri-states mutated to
 * render the wrong state, each observed failing, each reverted; the runs are
 * quoted in the issue report — and by FE-106 in visual/tri-state.pw.ts, which
 * holds the two properties a mutation run cannot leave behind: that the three
 * states differ from one another, and that each differs between light and
 * dark (so a `colorScheme` option that silently stopped applying could not
 * leave twelve baselines quietly passing as six).
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { PROBE_NAMES, SCENARIO_NAMES } from "../harness/Harness";
import { scanGreenLeaks, scanRenderedContrast } from "../support/browser-scan";
import { walkTabOrder } from "../support/keyboard";

const MIN_AREA_PX2 = 4; // the same threshold the gating contrast scan uses

test.describe("the probe scenarios are quarantined from every gating run", () => {
  test("no probe name is also a real scenario name", () => {
    const overlap = PROBE_NAMES.filter((name) => SCENARIO_NAMES.includes(name));
    expect(overlap, `probe scenarios leaked into the gated registry: ${overlap.join(", ")}`).toEqual(
      [],
    );
    // Every probe is prefixed, so a gated list can be grepped for one.
    expect(PROBE_NAMES.filter((n) => !n.startsWith("probe-"))).toEqual([]);
    expect(SCENARIO_NAMES.filter((n) => n.startsWith("probe-"))).toEqual([]);
    // A registry that emptied itself would make every test below vacuous.
    expect(PROBE_NAMES.length).toBeGreaterThan(0);
  });
});

test.describe("FE-102: the rendered-contrast scan refuses the issue #104 composition", () => {
  test.use({ colorScheme: "light" });

  test("accent text on the integrity fill is reported, at the ratio #104 measured", async ({
    page,
  }) => {
    await page.goto("/tests/harness/index.html?scenario=probe-issue-104");
    await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);
    await expect(page.locator("[data-probe-target]")).toBeVisible();

    const violations = await page.evaluate(scanRenderedContrast, {
      rootSelector: "[data-harness-root]",
      minAreaPx2: MIN_AREA_PX2,
    });

    expect(
      violations.length,
      "the scan found nothing on a scenario built from the exact composition issue #104 " +
        "measured at 1.07:1 — the detector, not the page, is what failed here",
    ).toBeGreaterThan(0);

    const link = violations.find((v) => v.text === "View evidence");
    expect(link, `no violation reported for the evidence link; got: ${JSON.stringify(violations)}`)
      .toBeDefined();
    // #104 measured 1.07:1 for #3a3ea1 on #9b1921. Asserting a band rather
    // than the exact number keeps this honest if the palette is ever
    // re-toned: what must not change is that the scan calls it a failure and
    // reports a ratio nowhere near the 4.5 floor.
    expect(link?.ratio ?? 0).toBeLessThan(2);
    expect(link?.required).toBe(4.5);
  });
});

test.describe("FE-103: the green audit refuses a green outside a verified state", () => {
  test("both planted greens are reported", async ({ page }) => {
    await page.goto("/tests/harness/index.html?scenario=probe-green-leak");
    await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);

    // Precondition, measured rather than assumed: the two probe elements
    // really do paint a green. If a future edit neutered the probe, this says
    // so instead of letting the leak assertion below pass for the wrong
    // reason — an empty page has no leaks either.
    const painted = await page.evaluate(() =>
      Array.from(document.querySelectorAll("[data-probe-target]")).map((el) => ({
        target: el.getAttribute("data-probe-target"),
        background: getComputedStyle(el).backgroundColor,
      })),
    );
    expect(painted).toEqual([
      { target: "saturated", background: "rgb(0, 255, 0)" },
      { target: "palette-adjacent", background: "rgb(18, 183, 106)" },
    ]);

    const leaks = await page.evaluate(scanGreenLeaks, {
      rootSelector: "[data-harness-root]",
    });

    const reported = leaks
      .filter((l) => l.property === "backgroundColor")
      .map((l) => l.value)
      .sort();
    expect(
      reported,
      `scanGreenLeaks did not report both planted greens; it returned: ${JSON.stringify(leaks)}`,
    ).toEqual(["rgb(0, 255, 0)", "rgb(18, 183, 106)"]);

    // Neither has a verification marker anywhere above it, which is what
    // makes them illegal rather than merely green.
    for (const leak of leaks) {
      expect(leak.nearestMarker).toBe("(none)");
    }
  });

  test("the permission is scoped to the marker, not to the page", async ({ page }) => {
    // The complement of the test above, and the one that would catch a scan
    // that permitted any green anywhere once a verified badge existed
    // somewhere on the page. `panel-verified` renders a real verified panel;
    // a green planted OUTSIDE it must still be reported.
    await page.goto("/tests/harness/index.html?scenario=panel-verified");
    await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);

    const before = await page.evaluate(scanGreenLeaks, { rootSelector: "[data-harness-root]" });
    expect(before, `the real verified panel leaked green: ${JSON.stringify(before)}`).toEqual([]);

    await page.evaluate(() => {
      const root = document.querySelector("[data-harness-root]");
      const p = document.createElement("p");
      p.textContent = "planted outside the verified panel";
      p.style.color = "#12b76a";
      root?.appendChild(p);
    });

    const after = await page.evaluate(scanGreenLeaks, { rootSelector: "[data-harness-root]" });
    // `color` cascades into `border-*-color` and `outline-color` through
    // `currentColor`, so one planted declaration is correctly reported on
    // several properties of the same element. What matters is that the
    // element was reported at all, that every report names the planted value,
    // and that the scan found no marker above it.
    expect(
      after.map((l) => l.property),
      "a green planted as a SIBLING of a verified panel was permitted — the scan is " +
        "scoping its permission to the page rather than to the nearest marker",
    ).toContain("color");
    expect(new Set(after.map((l) => l.value))).toEqual(new Set(["rgb(18, 183, 106)"]));
    expect(new Set(after.map((l) => l.nearestMarker))).toEqual(new Set(["(none)"]));
  });
});

test.describe("FE-104: the axe gate refuses a page with a WCAG violation", () => {
  test("image-alt and label are both reported by the same tag set the six views use", async ({
    page,
  }) => {
    await page.goto("/tests/harness/index.html?scenario=probe-axe-violation");
    await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();

    const ids = results.violations.map((v) => v.id).sort();
    expect(
      ids,
      "axe reported no violation on a page carrying an unlabelled image and an unlabelled " +
        "input — the gate in a11y/views.pw.ts would pass anything",
    ).toEqual(expect.arrayContaining(["image-alt", "label"]));
  });
});

test.describe("FE-105: the keyboard walkthrough refuses a suppressed focus ring", () => {
  test("a control with inline outline:none is reported as painting no visible outline", async ({
    page,
  }) => {
    await page.goto("/tests/harness/index.html?scenario=probe-focus-suppressed");
    await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);

    const stops = await walkTabOrder(page, 6);
    const probe = stops.filter((s) => s.tag === "button");
    expect(probe.length, `the probe button was never reached: ${JSON.stringify(stops)}`).toBe(1);
    expect(
      probe[0]?.outlineVisible,
      "walkTabOrder reported a visible outline on a button whose inline style sets " +
        "outline:none — the focus-ring half of FE-009 cannot fail",
    ).toBe(false);
    expect(probe[0]?.kind).toBe("element");
  });
});
