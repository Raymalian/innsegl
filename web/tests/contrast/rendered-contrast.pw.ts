// SPDX-License-Identifier: Apache-2.0

/*
 * FE-091 (proposed; doc 07 has no id for this — see the PR/issue report) —
 * WCAG 2.1 AA contrast, measured from RENDERED output, in both colour-scheme
 * modes, across every composed foreground/background pair a component
 * actually paints. Proves doc 06 §6.4 ("WCAG 2.1 AA contrast in both modes,
 * including semantic colors on their backgrounds") and closes issue #104.
 *
 * ── WHY THIS IS A DIFFERENT TEST FROM check-tokens.sh ───────────────────────
 *
 * `web/src/tokens/contrast-pairs.txt` and `check-tokens.sh` prove that 32
 * DECLARED pairs clear AA in both `light-dark()` arms — static analysis of
 * the token sheet, with no browser and no component involved. Issue #104:
 * "A component may compose ANY token over ANY background, and nothing checks
 * the combination it actually renders." `AlertBanner` proved it: it put
 * `--innsegl-color-accent-text` (defined against the page ground) on
 * `--innsegl-color-integrity-alert-surface` (a red fill) — 1.07:1 in light
 * mode, the evidence link on the product's most important alarm, invisible.
 * The manifest didn't have that pair to check, and jsdom (the other 458
 * component tests) resolves neither `light-dark()` nor inheritance, so
 * nothing rendered the actual cascade to measure it against.
 *
 * That specific composition is fixed on this branch (the link now inherits
 * the banner's own text colour — see web/src/components/common/styles.ts's
 * `linkOnFill`), which is exactly why this suite has to test rendered pixels
 * rather than re-read the source: a fix expressed as "inherit the parent's
 * colour" is invisible to any check that does not resolve inheritance.
 *
 * `support/browser-scan.ts`'s `scanRenderedContrast` is the general version
 * of the check that would have caught the original defect: every element with
 * its own visible text, its `getComputedStyle` foreground against the
 * ancestor-composited background actually behind it, WCAG 2.1 relative
 * luminance, both `prefers-color-scheme` modes.
 */

import { expect, test } from "@playwright/test";

import { scanRenderedContrast } from "../support/browser-scan";
import { RUN_ID } from "../support/api-fixtures";
import { installApiMocks } from "../support/mock-routes";
import { VIEWS } from "../support/views";

const MIN_AREA_PX2 = 4; // excludes the 1x1 sr-only announcer spans

function formatViolations(
  violations: readonly ReturnType<typeof scanRenderedContrast>[number][],
): string {
  return violations
    .map(
      (v) =>
        `${v.selector} "${v.text}" — ${v.foreground} on ${v.background} = ${v.ratio}:1 ` +
        `(needs ${v.required}:1, ${v.fontSizePx}px/${v.fontWeight})`,
    )
    .join("\n");
}

const HARNESS_SCENARIOS = [
  "panel-verified",
  "panel-failed",
  "panel-unavailable",
  "panel-mismatch",
  // The exact scenario issue #104 was found in: the evidence link on the
  // integrity banner's red fill.
  "alert-integrity",
  "alert-degraded",
  "alert-both",
  "identifier-chip",
  "identifier-chip-narrow",
] as const;

for (const mode of ["light", "dark"] as const) {
  test.describe(`FE-091: rendered contrast, all six views (${mode})`, () => {
    test.use({ colorScheme: mode });

    for (const view of VIEWS) {
      test(`${view.name}: every rendered text pair clears WCAG 2.1 AA`, async ({ page }) => {
        await installApiMocks(page);
        await page.goto(view.path);
        await expect(page).toHaveTitle(view.title);

        if (view.name === "run") {
          await page.getByRole("button", { name: "Verify this commit" }).click();
          await expect(page.getByRole("heading", { name: "Verification" })).toBeVisible();
        }

        const violations = await page.evaluate(scanRenderedContrast, {
          rootSelector: "body",
          minAreaPx2: MIN_AREA_PX2,
        });
        expect(violations, formatViolations(violations)).toEqual([]);
      });
    }
  });

  test.describe(`FE-091: rendered contrast, component scenarios (${mode})`, () => {
    test.use({ colorScheme: mode });

    for (const scenario of HARNESS_SCENARIOS) {
      test(`${scenario}: every rendered text pair clears WCAG 2.1 AA`, async ({ page }) => {
        await page.goto(`/tests/harness/index.html?scenario=${scenario}`);
        await expect(page.locator("[data-harness-unknown]")).toHaveCount(0);

        const violations = await page.evaluate(scanRenderedContrast, {
          rootSelector: "[data-harness-root]",
          minAreaPx2: MIN_AREA_PX2,
        });
        expect(violations, formatViolations(violations)).toEqual([]);
      });
    }
  });
}

test.describe("FE-091: the issue #104 regression, held explicitly", () => {
  test("the alert banner's evidence link measures at least 4.5:1 against the integrity fill, in both modes", async ({
    page,
  }) => {
    for (const mode of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: mode });
      await page.goto("/tests/harness/index.html?scenario=alert-integrity");
      const link = page.getByRole("link", { name: "View evidence" });
      await expect(link).toBeVisible();

      const [fg, bg] = await link.evaluate((el) => {
        const cs = getComputedStyle(el);
        let bgEl: Element | null = el;
        let bg = "";
        while (bgEl !== null) {
          const c = getComputedStyle(bgEl).backgroundColor;
          if (c !== "rgba(0, 0, 0, 0)" && c !== "transparent") {
            bg = c;
            break;
          }
          bgEl = bgEl.parentElement;
        }
        return [cs.color, bg];
      });

      const ratio = contrastOf(fg, bg);
      expect(ratio, `${mode} mode: ${fg} on ${bg} = ${ratio}:1`).toBeGreaterThanOrEqual(4.5);
    }
  });
});

function contrastOf(fgCss: string, bgCss: string): number {
  function parse(v: string): [number, number, number] {
    const m = /rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/.exec(v);
    if (m === null) throw new Error(`cannot parse colour: ${v}`);
    return [Number(m[1]), Number(m[2]), Number(m[3])];
  }
  function channel(c: number): number {
    const x = c / 255;
    return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
  }
  function luminance([r, g, b]: [number, number, number]): number {
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  }
  const la = luminance(parse(fgCss));
  const lb = luminance(parse(bgCss));
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
}

// The commit SHA fixture views/run-detail exposes, kept referenced so a
// future scenario addition here can open the run-detail live panel the same
// way green-audit.spec.ts does, without re-deriving the id.
void RUN_ID;
