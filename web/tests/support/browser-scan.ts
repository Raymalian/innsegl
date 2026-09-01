// SPDX-License-Identifier: Apache-2.0

/*
 * The two scans this issue exists to run — RM-049 (#57), and issue #104's
 * "extract pairs from rendered output" recommendation.
 *
 * Both functions below are passed straight to Playwright's `page.evaluate`,
 * which serializes a function by its OWN source text (`Function.toString()`)
 * and re-evaluates it inside the browser. That has one hard consequence for
 * how this file has to be written: a function handed to `page.evaluate` may
 * reference NOTHING from this module's outer scope — no imported helper, no
 * shared constant — because none of that travels with the serialized text.
 * Every helper both scans need is therefore declared INSIDE the function
 * itself. It reads as more repetition than a normal module would tolerate;
 * that repetition is the price of the function being real, checkable browser
 * code rather than a description of one.
 *
 * ── WHY THIS EXISTS AT ALL (issue #104) ─────────────────────────────────────
 *
 * `web/src/tokens/contrast-pairs.txt` asserts a fixed list of token pairs, and
 * `check-tokens.sh` proves each one holds in both `light-dark()` arms. Both of
 * those are static analysis of the SHEET — they prove a pair is readable if a
 * component ever composes it, never that a component didn't compose a
 * DIFFERENT, unlisted pair. `AlertBanner` did exactly that: it put the accent
 * (defined against the page ground) on the integrity banner's red fill and
 * measured 1.07:1, and neither the manifest nor the 458-test component suite
 * caught it, because jsdom resolves neither `light-dark()` nor inheritance.
 *
 * `scanRenderedContrast` is the fix: it reads `getComputedStyle` off the
 * elements a real Chromium actually painted, walks each element's ancestor
 * chain to find the background that is actually behind it (compositing, in
 * case of a translucent layer), and applies the same WCAG 2.1 relative-
 * luminance formula `check-tokens.sh` uses. It does not know or care what
 * token produced a colour — it measures the pixel, which is what a reader
 * sees and what doc 06 §6.4 requires ("WCAG 2.1 AA contrast in both modes").
 */

/** One text-bearing element whose foreground/background pair fails AA. */
export interface ContrastViolation {
  readonly selector: string;
  readonly text: string;
  readonly foreground: string;
  readonly background: string;
  readonly ratio: number;
  readonly required: number;
  readonly fontSizePx: number;
  readonly fontWeight: number;
}

export interface ContrastScanOptions {
  readonly rootSelector: string;
  readonly minAreaPx2: number;
}

/**
 * Walk every element under `rootSelector` that carries its own visible text
 * and report every one whose resolved foreground/background pair fails WCAG
 * 2.1 AA. SELF-CONTAINED — see the file comment. `options` is the only thing
 * that crosses the `page.evaluate` boundary as data; everything else is
 * declared inside. It is a single object, not two positional arguments,
 * because `page.evaluate(fn, arg)` passes exactly one `arg` — a wrapping
 * arrow function to destructure a tuple would itself have to reference `fn`
 * from outer scope, which is exactly what a serialized function may not do.
 */
export function scanRenderedContrast(options: ContrastScanOptions): ContrastViolation[] {
  const { rootSelector, minAreaPx2 } = options;
  function parseColor(value: string): { r: number; g: number; b: number; a: number } | null {
    // getComputedStyle always answers in one of these two forms in Chromium;
    // no other browser is in scope for this harness (playwright.config.ts).
    const rgb = /^rgb\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)\s*\)$/.exec(value);
    if (rgb) {
      return { r: Number(rgb[1]), g: Number(rgb[2]), b: Number(rgb[3]), a: 1 };
    }
    const rgba = /^rgba\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)\s*\)$/.exec(value);
    if (rgba) {
      return {
        r: Number(rgba[1]),
        g: Number(rgba[2]),
        b: Number(rgba[3]),
        a: Number(rgba[4]),
      };
    }
    return null;
  }

  /** The colour actually painted behind `el`: composite every ancestor's own
   * background, root to leaf, over a white canvas (a browser's own default),
   * so a translucent layer blends rather than masks what is under it. */
  function effectiveBackground(el: Element): { r: number; g: number; b: number } {
    const chain: Element[] = [];
    for (let node: Element | null = el; node !== null; node = node.parentElement) {
      chain.push(node);
    }
    let r = 255;
    let g = 255;
    let b = 255;
    for (let i = chain.length - 1; i >= 0; i--) {
      const layer = chain[i];
      if (layer === undefined) continue;
      const bg = parseColor(getComputedStyle(layer).backgroundColor);
      if (bg !== null && bg.a > 0) {
        r = bg.r * bg.a + r * (1 - bg.a);
        g = bg.g * bg.a + g * (1 - bg.a);
        b = bg.b * bg.a + b * (1 - bg.a);
      }
    }
    return { r, g, b };
  }

  function channel(c: number): number {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  }

  function luminance(c: { r: number; g: number; b: number }): number {
    return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
  }

  function contrast(
    a: { r: number; g: number; b: number },
    b: { r: number; g: number; b: number },
  ): number {
    const la = luminance(a);
    const lb = luminance(b);
    const hi = Math.max(la, lb);
    const lo = Math.min(la, lb);
    return (hi + 0.05) / (lo + 0.05);
  }

  function isHidden(el: Element): boolean {
    if (el.closest('[aria-hidden="true"]') !== null) return true;
    const cs = getComputedStyle(el);
    return cs.display === "none" || cs.visibility === "hidden" || Number(cs.opacity) === 0;
  }

  function describe(el: Element): string {
    const id = el.id === "" ? "" : `#${el.id}`;
    const cls =
      typeof el.className === "string" && el.className !== ""
        ? `.${el.className.trim().split(/\s+/).slice(0, 3).join(".")}`
        : "";
    return `${el.tagName.toLowerCase()}${id}${cls}`;
  }

  /** WCAG 2.1's large-text carve-out (1.4.3): 18pt regular or 14pt bold. */
  function isLargeText(fontSizePx: number, fontWeight: number): boolean {
    return fontSizePx >= 24 || (fontSizePx >= 18.66 && fontWeight >= 700);
  }

  const root = document.querySelector(rootSelector);
  if (root === null) {
    throw new Error(`scanRenderedContrast: no element matches ${rootSelector}`);
  }

  const violations: ContrastViolation[] = [];
  const all = root.querySelectorAll("*");

  for (const el of all) {
    if (isHidden(el)) continue;

    // A "text-bearing" element is one with its OWN direct, non-whitespace
    // text — not merely one that contains text somewhere in its subtree,
    // which would report the same pixel run once per ancestor.
    let ownText = "";
    for (const child of el.childNodes) {
      if (child.nodeType === Node.TEXT_NODE) {
        ownText += child.textContent ?? "";
      }
    }
    if (ownText.trim() === "") continue;

    const rect = el.getBoundingClientRect();
    if (rect.width * rect.height < minAreaPx2) continue; // e.g. an sr-only span

    const cs = getComputedStyle(el);
    const fg = parseColor(cs.color);
    if (fg === null || fg.a === 0) continue;

    const bg = effectiveBackground(el);
    const ratio = contrast(fg, bg);
    const fontSizePx = Number.parseFloat(cs.fontSize);
    const fontWeight = Number.parseInt(cs.fontWeight, 10) || 400;
    const required = isLargeText(fontSizePx, fontWeight) ? 3 : 4.5;

    if (ratio < required) {
      violations.push({
        selector: describe(el),
        text: ownText.trim().slice(0, 80),
        foreground: cs.color,
        background: `rgb(${Math.round(bg.r)}, ${Math.round(bg.g)}, ${Math.round(bg.b)})`,
        ratio: Math.round(ratio * 100) / 100,
        required,
        fontSizePx,
        fontWeight,
      });
    }
  }

  return violations;
}

/** One rendered element whose colour reads as green outside a verified
 * verification state. */
export interface GreenLeak {
  readonly selector: string;
  readonly property: string;
  readonly value: string;
  readonly hue: number;
  readonly saturation: number;
  readonly lightness: number;
  readonly nearestMarker: string;
}

/**
 * Walk every element under `rootSelector` and report every rendered colour
 * (text, background, border, SVG fill/stroke) that reads as green and is not
 * inside a verification state the app itself marks `verified`.
 *
 * doc 06 §5.3: "Green = cryptographic verification passed. Nothing else is
 * ever green." ADR-0038 deletes Tailwind's default palette and forbids the
 * word "green" in a token name, but its own consequences section names the
 * hole on purpose: `bg-[#00ff00]` still compiles, because arbitrary values are
 * how the sheet stays greppable rather than merely looking compliant. This is
 * where that hole is hunted — FE-013 wants it "from rendered output", which is
 * the only place a literal hex smuggled past the token layer would show up.
 *
 * WHAT COUNTS AS PERMITTED: `VerificationPanel` and `VerificationBadge` are
 * the only places in the product that mark verification state on the element
 * itself — `data-verdict="<verdict>"` on the rollup badge,
 * `data-check-result="<result>"` on each of the three check rows. Neither
 * marker is inherited or bubbled; a component author cannot make an unrelated
 * green legal by nesting it under someone else's verified badge, because this
 * scan asks each green element for the NEAREST such marker on itself or an
 * ancestor and requires that nearest marker's own value to be "verified". A
 * green with no marker in its ancestry at all — the failure mode ADR-0038
 * warns about — has no nearest marker and is refused by construction.
 */
export interface GreenScanOptions {
  readonly rootSelector: string;
}

export function scanGreenLeaks(options: GreenScanOptions): GreenLeak[] {
  const { rootSelector } = options;
  function parseColor(value: string): { r: number; g: number; b: number; a: number } | null {
    const rgb = /^rgb\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)\s*\)$/.exec(value);
    if (rgb) {
      return { r: Number(rgb[1]), g: Number(rgb[2]), b: Number(rgb[3]), a: 1 };
    }
    const rgba = /^rgba\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)\s*\)$/.exec(value);
    if (rgba) {
      return {
        r: Number(rgba[1]),
        g: Number(rgba[2]),
        b: Number(rgba[3]),
        a: Number(rgba[4]),
      };
    }
    return null;
  }

  function hsl(c: { r: number; g: number; b: number }): {
    h: number;
    s: number;
    l: number;
  } {
    const r = c.r / 255;
    const g = c.g / 255;
    const b = c.b / 255;
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const l = (max + min) / 2;
    if (max === min) return { h: 0, s: 0, l: l * 100 };
    const d = max - min;
    const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    let h: number;
    if (max === r) h = (g - b) / d + (g < b ? 6 : 0);
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h *= 60;
    return { h, s: s * 100, l: l * 100 };
  }

  /* The measured hues of every family in web/src/tokens/tokens.css cluster
   * tightly and far apart: verification 145-153°, degraded/failure/accent all
   * outside 70-170° entirely (measured against the shipped palette; see the
   * PR description for the per-token table). This band is deliberately wider
   * than the palette's own 145-153° so a HAND-TYPED green that is not one of
   * this project's own tokens — the exact failure mode ADR-0038 warns "still
   * compiles" — is caught too, not only a drift in the sheet's own value. */
  const GREEN_HUE_MIN = 70;
  const GREEN_HUE_MAX = 170;
  const MIN_SATURATION = 15;
  const MIN_LIGHTNESS = 5;
  const MAX_LIGHTNESS = 95;

  function readsAsGreen(c: { r: number; g: number; b: number }): {
    h: number;
    s: number;
    l: number;
  } | null {
    const { h, s, l } = hsl(c);
    if (s < MIN_SATURATION) return null; // a grey has no hue worth reading
    if (l < MIN_LIGHTNESS || l > MAX_LIGHTNESS) return null; // near-black/white
    if (h < GREEN_HUE_MIN || h > GREEN_HUE_MAX) return null;
    return { h, s, l };
  }

  function describe(el: Element): string {
    const id = el.id === "" ? "" : `#${el.id}`;
    const cls =
      typeof el.className === "string" && el.className !== ""
        ? `.${el.className.trim().split(/\s+/).slice(0, 3).join(".")}`
        : "";
    return `${el.tagName.toLowerCase()}${id}${cls}`;
  }

  /** The nearest element, self included, carrying either verification-state
   * marker, or null if this element's ancestry names no verification state at
   * all — which is the state a green with no permission looks like. */
  function nearestMarker(el: Element): { value: string; el: Element } | null {
    let node: Element | null = el;
    while (node !== null) {
      const verdict = node.getAttribute("data-verdict");
      if (verdict !== null) return { value: verdict, el: node };
      const checkResult = node.getAttribute("data-check-result");
      if (checkResult !== null) return { value: checkResult, el: node };
      node = node.parentElement;
    }
    return null;
  }

  function isHidden(el: Element): boolean {
    if (el.closest('[aria-hidden="true"]') !== null) return true;
    const cs = getComputedStyle(el);
    return cs.display === "none" || cs.visibility === "hidden" || Number(cs.opacity) === 0;
  }

  const root = document.querySelector(rootSelector);
  if (root === null) {
    throw new Error(`scanGreenLeaks: no element matches ${rootSelector}`);
  }

  const leaks: GreenLeak[] = [];
  const all: Element[] = [root, ...Array.from(root.querySelectorAll("*"))];
  const properties = [
    "color",
    "backgroundColor",
    "borderTopColor",
    "borderRightColor",
    "borderBottomColor",
    "borderLeftColor",
    "outlineColor",
    "fill",
    "stroke",
  ] as const;

  for (const el of all) {
    if (isHidden(el)) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width * rect.height === 0) continue;

    const cs = getComputedStyle(el);
    for (const property of properties) {
      const raw = cs[property];
      if (typeof raw !== "string") continue;
      const c = parseColor(raw);
      if (c === null || c.a === 0) continue;
      const green = readsAsGreen(c);
      if (green === null) continue;

      const marker = nearestMarker(el);
      if (marker !== null && marker.value === "verified") continue;

      leaks.push({
        selector: describe(el),
        property,
        value: raw,
        hue: Math.round(green.h),
        saturation: Math.round(green.s),
        lightness: Math.round(green.l),
        nearestMarker: marker === null ? "(none)" : `${describe(marker.el)}=${marker.value}`,
      });
    }
  }

  return leaks;
}
