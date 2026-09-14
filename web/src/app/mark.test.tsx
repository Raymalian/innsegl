// SPDX-License-Identifier: Apache-2.0

/*
 * FE-112 (NEW — proposed for doc 07 TC-FE by this change).
 *
 *   U | The mark is rendered in the application shell | The header draws
 *     `public/innsegl-mark.svg`'s reading-size drawing beside the wordmark; it
 *     is `aria-hidden` and `focusable="false"`, so the product name reaches
 *     assistive technology exactly once; the drawn geometry is identical to
 *     the file, so header and asset cannot drift | FD preamble, §3, §6.4
 *
 * Two things are being held still here, and the second is the one that would
 * rot quietly.
 *
 * 1. THE MARK IS NOT ANNOUNCED. It sits beside a label that already says
 *    "Innsegl". `public/innsegl-mark.svg` is authored to be opened on its own
 *    — it carries `role="img"`, an `aria-label` and a `<title>`, all three of
 *    which are exactly right for a standalone file and exactly wrong beside
 *    the wordmark, where they would make a screen reader say the product name
 *    twice. `Icon.tsx` already states the rule for this product ("`aria-hidden`
 *    always. The icon duplicates the label for sighted readers; announcing it
 *    as well would read the same fact twice"), and this is the shell's copy of
 *    that assertion.
 *
 * 2. THE HEADER AND THE FILE ARE ONE DRAWING. The header draws the mark inline
 *    rather than fetching it, for the reason ADR-0038 gives the icon set —
 *    nothing in the chrome is fetched. That buys a second copy of the
 *    geometry, and a second copy is a thing that drifts. So the file stays the
 *    source of truth and this test reads it: every geometry attribute the
 *    header paints must be the attribute the file carries, in order. Editing
 *    one without the other fails here rather than six months later when
 *    somebody notices the tab icon and the header icon are different seals.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";
import { en } from "./strings";
import markFile from "../../public/innsegl-mark.svg?raw";
import faviconFile from "../../public/favicon.svg?raw";

/** The attributes that are the drawing. Presentation-only attributes the
 * renderer may legitimately add (class, width, height) are not compared:
 * the claim is that the SHAPE is the same, not that the markup is. */
const GEOMETRY = [
  "d",
  "cx",
  "cy",
  "r",
  "fill",
  "stroke",
  "stroke-width",
  "stroke-linecap",
  "stroke-linejoin",
] as const;

/** Every drawing element under `root`, in document order, as
 * `tag attr=value …`. The root element itself is excluded: see note 1 above —
 * the file's root carries three attributes the shell's copy must not have. */
function drawing(root: Element): string[] {
  return Array.from(root.querySelectorAll("*"))
    .map((element) => {
      const attributes = GEOMETRY.filter((name) => element.hasAttribute(name)).map(
        (name) => `${name}=${element.getAttribute(name) ?? ""}`,
      );
      return attributes.length === 0
        ? ""
        : `${element.tagName.toLowerCase()} ${attributes.join(" ")}`;
    })
    .filter((line) => line !== "");
}

function parseSvg(source: string): Element {
  const root = new DOMParser().parseFromString(source, "image/svg+xml").documentElement;
  expect(root.tagName.toLowerCase(), "the asset did not parse as an <svg>").toBe("svg");
  return root;
}

/** `public/innsegl-mark.svg`, parsed. */
function fileMark(): Element {
  return parseSvg(markFile);
}

/** `public/favicon.svg` — the same drawing at the tab's heavier weight. */
function fileFavicon(): Element {
  return parseSvg(faviconFile);
}

/** The mark as the shell renders it. */
function shellMark(container: HTMLElement): Element {
  const mark = container.querySelector("[data-app-mark]");
  expect(mark, "the shell header renders no mark").not.toBeNull();
  return mark as Element;
}

describe("FE-112 the shell renders the mark", () => {
  it("draws it inside the banner, beside the wordmark", () => {
    const { container } = render(<App />);
    const mark = shellMark(container);
    expect(mark.tagName.toLowerCase()).toBe("svg");

    const banner = screen.getByRole("banner");
    expect(banner.contains(mark), "the mark is not in the header").toBe(true);
    expect(within(banner).getByText(en.labels.app.name)).toBeInTheDocument();
  });

  it("fetches nothing: the drawing is inline, not an <img> or a background", () => {
    // ADR-0038 decision 7 removes the webfont and the icon package, and
    // Icon.tsx states the rule the chrome follows: "Nothing here is fetched."
    // A second request for a 1 KB seal on every page load is the thing that
    // rule exists to prevent.
    const { container } = render(<App />);
    expect(within(screen.getByRole("banner")).queryByRole("img")).toBeNull();
    expect(container.querySelector("header img")).toBeNull();
    expect(shellMark(container).querySelectorAll("path").length).toBeGreaterThan(0);
  });
});

describe("FE-112 the mark is not announced a second time", () => {
  it("is aria-hidden and unfocusable", () => {
    const { container } = render(<App />);
    const mark = shellMark(container);
    expect(mark.getAttribute("aria-hidden")).toBe("true");
    // Legacy IE/Edge made an inline <svg> a tab stop. It is still the one
    // attribute that keeps a decorative drawing out of the tab order.
    expect(mark.getAttribute("focusable")).toBe("false");
  });

  it("carries none of the three things that would make it speak", () => {
    const { container } = render(<App />);
    const mark = shellMark(container);
    // The file has all three, correctly, for a reader who opens it alone.
    expect(fileMark().getAttribute("role")).toBe("img");
    expect(fileMark().getAttribute("aria-label")).toBe(en.labels.app.name);
    expect(fileMark().querySelector("title")).not.toBeNull();
    // The shell's copy has none of them.
    expect(mark.getAttribute("role")).toBeNull();
    expect(mark.getAttribute("aria-label")).toBeNull();
    expect(mark.querySelector("title")).toBeNull();
  });

  it("leaves exactly one 'Innsegl' in the header for a screen reader to read", () => {
    const { container } = render(<App />);
    // The mark has to actually be on the page for this to be a claim about
    // it — "said once" is trivially true of a header that draws nothing.
    shellMark(container);
    const banner = screen.getByRole("banner");
    expect(within(banner).getAllByText(en.labels.app.name)).toHaveLength(1);
  });
});

describe("FE-112 the assets the header is held against are real SVG documents", () => {
  /* Found by this test on the commit that added it, in both files: an XML
   * comment may not contain a double hyphen, and both carried the token name
   * `--innsegl-palette-verification-600` inside one. SVG is XML, so a browser
   * refuses the whole document — which means favicon.svg had never actually
   * rendered in a tab, and the drift comparison above would have been
   * comparing the header against a parse error. Both are one assertion away
   * from silently regressing again, so this is that assertion. */
  it.each([
    ["innsegl-mark.svg", markFile],
    ["favicon.svg", faviconFile],
  ])("%s parses", (_name, source) => {
    const parsed = new DOMParser().parseFromString(source, "image/svg+xml");
    expect(parsed.querySelector("parsererror")).toBeNull();
    expect(parsed.documentElement.tagName.toLowerCase()).toBe("svg");
  });
});

describe("FE-112 the header and the asset are one drawing", () => {
  it("paints the file's geometry, element for element and attribute for attribute", () => {
    const { container } = render(<App />);
    const fromFile = drawing(fileMark());

    // Anti-vacuity: if the extraction found nothing, the comparison below
    // would be `[] toEqual []` and would pass against a blank header.
    expect(fromFile.length).toBeGreaterThanOrEqual(5);
    expect(fromFile.some((line) => line.startsWith("circle "))).toBe(true);

    expect(drawing(shellMark(container))).toEqual(fromFile);
  });

  it("keeps the file's viewBox, so the drawing is not rescaled by hand", () => {
    const { container } = render(<App />);
    expect(shellMark(container).getAttribute("viewBox")).toBe(
      fileMark().getAttribute("viewBox"),
    );
  });

  it("uses the reading-size weight, not the tab weight", () => {
    // The two files are one drawing at two stroke weights (see the comment in
    // either of them): the favicon's rim and rune are heavier because a tab is
    // 16px. The header renders above 32px, so it takes the reading-size
    // weight. Asserted against BOTH files, because "matches the mark" alone
    // would be satisfied by a header that had quietly taken the favicon if the
    // two weights ever converged.
    const rimOf = (svg: Element) => svg.querySelector("circle")?.getAttribute("stroke-width");
    expect(rimOf(fileMark())).not.toBe(rimOf(fileFavicon()));

    const { container } = render(<App />);
    expect(rimOf(shellMark(container))).toBe(rimOf(fileMark()));
    expect(rimOf(shellMark(container))).not.toBe(rimOf(fileFavicon()));
  });
});
