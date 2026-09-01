// SPDX-License-Identifier: Apache-2.0

/*
 * What a person can actually perceive of a rendered subtree.
 *
 * The brief for this review names a specific failure this repository has
 * already produced once: a test proved two states differed by stripping
 * `class` and `style` from both while leaving a `data-*` attribute in place,
 * so the difference it "found" was invisible to every reader and the assertion
 * could not fail. Anti-pattern 2 ("any collapse of failed and unavailable into
 * one visual state") is exactly the claim that mistake would fake, so this
 * module inverts the method.
 *
 * Nothing here reads an attribute. A perception is BUILT from the channels a
 * reader has, and everything else is discarded rather than trusted:
 *
 *   SIGHTED   — the visible words, in order, with sr-only subtrees removed;
 *               the drawn geometry of every icon, as the path data actually in
 *               the DOM; and the colour, weight, border style and text
 *               decoration the BUILT stylesheet paints on each element, with
 *               var() resolved and light-dark() evaluated once per mode.
 *
 *   ANNOUNCED — the accessible text: visible words plus sr-only words plus
 *               `title`, `aria-label` and `alt`, with the roles and element
 *               names that carry semantics.
 *
 *   GREYSCALE — the sighted channel with every colour removed. doc 06 §6.4's
 *               "never color alone" is the claim that two states still differ
 *               here, and a printout of an audit report is where it is spent.
 *
 * `data-*`, `class` and `style` never enter any of the three. A difference
 * this module reports is a difference somebody can see or hear.
 */

import type { Stylesheet } from "./paint";
import { resolveValue } from "./paint";

/** Declarations that change what a reader perceives, as opposed to where
 * things sit. Layout is deliberately absent: jsdom computes none of it, and a
 * claim about position would be invented. */
const PERCEIVED = [
  "color",
  "background-color",
  "border-color",
  "border-top-color",
  "border-bottom-color",
  "border-style",
  "border-width",
  "border-top-width",
  "border-bottom-width",
  "outline-color",
  "outline-style",
  "outline-width",
  "text-decoration",
  "text-decoration-line",
  "text-decoration-style",
  "text-decoration-color",
  "font-family",
  "font-weight",
  "font-size",
  "font-style",
  "font-variant-numeric",
  "fill",
  "stroke",
  "stroke-width",
  "text-transform",
  "opacity",
  "--tw-border-style",
  "--tw-font-weight",
] as const;

const COLOUR_PROPERTIES = new Set([
  "color",
  "background-color",
  "border-color",
  "border-top-color",
  "border-bottom-color",
  "outline-color",
  "text-decoration-color",
  "fill",
  "stroke",
]);

export type Mode = "light" | "dark";

export interface PerceptionOptions {
  readonly mode?: Mode;
  /** Drop every colour, leaving the channels a greyscale printout keeps. */
  readonly greyscale?: boolean;
}

/** True when the built stylesheet hides this element from sight but not from
 * assistive technology — Tailwind's `sr-only`, detected by what it compiles to
 * rather than by its name. */
export function isVisuallyHidden(sheet: Stylesheet, element: Element): boolean {
  for (const className of Array.from(element.classList)) {
    const declarations = sheet.byClass.get(className);
    if (declarations === undefined) continue;
    const clip = declarations.get("clip-path");
    const position = declarations.get("position");
    const width = declarations.get("width");
    if (clip === "inset(50%)" && position === "absolute" && width === "1px") {
      return true;
    }
    if (declarations.get("display") === "none") return true;
  }
  return false;
}

function declarationsOf(sheet: Stylesheet, element: Element, options: PerceptionOptions): string[] {
  const mode = options.mode ?? "light";
  const collected = new Map<string, string>();
  for (const className of Array.from(element.classList)) {
    const declarations = sheet.byClass.get(className);
    if (declarations === undefined) continue;
    for (const property of PERCEIVED) {
      const declared = declarations.get(property);
      if (declared === undefined) continue;
      if (options.greyscale === true && COLOUR_PROPERTIES.has(property)) continue;
      let resolved: string;
      try {
        resolved = resolveValue(sheet, declared, mode);
      } catch (error) {
        resolved = `UNRESOLVED(${(error as Error).message})`;
      }
      collected.set(property, resolved);
    }
  }
  return [...collected].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`);
}

/** The geometry an icon actually draws, taken from the DOM rather than from
 * the name someone gave it. */
function shapeOf(element: Element): string {
  const parts: string[] = [];
  for (const child of Array.from(element.children)) {
    const attributes = Array.from(child.attributes)
      .filter((a) => ["d", "cx", "cy", "r", "x", "y", "width", "height", "rx", "points", "stroke-dasharray", "strokeDasharray", "fill"].includes(a.name))
      .map((a) => `${a.name}=${a.value}`)
      .sort()
      .join(" ");
    parts.push(`${child.tagName.toLowerCase()}(${attributes})`);
  }
  return parts.join(" ");
}

/** The visible rendering: words, drawn shapes and painted properties. */
export function sighted(
  sheet: Stylesheet,
  root: Element,
  options: PerceptionOptions = {},
): string {
  const lines: string[] = [];

  const walk = (node: Node, depth: number): void => {
    if (node.nodeType === node.TEXT_NODE) {
      const text = (node.textContent ?? "").replace(/\s+/g, " ").trim();
      if (text !== "") lines.push(`${"  ".repeat(depth)}"${text}"`);
      return;
    }
    if (node.nodeType !== node.ELEMENT_NODE) return;
    const element = node as Element;
    if (isVisuallyHidden(sheet, element)) return;

    const tag = element.tagName.toLowerCase();
    if (tag === "svg") {
      lines.push(`${"  ".repeat(depth)}<drawn ${shapeOf(element)}>`);
      const paint = declarationsOf(sheet, element, options);
      if (paint.length > 0) lines.push(`${"  ".repeat(depth + 1)}[${paint.join(" ")}]`);
      return;
    }

    const paint = declarationsOf(sheet, element, options);
    lines.push(`${"  ".repeat(depth)}<${tag}${paint.length === 0 ? "" : ` [${paint.join(" ")}]`}>`);
    for (const child of Array.from(element.childNodes)) walk(child, depth + 1);
  };

  walk(root, 0);
  return lines.join("\n");
}

/** Everything a screen reader would reach, in document order. */
export function announced(root: Element): string {
  const lines: string[] = [];

  const walk = (node: Node, depth: number): void => {
    if (node.nodeType === node.TEXT_NODE) {
      const text = (node.textContent ?? "").replace(/\s+/g, " ").trim();
      if (text !== "") lines.push(`${"  ".repeat(depth)}"${text}"`);
      return;
    }
    if (node.nodeType !== node.ELEMENT_NODE) return;
    const element = node as Element;
    if (element.getAttribute("aria-hidden") === "true") return;

    const semantics: string[] = [element.tagName.toLowerCase()];
    for (const name of ["role", "aria-label", "aria-live", "aria-current", "aria-busy", "title", "alt", "href", "type"]) {
      const value = element.getAttribute(name);
      if (value !== null && value !== "") semantics.push(`${name}=${value}`);
    }
    lines.push(`${"  ".repeat(depth)}<${semantics.join(" ")}>`);
    for (const child of Array.from(element.childNodes)) walk(child, depth + 1);
  };

  walk(root, 0);
  return lines.join("\n");
}

/** The visible words only, whitespace-collapsed. */
export function visibleText(sheet: Stylesheet, root: Element): string {
  const parts: string[] = [];
  const walk = (node: Node): void => {
    if (node.nodeType === node.TEXT_NODE) {
      const text = (node.textContent ?? "").replace(/\s+/g, " ");
      if (text.trim() !== "") parts.push(text);
      return;
    }
    if (node.nodeType !== node.ELEMENT_NODE) return;
    const element = node as Element;
    if (isVisuallyHidden(sheet, element)) return;
    for (const child of Array.from(element.childNodes)) walk(child);
  };
  walk(root);
  return parts.join(" ").replace(/\s+/g, " ").trim();
}

/** Every word a reader can reach by any channel, visible or announced. */
export function allText(root: Element): string {
  const parts: string[] = [];
  const walk = (node: Node): void => {
    if (node.nodeType === node.TEXT_NODE) {
      const text = (node.textContent ?? "").replace(/\s+/g, " ");
      if (text.trim() !== "") parts.push(text);
      return;
    }
    if (node.nodeType !== node.ELEMENT_NODE) return;
    const element = node as Element;
    for (const name of ["title", "aria-label", "alt", "placeholder"]) {
      const value = element.getAttribute(name);
      if (value !== null && value.trim() !== "") parts.push(value);
    }
    for (const child of Array.from(element.childNodes)) walk(child);
  };
  walk(root);
  return parts.join(" ").replace(/\s+/g, " ").trim();
}
