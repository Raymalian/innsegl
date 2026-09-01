// SPDX-License-Identifier: Apache-2.0

/*
 * The instrument this review measures colour with.
 *
 * jsdom implements no cascade for custom properties: `getComputedStyle(el).color`
 * on an element painted by `var(--innsegl-color-proof-verified-text)` returns
 * the literal `var(...)` string, and `light-dark()` is not evaluated at all. So
 * "read the computed colour out of the browser" is not available in this
 * repository (that is #57's harness, which this review may not depend on), and
 * asserting a colour from the component's source would be exactly what doc 06
 * §9 forbids.
 *
 * What IS available is the pair of artefacts a browser would itself combine:
 *
 *   1. the DOM a component actually rendered — class attribute included;
 *   2. `web/dist/assets/*.css`, the stylesheet `npm run build` compiled from
 *      the token sheet and the components' utilities.
 *
 * This module joins them the way a browser does, for the base state only: it
 * parses the built stylesheet, indexes every single-class rule by the class
 * name it paints, resolves `var()` chains against the `:root` block that the
 * build inlined from tokens.css, evaluates `light-dark()` once per mode, and
 * converts the result to a hue. The join is mechanical and its inputs are both
 * build output, so a colour reported here is one the build produced, not one a
 * reviewer read in a source file.
 *
 * Deliberate limits, stated because they bound every verdict that rests on this:
 *
 *   - Base state only. Rules with a pseudo-class (`:hover`, `:focus-visible`),
 *     a media condition or a combinator are indexed separately and never
 *     folded into an element's paint. A defect reachable only on hover is out
 *     of this instrument's range.
 *   - No inheritance. An element with no colour rule of its own is reported as
 *     inheriting, not as painted; the caller walks ancestors when it needs the
 *     effective value.
 *   - No layout. Nothing here knows what is on top of what, or what is
 *     visible.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export type Mode = "light" | "dark";

export interface Rule {
  readonly selector: string;
  readonly declarations: ReadonlyMap<string, string>;
  /** Enclosing at-rule preludes, outermost first. Empty for a top-level rule. */
  readonly context: readonly string[];
  /** Position in the stylesheet, so later can win a tie. */
  readonly order: number;
}

export interface Stylesheet {
  readonly path: string;
  readonly rules: readonly Rule[];
  /** `:root`/`:host` custom properties, unconditional ones only. */
  readonly rootVariables: ReadonlyMap<string, string>;
  /** Class name -> declarations, base state, in cascade order. */
  readonly byClass: ReadonlyMap<string, ReadonlyMap<string, string>>;
}

/* ── locating the build ─────────────────────────────────────────────────── */

export function builtStylesheetPath(webDir: string): string {
  const assets = join(webDir, "dist", "assets");
  const css = readdirSync(assets).filter((name) => name.endsWith(".css"));
  if (css.length !== 1) {
    throw new Error(
      `expected exactly one built stylesheet in ${assets}, found ${css.length}: ` +
        `${css.join(", ")}. Run \`npm run build\` in web/ first.`,
    );
  }
  return join(assets, css[0] as string);
}

/* ── parsing ────────────────────────────────────────────────────────────── */

/** A brace-matching walk. Not a CSS parser: it understands nesting, strings
 * and comments, which is all this stylesheet needs. */
export function parseStylesheet(path: string): Stylesheet {
  const text = readFileSync(path, "utf8");
  const rules: Rule[] = [];
  const context: string[] = [];
  let order = 0;

  let i = 0;
  let prelude = "";

  const flushBlock = (body: string, head: string): void => {
    // A block whose body contains a `{` holds nested rules, not declarations.
    if (body.includes("{")) return;
    const declarations = parseDeclarations(body);
    for (const selector of head.split(",")) {
      const trimmed = selector.trim();
      if (trimmed === "") continue;
      rules.push({
        selector: trimmed,
        declarations,
        context: [...context],
        order: order++,
      });
    }
  };

  while (i < text.length) {
    const ch = text[i] as string;
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
      continue;
    }
    if (ch === "{") {
      const head = prelude.trim();
      prelude = "";
      const body = readBlock(text, i);
      if (head.startsWith("@")) {
        context.push(head);
        // Recurse into the at-rule body by rewriting the walk over it.
        const inner = parseFragment(body.text, context, order);
        rules.push(...inner.rules);
        order = inner.order;
        context.pop();
      } else {
        flushBlock(body.text, head);
      }
      i = body.end;
      continue;
    }
    if (ch === "}") {
      i += 1;
      prelude = "";
      continue;
    }
    prelude += ch;
    i += 1;
  }

  return index(path, rules);
}

function parseFragment(
  text: string,
  context: readonly string[],
  startOrder: number,
): { rules: Rule[]; order: number } {
  const rules: Rule[] = [];
  const stack = [...context];
  let order = startOrder;
  let i = 0;
  let prelude = "";

  while (i < text.length) {
    const ch = text[i] as string;
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
      continue;
    }
    if (ch === "{") {
      const head = prelude.trim();
      prelude = "";
      const body = readBlock(text, i);
      if (head.startsWith("@")) {
        stack.push(head);
        const inner = parseFragment(body.text, stack, order);
        rules.push(...inner.rules);
        order = inner.order;
        stack.pop();
      } else if (!body.text.includes("{")) {
        const declarations = parseDeclarations(body.text);
        for (const selector of head.split(",")) {
          const trimmed = selector.trim();
          if (trimmed === "") continue;
          rules.push({ selector: trimmed, declarations, context: [...stack], order: order++ });
        }
      }
      i = body.end;
      continue;
    }
    if (ch === "}") {
      i += 1;
      prelude = "";
      continue;
    }
    prelude += ch;
    i += 1;
  }
  return { rules, order };
}

/** Read a `{ ... }` starting at `open`, returning the body and the index past
 * the closing brace. */
function readBlock(text: string, open: number): { text: string; end: number } {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return { text: text.slice(open + 1, i), end: i + 1 };
    }
  }
  return { text: text.slice(open + 1), end: text.length };
}

function parseDeclarations(body: string): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  let depth = 0;
  let current = "";
  const parts: string[] = [];
  for (const ch of body) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === ";" && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  for (const part of parts) {
    const colon = splitOnFirstColon(part);
    if (colon === null) continue;
    out.set(colon.property.trim(), colon.value.trim());
  }
  return out;
}

function splitOnFirstColon(part: string): { property: string; value: string } | null {
  let depth = 0;
  for (let i = 0; i < part.length; i += 1) {
    const ch = part[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") depth -= 1;
    else if (ch === ":" && depth === 0) {
      return { property: part.slice(0, i), value: part.slice(i + 1) };
    }
  }
  return null;
}

/* ── indexing ───────────────────────────────────────────────────────────── */

/** A selector that is exactly one class and nothing else, unescaped back into
 * the class attribute value that produces it. Returns null for anything with a
 * pseudo-class, a combinator, an attribute test or a second class. */
export function soleClassOf(selector: string): string | null {
  if (!selector.startsWith(".")) return null;
  let out = "";
  for (let i = 1; i < selector.length; i += 1) {
    const ch = selector[i] as string;
    if (ch === "\\") {
      const next = selector[i + 1] as string | undefined;
      if (next === undefined) return null;
      // Hex escapes: `\2c ` for a comma.
      if (/[0-9a-fA-F]/.test(next)) {
        const hex = /^[0-9a-fA-F]{1,6}/.exec(selector.slice(i + 1));
        if (hex === null) return null;
        out += String.fromCodePoint(Number.parseInt(hex[0], 16));
        i += hex[0].length;
        if (selector[i + 1] === " ") i += 1;
        continue;
      }
      out += next;
      i += 1;
      continue;
    }
    if (":.#[]()>+~, \t".includes(ch)) return null;
    out += ch;
  }
  return out === "" ? null : out;
}

function index(path: string, rules: readonly Rule[]): Stylesheet {
  const rootVariables = new Map<string, string>();
  const byClass = new Map<string, Map<string, string>>();

  for (const rule of rules) {
    const conditional = rule.context.some(
      (at) => at.startsWith("@media") || at.startsWith("@supports") || at.startsWith("@container"),
    );
    if (!conditional && (rule.selector === ":root" || rule.selector === ":host")) {
      for (const [property, value] of rule.declarations) {
        if (property.startsWith("--")) rootVariables.set(property, value);
      }
    }
    if (conditional) continue;
    const className = soleClassOf(rule.selector);
    if (className === null) continue;
    const target = byClass.get(className) ?? new Map<string, string>();
    for (const [property, value] of rule.declarations) target.set(property, value);
    byClass.set(className, target);
  }

  return { path, rules, rootVariables, byClass };
}

/* ── value resolution ───────────────────────────────────────────────────── */

/** Resolve `var()` chains and evaluate `light-dark()` for one mode. Throws on
 * a variable the sheet does not define, rather than returning a plausible
 * blank: an unresolvable colour is a finding, not a default. */
export function resolveValue(
  sheet: Stylesheet,
  value: string,
  mode: Mode,
  depth = 0,
): string {
  if (depth > 32) throw new Error(`variable cycle resolving ${value}`);
  let out = value.trim();

  const varAt = indexOfFunction(out, "var(");
  if (varAt !== null) {
    const args = splitArguments(varAt.args);
    const name = (args[0] ?? "").trim();
    const fallback = args.slice(1).join(",").trim();
    const defined = sheet.rootVariables.get(name);
    const replacement =
      defined !== undefined ? defined : fallback !== "" ? fallback : null;
    if (replacement === null) throw new Error(`undefined custom property ${name}`);
    return resolveValue(
      sheet,
      out.slice(0, varAt.start) + replacement + out.slice(varAt.end),
      mode,
      depth + 1,
    );
  }

  const ld = indexOfFunction(out, "light-dark(");
  if (ld !== null) {
    const args = splitArguments(ld.args);
    if (args.length !== 2) throw new Error(`light-dark() with ${args.length} arguments`);
    const chosen = (mode === "light" ? args[0] : args[1]) as string;
    return resolveValue(
      sheet,
      out.slice(0, ld.start) + chosen.trim() + out.slice(ld.end),
      mode,
      depth + 1,
    );
  }

  return out;
}

function indexOfFunction(
  text: string,
  head: string,
): { start: number; end: number; args: string } | null {
  const start = text.indexOf(head);
  if (start === -1) return null;
  let depth = 0;
  for (let i = start + head.length - 1; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) {
        return { start, end: i + 1, args: text.slice(start + head.length, i) };
      }
    }
  }
  return null;
}

function splitArguments(args: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of args) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

/* ── colour ─────────────────────────────────────────────────────────────── */

export interface Hue {
  readonly hex: string;
  readonly r: number;
  readonly g: number;
  readonly b: number;
  /** Degrees, 0-360. NaN for an achromatic value. */
  readonly hue: number;
  /** 0-1. */
  readonly saturation: number;
  /** 0-1. */
  readonly lightness: number;
  /** max - min channel, 0-1. The absolute distance from grey. */
  readonly chroma: number;
  readonly family: ColourFamily;
}

export type ColourFamily = "green" | "red" | "amber" | "blue-violet" | "other" | "grey";

export function parseColour(value: string): Hue | null {
  const text = value.trim().toLowerCase();
  let r: number;
  let g: number;
  let b: number;
  const hex6 = /^#([0-9a-f]{6})$/.exec(text);
  const hex3 = /^#([0-9a-f]{3})$/.exec(text);
  const rgb = /^rgba?\(([^)]*)\)$/.exec(text);
  if (hex6 !== null) {
    const h = hex6[1] as string;
    r = Number.parseInt(h.slice(0, 2), 16);
    g = Number.parseInt(h.slice(2, 4), 16);
    b = Number.parseInt(h.slice(4, 6), 16);
  } else if (hex3 !== null) {
    const h = hex3[1] as string;
    r = Number.parseInt((h[0] as string).repeat(2), 16);
    g = Number.parseInt((h[1] as string).repeat(2), 16);
    b = Number.parseInt((h[2] as string).repeat(2), 16);
  } else if (rgb !== null) {
    const parts = (rgb[1] as string).split(/[\s,/]+/).filter((p) => p !== "");
    if (parts.length < 3) return null;
    r = Number.parseFloat(parts[0] as string);
    g = Number.parseFloat(parts[1] as string);
    b = Number.parseFloat(parts[2] as string);
    if (!Number.isFinite(r) || !Number.isFinite(g) || !Number.isFinite(b)) return null;
  } else {
    return null;
  }

  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const lightness = (max + min) / 2;
  const chroma = max - min;
  const saturation =
    chroma === 0 ? 0 : chroma / (1 - Math.abs(2 * lightness - 1) || Number.EPSILON);

  let hue = Number.NaN;
  if (chroma > 0) {
    if (max === rn) hue = (((gn - bn) / chroma) % 6) * 60;
    else if (max === gn) hue = ((bn - rn) / chroma + 2) * 60;
    else hue = ((rn - gn) / chroma + 4) * 60;
    if (hue < 0) hue += 360;
  }

  return {
    hex: `#${[r, g, b].map((c) => Math.round(c).toString(16).padStart(2, "0")).join("")}`,
    r,
    g,
    b,
    hue,
    saturation,
    lightness,
    chroma,
    family: familyOf(hue, saturation, chroma),
  };
}

/**
 * Which band of the wheel a colour sits in.
 *
 * The green band is deliberately WIDE — 65° to 175° — and the saturation floor
 * deliberately LOW at 0.06. doc 06 §5.3 is a rule about what a reader will read
 * as a verdict, and a desaturated sage or a yellow-green would both be read as
 * one; a narrow band around pure green would let exactly those through. The
 * cost is false positives, which are cheap here: every hit is printed with its
 * hue and its element, for a human to overrule.
 */
export function familyOf(hue: number, saturation: number, chroma = 1): ColourFamily {
  // HSL saturation inflates near black and near white — the near-neutral ink
  // #161b1f reads as 0.17 saturated — so absolute chroma (max - min, 0-1)
  // gates as well. 0.05 is roughly two steps of an 8-bit channel: below it a
  // hue exists arithmetically and not perceptibly.
  if (!Number.isFinite(hue) || saturation < 0.06 || chroma < 0.05) return "grey";
  if (hue >= 65 && hue < 175) return "green";
  if (hue >= 345 || hue < 20) return "red";
  if (hue >= 20 && hue < 65) return "amber";
  if (hue >= 195 && hue < 300) return "blue-violet";
  return "other";
}

/* ── painting an element ────────────────────────────────────────────────── */

/** The colour-bearing properties this review reads. */
export const PAINT_PROPERTIES = [
  "color",
  "background-color",
  "border-color",
  "border-top-color",
  "border-bottom-color",
  "outline-color",
  "text-decoration-color",
  "fill",
  "stroke",
] as const;

export interface Painted {
  readonly property: string;
  readonly declared: string;
  readonly className: string;
  readonly light: Hue | null;
  readonly dark: Hue | null;
  readonly lightRaw: string;
  readonly darkRaw: string;
}

/** Every colour the built stylesheet paints on this element in the base state,
 * from its own class attribute alone. */
export function paintOf(sheet: Stylesheet, element: Element): Painted[] {
  const out: Painted[] = [];
  for (const className of Array.from(element.classList)) {
    const declarations = sheet.byClass.get(className);
    if (declarations === undefined) continue;
    for (const property of PAINT_PROPERTIES) {
      const declared = declarations.get(property);
      if (declared === undefined) continue;
      const lightRaw = safeResolve(sheet, declared, "light");
      const darkRaw = safeResolve(sheet, declared, "dark");
      out.push({
        property,
        declared,
        className,
        lightRaw,
        darkRaw,
        light: parseColour(lightRaw),
        dark: parseColour(darkRaw),
      });
    }
  }
  return out;
}

function safeResolve(sheet: Stylesheet, value: string, mode: Mode): string {
  try {
    return resolveValue(sheet, value, mode);
  } catch (error) {
    return `UNRESOLVED(${(error as Error).message})`;
  }
}

/** Every class on this element that the built stylesheet paints nothing for.
 * A class with no rule is a utility that did not compile — which is what
 * ADR-0038 claims happens to `bg-green-500`, and is a finding anywhere else. */
export function unstyledClasses(sheet: Stylesheet, element: Element): string[] {
  return Array.from(element.classList).filter(
    (name) => !sheet.byClass.has(name) && !hasAnyRuleFor(sheet, name),
  );
}

function hasAnyRuleFor(sheet: Stylesheet, className: string): boolean {
  return sheet.rules.some((rule) => {
    const sole = soleClassOf(rule.selector);
    if (sole === className) return true;
    // Pseudo-class and media variants: the class name appears escaped.
    return rule.selector.includes(escapeClass(className));
  });
}

function escapeClass(className: string): string {
  return className.replace(/[.:[\]()#%,/\\!*+>~=&|^$?'"@`{} ]/g, (c) => `\\${c}`);
}
