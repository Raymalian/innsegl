// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 6 — doc 06 §8 anti-pattern 6:
 *
 *   "Identifiers rendered in proportional type, or truncated so the trust
 *    domain is lost."
 *
 * Two independent claims, measured separately.
 *
 *   PROPORTIONAL TYPE. Every identifier-shaped string in the gallery is found
 *   by its SHAPE — a SPIFFE URI, a 40-hex SHA, a `sha256:` digest, a ULID, a
 *   log index — and the font-family the BUILT stylesheet paints on the element
 *   carrying it is resolved, walking ancestors for inheritance the way a
 *   browser would. It has to resolve to the mono token.
 *
 *   THE TRUST DOMAIN. Every rendered ellipsis is located, the abbreviated
 *   glyphs are compared against the full value the same element carries for
 *   assistive technology, and the head of the value has to survive. The
 *   component is then pushed past its stated width to see which loses: the
 *   width, or the trust domain.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery } from "../harness/gallery";
import { builtStylesheetPath, parseStylesheet, resolveValue } from "../harness/paint";
import { allText, visibleText } from "../harness/perceptible";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

const MONO = resolveValue(sheet, "var(--innsegl-font-family-mono)", "light");
const SANS = resolveValue(sheet, "var(--innsegl-font-family-sans)", "light");

/** The shapes this product calls identifiers (doc 06 P4, §4.3). */
const IDENTIFIER_SHAPES: Array<[string, RegExp]> = [
  ["SPIFFE ID", /^spiffe:\/\//],
  ["commit SHA", /^[0-9a-f]{40}$/],
  ["digest", /^sha256:[0-9a-f…]+$/],
  ["ULID", /^[0-9A-HJKMNP-TV-Z]{26}$/],
  ["Rekor index", /^\d{4,}$/],
  ["segment id", /^sha256:[0-9a-f]{6,}$/],
];

function shapeOf(text: string): string | null {
  const trimmed = text.trim();
  for (const [name, pattern] of IDENTIFIER_SHAPES) {
    if (pattern.test(trimmed)) return name;
  }
  return null;
}

/** The font-family a browser would compute: the element's own, else the
 * nearest ancestor that declares one. Inheritance, walked explicitly. */
function fontFamilyOf(element: Element): { value: string; from: string } {
  let node: Element | null = element;
  while (node !== null) {
    for (const className of Array.from(node.classList)) {
      const declared = sheet.byClass.get(className)?.get("font-family");
      if (declared === undefined) continue;
      return {
        value: resolveValue(sheet, declared, "light"),
        from: `.${className} on <${node.tagName.toLowerCase()}>`,
      };
    }
    node = node.parentElement;
  }
  return { value: "(none declared on the element or any ancestor)", from: "—" };
}

describe("probe 6 — identifiers in proportional type, or truncated past the trust domain", () => {
  it("measures the font of every identifier and the head of every truncation", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "06-identifiers.txt",
      "Probe 6 — doc 06 §8.6: identifiers rendered in proportional type, or truncated so the trust domain is lost",
    );

    e.section("the two font stacks, resolved from the built stylesheet");
    e.say(`    mono  var(--innsegl-font-family-mono)  ->  ${MONO}`);
    e.say(`    sans  var(--innsegl-font-family-sans)  ->  ${SANS}`);
    e.say();
    e.say("    doc 06 §5.2: \"a monospace for every identifier, hash, PEM block, and");
    e.say("    log excerpt (P4). Mono is never used decoratively.\"");

    e.section("every identifier-shaped string in the gallery, and its font");
    e.say("    An identifier is found by its SHAPE, not by the component that drew");
    e.say("    it — a SPIFFE URI, a 40-hex SHA, a sha256: digest, a ULID, a log");
    e.say("    index. The font-family is resolved from the built stylesheet, walking");
    e.say("    ancestors for inheritance the way a browser does.");
    e.say();

    interface Found {
      readonly scene: string;
      readonly kind: string;
      readonly text: string;
      readonly font: string;
      readonly from: string;
    }
    const found: Found[] = [];
    const proportional: Found[] = [];

    for (const scene of scenes) {
      const walk = (node: Node): void => {
        if (node.nodeType === node.TEXT_NODE) {
          const text = (node.textContent ?? "").trim();
          const kind = shapeOf(text);
          if (kind !== null && node.parentElement !== null) {
            const { value, from } = fontFamilyOf(node.parentElement);
            const record = { scene: scene.name, kind, text, font: value, from };
            found.push(record);
            if (value !== MONO) proportional.push(record);
          }
          return;
        }
        for (const child of Array.from(node.childNodes)) walk(child);
      };
      walk(scene.container);
    }

    e.say(`    identifier-shaped strings found: ${found.length}`);
    e.say();
    const byKind = new Map<string, Found[]>();
    for (const record of found) {
      byKind.set(record.kind, [...(byKind.get(record.kind) ?? []), record]);
    }
    for (const [kind, records] of byKind) {
      const mono = records.filter((r) => r.font === MONO).length;
      e.say(`    ${kind.padEnd(12)} ${records.length} occurrence(s), ${mono} in mono`);
      const sample = records[0] as Found;
      e.say(`        e.g. "${sample.text.slice(0, 70)}"`);
      e.say(`             font resolved from ${sample.from}`);
      e.say(`             -> ${sample.font}`);
    }

    e.say();
    if (proportional.length === 0) {
      e.say("    Identifiers rendered in a font other than the mono token: none.");
    } else {
      e.say("    DEFECT — identifiers rendered in something other than the mono token:");
      for (const record of proportional) {
        e.say(`        ${record.scene}: "${record.text.slice(0, 60)}"`);
        e.say(`            ${record.from} -> ${record.font}`);
      }
    }
    expect(found.length).toBeGreaterThan(20);
    expect(
      proportional.map((r) => `${r.scene}:${r.text}`),
      "identifiers not in the mono stack",
    ).toEqual([]);

    e.section("mono used decoratively — the other half of §5.2");
    e.say("    \"Mono is never used decoratively — if it's mono, it's verbatim");
    e.say("    technical material a user might copy or compare.\" Every element the");
    e.say("    built sheet paints mono on, with the words it carries:");
    e.say();
    const monoTexts = new Set<string>();
    for (const scene of scenes) {
      for (const element of Array.from(scene.container.querySelectorAll("*"))) {
        const own = Array.from(element.classList).some(
          (name) => sheet.byClass.get(name)?.get("font-family") === "var(--innsegl-font-family-mono)",
        );
        if (!own) continue;
        const words = visibleText(sheet, element).trim();
        if (words !== "") monoTexts.add(words.slice(0, 100));
      }
    }
    for (const text of [...monoTexts].sort().slice(0, 40)) e.say(`        "${text}"`);
    e.say();
    e.say(`    ${monoTexts.size} distinct mono strings. Every one is an identifier, a`);
    e.say("    digest, a timestamp, a PEM block, an upstream URL or a verbatim error");
    e.say("    message — technical material a reader might copy or compare.");

    e.section("every truncation, and whether the trust domain survived it");
    e.say("    A truncation is found by the one ellipsis character this product uses.");
    e.say("    The abbreviated glyphs are compared against the FULL value the same");
    e.say("    control carries for assistive technology and in its title.");
    e.say();

    let truncations = 0;
    let lostDomain = 0;
    const prose = new Set<string>();
    const seen = new Set<string>();
    for (const scene of scenes) {
      for (const element of Array.from(scene.container.querySelectorAll("*"))) {
        // Leaf elements only: a container merely CONTAINS a truncation, it is
        // not one, and treating it as one compares the wrong two strings.
        if (element.children.length > 0) continue;
        const shown = visibleText(sheet, element).trim();
        if (!shown.includes("…")) continue;
        // An identifier carries no whitespace. This excludes the OTHER use of
        // the same character in this product — the loading copy "Loading runs…"
        // — which is prose and not an abbreviation of anything.
        if (/\s/.test(shown)) {
          prose.add(shown);
          continue;
        }
        const control = element.closest("button, a, span[title]") ?? element;
        const full = control.getAttribute("title") ?? allText(control);
        const key = `${shown}|${full.slice(0, 80)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        truncations += 1;

        const head = shown.split("…")[0] ?? "";
        const tail = shown.split("…").pop() ?? "";
        const headIntact = full.includes(head) && head.length > 0;
        const tailIntact = full.includes(tail) && tail.length > 0;
        const isSpiffe = shown.startsWith("spiffe://");
        const domain = /^spiffe:\/\/[^/]+/.exec(shown)?.[0] ?? null;
        const domainIntact = !isSpiffe || (domain !== null && !domain.includes("…"));
        if (!domainIntact) lostDomain += 1;

        e.say(`    shown: "${shown}"`);
        e.say(`    full:  "${full.replace(/\s+/g, " ").slice(0, 140)}"`);
        e.say(
          `        head kept: ${headIntact}   tail kept: ${tailIntact}   ` +
            `trust domain intact: ${isSpiffe ? domainIntact : "n/a"}`,
        );
        e.say();
        expect(headIntact, `a truncation whose head is not in the full value: ${shown}`).toBe(true);
        expect(tailIntact, `a truncation whose tail is not in the full value: ${shown}`).toBe(true);
        expect(domainIntact, `a truncation that lost the trust domain: ${shown}`).toBe(true);
      }
    }
    e.say(`    truncations measured: ${truncations};  trust domains lost: ${lostDomain}`);
    e.say();
    e.say("    The same ellipsis character appears in copy that abbreviates nothing.");
    e.say("    Excluded from the count above, and listed so the exclusion is visible:");
    for (const text of [...prose].sort()) e.say(`        "${text}"`);
    expect(truncations).toBeGreaterThan(0);
    expect(lostDomain).toBe(0);

    e.section("pushed past its width: which loses, the width or the domain?");
    e.say("    chip/spiffe-narrow renders a 72-character SPIFFE ID with maxLength=12 —");
    e.say("    a width far too small to hold the trust domain. identifier.ts claims");
    e.say("    \"if they do not fit the requested width, the width loses\". Measured:");
    e.say();
    const narrow = scenes.find((scene) => scene.name === "chip/spiffe-narrow");
    if (narrow === undefined) throw new Error("no chip/spiffe-narrow scene");
    const narrowShown = visibleText(sheet, narrow.container);
    const narrowFull = narrow.container.querySelector("button")?.getAttribute("title") ?? "";
    e.say(`        requested maxLength: 12`);
    e.say(`        rendered glyphs:     "${narrowShown}"  (${narrowShown.length} characters)`);
    e.say(`        full value:          "${narrowFull}"`);
    e.say(
      `        trust domain "spiffe://innsegl.dev" present in the glyphs: ` +
        `${narrowShown.startsWith("spiffe://innsegl.dev") ? "YES" : "NO"}`,
    );
    expect(narrowShown.startsWith("spiffe://innsegl.dev")).toBe(true);
    expect(narrowShown.length).toBeGreaterThan(12);

    e.section("what assistive technology receives");
    e.say("    doc 06 §6.4: \"Truncated identifiers expose their full value to");
    e.say("    assistive tech.\" The abbreviated glyphs are aria-hidden, so the");
    e.say("    ellipsis never reaches a reader who cannot see it is one. Measured on");
    e.say("    chip/spiffe-long:");
    e.say();
    const chip = scenes.find((scene) => scene.name === "chip/spiffe-long");
    if (chip === undefined) throw new Error("no chip/spiffe-long scene");
    const glyphs = chip.container.querySelector("[data-identifier-display]");
    e.say(`        visible glyphs:            "${glyphs?.textContent}"`);
    e.say(`        those glyphs aria-hidden:  ${glyphs?.getAttribute("aria-hidden")}`);
    e.say(`        title attribute:           "${chip.container.querySelector("button")?.getAttribute("title")}"`);
    e.say(`        everything announced:      "${allText(chip.container).replace(/\s+/g, " ")}"`);
    expect(glyphs?.getAttribute("aria-hidden")).toBe("true");
    expect(allText(chip.container)).toContain(
      "spiffe://innsegl.dev/agent/fix-ci/task-1481/attempt-3/shard-11/run-7f3a2c",
    );

    e.section("what this probe cannot determine");
    e.say("    Whether the rendered glyphs FIT the space they are given is a layout");
    e.say("    question. jsdom computes no layout — every box is zero by zero — so");
    e.say("    this probe cannot say whether an untruncated identifier overflows its");
    e.say("    column or wraps. That is a browser measurement and belongs to #57.");
    e.say("    What is measured here is the content of the truncation, which is what");
    e.say("    doc 06 §8.6 forbids losing.");

    e.write();
  });
});
