// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 2 — doc 06 §8 anti-pattern 2:
 *
 *   "Any collapse of failed and unavailable into one visual state."
 *
 * This is the probe the brief's warning is about. A test that "proves" two
 * states differ by stripping `class` and `style` while leaving a `data-*`
 * attribute behind cannot fail, because a `data-verdict` a reader cannot
 * perceive is not a visual state. So nothing here reads an attribute at all:
 * the comparison is built out of the channels a person has, and each channel
 * is compared separately.
 *
 *   SIGHTED    words + drawn geometry + colours resolved from the built sheet
 *   GREYSCALE  the same, with every colour deleted — doc 06 §6.4's "never
 *              color alone" is precisely the claim that the two still differ
 *              here, and an audit report printed in black and white is where
 *              that claim gets spent
 *   ANNOUNCED  what a screen reader reaches
 *
 * The method's own falsifiability is demonstrated: the same comparison is run
 * over a pair that genuinely IS identical, and it says so.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery, type Scene } from "../harness/gallery";
import { builtStylesheetPath, parseStylesheet } from "../harness/paint";
import { announced, sighted, visibleText } from "../harness/perceptible";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

function find(scenes: readonly Scene[], name: string): Scene {
  const scene = scenes.find((s) => s.name === name);
  if (scene === undefined) throw new Error(`no scene named ${name}`);
  return scene;
}

interface Channels {
  readonly sightedLight: string;
  readonly sightedDark: string;
  readonly greyscale: string;
  readonly announced: string;
}

function channels(root: Element): Channels {
  return {
    sightedLight: sighted(sheet, root, { mode: "light" }),
    sightedDark: sighted(sheet, root, { mode: "dark" }),
    greyscale: sighted(sheet, root, { greyscale: true }),
    announced: announced(root),
  };
}

/** The first line-by-line difference between two renderings, so the evidence
 * shows WHERE they part rather than only that they do. */
function firstDifference(a: string, b: string): string {
  const left = a.split("\n");
  const right = b.split("\n");
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) {
      return `line ${i + 1}\n  failed:      ${left[i] ?? "(ends)"}\n  unavailable: ${right[i] ?? "(ends)"}`;
    }
  }
  return "(identical)";
}

describe("probe 2 — failed and unavailable collapsed into one visual state", () => {
  it("compares the two in every channel a reader has", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "02-failed-vs-unavailable.txt",
      "Probe 2 — doc 06 §8.2: any collapse of *failed* and *unavailable* into one visual state",
    );

    e.section("method, and why it is built this way");
    e.say("    The comparison below reads NO attribute. `class`, `style` and every");
    e.say("    `data-*` are absent from all four channels by construction — a");
    e.say("    perception is assembled from words, drawn geometry and the colours");
    e.say("    the built stylesheet resolves, not stripped down from markup.");
    e.say();
    e.say("    Falsifiability check first: the same comparison, run over a pair that");
    e.say("    IS identical, must report identical.");
    const control = find(scenes, "panel/failed");
    const controlChannels = channels(control.container);
    const controlAgain = channels(control.container);
    e.say();
    e.say(
      `        panel/failed vs itself, sighted:   ` +
        `${controlChannels.sightedLight === controlAgain.sightedLight ? "IDENTICAL" : "differs"}`,
    );
    e.say(
      `        panel/failed vs itself, greyscale: ` +
        `${controlChannels.greyscale === controlAgain.greyscale ? "IDENTICAL" : "differs"}`,
    );
    expect(controlChannels.sightedLight).toBe(controlAgain.sightedLight);

    const failed = channels(find(scenes, "panel/failed").container);
    const unavailable = channels(find(scenes, "panel/unavailable").container);

    e.section("the two panels, compared channel by channel");
    for (const [name, a, b] of [
      ["sighted, light mode", failed.sightedLight, unavailable.sightedLight],
      ["sighted, dark mode", failed.sightedDark, unavailable.sightedDark],
      ["greyscale (colour deleted)", failed.greyscale, unavailable.greyscale],
      ["announced", failed.announced, unavailable.announced],
    ] as const) {
      e.say(`    ${name}: ${a === b ? "*** COLLAPSED — IDENTICAL ***" : "differ"}`);
      e.block(firstDifference(a, b));
      e.say();
      expect(a, `failed and unavailable are identical in the ${name} channel`).not.toBe(b);
    }

    e.section("the rollup badge alone, which is what a table shows");
    for (const name of ["summary/verified", "summary/failed", "summary/unavailable"] as const) {
      const scene = find(scenes, name);
      const badge = scene.container.querySelector("summary");
      if (badge === null) throw new Error(`no summary in ${name}`);
      e.say(`    ${name}`);
      e.say(`        visible words   "${visibleText(sheet, badge)}"`);
      e.block(sighted(sheet, badge));
      e.say();
    }

    const summaries = ["summary/verified", "summary/failed", "summary/unavailable"].map(
      (name) => {
        const badge = find(scenes, name).container.querySelector("summary");
        if (badge === null) throw new Error(name);
        return { name, ...channels(badge) };
      },
    );
    for (let i = 0; i < summaries.length; i += 1) {
      for (let j = i + 1; j < summaries.length; j += 1) {
        const a = summaries[i] as (typeof summaries)[number];
        const b = summaries[j] as (typeof summaries)[number];
        expect(a.sightedLight, `${a.name} == ${b.name} sighted`).not.toBe(b.sightedLight);
        expect(a.greyscale, `${a.name} == ${b.name} greyscale`).not.toBe(b.greyscale);
        expect(a.announced, `${a.name} == ${b.name} announced`).not.toBe(b.announced);
      }
    }

    e.section("the three tri-state words, and the shape each carries");
    e.say("    doc 06 §4.2 asks for \"three distinct visual treatments (color + icon");
    e.say("    + label; never color alone)\". Measured, per verdict:");
    e.say();
    for (const [verdict, name] of [
      ["verified", "summary/verified"],
      ["failed", "summary/failed"],
      ["unavailable", "summary/unavailable"],
    ] as const) {
      const badge = find(scenes, name).container.querySelector("summary");
      if (badge === null) throw new Error(name);
      const svg = badge.querySelector("svg");
      const geometry = Array.from(svg?.children ?? [])
        .map((child) => child.tagName.toLowerCase())
        .join("+");
      e.say(
        `    ${verdict.padEnd(12)} word "${visibleText(sheet, badge)}"   shape ${geometry}`,
      );
    }

    e.section("the same distinction in the run-detail and public pages");
    for (const name of [
      "view/run-detail-proof-unavailable",
      "view/public-verify-upstreams-blocked",
      "view/public-verify-failed",
    ] as const) {
      const scene = find(scenes, name);
      e.say(`    ${name}`);
      e.say(`        ${scene.note}`);
      e.say(`        visible words: ${visibleText(sheet, scene.container).slice(0, 600)}`);
      e.say();
    }

    const blocked = visibleText(sheet, find(scenes, "view/public-verify-upstreams-blocked").container);
    const pageFailed = visibleText(sheet, find(scenes, "view/public-verify-failed").container);
    e.say(
      `    unreachable-upstreams page == failed-checks page? ` +
        `${blocked === pageFailed ? "*** COLLAPSED ***" : "no — they differ"}`,
    );
    expect(blocked).not.toBe(pageFailed);

    e.write();
  });
});
