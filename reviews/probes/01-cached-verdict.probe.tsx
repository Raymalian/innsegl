// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 1 — doc 06 §8 anti-pattern 1:
 *
 *   "A 'verified' state rendered from cache while the live check errored."
 *
 * Two questions, and they are different.
 *
 * BEHAVIOUR: given a proof whose three checks all passed, held from a cache,
 * with a live re-check that errored — what does the panel actually paint? The
 * answer is read out of the rendered DOM and the built stylesheet, not out of
 * rollup.ts.
 *
 * STRUCTURE: the brief records that `liveness` was once optional and defaulted
 * to live, which made the failure silent, and that it is now required. That is
 * a claim about the type system, so it is tested by writing the code the claim
 * forbids and recording the compiler's refusal.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery, type Scene } from "../harness/gallery";
import { builtStylesheetPath, paintOf, parseStylesheet } from "../harness/paint";
import { announced, sighted, visibleText } from "../harness/perceptible";
import { typecheck } from "../harness/violate";

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

/** Every `liveness=` in the dashboard's source, quoted from the files. */
function livenessCallSites(): string {
  try {
    return execFileSync(
      "grep",
      ["-rn", "--include=*.tsx", "--include=*.ts", "liveness=", "src"],
      { cwd: WEB_DIR, encoding: "utf8" },
    )
      .split("\n")
      .filter((line) => line.trim() !== "" && !line.includes("/tests/"))
      .map((line) => line.replace(/^/, "web/src/".slice(0, 0)))
      .join("\n");
  } catch {
    return "(no matches)";
  }
}
void resolve;

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

function find(scenes: readonly Scene[], name: string): Scene {
  const scene = scenes.find((s) => s.name === name);
  if (scene === undefined) throw new Error(`no scene named ${name}`);
  return scene;
}

/** The rollup badge: the panel's first element that carries a drawn mark and a
 * verdict word. Located by shape and position, never by a data attribute. */
function rollupBadge(scene: Scene): Element {
  const heading = scene.container.querySelector("h2");
  const row = heading?.parentElement;
  const badge = row?.querySelector("span:has(> svg)") ?? row?.querySelector("span");
  if (badge === null || badge === undefined) throw new Error(`no badge in ${scene.name}`);
  return badge;
}

describe("probe 1 — a cached verdict rendered as live", () => {
  it("measures what the panel paints, and what the compiler refuses", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "01-cached-verdict.txt",
      "Probe 1 — doc 06 §8.1: a \"verified\" state rendered from cache while the live check errored",
    );

    const cases = [
      "panel/verified-live",
      "panel/cached-verified-live-errored",
      "panel/cached-verified-no-error",
      "panel/live-upstream-unreachable",
    ] as const;

    e.section("the four scenes, and the verdict each one paints");
    e.say("    Every scene below carries the SAME three passing checks. Only where");
    e.say("    the proof came from, and whether anything answered, differs.");
    e.say();

    const verdicts = new Map<string, { text: string; colours: string[] }>();
    for (const name of cases) {
      const scene = find(scenes, name);
      const badge = rollupBadge(scene);
      const text = visibleText(sheet, badge);
      const colours = paintOf(sheet, badge).map(
        (p) =>
          `${p.property}=${p.lightRaw}/${p.darkRaw} (${p.light?.family}/${p.dark?.family})`,
      );
      verdicts.set(name, { text, colours });
      e.say(`    ${name}`);
      e.say(`        ${scene.note}`);
      e.say(`        badge reads   "${text}"`);
      for (const colour of colours) e.say(`        painted       ${colour}`);
      e.say();
    }

    e.section("the whole panel, in the anti-pattern's own scene");
    e.say("    doc 06 §8.1's exact input: three passing checks, from a cache, with a");
    e.say("    live error. Everything a sighted reader gets, with colours resolved");
    e.say("    out of the built stylesheet. No class, style or data-* attribute is");
    e.say("    read anywhere below.");
    e.say();
    e.block(sighted(sheet, find(scenes, "panel/cached-verified-live-errored").container));

    e.section("what the same scene announces");
    e.block(announced(find(scenes, "panel/cached-verified-live-errored").container));

    e.section("verdict, measured");
    const live = verdicts.get("panel/verified-live");
    const cached = verdicts.get("panel/cached-verified-live-errored");
    const quiet = verdicts.get("panel/cached-verified-no-error");
    const unreachable = verdicts.get("panel/live-upstream-unreachable");
    e.say(`    live check, three passes        -> "${live?.text}"`);
    e.say(`    cache + live error              -> "${cached?.text}"`);
    e.say(`    cache, no error reported        -> "${quiet?.text}"`);
    e.say(`    live check, upstream unreachable-> "${unreachable?.text}"`);
    e.say();
    e.say("    The green appears once, on the live check. The other three are the");
    e.say("    same three passing checks and none of them is painted green.");

    /* The measurement, asserted. Green must be present in the live scene and
     * absent from every scene that did not just check. */
    const greenIn = (name: string): boolean =>
      paintOf(sheet, rollupBadge(find(scenes, name))).some(
        (p) => p.light?.family === "green" || p.dark?.family === "green",
      );
    expect(greenIn("panel/verified-live")).toBe(true);
    expect(greenIn("panel/cached-verified-live-errored")).toBe(false);
    expect(greenIn("panel/cached-verified-no-error")).toBe(false);
    expect(greenIn("panel/live-upstream-unreachable")).toBe(false);

    e.section("the structural half: `liveness` is required");
    e.say("    The brief records that `liveness` was once optional and defaulted to");
    e.say("    live, which made the failure silent. Testing that claim means writing");
    e.say("    the code it forbids and seeing what happens.");

    const attempts: Array<[string, string, string]> = [
      [
        "omit-liveness",
        "omitting the prop entirely, as a caching view would by saying nothing",
        `import { VerificationPanel } from "../../src/components/verification/VerificationPanel";
import { verifiedProof } from "../../src/components/verification/fixtures";

export const attempt = <VerificationPanel proof={verifiedProof()} />;
`,
      ],
      [
        "omit-liveness-summary",
        "the same omission on the table's summary badge, which wraps the panel",
        `import { VerificationSummary } from "../../src/components/verification/VerificationSummary";
import { verifiedProof } from "../../src/components/verification/fixtures";

export const attempt = <VerificationSummary proof={verifiedProof()} />;
`,
      ],
      [
        "omit-passrate-liveness",
        "the same silence one level up, on the overview's pass rate",
        `import { PassRateCard } from "../../src/views/overview/PassRateCard";

export const attempt = (
  <PassRateCard
    commitsRecorded={4181}
    now={new Date()}
    verifyHref="/verify"
    rate={{
      verified: 100,
      failed: 0,
      unavailable: 0,
      checked: 100,
      measuredAt: new Date(),
    }}
  />
);
`,
      ],
    ];

    for (const [name, description, source] of attempts) {
      const attempt = typecheck(name, source);
      e.say();
      e.say(`    ATTEMPT: ${description}`);
      e.say();
      e.block(source.trimEnd());
      e.say();
      if (attempt.accepted) {
        e.say("    RESULT: the compiler ACCEPTED it. Nothing stopped the violation.");
      } else {
        e.say("    RESULT: refused —");
        e.block(attempt.refusal);
      }
      expect(attempt.accepted, `${name} was accepted by tsc`).toBe(false);
    }

    e.section("FINDING: the required prop has no required field");

    const empty = typecheck(
      "empty-liveness",
      `import { VerificationPanel } from "../../src/components/verification/VerificationPanel";
import { verifiedProof } from "../../src/components/verification/fixtures";

export const attempt = <VerificationPanel proof={verifiedProof()} liveness={{}} />;
`,
    );
    e.say("    VerificationPanel.tsx states the guarantee in these words:");
    e.say();
    e.say("        \"Required, a view that caches and stays quiet does not compile.");
    e.say("         Same move as ADR-0038 decision 3 — remove the step that can be");
    e.say("         wrong rather than check it afterwards.\"");
    e.say();
    e.say("    Measured, that holds for an OMITTED prop and not for an EMPTY one.");
    e.say("    `Liveness` declares `source?: \"live\" | \"cache\"` — optional — so:");
    e.say();
    e.block(empty.source.trimEnd());
    e.say();
    e.say(
      `    RESULT: the compiler ${empty.accepted ? "ACCEPTED it" : "refused it"}.`,
    );
    if (!empty.accepted) e.block(empty.refusal);
    expect(empty.accepted).toBe(true);

    e.say();
    e.say("    And this is what that empty object paints, measured the same way as");
    e.say("    every other scene above:");
    e.say();
    const emptyScene = find(scenes, "panel/liveness-empty-object");
    const emptyBadge = rollupBadge(emptyScene);
    e.say(`        badge reads   \"${visibleText(sheet, emptyBadge)}\"`);
    for (const p of paintOf(sheet, emptyBadge)) {
      e.say(
        `        painted       ${p.property}=${p.lightRaw}/${p.darkRaw} ` +
          `(${p.light?.family}/${p.dark?.family})`,
      );
    }
    const emptyIsGreen = paintOf(sheet, emptyBadge).some(
      (p) => p.light?.family === "green" || p.dark?.family === "green",
    );
    expect(emptyIsGreen).toBe(true);
    e.say();
    e.say("    So a caching view that writes `liveness={{}}` gets the green, and the");
    e.say("    type system does not object. Two facts bound how much this matters:");
    e.say("    nothing in web/src passes an empty object (grep recorded below), and");
    e.say("    the two callers that DO hold retained answers narrow the type so that");
    e.say("    `source` is required — views/runs/proofs.ts's StatedLiveness and");
    e.say("    views/overview/types.ts's MeasuredLiveness. The hole is in the panel's");
    e.say("    own contract, not in any shipped call site.");

    e.section("every `liveness=` in web/src, as the build actually passes it");
    e.block(livenessCallSites());

    e.say();
    e.say("    One further attempt is not refusable by any type and is recorded as");
    e.say("    such: a caller may write `liveness={{ source: \"live\" }}` over a proof");
    e.say("    it took from a cache. No type catches a caller that lies about its own");
    e.say("    state; what the required prop removes is the caller that says nothing,");
    e.say("    and what the optional field lets back in is the caller that says {}.");

    e.write();
  });
});
