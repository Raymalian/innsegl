// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 4 — doc 06 §8 anti-pattern 4:
 *
 *   "A verification summary that cannot be expanded to the three checks and
 *    their inputs."
 *
 * doc 06 §4.1 states the positive form: "the three checks never collapse into
 * a single icon at detail level; a summary badge may roll them up in tables
 * but always expands to the panel."
 *
 * So the measurement has two halves. Every rollup badge that appears anywhere
 * in the gallery is located — by shape, not by attribute — and each one has to
 * sit inside something a reader can open; and what is behind the disclosure has
 * to be the three named checks WITH their inputs, which is measured by opening
 * it and reading the words that appear.
 *
 * The structural half is ADR-0038's kind of claim, made by
 * VerificationSummary's own file comment: "There is no prop that turns the
 * panel off and no variant that renders the badge alone." That is tested by
 * writing the props that would turn it off.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery, type Scene } from "../harness/gallery";
import { builtStylesheetPath, parseStylesheet } from "../harness/paint";
import { announced, visibleText } from "../harness/perceptible";
import { typecheck } from "../harness/violate";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** doc 06 §4.1's three checks, spelled as the specification spells them. */
const THREE_CHECKS = [
  "Fulcio certificate chain valid",
  "Rekor inclusion proven",
  "Trailer matches certificate identity",
] as const;

/** The three verdict words a rollup badge can carry. */
const VERDICT_WORDS = ["Verified", "Failed", "Verification unavailable", "Unattributed"];

function find(scenes: readonly Scene[], name: string): Scene {
  const scene = scenes.find((s) => s.name === name);
  if (scene === undefined) throw new Error(`no scene named ${name}`);
  return scene;
}

/** Every element whose own visible words are exactly one verdict word and
 * which draws a mark beside them. Located by what it says and what it draws. */
function verdictBadges(root: Element): Element[] {
  const out: Element[] = [];
  for (const element of Array.from(root.querySelectorAll("span"))) {
    if (element.querySelector("svg") === null) continue;
    const words = visibleText(sheet, element);
    if (!VERDICT_WORDS.includes(words)) continue;
    // Keep only the outermost badge of a nest.
    if (out.some((seen) => seen.contains(element))) continue;
    out.push(element);
  }
  return out;
}

/** Whether an element sits inside something a reader can open. */
function expandableAncestor(element: Element): Element | null {
  let node: Element | null = element.parentElement;
  while (node !== null) {
    if (node.tagName.toLowerCase() === "details") return node;
    if (node.getAttribute("aria-expanded") !== null) return node;
    node = node.parentElement;
  }
  return null;
}

/** Whether the three named checks and their inputs are visible from here. */
function checksVisibleFrom(root: Element): { present: string[]; missing: string[] } {
  const words = visibleText(sheet, root);
  const present = THREE_CHECKS.filter((name) => words.includes(name));
  const missing = THREE_CHECKS.filter((name) => !words.includes(name));
  return { present: [...present], missing: [...missing] };
}

describe("probe 4 — a summary that cannot expand to the three checks", () => {
  it("finds every rollup badge and opens what is behind it", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "04-summary-expands.txt",
      "Probe 4 — doc 06 §8.4: a verification summary that cannot be expanded to the three checks and their inputs",
    );

    e.section("every rollup badge in the gallery, and what is behind it");
    e.say("    A badge is located by what it SAYS and what it DRAWS — an element whose");
    e.say("    visible words are one of doc 06 §4.2's four verdict words and which");
    e.say("    carries a drawn mark. No attribute is consulted.");
    e.say();

    let badges = 0;
    let unexpandable = 0;
    for (const scene of scenes) {
      const found = verdictBadges(scene.container);
      if (found.length === 0) continue;
      e.say(`    ${scene.name}  (${found.length} badge${found.length === 1 ? "" : "s"})`);
      for (const badge of found) {
        badges += 1;
        const words = visibleText(sheet, badge);
        const holder = expandableAncestor(badge);
        if (holder === null) {
          // Not inside a disclosure: then the three checks must already be
          // on the page beside it, which is the panel at detail level.
          const panel = badge.closest("section") ?? scene.container;
          const { present, missing } = checksVisibleFrom(panel);
          const ok = missing.length === 0;
          if (!ok) unexpandable += 1;
          e.say(
            `        "${words}" — not in a disclosure; the three checks are ` +
              `${ok ? "already on the page beside it" : `MISSING: ${missing.join(", ")}`}`,
          );
          e.say(`            checks found: ${present.join(" | ") || "(none)"}`);
        } else {
          const tag = holder.tagName.toLowerCase();
          const opened = tag === "details" ? (holder as HTMLDetailsElement) : null;
          const wasOpen = opened?.open ?? holder.getAttribute("aria-expanded") === "true";
          if (opened !== null) opened.open = true;
          const { present, missing } = checksVisibleFrom(holder);
          if (opened !== null) opened.open = wasOpen;
          const ok = missing.length === 0;
          if (!ok) unexpandable += 1;
          e.say(
            `        "${words}" — inside <${tag}>, initially ${wasOpen ? "open" : "closed"}; ` +
              `opening it reveals ${ok ? "all three checks" : `only ${present.length}`}`,
          );
          e.say(`            checks found: ${present.join(" | ") || "(none)"}`);
          if (!ok) e.say(`            MISSING: ${missing.join(", ")}`);
        }
      }
      e.say();
    }
    e.say(`    badges located: ${badges};  badges that cannot reach three checks: ${unexpandable}`);
    expect(badges).toBeGreaterThan(0);
    expect(unexpandable).toBe(0);

    e.section("one summary opened in full — the three checks AND their inputs");
    e.say("    doc 06 §8.4 says \"the three checks and their inputs\", so the inputs are");
    e.say("    measured too: the log index §4.1 requires beside check 2, the two");
    e.say("    identities §4.1 requires side by side, and the raw material §3.6 and");
    e.say("    §7 require for offline re-derivation.");
    e.say();

    const table = find(scenes, "view/runs-with-proofs");
    const details = Array.from(table.container.querySelectorAll("details"));
    e.say(`    view/runs-with-proofs holds ${details.length} <details> rollups.`);
    const first = details[0];
    if (first === undefined) throw new Error("no rollup in the runs table");
    e.say();
    e.say("    A LIMIT OF THIS HARNESS, stated before the measurement rather than");
    e.say("    after it. jsdom does not implement the user-agent rule that hides a");
    e.say("    closed <details>'s content, so this probe cannot show you the");
    e.say("    collapsed rendering — `open` is read and set, and the text is read out");
    e.say("    of the DOM either way. What it therefore measures is the question doc");
    e.say("    06 §8.4 actually asks — whether the three checks and their inputs are");
    e.say("    REACHABLE from the rollup — and not the separate question of whether");
    e.say("    they are visually hidden until it is opened. That second question");
    e.say("    needs a browser and is recorded as not determinable here.");
    e.say();
    e.say(
      `    The first rollup's own <summary> reads: ` +
        `"${visibleText(sheet, first.querySelector("summary") ?? first)}"`,
    );
    e.say(`    Its initial open state, as the element carries it: open=${(first as HTMLDetailsElement).open}`);
    (first as HTMLDetailsElement).open = true;
    for (const nested of Array.from(first.querySelectorAll("details"))) {
      (nested as HTMLDetailsElement).open = true;
    }
    const openedWords = visibleText(sheet, first);
    e.say();
    e.say("    Everything reachable behind that summary, in full:");
    e.block(openedWords);

    e.say();
    const inputs: Array<[string, boolean]> = [
      ["all three check names", THREE_CHECKS.every((name) => openedWords.includes(name))],
      ["the Rekor log index", /\b82914\b/.test(openedWords)],
      ["the commit SHA", openedWords.includes("4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291")],
      ["the trailer identity", openedWords.includes("spiffe://innsegl.dev")],
      ["a raw-material disclosure", /material|certificate|PEM|commit object/i.test(openedWords)],
      ["a per-check tri-state word", /Verified|Failed|Verification unavailable/.test(openedWords)],
    ];
    for (const [what, present] of inputs) {
      e.say(`        ${present ? "present" : "ABSENT "}  ${what}`);
    }
    for (const [what, present] of inputs) {
      expect(present, `${what} is not reachable from the rollup`).toBe(true);
    }

    e.section("what a screen reader reaches at the closed rollup");
    e.block(announced(first).split("\n").slice(0, 24).join("\n"));

    e.section("the structural half, tested by trying to turn the panel off");
    e.say("    VerificationSummary.tsx claims: \"There is no prop that turns the panel");
    e.say("    off and no variant that renders the badge alone: a table author who");
    e.say("    reaches for a summary gets the three checks with it, and the only way");
    e.say("    to ship anti-pattern 4 is to write a different component on purpose.\"");

    const attempts: Array<[string, string, string]> = [
      [
        "summary-panel-off",
        "asking the summary not to render its panel",
        `import { VerificationSummary } from "../../src/components/verification/VerificationSummary";
import { verifiedProof } from "../../src/components/verification/fixtures";

export const attempt = (
  <VerificationSummary
    proof={verifiedProof()}
    liveness={{ source: "live" }}
    panel={false}
  />
);
`,
      ],
      [
        "summary-collapsed-only",
        "asking for a badge-only variant",
        `import { VerificationSummary } from "../../src/components/verification/VerificationSummary";
import { verifiedProof } from "../../src/components/verification/fixtures";

export const attempt = (
  <VerificationSummary
    proof={verifiedProof()}
    liveness={{ source: "live" }}
    variant="badge"
  />
);
`,
      ],
    ];

    for (const [name, description, source] of attempts) {
      const attempt = typecheck(name, source);
      e.say();
      e.say(`    ATTEMPT: ${description}`);
      e.block(source.trimEnd());
      e.say();
      if (attempt.accepted) {
        e.say("    RESULT: the compiler ACCEPTED it.");
      } else {
        e.say("    RESULT: refused —");
        e.block(attempt.refusal);
      }
      expect(attempt.accepted, `${name} was accepted`).toBe(false);
    }

    e.section("FINDING: the badge-alone route the claim does not close");
    const badgeAlone = typecheck(
      "badge-alone",
      `import { VerificationBadge } from "../../src/components/verification";

export const attempt = <VerificationBadge verdict="verified" />;
`,
    );
    e.say("    `VerificationBadge` is exported from the package index. A table author");
    e.say("    who imports it directly gets a green rollup with nothing behind it —");
    e.say("    anti-pattern 4 exactly — and the compiler does not object:");
    e.say();
    e.block(badgeAlone.source.trimEnd());
    e.say();
    e.say(`    RESULT: ${badgeAlone.accepted ? "ACCEPTED by the compiler" : "refused"}`);
    if (!badgeAlone.accepted) e.block(badgeAlone.refusal);
    expect(badgeAlone.accepted).toBe(true);

    e.say();
    e.say("    The index says so itself: \"there is no exported badge that skips the");
    e.say("    panel except `VerificationBadge`, which `VerificationSummary` uses and");
    e.say("    which a table should not reach for on its own (doc 06 §8 anti-pattern");
    e.say("    4)\". Measured, no view does: every import of it in web/src is —");
    e.block(badgeImports());
    e.say();
    e.say("    So the anti-pattern is absent from the rendered product, and the");
    e.say("    barrier against it is a comment rather than a type.");

    e.write();
  });
});

import { execFileSync } from "node:child_process";

function badgeImports(): string {
  try {
    return execFileSync(
      "grep",
      ["-rn", "VerificationBadge", "--include=*.ts", "--include=*.tsx", "src"],
      { cwd: WEB_DIR, encoding: "utf8" },
    ).trim();
  } catch {
    return "(no matches)";
  }
}
