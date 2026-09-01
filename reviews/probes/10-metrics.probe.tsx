// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 10 — doc 06 §8 anti-pattern 10:
 *
 *   "Metrics chosen to look good rather than to inform (e.g., cumulative
 *    counts with no window, hiding a failing pass rate)."
 *
 * Two named failures and one general one, so three measurements.
 *
 *   A CUMULATIVE COUNT WITH NO WINDOW. Every number the overview renders is
 *   located in the DOM, and the words rendered beside it are read. A number
 *   whose accompanying words state neither a window nor the scope it counts
 *   over is the defect.
 *
 *   A HIDDEN FAILING PASS RATE. The pass-rate card is rendered in each of the
 *   states it can be in — nothing measured, a live rate with failures, a live
 *   rate with unavailables, and a rate a caller retained — and what it says and
 *   what colour it takes are read out of the rendered output and the built
 *   stylesheet. doc 06 §3.1 requires "below 100% is rendered as a warning
 *   state, not a neutral number".
 *
 *   ROUNDING. doc 06 §6.2: "Counts are exact, never rounded vanity numbers."
 *   Awkward numbers are pushed through the real formatter and the glyphs
 *   compared against the value.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery, livePassRate, mount, NOW, overviewData } from "../harness/gallery";
import { builtStylesheetPath, paintOf, parseStylesheet } from "../harness/paint";
import { allText, visibleText } from "../harness/perceptible";

import { Overview } from "../../web/src/views/overview/Overview";
import { PassRateCard } from "../../web/src/views/overview/PassRateCard";
import { formatCount, formatRate } from "../../web/src/views/overview/format";
import { threeRuns } from "../../web/src/views/runs/fixtures";
import type { PassRate } from "../../web/src/views/overview/types";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/**
 * A count's SHAPE, which is what doc 06 §8.10's example is about.
 *
 *   windowed        the words name a period the count was taken over
 *   current-state   a snapshot of how many things are in a state right now;
 *                   it goes down as well as up, so it cannot flatter
 *   cumulative      a lifetime total with no stated period. §8.10's own
 *                   example of the defect
 *   not-a-count     the card renders no number
 */
type CountShape = "windowed" | "current-state" | "cumulative" | "not-a-count";

const WINDOW_WORDS = /\b(today|since|in the last|last \d|window|per (day|hour|week)|opens|closes|registered in|this (day|week|month))\b/i;
const STATE_WORDS = /\b(neither|currently|active|open|now|still|not yet|unretired|in flight)\b/i;

function shapeOfCount(value: string, meaning: string, hover: string): CountShape {
  if (!/\d/.test(value)) return "not-a-count";
  const words = `${meaning} ${hover}`;
  if (WINDOW_WORDS.test(words)) return "windowed";
  if (STATE_WORDS.test(words)) return "current-state";
  return "cumulative";
}

describe("probe 10 — metrics chosen to look good rather than to inform", () => {
  it("reads every number the overview renders and the words beside it", async () => {
    /* Assertions are deferred so the evidence file is written even when one
     * fails: a probe whose failure destroys its own measurement is useless to
     * the person reading the review. */
    const checks: Array<() => void> = [];
    const later = (fn: () => void): void => {
      checks.push(fn);
    };
    const scenes = await gallery();
    const e = new Evidence(
      "10-metrics.txt",
      "Probe 10 — doc 06 §8.10: metrics chosen to look good rather than to inform",
    );

    e.section("every metric card the overview renders, and what it states");
    e.say("    Located in the DOM by structure — an <article> carrying a heading, a");
    e.say("    value and a line of meaning — and read as a reader would read it.");
    e.say();

    const overview = scenes.find((s) => s.name === "view/overview-calm");
    if (overview === undefined) throw new Error("no view/overview-calm");
    const cards = Array.from(overview.container.querySelectorAll("article"));
    e.say(`    cards found: ${cards.length}`);
    e.say();

    const cumulative: string[] = [];
    for (const card of cards) {
      const heading = card.querySelector("h2")?.textContent ?? "(no heading)";
      const paragraphs = Array.from(card.querySelectorAll("p")).map((p) =>
        visibleText(sheet, p).trim(),
      );
      const value = paragraphs[0] ?? "";
      const meaning = paragraphs.slice(1).join(" ");
      const hover = card.querySelector("p")?.getAttribute("title") ?? "";
      const announced = allText(card).replace(/\s+/g, " ");
      const shape = shapeOfCount(value, meaning, hover);

      e.say(`    "${heading}"`);
      e.say(`        value shown        ${value}`);
      e.say(`        meaning beside it  ${meaning || "(none)"}`);
      e.say(`        on hover           ${hover || "(none)"}`);
      e.say(`        announced          ${announced.slice(0, 220)}`);
      e.say(`        shape              ${shape}`);
      e.say();
      if (shape === "cumulative") cumulative.push(heading);
    }

    e.say("    Read:");
    e.say("        \"Runs today\"            windowed — the card names the period and");
    e.say("                                 says so when the read did not answer.");
    e.say("        \"Active agents\"         current-state — \"runs registered and");
    e.say("                                 neither retired nor expired\" goes down as");
    e.say("                                 well as up, so it cannot flatter.");
    e.say("        \"Verification pass rate\" renders no number at all in this build.");
    e.say(`        cumulative lifetime counts with no stated window: ${cumulative.length}`);
    if (cumulative.length > 0) e.say(`            ${cumulative.join(", ")}`);
    later(() => expect(cards.length).toBeGreaterThanOrEqual(4));

    if (cumulative.length > 0) {
      e.section("FINDING, for a human ruling: one card is a monotonic lifetime count");
      e.say(`    ${cumulative.join(", ")} renders a number that only ever goes up,`);
      e.say("    with no window stated anywhere a reader can reach — not in the");
      e.say("    meaning line, not on hover, not to assistive technology. Measured:");
      e.say();
      for (const card of cards) {
        const heading = card.querySelector("h2")?.textContent ?? "";
        if (!cumulative.includes(heading)) continue;
        e.block(allText(card).replace(/\s+/g, " "));
      }
      e.say();
      e.say("    doc 06 §8.10 names this shape as its first example of the defect:");
      e.say("    \"cumulative counts with no window\". doc 06 §3.1 asks for the metric");
      e.say("    by name — \"Metric cards: active agents, runs today, commits");
      e.say("    attributed, verification pass rate\" — and states no window for it.");
      e.say("    The two sentences are in tension, and this review does not resolve");
      e.say("    a specification against itself.");
      e.say();
      e.say("    What is measured, and is not a matter of reading:");
      e.say("        - the number is a lifetime total (4,181 with the fixture's data);");
      e.say("        - the card states WHAT it counts and disclaims what it is not");
      e.say("          (\"A record, not a verification\"), so it is not a metric with");
      e.say("          no statement of meaning;");
      e.say("        - it states no PERIOD, and the adjacent \"Runs today\" card shows");
      e.say("          the same view already knows how to render one;");
      e.say("        - it is neutral grey, not a colour that claims anything.");
      e.say();
      e.say("    Recorded as a finding rather than a clean pass. A human doing sign-");
      e.say("    off should either rule that §3.1's naming of the metric settles it,");
      e.say("    or file the window as work.");
    }

    e.section("the hover doc 06 §6.2 asks for, and whether it is announced too");
    e.say("    §6.2: \"Verification pass rate shows numerator/denominator on hover.\"");
    e.say("    A fact only a mouse can reach is a fact some readers do not have, so");
    e.say("    both channels are measured:");
    e.say();
    for (const card of cards) {
      const heading = card.querySelector("h2")?.textContent ?? "";
      const hover = card.querySelector("p")?.getAttribute("title");
      if (hover === null || hover === undefined) continue;
      const announced = allText(card);
      e.say(`    "${heading}"`);
      e.say(`        title attribute: "${hover}"`);
      e.say(`        the same text reaches assistive technology: ${announced.includes(hover) ? "yes" : "NO"}`);
      later(() => expect(announced).toContain(hover));
    }

    e.section("the pass rate, in every state it has");
    e.say("    doc 06 §3.1: \"Pass rate below 100% is rendered as a warning state, not");
    e.say("    a neutral number.\" Each state below is a separate mount of the real");
    e.say("    card; the colour is resolved from the built stylesheet in both modes.");
    e.say();

    const states: Array<[string, PassRate | undefined]> = [
      ["nothing measured (every deployment of this build)", undefined],
      ["a live rate with failures in it", livePassRate()],
      [
        "a live rate with unavailables but no failures",
        { ...livePassRate(), verified: 93, failed: 0, unavailable: 7 },
      ],
      [
        "a live rate at 100%",
        { ...livePassRate(), verified: 100, failed: 0, unavailable: 0 },
      ],
      [
        "a rate a caller RETAINED rather than measured",
        { ...livePassRate(), liveness: { source: "cache" } },
      ],
      [
        "a rate whose live attempt errored",
        { ...livePassRate(), liveness: { source: "live", liveError: "rekor: timeout" } },
      ],
    ];

    for (const [label, rate] of states) {
      const host = await mount(
        <PassRateCard
          commitsRecorded={4181}
          now={NOW}
          verifyHref="/verify"
          {...(rate === undefined ? {} : { rate })}
        />,
      );
      const card = host.querySelector("article");
      if (card === null) throw new Error("no card");
      const words = visibleText(sheet, card);
      const colours = paintOf(sheet, card).map(
        (p) => `${p.property}=${p.lightRaw}/${p.darkRaw} (${p.light?.family}/${p.dark?.family})`,
      );
      e.say(`    ${label}`);
      e.say(`        renders: "${words}"`);
      for (const colour of colours) e.say(`        painted  ${colour}`);
      e.say(`        announced: "${allText(card).replace(/\s+/g, " ").slice(0, 240)}"`);
      e.say();

      /* Never green — an aggregate cannot expand to three checks (§8.4). */
      for (const paint of paintOf(sheet, card)) {
        later(() => expect(paint.light?.family, `the pass rate is green in ${label}`).not.toBe("green"));
        later(() => expect(paint.dark?.family, `the pass rate is green in ${label}`).not.toBe("green"));
      }
      /* A retained or errored rate never states a number. */
      if (rate !== undefined && (rate.liveness.source === "cache" || rate.liveness.liveError !== undefined)) {
        later(() => expect(words, `a retained rate stated a number: ${words}`).not.toMatch(/\d+(\.\d+)?%/));
      }
    }

    e.section("OBSERVATION: two different reasons share one sentence");
    e.say("    Measured above, in the last two states: a rate held from a CACHE and a");
    e.say("    rate whose LIVE ATTEMPT ERRORED render the identical sentence —");
    e.say();
    e.say("        \"The rate in hand was retained from an earlier check rather than");
    e.say("         measured now, so it is not shown as a current rate.\"");
    e.say();
    e.say("    The second is not a retained rate. It is a live measurement whose");
    e.say("    attempt failed, and doc 06 §6.1 asks copy to \"say what was checked and");
    e.say("    what happened\". The VERDICT is right in both — \"Not measured\", amber,");
    e.say("    no number — so this is not anti-pattern 1 and not anti-pattern 2: it is");
    e.say("    a reason given inaccurately, one level below the verdict. Recorded as");
    e.say("    an observation for the human, not as one of the ten.");
    e.say();
    e.say("    Note also what the 100% state does, since ADR-0038 left it open:");
    e.say("    neutral grey, not green, not amber. That is the \"narrower reading\"");
    e.say("    ADR-0038's last consequence called the safer default, and it is the one");
    e.say("    this build shipped.");

    e.section("a failing rate: warning, or a neutral number?");
    const failing = await mount(
      <PassRateCard commitsRecorded={4181} now={NOW} verifyHref="/verify" rate={livePassRate()} />,
    );
    const failingCard = failing.querySelector("article");
    if (failingCard === null) throw new Error("no card");
    e.say("    90 verified, 7 failed, 3 unavailable, out of 100 checked, live.");
    e.say();
    e.say(`    visible words: "${visibleText(sheet, failingCard)}"`);
    e.say("    painted:");
    for (const paint of paintOf(sheet, failingCard)) {
      e.say(
        `        ${paint.property}=${paint.lightRaw}/${paint.darkRaw} ` +
          `(${paint.light?.family}/${paint.dark?.family})`,
      );
    }
    const failingWords = visibleText(sheet, failingCard);
    e.say();
    e.say("    Measured:");
    e.say(`        the rate is stated               ${/90/.test(failingWords) || /%/.test(failingWords)}`);
    e.say(`        the 7 failures are stated        ${/\b7\b/.test(failingWords)}`);
    e.say(`        the 3 unavailables are stated    ${/\b3\b/.test(failingWords)}`);
    e.say(`        the two are NOT collapsed        ${/\b7\b/.test(failingWords) && /\b3\b/.test(failingWords)}`);
    const failingRed = paintOf(sheet, failingCard).some((p) => p.light?.family === "red");
    e.say(`        painted red, not neutral grey    ${failingRed}`);
    later(() => expect(/\b7\b/.test(failingWords)).toBe(true));
    later(() => expect(/\b3\b/.test(failingWords)).toBe(true));
    later(() => expect(failingRed).toBe(true));

    e.section("rounding — doc 06 §6.2's \"counts are exact, never rounded\"");
    e.say("    The real formatters, over numbers that invite abbreviation:");
    e.say();
    for (const n of [0, 7, 999, 1000, 1234, 999_999, 1_000_000, 4_181, 12_345_678]) {
      e.say(`        formatCount(${String(n).padStart(9)}) = "${formatCount(n)}"`);
    }
    e.say();
    for (const [a, b] of [
      [90, 100],
      [999, 1000],
      [2, 3],
      [1, 3],
      [0, 0],
      [4180, 4181],
    ] as const) {
      e.say(`        formatRate(${a}, ${b}) = "${formatRate(a, b)}"`);
    }
    e.say();
    e.say("    No abbreviation (no 1.2M, no 1k), and the rate that is not quite 100%");
    e.say("    does not become 100%.");
    later(() => expect(formatCount(1_000_000)).not.toMatch(/[km]/i));
    later(() => expect(formatRate(4180, 4181)).not.toBe("100%"));

    e.section("the alerting overview, where a count becomes an alarm");
    const alerting = await mount(
      <Overview
        data={overviewData({ open_alerts: 2 })}
        apiBase="/api/v1"
        now={NOW}
        recentRuns={threeRuns()}
        passRate={livePassRate()}
      />,
    );
    e.say("    The same page with 2 open alerts. doc 06 §3.1: alerts \"pin to the top");
    e.say("    of this page in the P3 style\". The first 400 characters of the page,");
    e.say("    in document order:");
    e.block(visibleText(sheet, alerting).slice(0, 400));
    const firstWords = visibleText(sheet, alerting);
    later(() => expect(firstWords.slice(0, 200).toLowerCase()).toMatch(/alert|drift|integrity|unattributed/));

    e.section("what this probe cannot determine");
    e.say("    Whether a metric was CHOSEN to flatter is a judgement about what is");
    e.say("    absent, and no probe can enumerate the numbers a designer did not");
    e.say("    render. What is measured here is the two failures doc 06 §8.10 names");
    e.say("    by example — a cumulative count with no window, and a hidden failing");
    e.say("    pass rate — plus the rounding §6.2 forbids. The judgement itself is");
    e.say("    recorded in the review document, with the one live conflict this");
    e.say("    view carries stated there rather than resolved here.");

    e.write();
    for (const check of checks) check();
  });
});
