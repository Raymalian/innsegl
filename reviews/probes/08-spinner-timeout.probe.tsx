// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 8 — doc 06 §8 anti-pattern 8:
 *
 *   "Spinners without timeout-to-error."
 *
 * doc 06 §4.6: "No blank panels, no infinite spinners: loading states time out
 * into an explicit error."
 *
 * The measurement is a clock. Each view is mounted against a read that NEVER
 * RESOLVES — the promise is created and never settled, which is what a hung
 * dependency looks like from the browser — and the clock is then advanced. What
 * is on screen before and after the bound is read out of the DOM.
 *
 * A view that still shows the same loading state after the clock has run past
 * every bound in the product is an infinite spinner, and that is the defect.
 *
 * Two adjacent facts are measured while the clock is out, because they are the
 * other half of §8.8 and of doc 06 §5.5: nothing in the product spins, and the
 * theme ships no keyframe animation for anything to spin with.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { render } from "@testing-library/react";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { builtStylesheetPath, parseStylesheet } from "../harness/paint";
import { visibleText } from "../harness/perceptible";

import { DEFAULT_TIMEOUT_MS, LoadingState } from "../../web/src/components/common/LoadingState";
import { Overview } from "../../web/src/views/overview/Overview";
import { OverviewView } from "../../web/src/views/overview/OverviewView";
import { RunsView } from "../../web/src/views/runs/RunsView";
import { RunDetailView } from "../../web/src/views/run-detail/RunDetailView";
import { RepoView } from "../../web/src/views/repo/RepoView";
import { AgentTypeView } from "../../web/src/views/agent-type/AgentTypeView";
import { PublicVerifyView } from "../../web/src/views/public-verify/PublicVerifyView";
import { DEFAULT_REQUEST_TIMEOUT_MS } from "../../web/src/views/public-verify/client";
import { emptyRunsFilters } from "../../web/src/app/routes";
import { RUN_ID } from "../../web/src/views/run-detail/fixtures";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** A read that never answers. Not a rejection, not a slow resolve: a promise
 * that never settles, which is what a hung dependency is. */
const NEVER = <T,>(): Promise<T> => new Promise<T>(() => undefined);

/** Mount under fake timers: nothing flushes on its own, so every settle is an
 * explicit advance and the measurement is of the clock, not of luck. */
async function mountFake(node: React.ReactNode): Promise<HTMLElement> {
  const host = document.createElement("div");
  document.body.appendChild(host);
  await act(async () => {
    render(node, { container: host });
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  return host;
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/** The words present at t=60 s and absent at t=0, so the evidence shows the
 * transition rather than the first 300 characters of an unchanged header. */
function wordDelta(before: string, after: string): string {
  const seen = new Set(before.split(/(?<=[.!?])\s+|\s{2,}/).map((s) => s.trim()));
  const added = after
    .split(/(?<=[.!?])\s+|\s{2,}/)
    .map((s) => s.trim())
    .filter((s) => s !== "" && !seen.has(s));
  if (added.length > 0) return added.join("\n");
  // Fall back to a raw character diff when sentence splitting finds nothing.
  let i = 0;
  while (i < before.length && before[i] === after[i]) i += 1;
  return after.slice(Math.max(0, i - 20)).slice(0, 400) || "(no visible change)";
}

describe("probe 8 — spinners without timeout-to-error", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("hangs every read and advances the clock past every bound", async () => {
    const e = new Evidence(
      "08-spinner-timeout.txt",
      "Probe 8 — doc 06 §8.8: spinners without timeout-to-error",
    );

    e.section("the bounds this build ships, read from the modules that own them");
    e.say(`    components/common/LoadingState.DEFAULT_TIMEOUT_MS   ${DEFAULT_TIMEOUT_MS} ms`);
    e.say(`    views/public-verify/client.DEFAULT_REQUEST_TIMEOUT_MS  ${DEFAULT_REQUEST_TIMEOUT_MS} ms`);
    e.say();
    e.say("    The clock below is advanced to 60 s, four times the longer of the two,");
    e.say("    so a bound that exists but is longer than either would still fire.");

    e.section("the loading component itself, across its bound");
    const loading = await mountFake(<LoadingState what="runs" />);
    const before = visibleText(sheet, loading);
    e.say(`    t = 0 s`);
    e.block(before);
    await advance(DEFAULT_TIMEOUT_MS - 1);
    const justBefore = visibleText(sheet, loading);
    e.say();
    e.say(`    t = ${(DEFAULT_TIMEOUT_MS - 1) / 1000} s — one millisecond short of the bound`);
    e.block(justBefore);
    await advance(2);
    const after = visibleText(sheet, loading);
    e.say();
    e.say(`    t = ${DEFAULT_TIMEOUT_MS / 1000} s + 1 ms — one millisecond past it`);
    e.block(after);
    e.say();
    e.say("    The transition happens at the bound and not before it.");
    expect(justBefore).toBe(before);
    expect(after).not.toBe(before);
    expect(after.toLowerCase()).toContain("timed out after");

    e.section("the timed-out state's role, which is what an assistive reader hears");
    const alert = loading.querySelector("[role]");
    e.say(`    role on the timed-out element: ${alert?.getAttribute("role")}`);
    e.say(`    the busy state carried aria-busy: it is replaced, not annotated`);
    expect(alert?.getAttribute("role")).toBe("alert");

    e.section("every view, with a read that never answers");
    e.say("    Each view below is handed a promise that never settles. The clock is");
    e.say("    then advanced to 60 s. What is printed is what the view says at each");
    e.say("    point, read out of the DOM.");
    e.say();

    globalThis.fetch = (() => NEVER<Response>()) as typeof fetch;

    const views: Array<[string, React.ReactNode]> = [
      ["3.1 overview", <OverviewView now={new Date("2026-08-31T12:00:00Z")} />],
      [
        "3.2 runs",
        <RunsView route={{ view: "runs", filters: emptyRunsFilters() }} source={() => NEVER()} />,
      ],
      [
        "3.3 run detail",
        <RunDetailView route={{ view: "run", runId: RUN_ID }} fetchRun={() => NEVER()} />,
      ],
      [
        "3.4 repo",
        <RepoView
          route={{ view: "repo", repo: "innsegl.dev/core", from: "", to: "" }}
          load={() => NEVER()}
          now={new Date("2026-08-31T12:00:00Z")}
        />,
      ],
      [
        "3.5 agent type",
        <AgentTypeView
          route={{ view: "agentType", agentType: "fix-ci", from: "", to: "" }}
          load={() => NEVER()}
          now={new Date("2026-08-31T12:00:00Z")}
        />,
      ],
      [
        "3.6 public verification",
        <PublicVerifyView
          route={{
            view: "verify",
            commit: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
            repo: "innsegl",
          }}
        />,
      ],
    ];

    const stuck: string[] = [];
    for (const [name, node] of views) {
      const host = await mountFake(node);
      const t0 = visibleText(sheet, host);
      await advance(60_000);
      const t60 = visibleText(sheet, host);
      const changed = t0 !== t60;
      const explicit =
        /timed out|didn't answer|did not answer|could not|couldn't|unreachable|cannot|no answer|failed|Retry|try again/i.test(t60);
      e.say(`    ${name}`);
      e.say(`        t = 0 s : "${t0.slice(0, 200)}${t0.length > 200 ? " …" : ""}"`);
      e.say(`        moved out of loading: ${changed ? "yes" : "*** NO — still loading ***"}`);
      e.say(`        and says so explicitly: ${explicit ? "yes" : "NO"}`);
      e.say(`        what changed between t=0 and t=60 s, in the visible words:`);
      e.block(wordDelta(t0, t60));
      e.say();
      if (!changed || !explicit) stuck.push(name);
    }

    e.say(`    views still loading after 60 s with a hung read: ${stuck.length}`);
    if (stuck.length > 0) e.say(`        ${stuck.join(", ")}`);
    expect(stuck).toEqual([]);

    e.section("nothing spins — the other half of the anti-pattern's name");
    e.say("    doc 06 §5.5 permits motion for \"state transitions and focus movement");
    e.say("    only\", and ADR-0038 decision 4 says the theme ships no keyframe");
    e.say("    animation. Measured against the BUILT stylesheet:");
    e.say();
    const keyframes = sheet.rules.filter((rule) =>
      rule.context.some((at) => at.startsWith("@keyframes")),
    );
    const animationDeclarations: string[] = [];
    for (const rule of sheet.rules) {
      for (const [property, value] of rule.declarations) {
        if (property === "animation" || property.startsWith("animation-")) {
          animationDeclarations.push(`${rule.selector} { ${property}: ${value} }`);
        }
      }
    }
    e.say(`    @keyframes blocks in the built stylesheet:      ${keyframes.length}`);
    e.say(`    animation / animation-* declarations:          ${animationDeclarations.length}`);
    for (const line of animationDeclarations.slice(0, 10)) e.say(`        ${line}`);
    expect(keyframes.length).toBe(0);
    expect(animationDeclarations.length).toBe(0);

    e.say();
    e.say("    So the loading indicator cannot be a spinner: there is nothing in the");
    e.say("    build for it to spin with. What it draws instead, from the DOM:");
    const busy = await mountFake(<LoadingState what="runs" />);
    const svg = busy.querySelector("svg");
    e.block(
      Array.from(svg?.children ?? [])
        .map((child) => child.outerHTML)
        .join("\n") || "(no icon)",
    );

    e.section("prefers-reduced-motion, which is the transition's own bound");
    e.say("    doc 06 §5.5: \"Respect prefers-reduced-motion.\" The token sheet");
    e.say("    collapses both durations under the query rather than leaving it to");
    e.say("    each component. From the built stylesheet:");
    e.say();
    for (const rule of sheet.rules) {
      if (!rule.context.some((at) => at.includes("prefers-reduced-motion"))) continue;
      for (const [property, value] of rule.declarations) {
        e.say(`        ${rule.context.join(" ")} ${rule.selector} { ${property}: ${value} }`);
      }
    }

    e.section("what this probe cannot determine");
    e.say("    Whether the timed-out state is VISIBLE — painted, on screen, not");
    e.say("    covered — is a rendering question jsdom cannot answer. This probe");
    e.say("    measures that the DOM changes to an explicit error at the bound, and");
    e.say("    that the words are there to be read. A browser is needed to confirm");
    e.say("    that a reader sees them, and that is #57's harness.");

    e.write();
  });
});
