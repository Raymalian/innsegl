// SPDX-License-Identifier: Apache-2.0

/*
 * FE-132 (NEW — proposed for doc 07 TC-FE; see the report for #256).
 *
 *   U | No rendered string asserts that an agent is dead | Every string
 *     catalogue under web/src, and the rendered output of every view that
 *     names a run's state, is free of the vocabulary of death and of any
 *     claim about whether an agent is still running | #256, FD P2, IP E7
 *
 * ── THE CLAIM THIS PRODUCT IS NOT ENTITLED TO MAKE ─────────────────────────
 *
 * IP E7 forbids inferring liveness, and the reason is not squeamishness: an
 * agent waiting on a provider usage limit, running a long build, or sitting on
 * a sleeping machine is SILENT AND ALIVE, and no threshold separates that from
 * one that stopped. The reaper withdrawing a credential is this system acting
 * on silence; it is not an observation that anything ended.
 *
 * The dashboard used to say "the agent died unretired" — in a badge's title,
 * in its accessible description, and in the specification the badge was built
 * from. That is a guess presented as a fact, in the one product whose whole
 * proposition is that it does not ask to be believed.
 *
 * ── TWO HALVES, BECAUSE EITHER ALONE IS EVADABLE ───────────────────────────
 *
 * The SOURCE half scans every string literal in every non-test module under
 * web/src with comments removed, so a sentence assembled by a function is
 * caught as surely as a constant. Comments are removed because doc 06 §3.2 is
 * quoted verbatim in several files, death and all, and a rule that forbade
 * citing the specification would be a bad rule — what is forbidden is SAYING
 * it to a reader.
 *
 * The RENDERED half mounts every view that names a state and reads everything
 * a person can perceive — visible text, screen-reader text, and the title and
 * aria-label attributes a pointer or assistive technology reaches. A catalogue
 * can be clean while a component assembles two clean fragments into a claim.
 */

import { render } from "@testing-library/react";

import { StatusBadge } from "../components/common/StatusBadge";
import type { RunStatus } from "../components/common/StatusBadge";
import { Overview } from "../views/overview/Overview";
import type { OverviewData } from "../views/overview/types";
import { RunsTable } from "../views/runs/RunsTable";
import { threeRuns } from "../views/runs/fixtures";
import { RunHeader } from "../views/run-detail/RunHeader";
import { NOW, ledgerEvent, runDetail } from "../views/run-detail/fixtures";
import { EVENT_TYPES } from "../views/run-detail/types";

/* ── the vocabulary ────────────────────────────────────────────────────────
 *
 * Two lists. The first is death said outright. The second is the quieter
 * version — a claim about whether a process is still running, which this
 * system cannot observe and therefore must not state.
 */

const DEATH =
  /\b(?:dead|died|dies|dying|death|deaths|killed|kills|killing|deceased|perished)\b/i;

const LIVENESS_CLAIM: readonly RegExp[] = [
  /no longer (?:running|alive|working|active)/i,
  /stopped (?:running|working|responding)/i,
  /is not (?:running|alive)/i,
  /never (?:came back|returned|finished running)/i,
  /the agent (?:is gone|has gone|vanished|crashed)/i,
];

function claims(text: string): readonly string[] {
  const found: string[] = [];
  const death = DEATH.exec(text);
  if (death !== null) found.push(death[0]);
  for (const pattern of LIVENESS_CLAIM) {
    const hit = pattern.exec(text);
    if (hit !== null) found.push(hit[0]);
  }
  return found;
}

/* ── the source half ───────────────────────────────────────────────────────*/

const RAW = import.meta.glob("../**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out. What a reader sees is what is left. */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** Every string and template literal in a module. Approximate by design: it
 * over-collects rather than under-collects, and an identifier that happens to
 * sit inside quotes is still something a reader could be shown. */
function literals(code: string): readonly string[] {
  return code.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g) ?? [];
}

interface Module {
  readonly name: string;
  readonly literals: readonly string[];
}

const modules: readonly Module[] = Object.entries(RAW)
  .map(([path, raw]) => ({ path, raw }))
  .filter(({ path }) => !/\.test\.tsx?$/.test(path))
  .filter(({ path }) => !/\/fixtures\.ts$/.test(path))
  .map(({ path, raw }) => ({
    name: path.replace(/^\.\.\//, ""),
    literals: literals(withoutComments(raw)),
  }))
  .sort((a, b) => a.name.localeCompare(b.name));

describe("FE-132 no catalogue string claims an agent is dead", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = modules.map((m) => m.name);
    expect(names).toContain("components/common/strings.ts");
    expect(names).toContain("views/run-detail/strings.ts");
    expect(names).toContain("views/overview/strings.ts");
    expect(modules.reduce((n, m) => n + m.literals.length, 0)).toBeGreaterThan(200);
  });

  it("holds across every module under web/src", () => {
    const offenders: string[] = [];
    for (const module of modules) {
      for (const literal of module.literals) {
        for (const claim of claims(literal)) {
          offenders.push(`${module.name}: ${claim} — in ${literal.slice(0, 80)}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("would catch the sentence this rule was written for", () => {
    // The scanner has to be able to fail, and this is the exact string the
    // product used to ship in a badge's title and accessible description.
    expect(
      claims('"Credential expired before retirement; the agent died unretired"'),
    ).not.toEqual([]);
    expect(claims('"The agent is no longer running."')).not.toEqual([]);
  });
});

/* ── the rendered half ─────────────────────────────────────────────────────*/

const ALL: readonly RunStatus[] = ["active", "lapsed", "abandoned", "retired"];

const OVERVIEW: OverviewData = {
  active_runs: 7,
  lapsed_runs: 3,
  abandoned_runs: 2,
  retired_runs: 41,
  commits_recorded: 1284573,
  open_alerts: 0,
  restore_horizon_seconds: 30 * 24 * 60 * 60,
  anchor: {
    present: true,
    segment_id: "sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f",
    first_position: 8001,
    last_position: 8421,
    sealed_at: "2026-08-30T14:41:05Z",
    anchored: true,
    rekor_log_index: 82914,
  },
  data_as_of: "2026-08-30T14:44:05Z",
};

/** Everything a person can perceive: what is on screen, what is spoken, and
 * what a pointer or assistive technology can reach through an attribute. */
function perceivable(root: HTMLElement): string {
  const parts = [root.textContent ?? ""];
  for (const el of root.querySelectorAll("[title], [aria-label]")) {
    parts.push(el.getAttribute("title") ?? "", el.getAttribute("aria-label") ?? "");
  }
  return parts.join(" ");
}

function withdrawnRun(status: string) {
  const timeline = [
    ledgerEvent(EVENT_TYPES.runRegistered, 1, {
      canonical: { agent_type: "fix-ci", task_ref: "JIRA-118" },
    }),
    ledgerEvent(EVENT_TYPES.runExpired, 2, { source: "reaper" }),
  ];
  return runDetail(timeline, status, {
    last_activity_at: "2026-08-31T11:41:00.000Z",
    withdrawn_at: "2026-08-31T11:42:00.000Z",
    restorable_until: "2026-09-30T11:42:00.000Z",
    restore_horizon_seconds: 30 * 24 * 60 * 60,
  });
}

describe("FE-132 no rendered view claims an agent is dead", () => {
  it.each(ALL)("the %s badge", (status) => {
    const { container } = render(<StatusBadge status={status} />);
    expect(claims(perceivable(container))).toEqual([]);
    // Not vacuous: the badge does render words about the state.
    expect((container.textContent ?? "").length).toBeGreaterThan(5);
  });

  it.each(ALL)("the run page with a %s run", (status) => {
    const detail = withdrawnRun(status);
    const { container } = render(
      <RunHeader run={detail} events={detail.timeline ?? []} now={NOW} />,
    );
    expect(claims(perceivable(container))).toEqual([]);
  });

  it("the runs table", () => {
    const { container } = render(<RunsTable runs={threeRuns()} total={3} />);
    expect(claims(perceivable(container))).toEqual([]);
  });

  it("the overview", () => {
    const { container } = render(
      <Overview
        data={OVERVIEW}
        now={new Date("2026-08-30T14:44:05Z")}
        apiBase="/api/v1"
      />,
    );
    expect(claims(perceivable(container))).toEqual([]);
  });
});
