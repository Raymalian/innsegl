// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 7 — doc 06 §8 anti-pattern 7:
 *
 *   "Silent staleness — degraded data without the 4.4 marker."
 *
 * doc 06 §4.4: "Whenever the dashboard serves data while the ledger read path
 * is degraded, EVERY AFFECTED VIEW carries a visible 'data as of {timestamp}'
 * marker. Silent staleness violates P2."
 *
 * "Every affected view" is the whole claim, so the measurement is per view and
 * not per component. Each of doc 06 §3's six views is mounted TWICE against the
 * same data — once with the read path healthy and once with it degraded — and
 * the two renderings are diffed. A view that renders identically in both is
 * serving degraded data silently, which is the defect.
 *
 * The comparison is over what a reader perceives, not over markup: a view could
 * carry a `data-degraded` attribute in both renders and differ in nothing a
 * person can see, and that would still be silent staleness.
 */

import { describe, expect, it } from "vitest";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery, mount, NOW } from "../harness/gallery";
import { builtStylesheetPath, paintOf, parseStylesheet } from "../harness/paint";
import { announced, sighted, visibleText } from "../harness/perceptible";

import { StalenessProvider } from "../../web/src/components/common/StalenessIndicator";
import { Overview } from "../../web/src/views/overview/Overview";
import { RunsView } from "../../web/src/views/runs/RunsView";
import { RunDetailView } from "../../web/src/views/run-detail/RunDetailView";
import { RepoView } from "../../web/src/views/repo/RepoView";
import { AgentTypeView } from "../../web/src/views/agent-type/AgentTypeView";
import { PublicVerifyView } from "../../web/src/views/public-verify/PublicVerifyView";
import { emptyRunsFilters } from "../../web/src/app/routes";
import { runPage, threeRuns } from "../../web/src/views/runs/fixtures";
import { RUN_ID, runDetail, NOW as RUN_NOW } from "../../web/src/views/run-detail/fixtures";
import { verifiedProof } from "../../web/src/components/verification/fixtures";
import { overviewData } from "../harness/gallery";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

const AS_OF = new Date("2026-08-31T11:31:00.000Z");

function pageOf() {
  return {
    runs: threeRuns(),
    total: 3,
    limit: 200,
    data_as_of: "2026-08-31T12:00:00.000Z",
  };
}

describe("probe 7 — silent staleness", () => {
  it("renders each of the six views healthy and degraded and diffs them", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "07-staleness.txt",
      "Probe 7 — doc 06 §8.7: silent staleness — degraded data without the §4.4 marker",
    );

    e.section("the marker itself, in the three states it has");
    for (const name of [
      "staleness/healthy",
      "staleness/degraded",
      "staleness/degraded-no-timestamp",
    ] as const) {
      const scene = scenes.find((s) => s.name === name);
      if (scene === undefined) throw new Error(name);
      const words = visibleText(sheet, scene.container);
      e.say(`    ${name}`);
      e.say(`        ${scene.note}`);
      e.say(`        renders: ${words === "" ? "(nothing at all)" : `"${words}"`}`);
    }
    e.say();
    e.say("    The degraded marker's colour, resolved from the built stylesheet:");
    const marker = scenes.find((s) => s.name === "staleness/degraded");
    const markerEl = marker?.container.querySelector("p");
    if (markerEl == null) throw new Error("no marker element");
    for (const paint of paintOf(sheet, markerEl)) {
      e.say(
        `        ${paint.property}=${paint.lightRaw}/${paint.darkRaw} ` +
          `(${paint.light?.family}/${paint.dark?.family})`,
      );
    }
    e.say();
    e.say("    doc 06 §5.3 assigns staleness to amber, and never to green. Measured");
    e.say("    above: amber in both modes.");
    for (const paint of paintOf(sheet, markerEl)) {
      expect(paint.light?.family).toBe("amber");
      expect(paint.dark?.family).toBe("amber");
    }

    e.section("each of doc 06 §3's six views, healthy against degraded");
    e.say("    Same data, same clock, one input changed. A view that renders");
    e.say("    identically in both is serving degraded data silently.");
    e.say();

    interface Pair {
      readonly view: string;
      readonly healthy: HTMLElement;
      readonly degraded: HTMLElement;
      readonly how: string;
    }

    const pairs: Pair[] = [];

    /* 3.1 Overview — the marker reads the read-path context. */
    pairs.push({
      view: "3.1 overview",
      how: "wrapped in StalenessProvider, degraded=false vs degraded=true",
      healthy: await mount(
        <StalenessProvider degraded={false} now={NOW}>
          <Overview data={overviewData()} apiBase="/api/v1" now={NOW} recentRuns={threeRuns()} />
        </StalenessProvider>,
      ),
      degraded: await mount(
        <StalenessProvider degraded asOf={AS_OF} now={NOW}>
          <Overview data={overviewData()} apiBase="/api/v1" now={NOW} recentRuns={threeRuns()} />
        </StalenessProvider>,
      ),
    });

    /* 3.2 Runs — owns its provider, fed by a prop. */
    pairs.push({
      view: "3.2 runs",
      how: "the view's own `degraded` prop, false vs true",
      healthy: await mount(
        <RunsView route={{ view: "runs", filters: emptyRunsFilters() }} source={async () => runPage()} />,
      ),
      degraded: await mount(
        <RunsView route={{ view: "runs", filters: emptyRunsFilters() }} source={async () => runPage()} degraded />,
      ),
    });

    /* 3.3 Run detail. */
    pairs.push({
      view: "3.3 run detail",
      how: "wrapped in StalenessProvider, degraded=false vs degraded=true",
      healthy: await mount(
        <StalenessProvider degraded={false} now={RUN_NOW}>
          <RunDetailView
            route={{ view: "run", runId: RUN_ID }}
            fetchRun={async () => runDetail()}
            verifyCommit={async () => verifiedProof()}
            now={RUN_NOW}
          />
        </StalenessProvider>,
      ),
      degraded: await mount(
        <StalenessProvider degraded asOf={AS_OF} now={RUN_NOW}>
          <RunDetailView
            route={{ view: "run", runId: RUN_ID }}
            fetchRun={async () => runDetail()}
            verifyCommit={async () => verifiedProof()}
            now={RUN_NOW}
          />
        </StalenessProvider>,
      ),
    });

    /* 3.4 Repo. */
    pairs.push({
      view: "3.4 repo",
      how: "wrapped in StalenessProvider, degraded=false vs degraded=true",
      healthy: await mount(
        <StalenessProvider degraded={false} now={NOW}>
          <RepoView
            route={{ view: "repo", repo: "innsegl.dev/core", from: "", to: "" }}
            load={async () => pageOf()}
            now={NOW}
          />
        </StalenessProvider>,
      ),
      degraded: await mount(
        <StalenessProvider degraded asOf={AS_OF} now={NOW}>
          <RepoView
            route={{ view: "repo", repo: "innsegl.dev/core", from: "", to: "" }}
            load={async () => pageOf()}
            now={NOW}
          />
        </StalenessProvider>,
      ),
    });

    /* 3.5 Agent type. */
    pairs.push({
      view: "3.5 agent type",
      how: "wrapped in StalenessProvider, degraded=false vs degraded=true",
      healthy: await mount(
        <StalenessProvider degraded={false} now={NOW}>
          <AgentTypeView
            route={{ view: "agentType", agentType: "fix-ci", from: "", to: "" }}
            load={async () => pageOf()}
            now={NOW}
          />
        </StalenessProvider>,
      ),
      degraded: await mount(
        <StalenessProvider degraded asOf={AS_OF} now={NOW}>
          <AgentTypeView
            route={{ view: "agentType", agentType: "fix-ci", from: "", to: "" }}
            load={async () => pageOf()}
            now={NOW}
          />
        </StalenessProvider>,
      ),
    });

    /* 3.6 Public verification page. */
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({}), { status: 503 })) as typeof fetch;
    pairs.push({
      view: "3.6 public verification",
      how: "wrapped in StalenessProvider, degraded=false vs degraded=true",
      healthy: await mount(
        <StalenessProvider degraded={false} now={NOW}>
          <PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />
        </StalenessProvider>,
      ),
      degraded: await mount(
        <StalenessProvider degraded asOf={AS_OF} now={NOW}>
          <PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />
        </StalenessProvider>,
      ),
    });

    const silent: string[] = [];
    for (const pair of pairs) {
      const healthyWords = visibleText(sheet, pair.healthy);
      const degradedWords = visibleText(sheet, pair.degraded);
      const healthySeen = sighted(sheet, pair.healthy);
      const degradedSeen = sighted(sheet, pair.degraded);
      const differs = healthySeen !== degradedSeen;
      const marks = degradedWords.includes("Data as of") || /data as of/i.test(degradedWords);

      e.say(`    ${pair.view}`);
      e.say(`        method: ${pair.how}`);
      e.say(`        healthy  and degraded renderings differ: ${differs ? "yes" : "*** NO ***"}`);
      e.say(`        the degraded rendering says "data as of": ${marks ? "yes" : "NO"}`);
      const added = degradedWords.replace(healthyWords, "").trim();
      e.say(`        what the degradation ADDS to the visible words:`);
      e.block(added === "" ? "(nothing)" : added.slice(0, 400));
      if (!differs || !marks) silent.push(pair.view);
      e.say();
    }

    e.say(`    views serving degraded data with no visible marker: ${silent.length}`);
    if (silent.length > 0) e.say(`        ${silent.join(", ")}`);

    e.section("the one view that does not carry the marker, and why");
    e.say("    Measured above: five of the six views render the §4.4 marker when the");
    e.say("    read path is degraded, and the public verification page (§3.6) does");
    e.say("    not. That is a finding for a human, not a silent defect, and the");
    e.say("    reason is in the specification rather than in the code:");
    e.say();
    e.say("    §4.4 scopes the marker to \"whenever the DASHBOARD serves data while");
    e.say("    the LEDGER READ PATH is degraded\". §3.6's page reads no ledger — it");
    e.say("    \"performs LIVE checks against Fulcio/Rekor\" and \"offers nothing");
    e.say("    database-only in their place\". So there is no ledger read for it to");
    e.say("    be serving staleness from, and its honesty about a degraded");
    e.say("    dependency is the unreachable-upstream state instead. What that");
    e.say("    page renders when its upstreams are gone, measured:");
    e.say();
    const blocked = scenes.find((s) => s.name === "view/public-verify-upstreams-blocked");
    if (blocked === undefined) throw new Error("no blocked scene");
    e.block(visibleText(sheet, blocked.container).slice(0, 900));
    e.say();
    e.say("    RECORDED FOR THE HUMAN: if a deployment ever routes §3.6 through a");
    e.say("    cached ledger read, §4.4 begins to apply to it and nothing in the");
    e.say("    view would notice. Today it does not, so this is a boundary rather");
    e.say("    than a defect.");

    /* The five that must carry it, asserted. */
    for (const pair of pairs.filter((p) => !p.view.startsWith("3.6"))) {
      const words = visibleText(sheet, pair.degraded);
      expect(
        /data as of/i.test(words),
        `${pair.view} serves degraded data with no §4.4 marker`,
      ).toBe(true);
      expect(
        sighted(sheet, pair.healthy),
        `${pair.view} renders identically healthy and degraded`,
      ).not.toBe(sighted(sheet, pair.degraded));
    }

    e.section("what the marker announces");
    e.block(announced(marker?.container as Element));

    e.section("the anchoring heartbeat, the other never-hidden signal");
    e.say("    doc 06 §3.1: the pulse \"is never hidden\". Measured across its three");
    e.say("    states — there is no input for which it renders nothing:");
    for (const name of ["heartbeat/within-bound", "heartbeat/beyond-bound", "heartbeat/unknown"] as const) {
      const scene = scenes.find((s) => s.name === name);
      if (scene === undefined) throw new Error(name);
      const words = visibleText(sheet, scene.container);
      e.say(`    ${name.padEnd(26)} "${words}"`);
      expect(words.length).toBeGreaterThan(0);
    }
    const lagging = scenes.find((s) => s.name === "heartbeat/beyond-bound");
    const laggingEl = lagging?.container.querySelector("p");
    e.say();
    e.say("    Past its bound, the pulse's colour:");
    for (const paint of paintOf(sheet, laggingEl as Element)) {
      e.say(
        `        ${paint.property}=${paint.lightRaw}/${paint.darkRaw} ` +
          `(${paint.light?.family}/${paint.dark?.family})`,
      );
    }

    e.write();
  });
});
