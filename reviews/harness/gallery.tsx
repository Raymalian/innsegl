// SPDX-License-Identifier: Apache-2.0

/*
 * The gallery: every state this review reads, rendered once.
 *
 * doc 06 §9 asks for each anti-pattern to be "measured from rendered output,
 * not asserted from code reading", so the review's unit of evidence is a
 * SCENE — a named component or view, mounted in jsdom with the props that
 * would expose the defect, kept in the document so several probes can read the
 * same DOM rather than each inventing its own.
 *
 * Fixtures are the product's OWN fixture modules wherever they exist, because
 * a review that invents its own data is measuring something the product does
 * not ship. Where a state has no fixture — a cached proof, a lagging anchor —
 * the shape is built here from the exported types, and named as this file's.
 *
 * Nothing here asserts. The probes assert; this only renders.
 */

import { act } from "react";
import { render } from "@testing-library/react";

import { App } from "../../web/src/app/App";
import { views } from "../../web/src/app/views";
import { navigate } from "../../web/src/app/router";
import { emptyRunsFilters, type Route } from "../../web/src/app/routes";

import { AlertBanner } from "../../web/src/components/common/AlertBanner";
import { AnchoringHeartbeat } from "../../web/src/components/common/AnchoringHeartbeat";
import { EmptyState } from "../../web/src/components/common/EmptyState";
import { ErrorState } from "../../web/src/components/common/ErrorState";
import { IdentifierChip } from "../../web/src/components/common/IdentifierChip";
import { LoadingState } from "../../web/src/components/common/LoadingState";
import {
  StalenessIndicator,
  StalenessProvider,
} from "../../web/src/components/common/StalenessIndicator";
import { StatusBadge } from "../../web/src/components/common/StatusBadge";

import { VerificationPanel } from "../../web/src/components/verification/VerificationPanel";
import { VerificationSummary } from "../../web/src/components/verification/VerificationSummary";
import {
  failedProof,
  forgedTrailerProof,
  proofWithResults,
  unavailableProof,
  verifiedProof,
} from "../../web/src/components/verification/fixtures";
import type { Proof } from "../../web/src/components/verification/types";

import { Overview } from "../../web/src/views/overview/Overview";
import { OverviewView } from "../../web/src/views/overview/OverviewView";
import type { OverviewData, PassRate } from "../../web/src/views/overview/types";

import { RunsView } from "../../web/src/views/runs/RunsView";
import { runPage, emptyPage, threeRuns } from "../../web/src/views/runs/fixtures";
import type { CommitProof } from "../../web/src/views/runs/proofs";

import { RunDetailView } from "../../web/src/views/run-detail/RunDetailView";
import {
  NOW as RUN_NOW,
  RUN_ID,
  runDetail,
} from "../../web/src/views/run-detail/fixtures";

import { RepoView } from "../../web/src/views/repo/RepoView";
import { AgentTypeView } from "../../web/src/views/agent-type/AgentTypeView";
import { PublicVerifyView } from "../../web/src/views/public-verify/PublicVerifyView";
import {
  bothUpstreamsBlocked,
  wireProof,
} from "../../web/src/views/public-verify/fixtures";

export interface Scene {
  /** Stable name, used as the key in every evidence file. */
  readonly name: string;
  /** What state this is and why it is in the review. */
  readonly note: string;
  readonly container: HTMLElement;
}

export const NOW = new Date("2026-08-31T12:00:00.000Z");

const LONG_SPIFFE =
  "spiffe://innsegl.dev/agent/fix-ci/task-1481/attempt-3/shard-11/run-7f3a2c";

/* ── fixtures this review owns ──────────────────────────────────────────── */

/** A verified proof presented as a RETAINED answer whose live re-check failed.
 * doc 06 §8 anti-pattern 1, built as a caller would actually hold it. */
export function cachedVerifiedProof(): Proof {
  return verifiedProof();
}

export function overviewData(overrides: Partial<OverviewData> = {}): OverviewData {
  return {
    active_runs: 3,
    retired_runs: 118,
    expired_runs: 2,
    commits_recorded: 4181,
    open_alerts: 0,
    anchor: {
      present: true,
      segment_id: "sha256:1f9c0b",
      first_position: 4100,
      last_position: 4181,
      sealed_at: "2026-08-31T11:57:00.000Z",
      anchored: true,
      rekor_log_index: 82914,
    },
    data_as_of: "2026-08-31T12:00:00.000Z",
    ...overrides,
  };
}

/** A live pass rate with failures in it. Nothing in the build produces one;
 * this is the shape `PassRate` declares, so the card's measured branch can be
 * rendered at all. */
export function livePassRate(): PassRate {
  return {
    verified: 90,
    failed: 7,
    unavailable: 3,
    checked: 100,
    measuredAt: new Date("2026-08-31T11:58:00.000Z"),
    liveness: { source: "live" },
  };
}

/** The same rate, retained rather than measured. */
export function cachedPassRate(): PassRate {
  return { ...livePassRate(), liveness: { source: "cache" } };
}

/* ── mounting ───────────────────────────────────────────────────────────── */

const scenes: Scene[] = [];

async function scene(
  name: string,
  note: string,
  node: React.ReactNode,
  /** An interaction to perform once the scene has settled — a disclosure a
   * reader would open, and nothing else. Run inside act(), then flushed again. */
  after?: (host: HTMLElement) => void,
): Promise<void> {
  const host = document.createElement("div");
  host.setAttribute("data-scene", name);
  document.body.appendChild(host);
  await act(async () => {
    render(node, { container: host });
  });
  // Let any effect-driven read settle.
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  if (after !== undefined) {
    await act(async () => {
      after(host);
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
  scenes.push({ name, note, container: host });
}

/** A fetch that answers one JSON body for every request, so a view driven by
 * the global can be mounted without a network. */
function stubFetch(body: unknown, status = 200): void {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    })) as typeof fetch;
}

function runsRoute(): Route {
  return { view: "runs", filters: emptyRunsFilters() };
}

let built: readonly Scene[] | null = null;

/** Render every scene once per test file, and hand back all of them. */
export async function gallery(): Promise<readonly Scene[]> {
  if (built !== null) return built;

  /* ── the three-check panel, in every tri-state ───────────────────────── */

  await scene(
    "panel/verified-live",
    "doc 06 §4.1: three checks passing, from a check that just ran. The one " +
      "place in the product entitled to a green.",
    <VerificationPanel proof={verifiedProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "panel/failed",
    "A check ran and what it checked does not hold (doc 06 §4.1).",
    <VerificationPanel proof={failedProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "panel/unavailable",
    "A check could not run. doc 06 §8 anti-pattern 2 forbids this looking " +
      "like the scene above.",
    <VerificationPanel proof={unavailableProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "panel/cached-verified-live-errored",
    "doc 06 §8 anti-pattern 1 exactly: three passing checks, held from a " +
      "cache, whose live re-check errored.",
    <VerificationPanel
      proof={cachedVerifiedProof()}
      liveness={{ source: "cache", liveError: "fulcio: connection refused" }}
    />,
  );

  await scene(
    "panel/cached-verified-no-error",
    "Three passing checks from a cache, with no live error to report. The " +
      "quieter half of anti-pattern 1.",
    <VerificationPanel proof={cachedVerifiedProof()} liveness={{ source: "cache" }} />,
  );

  await scene(
    "panel/liveness-empty-object",
    "The gap probe 1 found: `liveness` is a required PROP whose every FIELD is " +
      "optional, so `liveness={{}}` compiles. This is what it paints.",
    <VerificationPanel proof={cachedVerifiedProof()} liveness={{}} />,
  );

  await scene(
    "panel/live-upstream-unreachable",
    "A live check whose upstream did not answer, with three passing checks " +
      "in the response.",
    <VerificationPanel
      proof={proofWithResults(["verified", "verified", "verified"], {
        upstreamsReachable: false,
      })}
      liveness={{ source: "live" }}
    />,
  );

  await scene(
    "panel/forged-trailer",
    "doc 06 §4.1's mismatch case, from the product's own forged-trailer " +
      "fixture.",
    <VerificationPanel proof={forgedTrailerProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "panel/server-asserts-verified-over-failed-check",
    "A response that CLAIMS verified while carrying a failed check. P1: the " +
      "checks answer the assertion.",
    <VerificationPanel
      proof={proofWithResults(["verified", "failed", "verified"], {
        verdict: "verified",
      })}
      liveness={{ source: "live" }}
    />,
  );

  await scene(
    "summary/verified",
    "doc 06 §4.1's rollup badge in a table. Anti-pattern 4 is a summary that " +
      "cannot expand.",
    <VerificationSummary proof={verifiedProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "summary/failed",
    "The same rollup, failed.",
    <VerificationSummary proof={failedProof()} liveness={{ source: "live" }} />,
  );

  await scene(
    "summary/unavailable",
    "The same rollup, unavailable.",
    <VerificationSummary proof={unavailableProof()} liveness={{ source: "live" }} />,
  );

  /* ── the shared components ───────────────────────────────────────────── */

  await scene(
    "badge/status-active",
    "doc 06 §3.2's run status. Neutral by §5.3 — not a verdict.",
    <StatusBadge status="active" />,
  );
  await scene("badge/status-retired", "Retired.", <StatusBadge status="retired" />);
  await scene(
    "badge/status-expired",
    "Expired — §3.2 requires this to be distinguishable from Retired.",
    <StatusBadge status="expired" />,
  );

  await scene(
    "chip/spiffe-long",
    "doc 06 §4.3 and §8 anti-pattern 6: a SPIFFE ID long enough to force " +
      "truncation.",
    <IdentifierChip value={LONG_SPIFFE} kind="spiffe" href="/runs/run-7f3a2c" />,
  );
  await scene(
    "chip/sha",
    "A 40-character commit SHA.",
    <IdentifierChip value="4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291" kind="sha" />,
  );
  await scene(
    "chip/rekor",
    "A Rekor entry index.",
    <IdentifierChip value="82914" kind="rekor" />,
  );
  await scene(
    "chip/spiffe-narrow",
    "The same SPIFFE ID with a width far too small for its trust domain — " +
      "anti-pattern 6's failure mode, attempted.",
    <IdentifierChip value={LONG_SPIFFE} kind="spiffe" maxLength={12} />,
  );

  await scene(
    "alert/integrity",
    "doc 06 §4.5 and P3: the loudest thing on the page.",
    <AlertBanner
      alerts={[
        {
          id: "drift",
          kind: "integrity",
          title: "Ledger drift detected",
          detail: "A SPIRE entry exists that the ledger has no record of.",
          evidenceHref: "/api/v1/alerts/drift-1",
        },
      ]}
    />,
  );
  await scene(
    "alert/degraded",
    "Anchoring-lag breach. Amber, not red (doc 06 §5.3).",
    <AlertBanner
      alerts={[
        {
          id: "lag",
          kind: "degraded",
          title: "Anchoring lag past its bound",
          detail: "The newest sealed segment is 41 min old; the bound is 15 min.",
          evidenceHref: "/api/v1/overview",
        },
      ]}
    />,
  );

  await scene(
    "staleness/degraded",
    "doc 06 §4.4's marker while the read path is degraded.",
    <StalenessProvider degraded asOf={new Date("2026-08-31T11:31:00.000Z")} now={NOW}>
      <StalenessIndicator />
    </StalenessProvider>,
  );
  await scene(
    "staleness/healthy",
    "The same component with a healthy read path — the calm state.",
    <StalenessProvider degraded={false} now={NOW}>
      <StalenessIndicator />
    </StalenessProvider>,
  );
  await scene(
    "staleness/degraded-no-timestamp",
    "Degraded with no known timestamp: what the marker does when it has " +
      "nothing to state.",
    <StalenessProvider degraded asOf={null} now={NOW}>
      <StalenessIndicator />
    </StalenessProvider>,
  );

  await scene(
    "loading/busy",
    "doc 06 §4.6 and §8 anti-pattern 8, before the bound.",
    <LoadingState what="runs" />,
  );

  await scene("empty/default", "doc 06 §4.6's empty state.", <EmptyState />);
  await scene(
    "error/default",
    "doc 06 §4.6's dependency-error state.",
    <ErrorState onRetry={() => undefined} evidenceHref="/api/v1/overview" />,
  );

  await scene(
    "heartbeat/within-bound",
    "doc 06 §3.1's pulse inside its bound. P3: the healthy state is calm.",
    <AnchoringHeartbeat
      segment={4181}
      anchoredAt={new Date("2026-08-31T11:57:00.000Z")}
      lagBoundMs={15 * 60_000}
      now={NOW}
    />,
  );
  await scene(
    "heartbeat/beyond-bound",
    "The same pulse past its bound.",
    <AnchoringHeartbeat
      segment={4181}
      anchoredAt={new Date("2026-08-31T11:12:00.000Z")}
      lagBoundMs={15 * 60_000}
      now={NOW}
    />,
  );
  await scene(
    "heartbeat/unknown",
    "Nothing anchored yet — neither healthy nor a breach.",
    <AnchoringHeartbeat segment={null} anchoredAt={null} lagBoundMs={15 * 60_000} now={NOW} />,
  );

  /* ── the six views ───────────────────────────────────────────────────── */

  await scene(
    "view/overview-calm",
    "doc 06 §3.1, healthy. Presentational component, so every number is the " +
      "fixture's.",
    <Overview data={overviewData()} apiBase="/api/v1" now={NOW} recentRuns={threeRuns()} />,
  );

  await scene(
    "view/overview-alerting",
    "The same view with open alerts and a pass rate carrying failures.",
    <Overview
      data={overviewData({ open_alerts: 2 })}
      apiBase="/api/v1"
      now={NOW}
      recentRuns={threeRuns()}
      passRate={livePassRate()}
    />,
  );

  await scene(
    "view/overview-cached-pass-rate",
    "A pass rate a caller retained rather than measured — anti-pattern 1 in " +
      "a metric card.",
    <Overview
      data={overviewData()}
      apiBase="/api/v1"
      now={NOW}
      recentRuns={threeRuns()}
      passRate={cachedPassRate()}
    />,
  );

  await scene(
    "view/overview-degraded-reads",
    "doc 06 §4.4: the overview while the ledger read path is degraded.",
    <StalenessProvider degraded asOf={new Date("2026-08-31T11:31:00.000Z")} now={NOW}>
      <Overview data={overviewData()} apiBase="/api/v1" now={NOW} recentRuns={threeRuns()} />
    </StalenessProvider>,
  );

  stubFetch({}, 503);
  await scene(
    "view/overview-read-failed",
    "The wired overview when the query API does not answer.",
    <OverviewView now={NOW} />,
  );

  navigate("/runs", { replace: true });
  await scene(
    "view/runs-ready",
    "doc 06 §3.2's table, three runs, one of each status.",
    <RunsView route={runsRoute()} source={async () => runPage()} />,
  );
  await scene(
    "view/runs-empty",
    "The table's empty state.",
    <RunsView route={runsRoute()} source={async () => emptyPage()} />,
  );
  await scene(
    "view/runs-failed",
    "The table when the read failed.",
    <RunsView
      route={runsRoute()}
      source={async () => {
        throw new Error("ledger: connection refused");
      }}
    />,
  );
  await scene(
    "view/runs-with-proofs",
    "doc 06 §3.2's rollup badge in a table — anti-pattern 4's scene. One row " +
      "carries a live verified proof, one a failed one, one none at all.",
    <RunsView
      route={runsRoute()}
      source={async () => runPage()}
      proofs={(run) => {
        const held: Record<string, readonly CommitProof[]> = {
          "run-7f3a2c": [{ proof: verifiedProof(), liveness: { source: "live" } }],
          "run-0e91bd": [{ proof: failedProof(), liveness: { source: "live" } }],
        };
        return held[run.run_id] ?? [];
      }}
    />,
  );

  await scene(
    "view/runs-degraded",
    "The table with the read path degraded — anti-pattern 7's scene.",
    <RunsView route={runsRoute()} source={async () => runPage()} degraded />,
  );

  navigate(`/runs/${RUN_ID}`, { replace: true });
  await scene(
    "view/run-detail",
    "doc 06 §3.3, a healthy timeline with a live proof for its commit.",
    <RunDetailView
      route={{ view: "run", runId: RUN_ID }}
      fetchRun={async () => runDetail()}
      verifyCommit={async () => verifiedProof()}
      now={RUN_NOW}
    />,
  );
  await scene(
    "view/run-detail-verification-open",
    "doc 06 §3.3 with the per-commit verification disclosure opened, which is " +
      "the only state in which run detail holds a proof at all.",
    <RunDetailView
      route={{ view: "run", runId: RUN_ID }}
      fetchRun={async () => runDetail()}
      verifyCommit={async () => verifiedProof()}
      now={RUN_NOW}
    />,
    (host) => {
      // The disclosure the reader presses, found by the words on it rather
      // than by a test id: run-detail/strings.ts spells it "Verify this commit".
      const expand = Array.from(host.querySelectorAll("button")).find(
        (button) => (button.textContent ?? "").trim() === "Verify this commit",
      );
      if (expand === undefined) throw new Error("no 'Verify this commit' button");
      expand.click();
    },
  );

  await scene(
    "view/run-detail-proof-unavailable",
    "The same view when the proof endpoint does not answer.",
    <RunDetailView
      route={{ view: "run", runId: RUN_ID }}
      fetchRun={async () => runDetail()}
      verifyCommit={async () => {
        throw new Error("proof: 503 Service Unavailable");
      }}
      now={RUN_NOW}
    />,
  );

  navigate("/repos/innsegl.dev%2Fcore", { replace: true });
  await scene(
    "view/repo",
    "doc 06 §3.4.",
    <RepoView
      route={{ view: "repo", repo: "innsegl.dev/core", from: "", to: "" }}
      load={async () => ({
        runs: threeRuns(),
        total: 3,
        limit: 200,
        data_as_of: "2026-08-31T12:00:00.000Z",
      })}
      now={NOW}
    />,
  );

  navigate("/agent-types/fix-ci", { replace: true });
  await scene(
    "view/agent-type",
    "doc 06 §3.5.",
    <AgentTypeView
      route={{ view: "agentType", agentType: "fix-ci", from: "", to: "" }}
      load={async () => ({
        runs: threeRuns(),
        total: 3,
        limit: 200,
        data_as_of: "2026-08-31T12:00:00.000Z",
      })}
      now={NOW}
    />,
  );

  navigate("/verify", { replace: true });
  await scene(
    "view/public-verify-idle",
    "doc 06 §3.6 with no commit submitted.",
    <PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />,
  );

  stubFetch(wireProof());
  await scene(
    "view/public-verify-proven",
    "doc 06 §3.6 with a live proof that holds.",
    <PublicVerifyView
      route={{
        view: "verify",
        commit: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
        repo: "innsegl",
      }}
    />,
  );

  stubFetch(bothUpstreamsBlocked());
  await scene(
    "view/public-verify-upstreams-blocked",
    "doc 06 §3.6 when Fulcio and Rekor are both unreachable — the page's " +
      "central honesty case.",
    <PublicVerifyView
      route={{
        view: "verify",
        commit: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
        repo: "innsegl",
      }}
    />,
  );

  stubFetch(wireProof({ results: ["verified", "failed", "failed"] }));
  await scene(
    "view/public-verify-failed",
    "doc 06 §3.6 with checks that ran and did not hold.",
    <PublicVerifyView
      route={{
        view: "verify",
        commit: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
        repo: "innsegl",
      }}
    />,
  );

  /* ── the whole shell, as the browser assembles it ────────────────────── */

  stubFetch({}, 503);
  navigate("/", { replace: true });
  await scene(
    "shell/overview",
    "The application shell with its real view registry, at /.",
    <App views={views} />,
  );

  built = scenes;
  return built;
}

export { LONG_SPIFFE };
