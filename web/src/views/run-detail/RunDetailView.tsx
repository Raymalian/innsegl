// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.3's run detail: the full evidence chain for one run.
 *
 * The view holds the read and nothing else. Everything it shows is a component
 * that already exists — the identifier chip, the status badge, the alert
 * banner, the staleness marker, the loading bound, and the three-check panel —
 * composed, not reimplemented. What is written here is the reading of the
 * response and the four states a read can be in, which doc 06 §4.6 and P2
 * require to be four and not two:
 *
 *   loading    with a bound, because §8's anti-pattern 8 is a spinner that
 *              never ends. `LoadingState` owns the bound so this cannot forget
 *              to set one.
 *   not found  neutral. A run that does not exist is not a degraded read path
 *              and rendering it amber would report a fault that is not there.
 *   failed     amber. doc 06 §5.3 gives red to "verification failed or
 *              integrity alert"; a ledger that did not answer is neither.
 *   loaded     the header, the alarm if there is one, and the chain.
 *
 * `<StalenessIndicator />` is rendered unconditionally and decides for itself
 * whether there is anything to say. doc 07's FE-006 asks for the marker "on
 * every affected view", and a view that chose when to show it is a view that
 * can forget — which is doc 06 §8's anti-pattern 7, silent staleness.
 *
 * doc 06 P3 puts the alarm first, so the banner is above the header: a broken
 * chain link or a drift event is the most important thing on this page and it
 * is not below a fold.
 */

import { useCallback, useEffect, useState } from "react";

import { ActivityLog } from "./ActivityLog";
import { AlertBanner } from "../../components/common/AlertBanner";
import type { Alert } from "../../components/common/AlertBanner";
import { EmptyState } from "../../components/common/EmptyState";
import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { StalenessIndicator } from "../../components/common/StalenessIndicator";
import type { Route } from "../../app/routes";
import type { VerifyCommit } from "./CommitVerification";
import { fetchProof } from "./CommitVerification";
import { RunHeader } from "./RunHeader";
import { Tabs } from "./Tabs";
import { Timeline } from "./Timeline";
import { strings } from "./strings";
import { block, viewShell } from "./styles";
import { conditionsOf, toolCallCount } from "./events";
import type { Condition } from "./events";
import type { RunDetail } from "./types";

/** A run this ledger does not hold. Distinct from a read that failed, because
 * the two are different facts and doc 06 P2 forbids collapsing them. */
export class RunNotFound extends Error {}

export type FetchRun = (runID: string, signal: AbortSignal) => Promise<RunDetail>;

/** The default read: `internal/api`'s `GET /api/v1/runs/{run_id}`. */
export const fetchRun: FetchRun = async (runID, signal) => {
  const response = await fetch(`/api/v1/runs/${encodeURIComponent(runID)}`, {
    signal,
  });
  if (response.status === 404) throw new RunNotFound(runID);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as RunDetail;
};

export interface RunDetailViewProps {
  /** The shell's route. Only `{ view: "run" }` names a run. */
  readonly route: Route;
  readonly fetchRun?: FetchRun;
  readonly verifyCommit?: VerifyCommit;
  /** Injected so a render is deterministic; defaults to the wall clock. */
  readonly now?: Date;
  readonly freshnessMs?: number;
}

type Read =
  | { readonly state: "loading" }
  | { readonly state: "loaded"; readonly detail: RunDetail }
  | { readonly state: "missing" }
  | { readonly state: "failed"; readonly error: string };

export function RunDetailView({
  route,
  fetchRun: read = fetchRun,
  verifyCommit = fetchProof,
  now,
  freshnessMs,
}: RunDetailViewProps) {
  const runID = route.view === "run" ? route.runId : "";
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<Read>({ state: "loading" });
  const clock = now ?? new Date();

  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setResult({ state: "loading" });
    void (async () => {
      try {
        const detail = await read(runID, controller.signal);
        if (live) setResult({ state: "loaded", detail });
      } catch (cause) {
        if (!live) return;
        if (cause instanceof RunNotFound) {
          setResult({ state: "missing" });
          return;
        }
        setResult({
          state: "failed",
          error: cause instanceof Error ? cause.message : String(cause),
        });
      }
    })();
    return () => {
      live = false;
      controller.abort();
    };
  }, [read, runID, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return (
    <div className={viewShell}>
      <StalenessIndicator />
      {result.state === "loading" ? (
        <LoadingState what={strings.view.loading} onRetry={retry} />
      ) : null}
      {result.state === "missing" ? (
        <EmptyState
          title={strings.view.notFound}
          detail={strings.view.notFoundDetail}
        />
      ) : null}
      {result.state === "failed" ? (
        <ErrorState
          title={strings.view.failed}
          detail={`${strings.view.failedDetail} ${result.error}`}
          onRetry={retry}
        />
      ) : null}
      {result.state === "loaded" ? (
        <Loaded
          detail={result.detail}
          now={clock}
          verifyCommit={verifyCommit}
          {...(freshnessMs === undefined ? {} : { freshnessMs })}
        />
      ) : null}
    </div>
  );
}

function Loaded({
  detail,
  now,
  verifyCommit,
  freshnessMs,
}: {
  readonly detail: RunDetail;
  readonly now: Date;
  readonly verifyCommit: VerifyCommit;
  readonly freshnessMs?: number;
}) {
  const events = detail.timeline ?? [];
  return (
    <>
      {/* doc 06 P3: design the alarm first, and put it first.
        *
        * OUTSIDE the tab control below, and that is the point of putting it
        * here rather than in a panel. doc 06 §4.5 makes this banner
        * "page-level, persistent until the underlying condition clears"; a tab
        * control is a new way to fail that, because a condition behind an
        * unselected tab is a condition the reader is not told about at all.
        * The scroll this change removed was bad; a silent alarm would be
        * worse. FE-113 holds it here with either tab open. */}
      <AlertBanner alerts={alertsFor(conditionsOf(events))} />
      <RunHeader run={detail} events={events} now={now} />
      {/* THE TIMELINE IS STILL FIRST, and still selected.
        *
        * The stacking this replaced was right about the order and wrong about
        * the reach. The timeline is the evidence chain and is what this page
        * is for; the activity log is the readable detail behind it, and doc 06
        * P3 puts the strongest claim first — so the timeline is tab one and
        * the tab that is open when the page loads, and nothing about that has
        * changed. What changed is what "second" costs. MEASURED on a real run:
        * 1220 tool calls, so "below the timeline" put the activity log several
        * hundred screens down and a reader had to scroll to the bottom of the
        * page to find out it existed. Second is now one key away.
        *
        * The counts live on the tabs for the same reason: §6.2's exact counts
        * are what tell a reader what is behind the tab they are not looking
        * at, which is the one thing a tab control takes away. doc 06 §3.3's
        * tool-call count is one of the two, and it now labels the panel that
        * actually holds the tool calls. */}
      <Tabs
        label={strings.tabs.region}
        tabs={[
          {
            id: "timeline",
            label: strings.timeline.heading,
            count: strings.tabs.events(events.length),
            panel: (
              <section className={block}>
                <Timeline
                  events={events}
                  now={now}
                  verifyCommit={verifyCommit}
                  {...(freshnessMs === undefined ? {} : { freshnessMs })}
                />
              </section>
            ),
          },
          {
            id: "activity",
            label: strings.activity.heading,
            count: strings.toolCall.count(toolCallCount(events)),
            panel: <ActivityLog runId={detail.run_id} />,
          },
        ]}
      />
    </>
  );
}

/** doc 06 §4.5's banner, one per condition, each linking to the event that
 * established it — "links directly to the evidence". */
function alertsFor(conditions: readonly Condition[]): readonly Alert[] {
  const copy = {
    drift: { title: strings.alert.drift, detail: strings.alert.driftDetail },
    unattributed: {
      title: strings.alert.unattributed,
      detail: strings.alert.unattributedDetail,
    },
    "chain-broken": {
      title: strings.alert.chainBroken,
      detail: strings.alert.chainBrokenDetail,
    },
  };
  return conditions.map((condition) => ({
    id: `${condition.kind}-${condition.anchorId}`,
    kind: "integrity" as const,
    title: copy[condition.kind].title,
    detail: copy[condition.kind].detail,
    evidenceHref: `#${condition.anchorId}`,
    evidenceLabel: strings.alert.evidence,
  }));
}
