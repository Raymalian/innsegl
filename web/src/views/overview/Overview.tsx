// SPDX-License-Identifier: Apache-2.0

/*
 * The overview — doc 06 §3.1. The landing view, and the system's public pulse.
 *
 * The order of this page is doc 06 P3 read literally: "Design the alarm first;
 * the calm state is what's left." Alerts are the first thing in the main
 * region, above the heading, above every metric — §3.1 says they "pin to the
 * top of this page in the P3 style" — and everything below them is quiet.
 *
 * What this view does NOT do is the part worth stating. It runs no
 * verification and renders no verdict. Every number on it is a count of rows
 * in an append-only ledger, and a count of records is not a claim that any of
 * them is provable: `commits_recorded` says the ledger holds a
 * `commit_recorded` event, nothing more. The one place doc 06 §3.1 asks for a
 * verdict-shaped number — the verification pass rate — is a genuine conflict
 * with doc 06 P2 and IP §6.11, and PassRateCard carries the argument.
 *
 * Presentational on purpose: it takes data and renders it. The fetching lives
 * in `data.ts` and the wiring in `OverviewView.tsx`, so every state this page
 * has is reachable in a test without a network.
 */

import {
  AlertBanner,
  StalenessIndicator,
  formatAbsoluteUtc,
} from "../../components/common";
import type { Alert } from "../../components/common";
import { useStrings } from "../../app/i18n";
import { routeToPath } from "../../app/routes";
import { AnchoringEvidence, AnchoringPulse, DEFAULT_LAG_BOUND_MS } from "./AnchoringPulse";
import { formatCount } from "./format";
import { MetricCard } from "./MetricCard";
import { PassRateCard } from "./PassRateCard";
import { RecentRuns } from "./RecentRuns";
import { strings } from "./strings";
import { cardGrid, heading, page, prose } from "./styles";
import type { OverviewData, PassRate, RunSummary, WindowedCount } from "./types";

export interface OverviewProps {
  readonly data: OverviewData;
  /** doc 06 §3.1's "runs today". Not in the overview response — it is
   * `GET /api/v1/runs?from=<midnight UTC>&limit=1`'s `total`. Absent when
   * that read did not answer, which the card says rather than guesses. */
  readonly runsToday?: WindowedCount;
  /** Null when the runs index did not answer; an empty array when it did and
   * there are none. */
  readonly recentRuns?: readonly RunSummary[] | null;
  /** A LIVE pass rate, if anything ever measures one. Nothing does. */
  readonly passRate?: PassRate;
  /** The configured anchoring-lag bound. Not served by the query API today —
   * `internal/segment`'s LagSnapshot has it and nothing exposes it — so this
   * defaults to the same 15 minutes `internal/segment/anchor.go` defaults to.
   * Reported as a gap. */
  readonly lagBoundMs?: number;
  /** Where the query API lives, for the links that point at raw material. */
  readonly apiBase: string;
  /** Injected for determinism; defaults to the wall clock. */
  readonly now?: Date;
}

export function Overview({
  data,
  runsToday,
  recentRuns = null,
  passRate,
  lagBoundMs = DEFAULT_LAG_BOUND_MS,
  apiBase,
  now,
}: OverviewProps) {
  const at = now ?? new Date();
  const appStrings = useStrings();

  return (
    <div className={page}>
      {/* P3, and §3.1's "alerts pin to the top of this page". */}
      <AlertBanner alerts={alertsOf(data.open_alerts, apiBase)} />

      <StalenessIndicator />

      <header className="flex flex-col gap-1">
        <h1 className={heading}>{appStrings.labels.views.overview}</h1>
        <p className={prose}>{strings.page.summary}</p>
      </header>

      <section aria-label={strings.metrics.regionLabel} className={cardGrid}>
        <MetricCard
          id="active-agents"
          label={strings.metrics.activeAgents.label}
          value={formatCount(data.active_runs)}
          meaning={strings.metrics.activeAgents.meaning}
        />
        <MetricCard
          id="runs-today"
          label={strings.metrics.runsToday.label}
          value={
            runsToday === undefined
              ? strings.metrics.runsToday.unknown
              : formatCount(runsToday.count)
          }
          meaning={
            runsToday === undefined
              ? strings.metrics.runsToday.unknownMeaning
              : strings.metrics.runsToday.meaning(formatAbsoluteUtc(runsToday.since))
          }
          tone={runsToday === undefined ? "degraded" : "neutral"}
        />
        <MetricCard
          id="commits"
          label={strings.metrics.commits.label}
          value={formatCount(data.commits_recorded)}
          meaning={strings.metrics.commits.meaning}
        />
        <PassRateCard
          commitsRecorded={data.commits_recorded}
          rate={passRate}
          now={at}
          verifyHref={routeToPath({ view: "verify", commit: "", repo: "" })}
        />
      </section>

      <section className="flex flex-col gap-2">
        <AnchoringPulse anchor={data.anchor} lagBoundMs={lagBoundMs} now={at} />
        <AnchoringEvidence anchor={data.anchor} />
      </section>

      <RecentRuns runs={recentRuns} />
    </div>
  );
}

/**
 * doc 06 §4.5's banner, from the one thing the query API says about drift.
 *
 * `open_alerts` is a COUNT of `unattributed_signature_detected` and
 * `ledger_drift_detected` events, and there is no endpoint that lists them —
 * they carry no `run_id`, so the runs index does not hold them either. P1 asks
 * every alert to link to its evidence; the closest honest link is the response
 * this count came from, and the copy says in as many words that the events
 * themselves are not exposed. Reported as a gap rather than papered over with
 * a link that goes nowhere.
 */
function alertsOf(openAlerts: number, apiBase: string): readonly Alert[] {
  if (openAlerts <= 0) return [];
  return [
    {
      id: "open-alerts",
      kind: "integrity",
      title: strings.alerts.title(openAlerts),
      detail: strings.alerts.detail,
      evidenceHref: `${apiBase}/overview`,
      evidenceLabel: strings.alerts.evidenceLabel,
    },
  ];
}
