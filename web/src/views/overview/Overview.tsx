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
import type { AlertRecord, OverviewData, PassRate, RunSummary, WindowedCount } from "./types";

/** doc 06 §3.1's "drift/alert feed": how many individual alerts the page
 * renders as their own banner before it stops naming them one by one and
 * summarises the rest (FE-111). P3 makes this the loudest thing on the
 * page — a banner per row past this bound would defeat "the calm state is
 * what's left" for everything below it. */
const MAX_ALERT_BANNERS = 10;

export interface OverviewProps {
  readonly data: OverviewData;
  /** doc 06 §3.1's "runs today". Not in the overview response — it is
   * `GET /api/v1/runs?from=<midnight UTC>&limit=1`'s `total`. Absent when
   * that read did not answer, which the card says rather than guesses. */
  readonly runsToday?: WindowedCount;
  /** Null when the runs index did not answer; an empty array when it did and
   * there are none. */
  readonly recentRuns?: readonly RunSummary[] | null;
  /** RM-102, #167. Null (or omitted) when the alerts read did not answer —
   * the banner falls back to `data.open_alerts`'s aggregate count rather than
   * rendering nothing. */
  readonly alerts?: readonly AlertRecord[] | null;
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
  alerts = null,
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
      <AlertBanner alerts={alertsOf(data, alerts, apiBase)} />

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
 * doc 06 §3.1's "drift/alert feed" and §4.5's banner — RM-102, #167.
 *
 * One AlertBanner entry per OPEN alert event, newest first, each carrying the
 * identifying fields #167 names and a link to its own evidence (P1): a drift
 * alert whose subject is a run's own record links to that run's detail view;
 * an unattributed alert names no run (doc 02 §3) and links to the filtered
 * raw record instead, the closest thing to "this alert's own page" that
 * exists without inventing a seventh view (doc 06 §3's six are fixed, and
 * FE-016 measures the count).
 *
 * `alerts === null` means the richer read did not answer, and the banner
 * falls back to `data.open_alerts`'s aggregate count (FE-111) — P2: a failed
 * list must not make the page say less than the count it already has.
 */
function alertsOf(
  data: OverviewData,
  alerts: readonly AlertRecord[] | null,
  apiBase: string,
): readonly Alert[] {
  if (alerts === null) {
    if (data.open_alerts <= 0) return [];
    return [
      {
        id: "open-alerts",
        kind: "integrity",
        title: strings.alerts.title(data.open_alerts),
        detail: strings.alerts.detail,
        evidenceHref: `${apiBase}/overview`,
        evidenceLabel: strings.alerts.evidenceLabel,
      },
    ];
  }

  const open = alerts.filter((a) => !a.resolved);
  if (open.length === 0) return [];

  const shown = open.slice(0, MAX_ALERT_BANNERS).map((a) => alertBannerOf(a, apiBase));
  const remaining = Math.max(data.open_alerts - shown.length, open.length - shown.length);
  if (remaining <= 0) return shown;

  return [
    ...shown,
    {
      id: "more-open-alerts",
      kind: "integrity",
      title: strings.alerts.moreTitle(remaining),
      detail: strings.alerts.moreDetail,
      evidenceHref: `${apiBase}/alerts`,
      evidenceLabel: strings.alerts.evidenceLabel,
    },
  ];
}

/** One alert event as one AlertBanner entry, per #167's identifying fields. */
function alertBannerOf(alert: AlertRecord, apiBase: string): Alert {
  if (alert.event_type === "ledger_drift_detected") {
    return {
      id: alert.event_id,
      kind: "integrity",
      title: strings.alerts.driftTitle,
      detail: strings.alerts.driftDetail(alert.reason ?? "", alert.subject_event_id ?? ""),
      evidenceHref: alert.run_id
        ? routeToPath({ view: "run", runId: alert.run_id })
        : `${apiBase}/alerts?event_type=ledger_drift_detected`,
      evidenceLabel: alert.run_id ? strings.alerts.viewRun : strings.alerts.rawRecord,
    };
  }
  return {
    id: alert.event_id,
    kind: "integrity",
    title: strings.alerts.unattributedTitle,
    detail: strings.alerts.unattributedDetail(
      alert.certificate_identity ?? "",
      alert.rekor_entry_uuid ?? "",
      alert.rekor_log_index ?? 0,
    ),
    evidenceHref: `${apiBase}/alerts?event_type=unattributed_signature_detected`,
    evidenceLabel: strings.alerts.rawRecord,
  };
}
