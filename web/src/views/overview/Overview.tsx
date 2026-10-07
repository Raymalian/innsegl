// SPDX-License-Identifier: Apache-2.0

/*
 * The overview — doc 06 §3.1. The landing view, and the system's public pulse.
 *
 * Open alerts are not on this page. They were banners stacked above the
 * heading, as §3.1 and §4.5 asked; ADR-0054 moved them to a notification menu
 * in the persistent header, where they are on every view rather than this one
 * and no longer push the metrics below a fold. P3 is kept by that menu's red
 * badge — see views/alerts.
 *
 * What this view does NOT do is the part worth stating. It runs no
 * verification and renders no verdict. Every number on it is a count of rows
 * in an append-only ledger, and a count of records is not a claim that any of
 * them is provable: `commits_recorded` says the ledger holds a
 * `commit_recorded` event, nothing more. The one place doc 06 §3.1 asks for a
 * verdict-shaped number — the verification pass rate — is a genuine conflict
 * with doc 06 P2 and IP §6.11, and PassRateCard carries the argument.
 *
 * ── THE PULSE IS NOT ON THIS PAGE (FE-114) ─────────────────────────────────
 *
 * doc 06 §3.1 puts the anchoring heartbeat in ONE place and says which:
 * "Anchoring heartbeat in the persistent header (all views)". The shell owns
 * that header and takes the pulse as a prop; `OverviewHeartbeat` fills the
 * slot. This page rendered a second `AnchoringPulse` of its own, so a reader
 * on "/" saw the same sentence twice.
 *
 * Two renderings of one fact is not redundancy here, it is a second place the
 * fact can be wrong: the two read the same endpoint through two independent
 * hooks, so a slow or failing second read put "Ledger segment 8421 anchored 3
 * min ago" directly above "Couldn't read the anchoring heartbeat" on one
 * screen — which is P2's collapse of "current" and "unknown" arrived at by
 * accident rather than by design. The approved artboard shows one pulse per
 * screen and puts it beside the view heading, because that artboard has no
 * persistent header to put it in; this application does, and §3.1 names it.
 *
 * `AnchoringEvidence` stays, and is not the pulse: the chain positions, the
 * segment digest and the Rekor index are the MATERIAL behind the claim (P1),
 * they appear nowhere else in the product, and a one-line header cannot carry
 * them.
 *
 * Presentational on purpose: it takes data and renders it. The fetching lives
 * in `data.ts` and the wiring in `OverviewView.tsx`, so every state this page
 * has is reachable in a test without a network.
 */

import { StalenessIndicator, formatAbsoluteUtc } from "../../components/common";
import { useStrings } from "../../app/i18n";
import { routeToPath } from "../../app/routes";
import { AnchoringEvidence } from "./AnchoringPulse";
import { formatCount } from "./format";
import { formatDuration } from "../../components/common";
import { MetricCard } from "./MetricCard";
import { PassRateCard } from "./PassRateCard";
import { RecentRuns } from "./RecentRuns";
import { strings } from "./strings";
import { cardGrid, heading, link, mutedText, page, prose } from "./styles";
import { TrustExpiryNotice } from "./TrustExpiryNotice";
import type { TrustExpiry, TrustProblem } from "./TrustExpiryNotice";
import type { OverviewData, PassRate, RunSummary, WindowedCount } from "./types";

/** The alerts view lives at this path. */
const ALERTS_PATH = "/alerts";

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
  /** The live pass rate is being measured. */
  readonly measuring?: boolean;
  /** ADR-0073: the CAs in use and when they expire; a warning renders for
   * any within a year. Empty renders nothing. */
  readonly trustExpiries?: readonly TrustExpiry[];
  /** ADR-0073: what the trust watch's last pass found wrong. */
  readonly trustProblems?: readonly TrustProblem[];
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
  measuring = false,
  trustExpiries = [],
  trustProblems = [],
  now,
}: OverviewProps) {
  const at = now ?? new Date();
  const appStrings = useStrings();

  return (
    <div className={page}>
      <StalenessIndicator />

      <header className="flex flex-col gap-1">
        <h1 className={heading}>{appStrings.labels.views.overview}</h1>
        <p className={prose}>{strings.page.summary}</p>
      </header>

      <TrustExpiryNotice expiries={trustExpiries} problems={trustProblems} />

      <section aria-label={strings.metrics.regionLabel} className={cardGrid}>
        <MetricCard
          id="active-agents"
          label={strings.metrics.activeAgents.label}
          value={formatCount(data.active_runs - (data.idle_runs ?? 0))}
          description={strings.metrics.activeAgents.description}
          definition={
            <>
              <p>{strings.metrics.activeAgents.meaning}</p>
              <WithdrawnHorizon data={data} />
            </>
          }
        >
          <IdleBreakdown data={data} />
          <WithdrawnBreakdown data={data} />
        </MetricCard>
        <MetricCard
          id="runs-today"
          label={strings.metrics.runsToday.label}
          value={
            runsToday === undefined
              ? strings.metrics.runsToday.unknown
              : formatCount(runsToday.count)
          }
          description={
            runsToday === undefined
              ? strings.metrics.runsToday.unknownDescription
              : strings.metrics.runsToday.description
          }
          definition={
            <p>
              {runsToday === undefined
                ? strings.metrics.runsToday.unknownMeaning
                : strings.metrics.runsToday.meaning(formatAbsoluteUtc(runsToday.since))}
            </p>
          }
          tone={runsToday === undefined ? "degraded" : "neutral"}
        />
        <MetricCard
          id="commits"
          label={strings.metrics.commits.label}
          value={formatCount(data.commits_recorded)}
          description={strings.metrics.commits.description}
          definition={<p>{strings.metrics.commits.meaning}</p>}
        />
        <MetricCard
          id="open-alerts"
          label={strings.metrics.openAlerts.label}
          value={formatCount(data.open_alerts)}
          description={strings.metrics.openAlerts.description}
          definition={<p>{strings.metrics.openAlerts.meaning}</p>}
        >
          <a href={ALERTS_PATH} className={link}>
            {strings.metrics.openAlerts.link}
          </a>
        </MetricCard>
      </section>

      <PassRateCard
        commitsRecorded={data.commits_recorded}
        rate={passRate}
        measuring={measuring}
        now={at}
        verifyHref={routeToPath({ view: "verify", commit: "", repo: "" })}
      />

      {/* The PULSE is not here — see the note on the duplicate below. The
        * material behind it is: doc 06 P1 wants the claim and its evidence
        * together, and a one-line header cannot carry a chain range, a segment
        * digest and a Rekor index. */}
      <AnchoringEvidence anchor={data.anchor} now={at} />

      <RecentRuns runs={recentRuns} now={at} />
    </div>
  );
}

/**
 * What became of the runs that are not active — #256.
 *
 * Two counts and the horizon that separates them, under the active figure and
 * never added into it. They are on this card rather than on cards of their own
 * for a reason the design system already states: MetricCard's `children` slot
 * is for "a breakdown, a link to the material", and a lapsed run is exactly a
 * breakdown of the question "and the rest?" that the active number raises.
 *
 * Neither line says anything about an agent. "Lapsed" and "Abandoned" are
 * statements about what this system will and will not do with an identity —
 * restore it, or refuse to — and nothing here can see whether an agent is
 * still working (IP E7). FE-131 and FE-132 hold that.
 */
/** Active runs that have recorded nothing lately: registered, not ended, and
 * not working now. Kept out of the headline so it answers "how many are
 * working", and named here so no run disappears from the card. */
function IdleBreakdown({ data }: { readonly data: OverviewData }) {
  const idle = data.idle_runs ?? 0;
  if (idle === 0) return null;
  const after = formatDuration((data.idle_after_seconds ?? 15 * 60) * 1000);
  return (
    <p className={mutedText}>
      {strings.metrics.activeAgents.idle(formatCount(idle), after)}
    </p>
  );
}

/** The two counts kept apart from "active", one line, only when there is one. */
function WithdrawnBreakdown({ data }: { readonly data: OverviewData }) {
  if (data.lapsed_runs === 0 && data.abandoned_runs === 0) return null;
  return (
    <p className={mutedText}>
      {strings.metrics.activeAgents.breakdown(
        formatCount(data.lapsed_runs),
        formatCount(data.abandoned_runs),
      )}
    </p>
  );
}

/** The horizon the two were split with: part of the definition. */
function WithdrawnHorizon({ data }: { readonly data: OverviewData }) {
  if (data.lapsed_runs === 0 && data.abandoned_runs === 0) return null;
  const seconds = data.restore_horizon_seconds;
  const horizon =
    seconds === undefined
      ? strings.metrics.activeAgents.horizonUnknown
      : seconds <= 0
        ? strings.metrics.activeAgents.noHorizon
        : strings.metrics.activeAgents.horizon(formatDuration(seconds * 1000));
  return <p>{horizon}</p>;
}
