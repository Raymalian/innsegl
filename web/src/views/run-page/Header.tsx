// SPDX-License-Identifier: Apache-2.0

/*
 * The run page's header — Main.dc.html's breadcrumb, heading, status pill and
 * four fact cards. doc 06 §3.3's "full SPIFFE ID (mono, copyable), agent
 * type, task ref" plus the mockup's own activity/witness rollup.
 */

import { Icon } from "../../components/common/Icon";
import type { IconName } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import type { RunStatus } from "../../components/common/StatusBadge";
import { formatAbsoluteUtcShort } from "../../components/common/time";
import { Link } from "../../app/router";
import { Instant } from "../run-detail";
import {
  activitySummary,
  allWitnessesAgree,
  everyBodyStoredAndVerified,
  shortRepo,
} from "./derive";
import { strings } from "./strings";
import {
  bodyNote,
  breadcrumb,
  factCard,
  factGrid,
  factLabel,
  factRowIcon,
  factValue,
  headerRow,
  pageHeading,
  statusPill,
} from "./styles";
import type { RunRecord } from "./types";

const KNOWN_STATUSES: readonly RunStatus[] = ["active", "lapsed", "abandoned", "retired"];

export interface HeaderProps {
  readonly record: RunRecord;
  readonly now: Date;
}

export function Header({ record, now }: HeaderProps) {
  const { run, witness } = record;
  const activity = activitySummary(record);
  const status = KNOWN_STATUSES.find((s) => s === run.status);

  return (
    <div className="flex flex-col gap-3">
      <nav aria-label={strings.header.runsCrumb} className={breadcrumb}>
        <Link to={{ view: "runs", filters: emptyFilters() }}>{strings.header.runsCrumb}</Link>
        <span aria-hidden="true">{strings.punctuation.slash}</span>
        <Link to={{ view: "repo", repo: run.repo, from: "", to: "" }}>{run.repo}</Link>
        <span aria-hidden="true">{strings.punctuation.slash}</span>
        <IdentifierChip value={run.run_id} kind="run" maxLength={28} />
      </nav>

      <div className={headerRow}>
        <h1 className={pageHeading}>{strings.header.heading(run.agent_type)}</h1>

        {status === undefined ? null : (
          <span className={statusPill} data-run-status={status}>
            <Icon name={STATUS_ICON[status]} className="shrink-0" />
            <span className="font-medium">{statusLabel(status)}</span>
            {run.status_at === undefined || run.status_at === null || run.status_at === "" ? null : (
              <>
                {/* The mockup shows the absolute instant visibly, beside the
                  * relative one ("Retired 14:31:58 UTC · 3 min ago") — unlike
                  * the rest of the product's RelativeTime convention, which
                  * keeps the absolute behind hover/focus. `Instant` still
                  * carries that pattern for the relative half; this span is
                  * the one place on this page the absolute is stated outright
                  * rather than only reachable. The time of day when it was
                  * today (UTC), as the approved mockup shows it; the full
                  * date otherwise (formatAbsoluteUtcShort). */}
                <span aria-hidden="true">{formatAbsoluteUtcShort(new Date(run.status_at), now)}</span>
                <span aria-hidden="true">{strings.punctuation.middot}</span>
                <Instant value={run.status_at} now={now} label={statusLabel(status)} />
              </>
            )}
          </span>
        )}

        <div className="flex-grow" />

        <span className={bodyNote}>
          {everyBodyStoredAndVerified(witness)
            ? strings.header.witnessesComplete
            : strings.header.witnessesIncomplete(
                witness.bodies_stored,
                witness.bodies_verified,
                witness.steps,
              )}
        </span>
      </div>

      <dl className={factGrid}>
        <div className={factCard}>
          <dt className={factLabel}>{strings.facts.identity}</dt>
          <dd className={factValue}>
            <IdentifierChip
              value={run.spiffe_id}
              kind="spiffe"
              maxLength={40}
            />
          </dd>
        </div>
        <div className={factCard}>
          <dt className={factLabel}>{strings.facts.repoBranch}</dt>
          <dd className={`${factValue} font-mono text-micro`}>
            {shortRepo(run.repo)}
            {strings.punctuation.middot}
            {run.branch}
          </dd>
        </div>
        <div className={factCard}>
          <dt className={factLabel}>{strings.facts.activity}</dt>
          <dd className={factValue}>
            {strings.facts.activitySummary(
              activity.steps,
              activity.commits,
              activity.subagents,
              activity.files,
            )}
          </dd>
        </div>
        <div className={factCard}>
          <dt className={factLabel}>{strings.facts.witnesses}</dt>
          <dd className={`${factValue} ${factRowIcon}`}>
            <WitnessGlyph agree={allWitnessesAgree(witness)} />
            <span>
              {allWitnessesAgree(witness)
                ? strings.facts.witnessesAgreeAll(witness.steps)
                : strings.facts.witnessesDisagreeSummary(witness.disagree, witness.steps)}
            </span>
          </dd>
        </div>
      </dl>
    </div>
  );
}

function emptyFilters() {
  return {
    repo: "",
    agentType: "",
    status: "" as const,
    search: "",
    from: "",
    to: "",
    cursor: "",
    limit: "",
    order: "" as const,
  };
}

/** The four run-status icons, named the same way StatusBadge's own
 * presentation table names them (components/common/StatusBadge.tsx) — the
 * pill here carries its own word and timestamp beside it, in the mockup's
 * single-line shape, so only the glyph is reused rather than the whole
 * badge. */
const STATUS_ICON: Record<RunStatus, IconName> = {
  active: "status-active",
  lapsed: "status-lapsed",
  abandoned: "status-abandoned",
  retired: "status-retired",
};

function statusLabel(status: RunStatus): string {
  const labels: Record<RunStatus, string> = {
    active: "Active",
    lapsed: "Lapsed",
    abandoned: "Abandoned",
    retired: "Retired",
  };
  return labels[status];
}

function WitnessGlyph({ agree }: { readonly agree: boolean }) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 24 24"
      width="14"
      height="14"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
    >
      {agree ? (
        <path d="M4 12l5 5L20 6" strokeLinecap="round" strokeLinejoin="round" />
      ) : (
        <path d="M12 7v6M12 16.5v.5" strokeLinecap="round" />
      )}
    </svg>
  );
}
