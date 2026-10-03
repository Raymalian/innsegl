// SPDX-License-Identifier: Apache-2.0

/*
 * The runs table — doc 06 §3.2's five columns.
 *
 *   "Filterable, paginated table: agent run (mono ID), task, repo, commit
 *    count with per-run verification rollup, status badge (Active / Retired /
 *    Expired ...)."
 *
 * ── IT IS A TABLE ──────────────────────────────────────────────────────────
 *
 * doc 06 §6.4: "Screen-reader semantics: tables are real tables." So this is
 * <table>, <caption>, <thead>, <th scope="col"> and a <th scope="row"> per
 * row, and not a grid of divs with ARIA roles bolted on. A native table gives
 * a screen-reader user row and column announcements, table navigation
 * commands, and a count of rows, none of which a div acquires by being told it
 * is a row. FE-050 asserts the structure from rendered output.
 *
 * The run id is the row header because it is what the other four cells are
 * about: with `scope="row"` a reader who lands on a status badge four columns
 * in is told which run it belongs to.
 *
 * ── THE VERIFICATION CELL DOES NOT ROLL ANYTHING UP BY ITSELF ──────────────
 *
 * doc 06 §8 anti-pattern 4 is "a verification summary that cannot be expanded
 * to the three checks and their inputs", and §4.1 permits a rollup badge in a
 * table only where it "always expands to the panel". VerificationSummary is
 * that component — a native <details> whose summary is the badge and whose
 * body is the three-check panel — so this cell composes it once per commit
 * proof rather than inventing a row-level icon.
 *
 * There is no run-level badge across several commits, and that is a reading of
 * doc 06 rather than an omission: §4.1 defines a rollup over the three CHECKS
 * of one commit, and a second rollup over several commits would be a new
 * verdict with no expansion behind it — anti-pattern 4 at the row level. Two
 * commits, two badges, each expanding to its own evidence.
 *
 * Nothing in this file spends a colour that means anything. The one green in
 * the product belongs to components/verification, and a row reaches it only by
 * handing a proof to that component (see proofs.ts).
 */

import {
  StatusBadge,
  formatAbsoluteUtc,
  toDateTimeAttribute,
} from "../../components/common";
import { formatAbsoluteUtcShort } from "../../components/common/time";
import { VerificationSummary } from "../../components/verification";
import { Link } from "../../app/router";
import { lastSeenAgo } from "./lastseen";
import type { RunsFilters } from "../../app/routes";

import type { RunSummary } from "./api";
import { runsLinkPath } from "./api";
import type { CommitProof, RunProofSource } from "./proofs";
import { strings } from "./strings";
import {
  orderToggle,
  cell,
  cellList,
  cellStack,
  columnHeader,
  commitCount,
  mutedCell,
  repoLink,
  rowHeader,
  table,
  tableCaption,
  tablePanel,
  tableScroll,
  taskText,
} from "./styles";

export interface RunsTableProps {
  readonly runs: readonly RunSummary[];
  /** The filters this page was fetched with. The order control needs them so
   *  that flipping the direction keeps every filter and drops only the cursor,
   *  which is a position in the OLD ordering and means nothing in the new one. */
  readonly filters?: RunsFilters;
  /** The number of runs the FILTER matched, which is not the number on screen. */
  readonly total: number;
  readonly proofs?: RunProofSource;
}

export function RunsTable({ runs, total, proofs, filters }: RunsTableProps) {
  const ascending = filters?.order === "asc";
  return (
    /* The same card the overview's recent runs sit in, from the same module
       (FE-121). doc 06 §3.1 and §3.2 are one treatment; two copies kept in
       agreement by hand is what drifts. */
    <div className={tablePanel}>
      <div className={tableScroll}>
        <table className={table}>
          {/* The table's accessible name, with both exact counts (doc 06 §6.2). */}
          <caption className={tableCaption}>
            {strings.formats.caption(runs.length, total)}
          </caption>
          <thead>
            <tr>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.status}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.repo}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.agentType}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.task}
              </th>
              <th
                scope="col"
                className={columnHeader}
                /* The ledger sorts by chain position, which is registration
                 * order: this is the column that order belongs to. Stated
                 * explicitly so a reader need not infer it from the rows. */
                aria-sort={ascending ? "ascending" : "descending"}
              >
                {strings.labels.columns.started}
                {filters ? (
                  <>
                    {" "}
                    <a
                      className={orderToggle}
                      href={runsLinkPath({
                        ...filters,
                        order: ascending ? "desc" : "asc",
                        cursor: "",
                      })}
                    >
                      {ascending
                        ? strings.labels.order.switchToNewest
                        : strings.labels.order.switchToOldest}
                    </a>
                  </>
                ) : null}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.lastSeen}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.labels.columns.commits}
              </th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <RunRow key={run.run_id} run={run} proofs={proofs?.(run) ?? []} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RunRow({
  run,
  proofs,
}: {
  readonly run: RunSummary;
  readonly proofs: readonly CommitProof[];
}) {
  const now = new Date();
  return (
    <tr>
      <td className={cell}>
        <StatusBadge status={run.status} />
      </td>
      <td className={cell}>
        <Repos repos={run.repos} />
      </td>
      <td className={`${cell} ${taskText}`}>{run.agent_type}</td>
      {/* The row's name: the task, linked to the run (doc 06 P4). The run ID
        * is the link's tooltip, and is on the run's own page. */}
      <th scope="row" className={rowHeader}>
        <Link
          to={{ view: "run", runId: run.run_id }}
          className={repoLink}
          title={run.run_id}
        >
          {run.task_ref}
        </Link>
      </th>
      <td className={cell}>
        <Moment at={run.registered_at} now={now} />
      </td>
      <td className={cell}>
        <Moment at={run.last_event_at} now={now} relative />
      </td>
      <td className={cell}>
        <Commits run={run} proofs={proofs} />
      </td>
    </tr>
  );
}

/** A time a reader can read at a glance, with the exact UTC moment on hover
 * and in the markup (doc 06 §6.2). */
function Moment({
  at,
  now,
  relative = false,
}: {
  readonly at: string;
  readonly now: Date;
  readonly relative?: boolean;
}) {
  const when = new Date(at);
  if (at === "" || Number.isNaN(when.getTime())) {
    return <span className={mutedCell}>{strings.labels.table.noTime}</span>;
  }
  return (
    <time
      dateTime={toDateTimeAttribute(when)}
      title={formatAbsoluteUtc(when)}
      className="tabular-nums"
    >
      {relative ? lastSeenAgo(at, now) : formatAbsoluteUtcShort(when, now)}
    </time>
  );
}

function Repos({ repos }: { readonly repos: readonly string[] }) {
  if (repos.length === 0) {
    return <span className={mutedCell}>{strings.labels.table.noRepos}</span>;
  }
  return (
    <ul className={cellList}>
      {repos.map((repo) => (
        <li key={repo}>
          <Link
            to={{ view: "repo", repo, from: "", to: "" }}
            className={repoLink}
          >
            {repo}
          </Link>
        </li>
      ))}
    </ul>
  );
}

function Commits({
  run,
  proofs,
}: {
  readonly run: RunSummary;
  readonly proofs: readonly CommitProof[];
}) {
  /* No note here: the one note that says this list runs no live check is
   * above the table. A row shows a verdict only when it was handed a proof. */
  return (
    <div className={cellStack}>
      <span className={commitCount}>{strings.formats.commits(run.commits)}</span>
      {proofs.map((commit) => (
        <VerificationSummary
          key={commit.proof.commit_sha}
          proof={commit.proof}
          liveness={commit.liveness}
          findings={commit.findings}
          id={`${run.run_id}-${commit.proof.commit_sha}`}
        />
      ))}
    </div>
  );
}
