// SPDX-License-Identifier: Apache-2.0

/*
 * The recent runs table — doc 06 §3.1, §4.6, §6.4, P4.
 *
 *   §3.1: "Recent runs list (last ~10)".
 *
 * It WAS a list, and the artboard is the argument against it: five facts per
 * run — status, run id, agent, task, commit count — flowed inline with nothing
 * naming which was which, no way to read one fact down the page, and, the part
 * doc 06 §6.4 governs outright, nothing a screen reader could navigate as
 * tabular data:
 *
 *   "Screen-reader semantics: tables are real tables."
 *
 * So this is <table>, <caption>, <thead>, <th scope="col"> per column and a
 * <th scope="row"> per run, and not a grid of divs with roles bolted on. A
 * native table gives a screen-reader user row and column announcements, table
 * navigation commands and a row count, none of which a div acquires by being
 * told it is a row. The run id is the row header because it is what the other
 * four cells are about: a reader who lands on a commit count four columns in
 * is told whose it is.
 *
 * ── IT IS THE SAME TABLE AS THE RUNS VIEW, AND THAT IS ENFORCED ────────────
 *
 * The earlier argument for a list was that doc 06 §3.2's runs table is a
 * different component and a second table here would be its poorer twin, kept
 * in agreement by hand. That was right about the hazard and wrong about the
 * fix: the two are one treatment now, drawn from components/common/styles.ts
 * by both, and FE-121 compares the rendered class of a header cell and a body
 * cell in each. Restyling a table restyles both, by construction.
 *
 * What stays different is the CONTENT, and that is doc 06 rather than taste.
 *
 * NO VERIFICATION ROLLUP. §3.2 puts one on the runs table, where a row's
 * commits can be rolled up from live proofs. Nothing here has run a check, so
 * nothing here renders a verdict — not even an empty one (P2, IP §6.11). The
 * commits column is a count of records, which is what §3.1 asks for.
 *
 * NO FILTERS AND NO PAGINATION. Those are §3.2's, and this is the last ten.
 */

import { EmptyState, IdentifierChip, StatusBadge } from "../../components/common";
import { routeToPath } from "../../app/routes";
import { formatCount } from "./format";
import { strings } from "./strings";
import {
  cell,
  cellText,
  columnHeader,
  listHeading,
  listNote,
  numericCell,
  rowHeader,
  table,
  tableCaption,
  tablePanel,
  tablePanelHeader,
  tableScroll,
} from "./styles";
import type { RunSummary } from "./types";

export interface RecentRunsProps {
  /** Null when the runs index did not answer: an absent list is not an empty
   * one, and this renders neither as the other (P2). */
  readonly runs: readonly RunSummary[] | null;
}

export function RecentRuns({ runs }: RecentRunsProps) {
  if (runs === null) return null;
  return (
    <section aria-label={strings.recentRuns.heading} className={tablePanel}>
      <div className={tablePanelHeader}>
        <h2 className={listHeading}>{strings.recentRuns.heading}</h2>
        <span className={listNote}>{strings.recentRuns.order}</span>
      </div>
      {runs.length === 0 ? (
        <EmptyState
          title={strings.recentRuns.emptyTitle}
          detail={strings.recentRuns.emptyDetail}
        />
      ) : (
        <div className={tableScroll}>
          <table className={table}>
            {/* The accessible name, with the exact count (doc 06 §6.2). */}
            <caption className={tableCaption}>
              {strings.recentRuns.caption(runs.length)}
            </caption>
            <thead>
              <tr>
                <th scope="col" className={columnHeader}>
                  {strings.recentRuns.columns.status}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.recentRuns.columns.run}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.recentRuns.columns.agent}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.recentRuns.columns.task}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.recentRuns.columns.commits}
                </th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <RunRow key={run.run_id} run={run} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function RunRow({ run }: { readonly run: RunSummary }) {
  return (
    <tr>
      <td className={cell}>
        <StatusBadge status={run.status} />
      </td>
      {/* doc 06 P4: mono, middle-truncated, copyable, linked to its view. */}
      <th scope="row" className={rowHeader}>
        <IdentifierChip
          value={run.run_id}
          kind="run"
          href={routeToPath({ view: "run", runId: run.run_id })}
        />
      </th>
      <td className={`${cell} ${cellText}`}>{run.agent_type}</td>
      <td className={`${cell} ${cellText}`}>{run.task_ref}</td>
      <td className={numericCell}>{formatCount(run.commits)}</td>
    </tr>
  );
}
