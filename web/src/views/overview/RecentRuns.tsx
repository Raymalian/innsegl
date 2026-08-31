// SPDX-License-Identifier: Apache-2.0

/*
 * The recent runs list — doc 06 §3.1, §4.6, P4.
 *
 *   §3.1: "Recent runs list (last ~10)".
 *
 * A list and not a table, deliberately. doc 06 §3.2's runs table is RM-045's,
 * it carries filters, pagination and a per-run verification rollup, and a
 * second table here would be that component's poorer twin — kept in agreement
 * by hand and drifting the first time either changes. This is a list of
 * pointers into it: who ran, what state they are in, how many commits they
 * made, and a link to the run.
 *
 * NO VERIFICATION ROLLUP. §3.2 puts one on the runs table, where a row's
 * commits can be rolled up from live proofs. Nothing here has run a check, so
 * nothing here renders a verdict — not even an empty one (P2, IP §6.11).
 */

import { IdentifierChip, StatusBadge } from "../../components/common";
import { EmptyState } from "../../components/common";
import { routeToPath } from "../../app/routes";
import { strings } from "./strings";
import { listBase, listHeading, listRow, mutedText, secondaryText } from "./styles";
import type { RunSummary } from "./types";

export interface RecentRunsProps {
  /** Null when the runs index did not answer: an absent list is not an empty
   * one, and this renders neither as the other (P2). */
  readonly runs: readonly RunSummary[] | null;
}

export function RecentRuns({ runs }: RecentRunsProps) {
  if (runs === null) return null;
  return (
    <section className="flex flex-col gap-2">
      <h2 className={listHeading}>{strings.recentRuns.heading}</h2>
      {runs.length === 0 ? (
        <EmptyState
          title={strings.recentRuns.emptyTitle}
          detail={strings.recentRuns.emptyDetail}
        />
      ) : (
        <ul className={listBase}>
          {runs.map((run) => (
            <li key={run.run_id} className={listRow}>
              <StatusBadge status={run.status} />
              <IdentifierChip
                value={run.run_id}
                kind="run"
                href={routeToPath({ view: "run", runId: run.run_id })}
              />
              <span className={secondaryText}>{run.agent_type}</span>
              <span className={mutedText}>{strings.recentRuns.commits(run.commits)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
