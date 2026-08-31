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

import { Icon } from "../../components/common";
import { IdentifierChip } from "../../components/common";
import { StatusBadge } from "../../components/common";
import { VerificationSummary } from "../../components/verification";
import { Link } from "../../app/router";
import { routeToPath } from "../../app/routes";

import type { RunSummary } from "./api";
import type { CommitProof, RunProofSource } from "./proofs";
import { strings } from "./strings";
import {
  cell,
  cellList,
  cellStack,
  columnHeader,
  commitCount,
  mutedCell,
  notChecked,
  repoLink,
  rowHeader,
  srOnly,
  table,
  tableCaption,
  tableScroll,
  taskText,
} from "./styles";

export interface RunsTableProps {
  readonly runs: readonly RunSummary[];
  /** The number of runs the FILTER matched, which is not the number on screen. */
  readonly total: number;
  readonly proofs?: RunProofSource;
}

export function RunsTable({ runs, total, proofs }: RunsTableProps) {
  return (
    <div className={tableScroll}>
      <table className={table}>
        {/* The table's accessible name, with both exact counts (doc 06 §6.2). */}
        <caption className={tableCaption}>
          {strings.formats.caption(runs.length, total)}
        </caption>
        <thead>
          <tr>
            <th scope="col" className={columnHeader}>
              {strings.labels.columns.runId}
            </th>
            <th scope="col" className={columnHeader}>
              {strings.labels.columns.task}
            </th>
            <th scope="col" className={columnHeader}>
              {strings.labels.columns.repo}
            </th>
            <th scope="col" className={columnHeader}>
              {strings.labels.columns.commits}
            </th>
            <th scope="col" className={columnHeader}>
              {strings.labels.columns.status}
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
  );
}

function RunRow({
  run,
  proofs,
}: {
  readonly run: RunSummary;
  readonly proofs: readonly CommitProof[];
}) {
  return (
    <tr>
      <th scope="row" className={rowHeader}>
        {/* doc 06 P4: mono, middle-truncated, copyable, linked to its view. */}
        <IdentifierChip
          value={run.run_id}
          kind="run"
          href={routeToPath({ view: "run", runId: run.run_id })}
        />
      </th>
      <td className={cell}>
        <span className={taskText}>{run.task_ref}</span>
      </td>
      <td className={cell}>
        <Repos repos={run.repos} />
      </td>
      <td className={cell}>
        <Commits run={run} proofs={proofs} />
      </td>
      <td className={cell}>
        <StatusBadge status={run.status} />
      </td>
    </tr>
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
  return (
    <div className={cellStack}>
      <span className={commitCount}>{strings.formats.commits(run.commits)}</span>
      {proofs.length === 0 ? (
        <NotChecked />
      ) : (
        proofs.map((commit) => (
          <VerificationSummary
            key={commit.proof.commit_sha}
            proof={commit.proof}
            liveness={commit.liveness}
            findings={commit.findings}
            id={`${run.run_id}-${commit.proof.commit_sha}`}
          />
        ))
      )}
    </div>
  );
}

/**
 * What a row says when nobody verified anything for it.
 *
 * Not a badge, not a verdict, and not amber. doc 06 P2's three states describe
 * the outcome of a check; this is the absence of one, and dressing it as
 * "verification unavailable" would claim a check was attempted. The row says
 * what happened — nothing — and the run id beside it links to where the three
 * checks can actually run.
 */
function NotChecked() {
  return (
    <p
      className={notChecked}
      title={strings.sentences.verification.notChecked}
    >
      <Icon name="unknown" className="mt-[0.15em] shrink-0" />
      <span>{strings.labels.verification.notChecked}</span>
      <span className={srOnly}>{strings.sentences.verification.notChecked}</span>
    </p>
  );
}
