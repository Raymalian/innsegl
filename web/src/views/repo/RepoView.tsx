// SPDX-License-Identifier: Apache-2.0

/*
 * The repository view — doc 06 §3.4.
 *
 *   "All attributed commits in a repo, grouped by agent identity; attribution
 *    coverage ('% of commits in window with verified agent identity');
 *    link-out to the repo host."
 *
 * ── WHAT THIS VIEW SHOWS, AND WHAT IT REFUSES TO ───────────────────────────
 *
 * COMMITS. internal/api exposes no commit-level listing: its five routes are
 * runs, one run, the overview, one commit's live proof, and health. The
 * commits are reachable — they are `commit_recorded` events inside each run's
 * timeline — but only one run at a time, which for a repository's whole window
 * is N+1 requests and is doc 06 §7's "ship-the-table-to-the-client" with extra
 * steps. So this view groups the RUNS by agent identity, says so, and links
 * each one to the detail view that holds its commits and their three-check
 * panels. The missing endpoint is reported rather than worked around.
 *
 * COVERAGE. Refused, in prose, with both reasons. See strings.ts — the
 * denominator is a fact about the repository host and the numerator would have
 * to be verified rather than recorded. The only percentage this data can
 * produce is 100%, forever, which is doc 06 §8's tenth anti-pattern in its
 * purest form.
 *
 * VERIFICATION. None. This view holds no proof, renders no verdict and spends
 * no green. That is why it imports nothing from components/verification: doc 06
 * §4.1 does list the repo view among the panel's homes, but the panel takes a
 * proof for a named commit and this view has no commit to name. A badge here
 * would be a verdict about nothing, and a cached one would be doc 06 §8's
 * first anti-pattern.
 *
 * COUNTS. Two, and both are the server's. `total` is `count(*) OVER ()` inside
 * internal/api's own statement, taken over the window this page prints; the
 * number of rows drawn is what is in front of the reader. Where those agree
 * the grouping is the whole windowed set and each identity's count is printed;
 * where they do not, no count is taken over the page. There is no sum of
 * commits anywhere: `commits` is a run's total across every repository it
 * touched, so adding a page of them up would produce a confident wrong number
 * for this one.
 */

import { useEffect, useMemo, useState } from "react";

import {
  EmptyState,
  ErrorState,
  Icon,
  IdentifierChip,
  LoadingState,
  StalenessIndicator,
  StatusBadge,
  formatAbsoluteUtc,
  toDateTimeAttribute,
} from "../../components/common";
import { Link } from "../../app/router";
import type { Route } from "../../app/routes";
import { PAGE_LIMIT, fetchRuns } from "./query";
import type { LoadRuns, RunPage, RunSummary } from "./query";
import { groupByIdentity, hostUrlOf, isComplete, resolveWindow } from "./repo";
import type { IdentityGroup, StatedWindow } from "./repo";
import { strings } from "./strings";
import {
  explanation,
  factList,
  factRow,
  factTerm,
  identifierText,
  identityGroup,
  inlineRow,
  link,
  mutedText,
  sectionHeading,
  sectionShell,
  secondaryText,
  table,
  tableCaption,
  tableCell,
  tableHeader,
  viewHeading,
  viewShell,
} from "./styles";

export interface RepoViewProps {
  /** The shell hands every view the whole route union; this one renders the
   * `repo` member of it and refuses the rest rather than guessing. */
  readonly route: Route;
  /** The read. Injected so a test needs no network and a render is
   * deterministic; there is no second path to the query API from here. */
  readonly load?: LoadRuns;
  /** The clock the default window is measured back from. Injected for the
   * same reason. */
  readonly now?: Date;
}

export function RepoView({ route, load = fetchRuns, now }: RepoViewProps) {
  if (route.view !== "repo") {
    return (
      <ErrorState
        title={strings.labels.wrongRoute}
        detail={strings.sentences.wrongRoute}
      />
    );
  }
  return (
    <Repository repo={route.repo} from={route.from} to={route.to} load={load} now={now} />
  );
}

type Phase =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly page: RunPage }
  | { readonly phase: "error"; readonly message: string };

function Repository({
  repo,
  from,
  to,
  load,
  now,
}: {
  readonly repo: string;
  readonly from: string;
  readonly to: string;
  readonly load: LoadRuns;
  readonly now: Date | undefined;
}) {
  // One clock per mount, so a re-render cannot move the default window under
  // the counts already drawn against it.
  const [mountedAt] = useState(() => new Date());
  const clock = now ?? mountedAt;
  const window = useMemo(() => resolveWindow(from, to, clock), [from, to, clock]);

  const [state, setState] = useState<Phase>({ phase: "loading" });
  const [attempt, setAttempt] = useState(0);
  const fromMs = window.from.getTime();
  const toMs = window.to.getTime();

  useEffect(() => {
    const controller = new AbortController();
    setState({ phase: "loading" });
    load(
      { repo, from: new Date(fromMs), to: new Date(toMs), limit: PAGE_LIMIT },
      controller.signal,
    ).then(
      (page) => {
        if (!controller.signal.aborted) setState({ phase: "ready", page });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setState({ phase: "error", message: messageOf(error) });
        }
      },
    );
    return () => controller.abort();
  }, [load, repo, fromMs, toMs, attempt]);

  const hostUrl = hostUrlOf(repo);
  const retry = () => setAttempt((n) => n + 1);

  return (
    <div className={viewShell}>
      <header className="flex flex-col gap-2">
        <p className={mutedText}>{strings.labels.repository}</p>
        <h1 className={viewHeading}>{repo}</h1>
        {hostUrl === null ? (
          <p className={secondaryText}>{strings.sentences.noHostLink}</p>
        ) : (
          <a href={hostUrl} rel="noreferrer" className={`${link} ${inlineRow}`}>
            <Icon name="open" />
            <span>{strings.labels.openOnHost}</span>
          </a>
        )}
      </header>

      {/* doc 06 §4.4: every affected view carries the marker, and this
       * component renders nothing at all while the read path is healthy. */}
      <StalenessIndicator />

      <Summary window={window} state={state} />
      <Coverage />

      {state.phase === "loading" ? (
        <LoadingState what={strings.nouns.runs} onRetry={retry} />
      ) : null}
      {state.phase === "error" ? (
        <ErrorState detail={state.message} onRetry={retry} />
      ) : null}
      {state.phase === "ready" ? <Attributed page={state.page} /> : null}
    </div>
  );
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/* ── the window, and the two counts measured over it ──────────────────────── */

/**
 * doc 06 §8's tenth anti-pattern names "cumulative counts with no window". The
 * window is a property of the address rather than of the answer, so it renders
 * before the answer arrives and beside it afterwards — a reader never sees a
 * number here without the bounds it was counted over.
 */
function Summary({
  window,
  state,
}: {
  readonly window: StatedWindow;
  readonly state: Phase;
}) {
  return (
    <div role="group" aria-label={strings.labels.summary} className={sectionShell}>
      <dl className={factList}>
        <Fact term={strings.labels.windowFrom}>
          <Instant at={window.from} />
        </Fact>
        <Fact term={strings.labels.windowTo}>
          <Instant at={window.to} />
        </Fact>
        {state.phase === "ready" ? (
          <>
            <Fact term={strings.labels.runsInWindow}>{state.page.total}</Fact>
            <Fact term={strings.labels.runsShown}>{state.page.runs.length}</Fact>
          </>
        ) : null}
      </dl>
      {window.source === "default" ? (
        <p className={secondaryText}>{strings.sentences.defaultWindow}</p>
      ) : null}
    </div>
  );
}

function Fact({
  term,
  children,
}: {
  readonly term: string;
  readonly children: React.ReactNode;
}) {
  return (
    <div className={factRow}>
      <dt className={factTerm}>{term}</dt>
      <dd className={identifierText}>{children}</dd>
    </div>
  );
}

/** doc 06 §6.2: absolute, with its timezone, and machine-readable beside it. */
function Instant({ at }: { readonly at: Date }) {
  const absolute = formatAbsoluteUtc(at);
  return (
    <time dateTime={toDateTimeAttribute(at)} title={absolute}>
      {absolute}
    </time>
  );
}

/* ── attribution coverage, refused ────────────────────────────────────────── */

/**
 * The metric doc 06 §3.4 asks for, and the reasons it is not here.
 *
 * NEUTRAL, not amber. doc 06 §5.3 gives amber to "degraded/unavailable", and
 * this is unavailable — but amber is a state that CLEARS, and this one cannot:
 * it would be amber on every repository on every day for as long as the query
 * API has no coverage endpoint. A permanent amber teaches a reader to skip
 * amber, and the amber that matters is the one beside a verification that
 * could not run. So the absence is carried by prose and by the ruled-block
 * icon, which is the set's mark for "this claims nothing", and no alarm colour
 * is spent on a fact that is not an alarm.
 */
function Coverage() {
  return (
    <section
      role="group"
      aria-label={strings.labels.coverage}
      className={sectionShell}
    >
      <h2 className={sectionHeading}>
        <Icon name="empty" className="shrink-0" />
        {strings.labels.coverage}
      </h2>
      <p className={explanation}>{strings.sentences.coverageDenominator}</p>
      <p className={explanation}>{strings.sentences.coverageNumerator}</p>
      <p className={explanation}>{strings.sentences.coverageRefusal}</p>
      <p className={explanation}>{strings.sentences.coverageNeeded}</p>
    </section>
  );
}

/* ── the runs, grouped by the identity that made them ─────────────────────── */

function Attributed({ page }: { readonly page: RunPage }) {
  const groups = groupByIdentity(page.runs);
  if (groups.length === 0) {
    return (
      <EmptyState title={strings.labels.noRuns} detail={strings.sentences.empty} />
    );
  }
  const complete = isComplete(page);
  return (
    <section className={sectionShell}>
      <h2 className={sectionHeading}>{strings.labels.groupedByIdentity}</h2>
      <p className={explanation}>
        {complete ? strings.sentences.setIsComplete : strings.sentences.setIsTruncated}
      </p>
      {groups.map((group) => (
        <Identity key={group.identity} group={group} complete={complete} />
      ))}
    </section>
  );
}

function Identity({
  group,
  complete,
}: {
  readonly group: IdentityGroup;
  readonly complete: boolean;
}) {
  return (
    <div role="group" aria-label={group.identity} className={identityGroup}>
      <div className={inlineRow}>
        <span className={factTerm}>{strings.labels.identity}</span>
        <IdentifierChip value={group.identity} kind="spiffe" />
      </div>

      {/* A count over a page is a number about a page. It is printed only when
       * the page is the whole windowed set the server counted. */}
      {complete ? (
        <dl className={factList}>
          <Fact term={strings.labels.runsForIdentity}>{group.runs.length}</Fact>
        </dl>
      ) : null}

      <table className={table}>
        <caption className={tableCaption}>{strings.labels.runsTable}</caption>
        <thead>
          <tr>
            <th scope="col" className={tableHeader}>{strings.labels.runId}</th>
            <th scope="col" className={tableHeader}>{strings.labels.agentType}</th>
            <th scope="col" className={tableHeader}>{strings.labels.task}</th>
            <th scope="col" className={tableHeader}>{strings.labels.status}</th>
            <th scope="col" className={tableHeader}>{strings.labels.commits}</th>
            <th scope="col" className={tableHeader}>{strings.labels.registered}</th>
          </tr>
        </thead>
        <tbody>
          {group.runs.map((run) => (
            <Row key={run.run_id} run={run} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ run }: { readonly run: RunSummary }) {
  return (
    <tr>
      <td className={tableCell}>
        <Link to={{ view: "run", runId: run.run_id }} className={`${link} ${identifierText}`}>
          {run.run_id}
        </Link>
      </td>
      <td className={tableCell}>
        <Link
          to={{ view: "agentType", agentType: run.agent_type, from: "", to: "" }}
          className={`${link} ${identifierText}`}
        >
          {run.agent_type}
        </Link>
      </td>
      <td className={`${tableCell} ${identifierText}`}>{run.task_ref}</td>
      <td className={tableCell}>
        <StatusBadge status={run.status} />
      </td>
      <td className={tableCell}>
        <span className={identifierText}>{run.commits}</span>
        {/* A run's commit count spans every repository it touched, so on this
         * page it is this repository's only when there was just the one. */}
        {run.repos.length > 1 ? (
          <p className={secondaryText}>{strings.sentences.commitsSpanRepos}</p>
        ) : null}
      </td>
      <td className={tableCell}>
        <Instant at={new Date(run.registered_at)} />
      </td>
    </tr>
  );
}
