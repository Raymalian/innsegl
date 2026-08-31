// SPDX-License-Identifier: Apache-2.0

/*
 * The agent-type view — doc 06 §3.5.
 *
 *   "All runs of one agent type across time: run frequency, repos touched,
 *    aggregate verification status. This is the 'what has fix-ci been doing
 *    all month' view."
 *
 * ── THE THREE THINGS §3.5 ASKS FOR, AND WHAT EACH ONE COST ─────────────────
 *
 * RUN FREQUENCY is real, and it is the server's. Six windowed counts, one per
 * bucket boundary, differenced so no run is counted twice and none falls
 * between the buckets (frequency.ts). Nothing is binned in the browser, which
 * is doc 06 §7's requirement rather than a preference.
 *
 * REPOS TOUCHED is derived from the runs on the page, because the query API
 * exposes no distinct-repo aggregate. Every count beside it would therefore be
 * a number about a page, so there is none: the list is rendered, and the view
 * says whether the rows it came from were the whole windowed set.
 *
 * AGGREGATE VERIFICATION STATUS is refused, and this is the sharpest thing in
 * the issue. See strings.ts. There is no aggregate to fetch, no commit listing
 * to iterate, and a tally assembled from the ledger's stored rows would be a
 * database-only verdict — IP §6.11 and doc 06 P2 in as many words, and the
 * same wall internal/api hit for the overview's pass rate and documented
 * rather than climbed. So the block states that nothing here was verified
 * live, says why a stored answer would not be a verification, and links to the
 * page that checks one commit against Fulcio and Rekor.
 *
 * Which is why this file imports nothing from components/verification. There
 * is no proof here, so there is no `liveness` to pass and no badge to render:
 * a verdict about nothing is worse than no verdict, and a green one would be
 * doc 06 §8's anti-patterns 1 and 3 at once.
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
import { FREQUENCY_BUCKETS, bucketCounts, bucketsOf } from "./frequency";
import type { Bucket } from "./frequency";
import { PAGE_LIMIT, fetchRuns } from "./query";
import type { LoadRuns, RunPage, RunSummary } from "./query";
import { isComplete, reposNamedBy, resolveWindow } from "./window";
import type { StatedWindow } from "./window";
import { strings } from "./strings";
import {
  explanation,
  factList,
  factRow,
  factTerm,
  identifierText,
  stackedList,
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

export interface AgentTypeViewProps {
  /** The shell hands every view the whole route union; this one renders the
   * `agentType` member of it and refuses the rest rather than guessing. */
  readonly route: Route;
  /** The read. Injected so a test needs no network and a render is
   * deterministic; there is no second path to the query API from here. */
  readonly load?: LoadRuns;
  /** The clock the default window is measured back from. */
  readonly now?: Date;
}

export function AgentTypeView({ route, load = fetchRuns, now }: AgentTypeViewProps) {
  if (route.view !== "agentType") {
    return (
      <ErrorState
        title={strings.labels.wrongRoute}
        detail={strings.sentences.wrongRoute}
      />
    );
  }
  return (
    <AgentType
      agentType={route.agentType}
      from={route.from}
      to={route.to}
      load={load}
      now={now}
    />
  );
}

interface Answer {
  readonly page: RunPage;
  /** One per bucket, in order: the server's count from the window's start to
   * that bucket's upper bound. The last is the window's own total. */
  readonly cumulative: readonly number[];
}

type Phase =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly answer: Answer }
  | { readonly phase: "error"; readonly message: string };

function AgentType({
  agentType,
  from,
  to,
  load,
  now,
}: {
  readonly agentType: string;
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
  const fromMs = window.from.getTime();
  const toMs = window.to.getTime();
  const buckets = useMemo(
    () => bucketsOf(new Date(fromMs), new Date(toMs), FREQUENCY_BUCKETS),
    [fromMs, toMs],
  );

  const [state, setState] = useState<Phase>({ phase: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState({ phase: "loading" });

    // The page first, then one count per INTERIOR boundary: the last bucket's
    // cumulative answer is the window's own total, which the page already
    // carries, so it is never asked for twice.
    const pageRead = load(
      { agentType, from: new Date(fromMs), to: new Date(toMs), limit: PAGE_LIMIT },
      controller.signal,
    );
    const counts = buckets
      .slice(0, -1)
      .map((bucket) =>
        load(
          { agentType, from: new Date(fromMs), to: bucket.to, limit: 1 },
          controller.signal,
        ),
      );

    Promise.all([pageRead, ...counts]).then(
      ([page, ...interior]) => {
        if (controller.signal.aborted || page === undefined) return;
        setState({
          phase: "ready",
          answer: {
            page,
            cumulative: [...interior.map((answer) => answer.total), page.total],
          },
        });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setState({ phase: "error", message: messageOf(error) });
        }
      },
    );
    return () => controller.abort();
  }, [load, agentType, fromMs, toMs, buckets, attempt]);

  const retry = () => setAttempt((n) => n + 1);

  return (
    <div className={viewShell}>
      <header className="flex flex-col gap-2">
        <p className={mutedText}>{strings.labels.agentType}</p>
        <h1 className={viewHeading}>{agentType}</h1>
      </header>

      {/* doc 06 §4.4: every affected view carries the marker, and this
       * component renders nothing at all while the read path is healthy. */}
      <StalenessIndicator />

      <Summary window={window} state={state} />
      <AggregateVerification />

      {state.phase === "loading" ? (
        <LoadingState what={strings.nouns.runs} onRetry={retry} />
      ) : null}
      {state.phase === "error" ? (
        <ErrorState detail={state.message} onRetry={retry} />
      ) : null}
      {state.phase === "ready" ? (
        <Answered answer={state.answer} buckets={buckets} />
      ) : null}
    </div>
  );
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/* ── the window, and the two counts measured over it ──────────────────────── */

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
            <Fact term={strings.labels.runsInWindow}>{state.answer.page.total}</Fact>
            <Fact term={strings.labels.runsShown}>
              {state.answer.page.runs.length}
            </Fact>
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

/* ── aggregate verification status, refused ───────────────────────────────── */

/**
 * NEUTRAL, not amber, and not a badge.
 *
 * doc 06 §5.3 gives amber to "degraded/unavailable" and this is unavailable —
 * but amber is a state that CLEARS, and this one cannot: it would be amber on
 * every agent type on every day for as long as the query API verifies one
 * commit at a time, which is the design rather than an outage. A permanent
 * amber teaches a reader to skip amber, and the amber that matters is the one
 * beside a verification that could not run.
 *
 * And no VerificationBadge. doc 06 §4.1 permits a rollup badge only where it
 * expands to the three checks, and there are no checks here to expand to; a
 * badge reading "verification unavailable" would be a verdict about a commit
 * this page has not named.
 */
function AggregateVerification() {
  return (
    <section
      role="group"
      aria-label={strings.labels.aggregateVerification}
      className={sectionShell}
    >
      <h2 className={sectionHeading}>
        <Icon name="empty" className="shrink-0" />
        {strings.labels.aggregateVerification}
      </h2>
      <p className={explanation}>{strings.sentences.verificationNotLive}</p>
      <p className={explanation}>{strings.sentences.verificationNoAggregate}</p>
      <p className={explanation}>{strings.sentences.verificationDatabaseOnly}</p>
      <Link to={{ view: "verify", commit: "", repo: "" }} className={`${link} ${inlineRow}`}>
        {strings.labels.verifyACommit}
      </Link>
    </section>
  );
}

/* ── the answer ───────────────────────────────────────────────────────────── */

function Answered({
  answer,
  buckets,
}: {
  readonly answer: Answer;
  readonly buckets: readonly Bucket[];
}) {
  if (answer.page.total === 0 && answer.page.runs.length === 0) {
    return (
      <EmptyState title={strings.labels.noRuns} detail={strings.sentences.empty} />
    );
  }
  const complete = isComplete(answer.page);
  return (
    <>
      <Frequency buckets={buckets} cumulative={answer.cumulative} />
      <ReposTouched runs={answer.page.runs} complete={complete} />
      <Runs runs={answer.page.runs} complete={complete} />
    </>
  );
}

function Frequency({
  buckets,
  cumulative,
}: {
  readonly buckets: readonly Bucket[];
  readonly cumulative: readonly number[];
}) {
  const counts = bucketCounts(cumulative);
  return (
    <section className={sectionShell}>
      <table className={table}>
        <caption className={tableCaption}>{strings.labels.frequency}</caption>
        <thead>
          <tr>
            <th scope="col" className={tableHeader}>{strings.labels.bucketFrom}</th>
            <th scope="col" className={tableHeader}>{strings.labels.bucketTo}</th>
            <th scope="col" className={tableHeader}>{strings.labels.bucketRuns}</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((bucket, index) => (
            <tr key={bucket.to.toISOString()}>
              <td className={tableCell}>
                <Instant at={bucket.from} />
              </td>
              <td className={tableCell}>
                <Instant at={bucket.to} />
              </td>
              <td className={`${tableCell} ${identifierText}`}>{counts[index] ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={explanation}>{strings.sentences.bucketBounds}</p>
    </section>
  );
}

function ReposTouched({
  runs,
  complete,
}: {
  readonly runs: readonly RunSummary[];
  readonly complete: boolean;
}) {
  const repos = reposNamedBy(runs);
  return (
    <section
      role="group"
      aria-label={strings.labels.reposTouched}
      className={sectionShell}
    >
      <h2 className={sectionHeading}>{strings.labels.reposTouched}</h2>
      <p className={explanation}>
        {complete ? strings.sentences.reposComplete : strings.sentences.reposFromPage}
      </p>
      <ul className={`${inlineRow} list-none p-0`}>
        {repos.map((repo) => (
          <li key={repo}>
            <Link
              to={{ view: "repo", repo, from: "", to: "" }}
              className={`${link} ${identifierText}`}
            >
              {repo}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Runs({
  runs,
  complete,
}: {
  readonly runs: readonly RunSummary[];
  readonly complete: boolean;
}) {
  return (
    <section className={sectionShell}>
      <table className={table}>
        <caption className={tableCaption}>{strings.labels.runs}</caption>
        <thead>
          <tr>
            <th scope="col" className={tableHeader}>{strings.labels.runId}</th>
            <th scope="col" className={tableHeader}>{strings.labels.identity}</th>
            <th scope="col" className={tableHeader}>{strings.labels.task}</th>
            <th scope="col" className={tableHeader}>{strings.labels.status}</th>
            <th scope="col" className={tableHeader}>{strings.labels.commits}</th>
            <th scope="col" className={tableHeader}>{strings.labels.repos}</th>
            <th scope="col" className={tableHeader}>{strings.labels.registered}</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <Row key={run.run_id} run={run} />
          ))}
        </tbody>
      </table>
      <p className={explanation}>
        {complete ? strings.sentences.runsComplete : strings.sentences.runsTruncated}
      </p>
    </section>
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
        <IdentifierChip value={run.spiffe_id} kind="spiffe" />
      </td>
      <td className={`${tableCell} ${identifierText}`}>{run.task_ref}</td>
      <td className={tableCell}>
        <StatusBadge status={run.status} />
      </td>
      <td className={`${tableCell} ${identifierText}`}>{run.commits}</td>
      <td className={tableCell}>
        <ul className={`${stackedList} list-none p-0`}>
          {run.repos.map((repo) => (
            <li key={repo} className={identifierText}>
              {repo}
            </li>
          ))}
        </ul>
      </td>
      <td className={tableCell}>
        <Instant at={new Date(run.registered_at)} />
      </td>
    </tr>
  );
}
