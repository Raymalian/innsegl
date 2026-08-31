// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.2's runs view: the filterable, paginated table.
 *
 * ── NOTHING IS RETAINED ────────────────────────────────────────────────────
 *
 * This is the property to read the file for. doc 06 §8's first anti-pattern is
 * "a 'verified' state rendered from cache while the live check errored", and a
 * runs table is the most likely thing in this product to acquire a cache: it
 * is the busiest view, its query changes on every keystroke a reader applies,
 * and a library that keeps the last page around while the next one loads is
 * one `npm install` away.
 *
 * So there is no cache here, of any kind. No query library, no store, no
 * memoised page, no `keepPreviousData`. What there is instead is a rule the
 * render obeys:
 *
 *     a row is rendered only for the request currently in the address bar.
 *
 * The fetched result carries the request that produced it, and the render
 * compares it with the request the URL now describes. A response for a query
 * that is no longer on screen is not shown for one frame — not stale-while-
 * revalidate, not "the old rows while the new ones load". Changing a filter
 * shows the loading state, then the answer to the question actually asked.
 * FE-052 asserts it by holding a response open and changing the filter.
 *
 * That is also why the verification rollups can be trusted: a proof this view
 * renders came in with the page it belongs to, and a caller that retains one
 * must say so (proofs.ts narrows `Liveness.source` to a required field).
 *
 * ── THE CLIENT NEVER ASKS FOR AN UNBOUNDED PAGE ────────────────────────────
 *
 * doc 06 §7 forbids shipping the table to the client. The server enforces that
 * with MaxPageSize; this view keeps its own half so that the URL a reader
 * copies is the query that ran: the address bar is canonicalised to the
 * clamped filters, and the request is that path with `/runs` swapped for the
 * API's. No code path in this directory fetches more than one page, and none
 * filters, searches or sorts rows in the browser.
 *
 * ── AND IT TIMES OUT ───────────────────────────────────────────────────────
 *
 * doc 06 §8 anti-pattern 8 is "spinners without timeout-to-error". The bound
 * belongs to LoadingState, which owns its own timer and turns into the
 * dependency-error state without any cooperation from this file.
 */

import { useCallback, useEffect, useState } from "react";

import {
  EmptyState,
  ErrorState,
  LoadingState,
  StalenessIndicator,
  StalenessProvider,
} from "../../components/common";
import { currentPath, navigate, useRoute } from "../../app/router";
import { emptyRunsFilters, type Route, type RunsFilters } from "../../app/routes";

import {
  fetchRuns,
  runsLinkPath,
  runsRequestPath,
  type RunPage,
  type RunsSource,
} from "./api";
import type { RunProofSource } from "./proofs";
import { RunsFilterForm } from "./RunsFilterForm";
import { RunsPager } from "./RunsPager";
import { RunsTable } from "./RunsTable";
import { strings } from "./strings";
import { heading, view } from "./styles";

/** What has been read, and for which request. The pairing is the point. */
type Result =
  | { readonly request: string; readonly phase: "loading" }
  | { readonly request: string; readonly phase: "ready"; readonly page: RunPage }
  | { readonly request: string; readonly phase: "failed"; readonly message: string };

export interface RunsViewProps {
  /** Supplied by the shell's view registry; omitted, the view reads the
   * address bar itself, which is the same source. */
  readonly route?: Route;
  /** Where a page comes from. Must be referentially stable: it is a
   * dependency of the read, so a function rebuilt on every parent render
   * would re-read on every parent render. The default is `fetchRuns`, which
   * is a module constant. */
  readonly source?: RunsSource;
  /** Verifications a caller already holds. This view fetches none — see
   * proofs.ts for why, and for why a retained one has to say so. */
  readonly proofs?: RunProofSource;
  /** doc 06 §4.4: whether the ledger read path is degraded. Silent staleness
   * is anti-pattern 7, so the marker is wired even though nothing sets it yet. */
  readonly degraded?: boolean;
}

export function RunsView({
  route: given,
  source = fetchRuns,
  proofs,
  degraded = false,
}: RunsViewProps) {
  const here = useRoute();
  const route = given ?? here;
  const filters: RunsFilters =
    route.view === "runs" ? route.filters : emptyRunsFilters();

  const link = runsLinkPath(filters);
  const request = runsRequestPath(filters);

  /* The address bar is made to say what the query actually is: a `limit` past
   * the server's maximum, or a `status` the route table refused, would
   * otherwise leave a reader copying a link that describes a query nobody
   * ran. */
  useEffect(() => {
    if (route.view !== "runs") return;
    if (currentPath() !== link) navigate(link, { replace: true });
  }, [link, route.view]);

  const [result, setResult] = useState<Result>({ request: "", phase: "loading" });
  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let listening = true;
    source(request, controller.signal).then(
      (page) => {
        if (listening) setResult({ request, phase: "ready", page });
      },
      (error: unknown) => {
        if (listening) setResult({ request, phase: "failed", message: messageOf(error) });
      },
    );
    return () => {
      listening = false;
      controller.abort();
    };
  }, [attempt, request, source]);

  /* The rule this file exists for. A result for any other request is not
   * rendered, however recent it is. */
  const shown: Result =
    result.request === request ? result : { request, phase: "loading" };

  return (
    <StalenessProvider
      degraded={degraded}
      asOf={shown.phase === "ready" ? new Date(shown.page.data_as_of) : null}
    >
      <section className={view}>
        <h1 className={heading}>{strings.labels.view.heading}</h1>
        <StalenessIndicator />
        <RunsFilterForm key={link} filters={filters} />
        <Answer
          attempt={attempt}
          filters={filters}
          proofs={proofs}
          result={shown}
          retry={retry}
        />
      </section>
    </StalenessProvider>
  );
}

function Answer({
  attempt,
  filters,
  proofs,
  result,
  retry,
}: {
  readonly attempt: number;
  readonly filters: RunsFilters;
  readonly proofs?: RunProofSource;
  readonly result: Result;
  readonly retry: () => void;
}) {
  if (result.phase === "loading") {
    /* The key restarts LoadingState's own timeout. Without it the bound
     * belongs to the first read the view ever made: a filter changed at 14
     * seconds would inherit one second, and a retry would re-read behind an
     * error state that never went away. doc 06 §4.6 wants the bound per
     * attempt, not per view. */
    return (
      <LoadingState
        key={`${result.request}#${attempt}`}
        what={strings.fragments.what}
        onRetry={retry}
      />
    );
  }
  if (result.phase === "failed") {
    return <ErrorState detail={result.message} onRetry={retry} />;
  }
  if (result.page.runs.length === 0) {
    return (
      <EmptyState
        title={strings.labels.empty.title}
        detail={strings.sentences.empty.detail}
      />
    );
  }
  return (
    <>
      <RunsTable
        runs={result.page.runs}
        total={result.page.total}
        proofs={proofs}
      />
      <RunsPager filters={filters} page={result.page} />
    </>
  );
}

/** A thrown thing, as a sentence a reader can act on. */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
