// SPDX-License-Identifier: Apache-2.0

/*
 * What the overview reads, and from where — doc 06 §7.
 *
 *   "Read-only API consumer. The frontend talks to a query API over the hot
 *    tier plus live Fulcio/Rekor checks; it holds no credentials capable of
 *    writing anywhere."
 *
 * Three GETs, all of them `internal/api`'s, none of them a verification:
 *
 *   GET /api/v1/overview                        the counts and the anchor
 *   GET /api/v1/runs?from=<midnight UTC>&limit=1  "runs today", as `total`
 *   GET /api/v1/runs?limit=10                    the recent runs list
 *
 * The second one is worth a word. doc 06 §3.1 asks for "runs today" and the
 * overview response has no such field; doc 06 §8 anti-pattern 10 rules out
 * counting one without a window. `RunFilter.From` is applied in SQL and
 * `RunPage.total` is `count(*) OVER ()` over the filtered set, so asking the
 * server for one row and reading its total is an exact windowed count that
 * costs one round trip and ships no table to the client (§7).
 *
 * They are requested together and reported apart. A failure of the runs index
 * must not blank the counts that did arrive, and an absent count must not
 * render as zero (P2) — so each result is either a value or a null, and the
 * cards say which.
 *
 * NOTHING HERE IS CACHED. There is no store, no stale-while-revalidate and no
 * retained response between mounts: `reload` re-runs the reads. That is not
 * frugality, it is doc 06 §8 anti-pattern 1 — a retained answer rendered as a
 * current one — kept out by having nowhere for it to live. This view renders
 * no verification verdict at all, so no `liveness` is in play here; if that
 * ever changes, a retained response has to be reported as `{ source: "cache" }`
 * and the compiler will insist.
 */

import { useCallback, useEffect, useState } from "react";

import { startOfUtcDay } from "./format";
import type { OverviewData, RunPage, RunSummary, WindowedCount } from "./types";

/** Same-origin by default: the dashboard is served beside its query API. */
export const DEFAULT_API_BASE = "/api/v1";

/** doc 06 §3.1's "last ~10". */
export const RECENT_RUNS_LIMIT = 10;

async function getJSON(url: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    signal,
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`${url} answered ${response.status}`);
  }
  return (await response.json()) as unknown;
}

/** `GET /api/v1/overview`. */
export async function fetchOverview(
  base: string,
  signal: AbortSignal,
): Promise<OverviewData> {
  const body = await getJSON(`${base}/overview`, signal);
  if (!isOverview(body)) {
    throw new Error(`${base}/overview did not answer with an overview`);
  }
  return body;
}

/** Runs registered since midnight UTC, counted by the server. */
export async function fetchRunsToday(
  base: string,
  now: Date,
  signal: AbortSignal,
): Promise<WindowedCount> {
  const since = startOfUtcDay(now);
  const url = `${base}/runs?from=${encodeURIComponent(since.toISOString())}&limit=1`;
  const body = await getJSON(url, signal);
  if (!isRunPage(body)) throw new Error(`${url} did not answer with a run page`);
  return { count: body.total, since };
}

/** The most recent runs, newest first — the server's own ordering. */
export async function fetchRecentRuns(
  base: string,
  signal: AbortSignal,
): Promise<readonly RunSummary[]> {
  const url = `${base}/runs?limit=${RECENT_RUNS_LIMIT}`;
  const body = await getJSON(url, signal);
  if (!isRunPage(body)) throw new Error(`${url} did not answer with a run page`);
  return body.runs;
}

/** What the view has in hand. Three reads, reported separately. */
export interface OverviewResource {
  readonly status: "loading" | "ready" | "failed";
  readonly overview: OverviewData | null;
  /** Undefined when the count did not arrive: the card says "not counted"
   * rather than showing a zero nobody measured. */
  readonly runsToday: WindowedCount | undefined;
  /** Null when the list did not arrive; empty when it did and there are none. */
  readonly recentRuns: readonly RunSummary[] | null;
  /** Verbatim, for the reader (doc 06 §6.1). */
  readonly error: string;
  readonly reload: () => void;
}

interface Fetched {
  readonly status: "loading" | "ready" | "failed";
  readonly overview: OverviewData | null;
  readonly runsToday: WindowedCount | undefined;
  readonly recentRuns: readonly RunSummary[] | null;
  readonly error: string;
}

const PENDING: Fetched = {
  status: "loading",
  overview: null,
  runsToday: undefined,
  recentRuns: null,
  error: "",
};

export interface UseOverviewOptions {
  readonly base?: string;
  /** Injected for determinism; defaults to the wall clock at fetch time. */
  readonly now?: Date;
}

/** The overview's reads, run once per mount and again on `reload`. */
export function useOverview({
  base = DEFAULT_API_BASE,
  now,
}: UseOverviewOptions = {}): OverviewResource {
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<Fetched>(PENDING);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const clock = now?.getTime();

  useEffect(() => {
    const controller = new AbortController();
    const at = clock === undefined ? new Date() : new Date(clock);
    let live = true;
    setState(PENDING);

    void (async () => {
      const [overview, runsToday, recentRuns] = await Promise.allSettled([
        fetchOverview(base, controller.signal),
        fetchRunsToday(base, at, controller.signal),
        fetchRecentRuns(base, controller.signal),
      ]);
      if (!live) return;
      setState({
        status: overview.status === "fulfilled" ? "ready" : "failed",
        overview: overview.status === "fulfilled" ? overview.value : null,
        runsToday: runsToday.status === "fulfilled" ? runsToday.value : undefined,
        recentRuns: recentRuns.status === "fulfilled" ? recentRuns.value : null,
        error: overview.status === "rejected" ? messageOf(overview.reason) : "",
      });
    })();

    return () => {
      live = false;
      controller.abort();
    };
  }, [base, clock, nonce]);

  return { ...state, reload };
}

function messageOf(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

/* The two shape checks. They are narrow on purpose: enough to know the body is
 * the response it claims to be, and no schema layer to drift from the Go
 * types. A body that fails one is an error the reader is told about, never a
 * partial render of whatever did parse. */

function isOverview(body: unknown): body is OverviewData {
  if (typeof body !== "object" || body === null) return false;
  const o = body as Record<string, unknown>;
  return (
    typeof o["active_runs"] === "number" &&
    typeof o["commits_recorded"] === "number" &&
    typeof o["open_alerts"] === "number" &&
    typeof o["anchor"] === "object" &&
    o["anchor"] !== null
  );
}

function isRunPage(body: unknown): body is RunPage {
  if (typeof body !== "object" || body === null) return false;
  const o = body as Record<string, unknown>;
  return typeof o["total"] === "number" && Array.isArray(o["runs"]);
}
