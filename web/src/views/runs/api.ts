// SPDX-License-Identifier: Apache-2.0

/*
 * The runs query, client side — doc 06 §3.2, §7.
 *
 * ── ONE ENCODER, TWO PATHS ─────────────────────────────────────────────────
 *
 * doc 06 §7 asks for shareability ("every view's state ... lives in the URL")
 * and RM-041 answered it by giving the dashboard's query string the query
 * API's OWN parameter names — `repo`, `agent_type`, `status`, `q`, `from`,
 * `to`, `cursor`, `limit`, read out of internal/api/server.go's
 * `runFilterFrom`. The property that buys is this:
 *
 *     the link a reader copies and the request it produces differ ONLY in
 *     their path.
 *
 * A property is worth nothing if it is maintained by two functions agreeing.
 * So there is one encoder — `routeToPath` in src/app/routes.ts — and the
 * request is literally the link with its path swapped. There is no second
 * query-string builder here to drift out of step, and FE-010 asserts the
 * identity over a URL carrying all eight parameters.
 *
 * ── THE PAGE IS BOUNDED BEFORE IT IS ASKED FOR ─────────────────────────────
 *
 * doc 06 §7: "server-side pagination, filtering, and search only — never
 * ship-the-table-to-the-client", and §3.2 wants the table responsive at
 * millions of rows. internal/api enforces that with MaxPageSize = 200, and a
 * server-side bound is the one that counts: a client is a suggestion.
 *
 * This file keeps the client's half anyway, because the alternative — a
 * dashboard link that asks for a million rows and quietly receives 200 — is a
 * link that lies about what it shows. `boundedFilters` clamps `limit` to the
 * server's own maximum, and the view canonicalises the ADDRESS BAR to the
 * clamped value, so the URL a reader copies is the query that actually ran.
 *
 * There is no "fetch everything" path in this module, and no client-side
 * filter, sort or search anywhere in this directory. FE-051 asserts that from
 * behaviour rather than from this paragraph.
 *
 * ── AND NOTHING IS RETAINED ────────────────────────────────────────────────
 *
 * `fetchRuns` asks the browser not to cache (`cache: "no-store"`, matching the
 * `Cache-Control: no-store` internal/api sets on every response), and this
 * module holds no state of any kind. doc 06 §8's first anti-pattern is a
 * verified state rendered from a cache, and the cheapest route to it is a
 * retained page of runs whose verification rollups have gone stale.
 */

import {
  routeToPath,
  type RunStatus,
  type RunsFilters,
} from "../../app/routes";

/** The dashboard path the runs table lives at (src/app/routes.ts). */
export const RUNS_PATH = "/runs";

/** The query API's runs endpoint (internal/api/server.go's route table). */
export const RUNS_ENDPOINT = "/api/v1/runs";

/** internal/api/query.go's DefaultPageSize: the page a request naming none gets. */
export const DEFAULT_PAGE_SIZE = 50;

/** internal/api/query.go's MaxPageSize: the largest page the server will serve,
 * whatever is asked for. The client asks for no more. */
export const MAX_PAGE_SIZE = 200;

/** One row of the runs table — internal/api/query.go's RunSummary, field for
 * field and spelling for spelling. */
export interface RunSummary {
  readonly run_id: string;
  readonly spiffe_id: string;
  readonly agent_type: string;
  readonly task_ref: string;
  readonly status: RunStatus;
  readonly repos: readonly string[];
  readonly commits: number;
  readonly chain_position: number;
  readonly registered_at: string;
  readonly last_event_at: string;
}

/** One page of the runs table — internal/api/query.go's RunPage. */
export interface RunPage {
  readonly runs: readonly RunSummary[];
  readonly total: number;
  readonly limit: number;
  /** Absent at the end of the set. A keyset cursor, not an offset. */
  readonly next_cursor?: string;
  readonly data_as_of: string;
}

/**
 * The filters with `limit` clamped to what the server will actually serve.
 * An absent or unparsable limit is left absent: internal/api applies
 * DEFAULT_PAGE_SIZE, and inventing a number here would put a value in a shared
 * link that the reader never chose.
 */
export function boundedFilters(filters: RunsFilters): RunsFilters {
  if (filters.limit === "") return filters;
  /* Spelled the way internal/api will read it, or not spelled at all.
   * `runFilterFrom` uses strconv.Atoi and answers 400 to anything it refuses,
   * so `1e9` and ` 500` are not small limits — they are broken links. The
   * digits are checked before the value is, because Number.parseInt("1e9", 10)
   * is 1, which would have passed a bound test and then failed the server. */
  if (!/^[0-9]+$/.test(filters.limit)) return { ...filters, limit: "" };
  const asked = Number.parseInt(filters.limit, 10);
  if (asked <= 0) return { ...filters, limit: "" };
  if (asked <= MAX_PAGE_SIZE) return filters;
  return { ...filters, limit: String(MAX_PAGE_SIZE) };
}

/** The one canonical dashboard path for a filter set — what a reader copies. */
export function runsLinkPath(filters: RunsFilters): string {
  return routeToPath({ view: "runs", filters: boundedFilters(filters) });
}

/** The request that link produces. The same string with a different path. */
export function runsRequestPath(filters: RunsFilters): string {
  return RUNS_ENDPOINT + runsLinkPath(filters).slice(RUNS_PATH.length);
}

/**
 * Where a page of runs comes from. Injected so a test drives the view without
 * a network, and so a deployment can put the query API somewhere else without
 * the view knowing.
 */
export type RunsSource = (
  request: string,
  signal: AbortSignal,
) => Promise<RunPage>;

/** internal/api's error envelope: `{"error":{"code":…,"message":…}}`. */
interface ErrorEnvelope {
  readonly error?: { readonly code?: string; readonly message?: string };
}

/**
 * The default source: one GET, uncached, aborted when the query changes.
 *
 * A failed read is raised with the server's own message rather than a status
 * code. doc 06 §6.1: "Errors state what failed and what the user can do", and
 * "500" states neither.
 */
export const fetchRuns: RunsSource = async (request, signal) => {
  const response = await fetch(request, {
    signal,
    method: "GET",
    cache: "no-store",
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new Error(await problemOf(response));
  return (await response.json()) as RunPage;
};

async function problemOf(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as ErrorEnvelope;
    const message = body.error?.message ?? "";
    if (message !== "") return message;
  } catch {
    // A body that is not the envelope tells us nothing; fall through to the
    // status line, which at least says what the server did.
  }
  return `${response.status} ${response.statusText}`.trim();
}
