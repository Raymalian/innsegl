// SPDX-License-Identifier: Apache-2.0

/*
 * The agent-type view's read of the query API — internal/api/server.go's
 * `GET /api/v1/runs`.
 *
 * Every name below is the JSON name the Go type carries, snake_case and all,
 * for the reason components/verification/types.ts gives for doing the same:
 * the alternative is a second vocabulary kept in agreement with the first by
 * hand. internal/api/query.go's RunSummary and RunPage are the source.
 *
 * ── WHY THIS FILE IS DUPLICATED IN views/repo ──────────────────────────────
 *
 * There is no shared frontend API client yet, and there was nowhere to put one
 * that both of this issue's directories and the three views being written
 * beside them could agree on. views/runs is growing its own `api` module for
 * the same reason. The precedent is components/verification/strings.ts, which
 * says it plainly: "kept in this directory because this directory is
 * separately owned; folding the two together is a mechanical edit whenever
 * somebody wants one file." That fold is reported as work for whoever owns the
 * wave that adds web/src/api.
 *
 * ── WHAT THIS FILE DELIBERATELY CANNOT DO ──────────────────────────────────
 *
 * There is no verification here and no way to ask for one. FD §7 forbids
 * shipping the table to the client and IP §6.11 forbids a verdict read out of
 * a database; the runs endpoint returns neither commits nor verification
 * results, and this module adds nothing to it. Every aggregate the views
 * render is either a number the SERVER counted (`total`, under a filter the
 * request carried) or is refused in as many words.
 */

/** One row of internal/api's runs table. */
export interface RunSummary {
  readonly run_id: string;
  readonly spiffe_id: string;
  readonly agent_type: string;
  readonly task_ref: string;
  /** internal/api/query.go's StatusActive / StatusRetired / StatusExpired. */
  readonly status: "active" | "retired" | "expired";
  readonly repos: readonly string[];
  /** Commits this RUN recorded, across every repository it touched. */
  readonly commits: number;
  readonly chain_position: number;
  readonly registered_at: string;
  readonly last_event_at: string;
}

/** One page of it. `total` is the server's count of the whole filtered set —
 * `count(*) OVER ()` inside listRunsSQL, taken before the cursor and the limit
 * — which is what makes it the one aggregate these views may print. */
export interface RunPage {
  readonly runs: readonly RunSummary[];
  readonly total: number;
  readonly limit: number;
  readonly next_cursor?: string;
  readonly data_as_of: string;
}

/** A runs query, in this module's own vocabulary. `runsPath` is the only place
 * that knows how the API spells these. */
export interface RunsQuery {
  readonly repo?: string;
  readonly agentType?: string;
  readonly from?: Date;
  readonly to?: Date;
  readonly limit?: number;
  readonly cursor?: string;
}

/** The seam a test replaces and a view never reaches around. */
export type LoadRuns = (query: RunsQuery, signal: AbortSignal) => Promise<RunPage>;

/**
 * The page these views ask for: internal/api/query.go's MaxPageSize, which is
 * the largest the server will serve whatever is requested. Asking for the
 * server's own bound is not "shipping the table" — the bound is the server's
 * and it keeps it — and it is what lets the view tell a reader whether the
 * rows in front of them are the whole windowed set or the most recent slice
 * of it.
 */
export const PAGE_LIMIT = 200;

/** The base path of the query API's runs endpoint. */
const RUNS_ENDPOINT = "/api/v1/runs";

/**
 * The request URL, with internal/api/server.go's own parameter names —
 * `repo`, `agent_type`, `from`, `to`, `limit`, `cursor`, read out of
 * runFilterFrom. Timestamps go over the wire as RFC 3339, which is what
 * runFilterFrom parses.
 */
export function runsPath(query: RunsQuery): string {
  const params = new URLSearchParams();
  if (query.repo !== undefined && query.repo !== "") params.set("repo", query.repo);
  if (query.agentType !== undefined && query.agentType !== "") {
    params.set("agent_type", query.agentType);
  }
  if (query.from !== undefined) params.set("from", query.from.toISOString());
  if (query.to !== undefined) params.set("to", query.to.toISOString());
  if (query.cursor !== undefined && query.cursor !== "") params.set("cursor", query.cursor);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const search = params.toString();
  return search === "" ? RUNS_ENDPOINT : `${RUNS_ENDPOINT}?${search}`;
}

/** The message the query API put in its error envelope, or null. */
function envelopeMessage(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("error" in body)) return null;
  const error = (body as { error: unknown }).error;
  if (typeof error !== "object" || error === null || !("message" in error)) return null;
  const message = (error as { message: unknown }).message;
  return typeof message === "string" && message !== "" ? message : null;
}

/**
 * The default loader. It reports what the server said rather than a sentence
 * of its own: doc 06 §6.1 wants an error to state what failed, and a message
 * this module invented would be a summary of one it threw away.
 */
export const fetchRuns: LoadRuns = async (query, signal) => {
  const response = await fetch(runsPath(query), {
    signal,
    headers: { accept: "application/json" },
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(envelopeMessage(body) ?? `${response.status} ${response.statusText}`);
  }
  return body as RunPage;
};
