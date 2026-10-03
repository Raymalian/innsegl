// SPDX-License-Identifier: Apache-2.0

/*
 * The repositories index's read of the query API — internal/api/repos.go's
 * `GET /api/v1/repos`. Names are the Go type's JSON names.
 */

/** One repository the ledger holds a run or commit for. */
export interface RepoSummary {
  readonly repo: string;
  readonly runs: number;
  /** Commits recorded in this repository alone. */
  readonly commits: number;
  readonly last_event_at: string;
}

export interface RepoList {
  readonly repos: readonly RepoSummary[];
  readonly data_as_of: string;
}

export type LoadRepos = (signal: AbortSignal) => Promise<RepoList>;

export const REPOS_ENDPOINT = "/api/v1/repos";

function envelopeMessage(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("error" in body)) return null;
  const error = (body as { error: unknown }).error;
  if (typeof error !== "object" || error === null || !("message" in error)) return null;
  const message = (error as { message: unknown }).message;
  return typeof message === "string" && message !== "" ? message : null;
}

/** Reports what the server said rather than a sentence of its own. */
export const fetchRepos: LoadRepos = async (signal) => {
  const response = await fetch(REPOS_ENDPOINT, {
    signal,
    headers: { accept: "application/json" },
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(envelopeMessage(body) ?? `${response.status} ${response.statusText}`);
  }
  return body as RepoList;
};
