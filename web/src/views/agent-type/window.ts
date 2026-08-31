// SPDX-License-Identifier: Apache-2.0

/*
 * The window every count on the agent-type view is measured over.
 *
 * doc 06 §8's tenth anti-pattern names "cumulative counts with no window", and
 * this file is the reason there is no code path in this view that asks the
 * server for an unbounded set. The window comes off the address or it is the
 * default; either way the view prints both of its bounds.
 *
 * A window that is not a positive interval — absent, malformed, reversed, or
 * zero-width — is not usable and is replaced by the default, which is stated
 * rather than silently substituted. A default a reader was not told about is a
 * window they will read as a choice.
 *
 * Duplicated from views/repo for the reason query.ts gives: the two
 * directories are separately owned and there is no shared client yet.
 */

/** The span a view falls back to when the address names no usable one. */
export const DEFAULT_WINDOW_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface StatedWindow {
  readonly from: Date;
  readonly to: Date;
  readonly source: "url" | "default";
}

/**
 * RFC 3339, which is what internal/api's runFilterFrom parses and refuses.
 * Checked here rather than left to `new Date`, whose parser accepts "2026-08"
 * and a good deal else — a bound the API would reject is not a bound this view
 * should quietly adopt.
 */
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

function instantOf(value: string): Date | null {
  if (!RFC3339.test(value)) return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at;
}

/** The window this render is measured over, and where it came from. */
export function resolveWindow(from: string, to: string, now: Date): StatedWindow {
  const start = instantOf(from);
  const end = instantOf(to);
  if (start !== null && end !== null && end.getTime() > start.getTime()) {
    return { from: start, to: end, source: "url" };
  }
  return {
    from: new Date(now.getTime() - DEFAULT_WINDOW_DAYS * DAY_MS),
    to: new Date(now.getTime()),
    source: "default",
  };
}

/**
 * Whether the rows in hand are the whole filtered set the server counted.
 *
 * Both halves are needed. `total` says how many rows matched; `next_cursor`
 * says the server believes there is another page. A view that trusted either
 * alone would describe a slice as the window's whole set on the day the other
 * disagreed.
 */
export function isComplete(page: { readonly runs: readonly unknown[]; readonly total: number; readonly next_cursor?: string }): boolean {
  return page.runs.length >= page.total && (page.next_cursor ?? "") === "";
}

/**
 * The repositories named by a set of runs, in first-seen order.
 *
 * doc 06 §3.5 asks for "repos touched". The query API exposes no distinct-repo
 * aggregate — `repos` is an array on each run row and nothing counts them
 * server-side — so this list is derived from the rows in hand, and the view
 * says which rows those were. When the page IS the whole windowed set the list
 * is the window's whole set too; when it is not, it is the set named by the
 * runs drawn and may be short. Both are stated; neither is guessed at.
 */
export function reposNamedBy(
  runs: readonly { readonly repos: readonly string[] }[],
): readonly string[] {
  const seen = new Set<string>();
  const order: string[] = [];
  for (const run of runs) {
    for (const repo of run.repos) {
      if (seen.has(repo)) continue;
      seen.add(repo);
      order.push(repo);
    }
  }
  return order;
}
