// SPDX-License-Identifier: Apache-2.0

/*
 * The repo view's arithmetic: the window every count is measured over, the
 * link out to the repository host, the grouping by agent identity, and the one
 * question that decides whether a group count may be printed at all.
 *
 * doc 06 §8's tenth anti-pattern is what this file exists to keep out:
 *
 *   "10. Metrics chosen to look good rather than to inform (e.g., cumulative
 *    counts with no window, hiding a failing pass rate)."
 *
 * Two different ways to break that rule are answered here.
 *
 * A COUNT WITH NO WINDOW is answered by `resolveWindow`. There is no code path
 * in this view that asks the server for an unbounded set: the window comes off
 * the address or it is the default, and either way the view prints both of its
 * bounds. A window that is not a positive interval — absent, malformed,
 * reversed, or zero-width — is not usable and is replaced by the default,
 * which is stated rather than silently substituted.
 *
 * A COUNT OVER A PAGE is answered by `isComplete`. internal/api serves at most
 * MaxPageSize rows and reports the size of the whole filtered set alongside
 * them. When those two numbers agree and no cursor follows, the rows in hand
 * ARE the windowed set and a count taken over them is the server's number by
 * another route. When they disagree, any count over the rows is a number about
 * a page being presented as a number about a repository, and the view prints
 * none.
 */

import type { RunPage, RunSummary } from "./query";

/* ── the window ───────────────────────────────────────────────────────────── */

/** The span a view falls back to when the address names no usable one. */
export const DEFAULT_WINDOW_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface StatedWindow {
  readonly from: Date;
  readonly to: Date;
  /** Where the bounds came from. Rendered, because a default a reader was not
   * told about is a window they will read as a choice. */
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

/* ── the link out to the repository host ──────────────────────────────────── */

/**
 * doc 02 §5: "`repo` is `host/org/name` (e.g. `github.com/acme/api`),
 * lowercase host." That grammar is the whole of what the ledger records, and
 * it is enough to address the repository over https and nothing more.
 *
 * Everything else returns null, and the view says so rather than guessing.
 * A link-out assembled from a value that is not that grammar is a link to
 * somewhere nobody chose — `evil.com@github.com/a/b` and `github.com/a/../..`
 * are the two shapes that matter, and both are refused twice: once by the
 * grammar and once by re-reading the parsed URL back.
 *
 * MEASURED: mutating away the grammar's lowercase-host rule, or the explicit
 * traversal guard, leaves FE-043 passing — the hostname and pathname re-reads
 * below catch both on their own. The two layers are belt and braces and the
 * re-reads are the half that bites; removing a layer from each pair kills the
 * corresponding case at once. Both halves stay, because a URL parser's
 * normalisation is a thing to check an assumption against, not a thing to
 * depend on for a security property.
 */
const REPO_GRAMMAR =
  /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(\/[A-Za-z0-9._-]+){2,}$/;

export function hostUrlOf(repo: string): string | null {
  if (!REPO_GRAMMAR.test(repo)) return null;
  const segments = repo.split("/");
  if (segments.some((segment) => segment === "." || segment === "..")) return null;
  let url: URL;
  try {
    url = new URL(`https://${repo}`);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.hostname !== segments[0]) return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;
  if (url.pathname !== `/${segments.slice(1).join("/")}`) return null;
  return url.toString();
}

/* ── the grouping, and whether it may be counted ──────────────────────────── */

export interface IdentityGroup {
  /** The SPIFFE ID the certificate proves for every run below it. */
  readonly identity: string;
  readonly runs: readonly RunSummary[];
}

/**
 * doc 06 §3.4: "All attributed commits in a repo, grouped by agent identity."
 * The query API exposes no commit listing, so what is grouped is the runs that
 * made the commits; the view says so, and each run links to the detail view
 * that holds its commits.
 *
 * Order is first appearance, which is the server's own ordering (newest chain
 * position first) collapsed. Nothing is re-sorted: a view that re-ordered the
 * server's answer would be presenting a different set from the one the cursor
 * and the total describe.
 */
export function groupByIdentity(runs: readonly RunSummary[]): readonly IdentityGroup[] {
  const order: string[] = [];
  const byIdentity = new Map<string, RunSummary[]>();
  for (const run of runs) {
    const existing = byIdentity.get(run.spiffe_id);
    if (existing === undefined) {
      order.push(run.spiffe_id);
      byIdentity.set(run.spiffe_id, [run]);
    } else {
      existing.push(run);
    }
  }
  return order.map((identity) => ({
    identity,
    runs: byIdentity.get(identity) ?? [],
  }));
}

/**
 * Whether the rows in hand are the whole filtered set the server counted.
 *
 * Both halves are needed. `total` says how many rows matched; `next_cursor`
 * says the server believes there is another page. A view that trusted either
 * alone would print a per-identity count over a slice on the day the other
 * disagreed.
 */
export function isComplete(page: RunPage): boolean {
  return page.runs.length >= page.total && (page.next_cursor ?? "") === "";
}
