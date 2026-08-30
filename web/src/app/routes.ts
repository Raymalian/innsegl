// SPDX-License-Identifier: Apache-2.0

// The route table. This file is the whole of the dashboard's navigation
// vocabulary, and it is deliberately data rather than a framework.
//
// Two rules from doc 06 shape it, and neither is a preference:
//
//   §3 — "Six views. Navigation is a flat left rail or top bar — no nesting
//   deeper than view → detail." So a route has at most two path segments, and
//   FE-016 measures that from the paths this file produces rather than from a
//   comment claiming it.
//
//   §7 — "every view's state (filters, selected run, verification input) lives
//   in the URL". So there is no view state anywhere else: a Route is the
//   complete description of what the shell renders, `parseRoute` is the only
//   way to obtain one, and a component that wants a filter reads it from here.
//   A filter held in React state would survive a reload and not a copied link,
//   which is the failure FD §7 calls shareability and names as a requirement.
//
// The runs query string uses the query API's own parameter names — `repo`,
// `agent_type`, `status`, `q`, `from`, `to`, `cursor`, `limit`, read out of
// internal/api/server.go's runFilterFrom. A copied dashboard link and the
// request it produces then differ only in their path, and there is no
// translation table between them to drift.

/** The six views of doc 06 §3, in the order that document lists them. */
export const VIEWS = [
  "overview",
  "runs",
  "run",
  "repo",
  "agentType",
  "verify",
] as const;

export type ViewName = (typeof VIEWS)[number];

/** Run status, as internal/api/query.go spells it (FD §4.2). */
export const RUN_STATUSES = ["active", "retired", "expired"] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];

/**
 * The runs table's filter set (FD §3.2). Every field is a string because the
 * URL is the source of truth and the query API takes strings; an absent filter
 * is the empty string, so there is one falsy value rather than two.
 */
export interface RunsFilters {
  repo: string;
  agentType: string;
  status: RunStatus | "";
  search: string;
  from: string;
  to: string;
  cursor: string;
  limit: string;
}

export function emptyRunsFilters(): RunsFilters {
  return {
    repo: "",
    agentType: "",
    status: "",
    search: "",
    from: "",
    to: "",
    cursor: "",
    limit: "",
  };
}

export type Route =
  | { view: "overview" }
  | { view: "runs"; filters: RunsFilters }
  | { view: "run"; runId: string }
  | { view: "repo"; repo: string; from: string; to: string }
  | { view: "agentType"; agentType: string; from: string; to: string }
  | { view: "verify"; commit: string; repo: string }
  | { view: "notFound"; path: string };

/** The path a nav destination points at, with no state attached. */
export const VIEW_ROOTS: Record<ViewName, string> = {
  overview: "/",
  runs: "/runs",
  run: "/runs",
  repo: "/repos",
  agentType: "/agent-types",
  verify: "/verify",
};

/**
 * The destinations the nav rail offers.
 *
 * Three of the six views, and the omission is a reading of doc 06 rather than
 * an oversight. §3 asks for flat navigation across six views; §3.3, §3.4 and
 * §3.5 each describe a view OF something — a run, a repository, an agent type
 * — and doc 06 specifies no index for any of them. A rail item for "repos"
 * would therefore have to invent a seventh view the spec does not define, and
 * a disabled rail item is worse than an absent one. Those three views are
 * reached by their links from the data that names them, which is what §3's
 * "view → detail" describes. Reported as a question for the human.
 */
export const NAV_VIEWS = [
  "overview",
  "runs",
  "verify",
] as const satisfies readonly ViewName[];

/** The address a nav destination points at, with no state selected. */
export function navRoute(view: (typeof NAV_VIEWS)[number]): Route {
  switch (view) {
    case "overview":
      return { view: "overview" };
    case "runs":
      return { view: "runs", filters: emptyRunsFilters() };
    case "verify":
      return { view: "verify", commit: "", repo: "" };
  }
}

const isRunStatus = (v: string): v is RunStatus =>
  (RUN_STATUSES as readonly string[]).includes(v);

// A limit the API would reject is not carried in a link. internal/api's
// runFilterFrom refuses anything that is not a positive number, so forwarding
// one would turn a shared URL into a 400 for whoever opened it.
const isPositiveWholeNumber = (v: string): boolean => /^[1-9][0-9]*$/.test(v);

/**
 * Parse a same-origin path (with query string) into a Route. Anything that is
 * not one of the six views — including a path nested deeper than view → detail
 * — is `notFound`, never a view rendered with a guess at its arguments.
 */
export function parseRoute(pathWithQuery: string): Route {
  const url = new URL(pathWithQuery, "http://dashboard.invalid");
  const q = url.searchParams;
  const segments = url.pathname.split("/").filter((s) => s !== "");
  const decoded = segments.map(decodeURIComponent);

  if (decoded.length === 0) return { view: "overview" };

  if (decoded.length === 1) {
    switch (decoded[0]) {
      case "runs":
        return { view: "runs", filters: filtersFrom(q) };
      case "verify":
        return {
          view: "verify",
          commit: q.get("commit") ?? "",
          repo: q.get("repo") ?? "",
        };
    }
  }

  if (decoded.length === 2) {
    const [root, detail = ""] = decoded as [string, string];
    if (detail !== "") {
      switch (root) {
        case "runs":
          return { view: "run", runId: detail };
        case "repos":
          return {
            view: "repo",
            repo: detail,
            from: q.get("from") ?? "",
            to: q.get("to") ?? "",
          };
        case "agent-types":
          return {
            view: "agentType",
            agentType: detail,
            from: q.get("from") ?? "",
            to: q.get("to") ?? "",
          };
      }
    }
  }

  return { view: "notFound", path: url.pathname };
}

function filtersFrom(q: URLSearchParams): RunsFilters {
  const status = q.get("status") ?? "";
  const limit = q.get("limit") ?? "";
  return {
    repo: q.get("repo") ?? "",
    agentType: q.get("agent_type") ?? "",
    status: isRunStatus(status) ? status : "",
    search: q.get("q") ?? "",
    from: q.get("from") ?? "",
    to: q.get("to") ?? "",
    cursor: q.get("cursor") ?? "",
    limit: isPositiveWholeNumber(limit) ? limit : "",
  };
}

/**
 * Render a Route as the one canonical path that produces it. Canonical means
 * a fixed parameter order and no empty parameters, so two people who reached
 * the same filtered view by different routes copy the same link.
 */
export function routeToPath(route: Route): string {
  switch (route.view) {
    case "overview":
      return "/";
    case "runs":
      return withQuery("/runs", [
        ["repo", route.filters.repo],
        ["agent_type", route.filters.agentType],
        ["status", route.filters.status],
        ["q", route.filters.search],
        ["from", route.filters.from],
        ["to", route.filters.to],
        ["cursor", route.filters.cursor],
        ["limit", route.filters.limit],
      ]);
    case "run":
      return `/runs/${encodeURIComponent(route.runId)}`;
    case "repo":
      return withQuery(`/repos/${encodeURIComponent(route.repo)}`, [
        ["from", route.from],
        ["to", route.to],
      ]);
    case "agentType":
      return withQuery(`/agent-types/${encodeURIComponent(route.agentType)}`, [
        ["from", route.from],
        ["to", route.to],
      ]);
    case "verify":
      return withQuery("/verify", [
        ["commit", route.commit],
        ["repo", route.repo],
      ]);
    case "notFound":
      return route.path;
  }
}

function withQuery(path: string, pairs: Array<[string, string]>): string {
  const q = new URLSearchParams();
  for (const [name, value] of pairs) {
    if (value !== "") q.set(name, value);
  }
  const s = q.toString();
  return s === "" ? path : `${path}?${s}`;
}
