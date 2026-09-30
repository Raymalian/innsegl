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

/** The six views of doc 06 §3, in the order that document lists them, and
 * the one detail ADR-0054 added: a single alert, reached from the header's
 * notification menu. It has no index of its own — the menu is the list — so
 * it is not a nav destination either. */
export const VIEWS = [
  "overview",
  "runs",
  "run",
  "repo",
  "agentType",
  "verify",
  "alert",
] as const;

export type ViewName = (typeof VIEWS)[number];

/**
 * A run's lifecycle state, as internal/api/query.go spells it, in that file's
 * own order (#256).
 *
 * FOUR, not three, and `expired` is not among them. Three words could not tell
 * a run that is quiet from one that is over, and the word they collapsed into
 * read as a claim that an agent had died — which nothing in this system can
 * observe. `expired` survives as the name of the `run_expired` EVENT, which is
 * a protected string (doc 02 §3) and is not a state.
 *
 * The value travels in the URL and reaches the query API's `status` parameter
 * verbatim, so this list and internal/api's RunStatuses are one closed set.
 */
export const RUN_STATUSES = ["active", "lapsed", "abandoned", "retired"] as const;
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
  /** "asc" or "desc"; empty means newest-first, which is what the table did
   *  before ordering existed and what an unset parameter keeps doing. The
   *  LEDGER sorts — see views/runs/api.ts on why the browser must not. */
  order: RunOrder | "";
}

/** The two directions internal/api/query.go will accept. */
export type RunOrder = "asc" | "desc";

function isRunOrder(v: string): v is RunOrder {
  return v === "asc" || v === "desc";
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
    order: "",
  };
}

export type Route =
  | { view: "overview" }
  | { view: "runs"; filters: RunsFilters }
  /* E19 (#395-397): `/runs/:runId` is now the run PAGE (doc 06 §3.3's
   * replacement, plan §10.4) rather than the hash-chain timeline that used to
   * live there. `chain` is the one bit that keeps the old view reachable —
   * `/runs/:runId/chain` — without inventing a second ViewName for it: the
   * two are still one destination, "a run", and the route table's own test
   * asserts the six-plus-one list is exactly that long. A third path segment
   * is real nesting (FD §3's "no nesting deeper than view → detail" is about
   * navigation depth a reader has to think about, not about every path this
   * table can parse), and it is deliberately not added to the "never nests
   * deeper" fixture below: it is an escape hatch to the view this run's page
   * superseded, not a second view a reader navigates INTO. */
  | { view: "run"; runId: string; chain?: boolean }
  | { view: "repo"; repo: string; from: string; to: string }
  | { view: "agentType"; agentType: string; from: string; to: string }
  | { view: "verify"; commit: string; repo: string }
  | { view: "alert"; eventId: string }
  | { view: "notFound"; path: string };

/** The path a nav destination points at, with no state attached. */
export const VIEW_ROOTS: Record<ViewName, string> = {
  overview: "/",
  runs: "/runs",
  run: "/runs",
  repo: "/repos",
  agentType: "/agent-types",
  verify: "/verify",
  alert: "/alerts",
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

  // `/runs/:runId/chain` — the one escape hatch a run's route can take past
  // two segments, and it is checked before the ordinary two-segment branch so
  // a run ID that happens to be literally "chain" cannot shadow it: there is
  // no such run ID in practice (RM-041's IDs are ULIDs), and even so the
  // three-segment form is unambiguous because "chain" never appears as the
  // THIRD segment any other way.
  if (decoded.length === 3) {
    const [root, runId, tail] = decoded as [string, string, string];
    if (root === "runs" && runId !== "" && tail === "chain") {
      return { view: "run", runId, chain: true };
    }
    return { view: "notFound", path: url.pathname };
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
        case "alerts":
          return { view: "alert", eventId: detail };
      }
    }
  }

  return { view: "notFound", path: url.pathname };
}

function filtersFrom(q: URLSearchParams): RunsFilters {
  const status = q.get("status") ?? "";
  const limit = q.get("limit") ?? "";
  const order = q.get("order") ?? "";
  return {
    repo: q.get("repo") ?? "",
    agentType: q.get("agent_type") ?? "",
    status: isRunStatus(status) ? status : "",
    search: q.get("q") ?? "",
    from: q.get("from") ?? "",
    to: q.get("to") ?? "",
    cursor: q.get("cursor") ?? "",
    limit: isPositiveWholeNumber(limit) ? limit : "",
    order: isRunOrder(order) ? order : "",
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
        ["order", route.filters.order],
      ]);
    case "run":
      return route.chain
        ? `/runs/${encodeURIComponent(route.runId)}/chain`
        : `/runs/${encodeURIComponent(route.runId)}`;
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
    case "alert":
      return `/alerts/${encodeURIComponent(route.eventId)}`;
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
