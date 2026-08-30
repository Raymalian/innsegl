// SPDX-License-Identifier: Apache-2.0

// FE-010 — URL state: filters/selection encoded and restorable (doc 07).
// FE-016 — the route table itself: six views, flat depth, canonical round-trip.
//
// FD §7: "every view's state (filters, selected run, verification input) lives
// in the URL". FD §3: "no nesting deeper than view → detail".

import { describe, expect, it } from "vitest";

import {
  VIEWS,
  emptyRunsFilters,
  parseRoute,
  routeToPath,
  type Route,
} from "./routes";

describe("FE-016 route table", () => {
  it("names exactly the six views doc 06 §3 specifies", () => {
    expect([...VIEWS]).toEqual([
      "overview",
      "runs",
      "run",
      "repo",
      "agentType",
      "verify",
    ]);
  });

  it("never nests deeper than view → detail", () => {
    const routes: Route[] = [
      { view: "overview" },
      { view: "runs", filters: emptyRunsFilters() },
      { view: "run", runId: "run-7f3a" },
      { view: "repo", repo: "acme/widgets", from: "", to: "" },
      { view: "agentType", agentType: "fix-ci", from: "", to: "" },
      { view: "verify", commit: "", repo: "" },
    ];
    for (const route of routes) {
      const path = routeToPath(route).split("?")[0] ?? "";
      const segments = path.split("/").filter((s) => s !== "");
      expect(segments.length, `${route.view} → ${path}`).toBeLessThanOrEqual(2);
    }
  });

  it("routes an unknown path to notFound rather than to a view", () => {
    expect(parseRoute("/runs/a/b/c")).toEqual({
      view: "notFound",
      path: "/runs/a/b/c",
    });
    expect(parseRoute("/nope")).toEqual({ view: "notFound", path: "/nope" });
  });
});

describe("FE-010 URL carries every view's state", () => {
  const canonical = [
    "/",
    "/runs",
    "/runs?repo=acme%2Fwidgets",
    "/runs?repo=acme%2Fwidgets&agent_type=fix-ci&status=expired&q=flake&from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z&cursor=4821&limit=25",
    "/runs/run-7f3a",
    "/repos/acme%2Fwidgets",
    "/repos/acme%2Fwidgets?from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z",
    "/agent-types/fix-ci",
    "/verify",
    "/verify?commit=9d4e1f0c",
    "/verify?commit=9d4e1f0c&repo=acme%2Fwidgets",
  ];

  it.each(canonical)("round-trips %s byte for byte", (path) => {
    expect(routeToPath(parseRoute(path))).toBe(path);
  });

  it("restores every runs filter from a copied link", () => {
    const route = parseRoute(
      "/runs?repo=acme%2Fwidgets&agent_type=fix-ci&status=expired&q=flake&from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z&cursor=4821&limit=25",
    );
    expect(route).toEqual({
      view: "runs",
      filters: {
        repo: "acme/widgets",
        agentType: "fix-ci",
        status: "expired",
        search: "flake",
        from: "2026-08-01T00:00:00Z",
        to: "2026-08-30T00:00:00Z",
        cursor: "4821",
        limit: "25",
      },
    });
  });

  it("uses the query API's own parameter names, so a filtered view and its request agree", () => {
    const path = routeToPath({
      view: "runs",
      filters: {
        repo: "acme/widgets",
        agentType: "fix-ci",
        status: "active",
        search: "flake",
        from: "2026-08-01T00:00:00Z",
        to: "2026-08-30T00:00:00Z",
        cursor: "4821",
        limit: "25",
      },
    });
    const names = [...new URL(path, "https://x").searchParams.keys()];
    expect(names).toEqual([
      "repo",
      "agent_type",
      "status",
      "q",
      "from",
      "to",
      "cursor",
      "limit",
    ]);
  });

  it("canonicalises a hand-edited link: reordered, empty and unknown parameters", () => {
    const messy = "/runs?limit=25&nonsense=1&repo=acme%2Fwidgets&q=&status=";
    expect(routeToPath(parseRoute(messy))).toBe(
      "/runs?repo=acme%2Fwidgets&limit=25",
    );
  });

  it("drops a limit that is not a positive whole number", () => {
    expect(parseRoute("/runs?limit=abc")).toEqual({
      view: "runs",
      filters: emptyRunsFilters(),
    });
    expect(parseRoute("/runs?limit=0")).toEqual({
      view: "runs",
      filters: emptyRunsFilters(),
    });
  });

  it("drops a status the API does not define rather than forwarding it", () => {
    const route = parseRoute("/runs?status=deleted");
    expect(route).toEqual({ view: "runs", filters: emptyRunsFilters() });
  });

  it("keeps a repository's slash intact through the path segment", () => {
    expect(parseRoute("/repos/acme%2Fwidgets")).toEqual({
      view: "repo",
      repo: "acme/widgets",
      from: "",
      to: "",
    });
    expect(parseRoute("/repos/acme/widgets").view).toBe("notFound");
  });

  it("carries the public page's verification input in the URL (FD §3.6)", () => {
    expect(parseRoute("/verify?commit=9d4e1f0c&repo=acme%2Fwidgets")).toEqual({
      view: "verify",
      commit: "9d4e1f0c",
      repo: "acme/widgets",
    });
  });

  it("selects a run by id in the path, not in component state", () => {
    expect(parseRoute("/runs/run-7f3a")).toEqual({
      view: "run",
      runId: "run-7f3a",
    });
  });
});
