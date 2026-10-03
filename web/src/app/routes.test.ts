// SPDX-License-Identifier: Apache-2.0

// FE-010 — URL state: filters/selection encoded and restorable (doc 07).
// FE-016 — the route table itself: six views plus the alert detail
// (ADR-0054), flat depth, canonical round-trip.
//
// FD §7: "every view's state (filters, selected run, verification input) lives
// in the URL". FD §3: "no nesting deeper than view → detail".

import { describe, expect, it } from "vitest";

import {
  VIEWS,
  emptyRunsFilters,
  isAccountPath,
  isSetupPath,
  parseRoute,
  routeToPath,
  setupCodeFrom,
  type Route,
} from "./routes";

describe("FE-016 route table", () => {
  it("names the six views doc 06 §3 specifies, the alerts page, and ADR-0054's alert detail", () => {
    expect([...VIEWS]).toEqual([
      "overview",
      "runs",
      "run",
      "repos",
      "repo",
      "agentType",
      "verify",
      "alerts",
      "alert",
    ]);
  });

  it("addresses one alert by its event ID, one level deep (ADR-0054)", () => {
    expect(parseRoute("/alerts/01a077c2-eff1-7762-8a61-91a3a5c390e8")).toEqual({
      view: "alert",
      eventId: "01a077c2-eff1-7762-8a61-91a3a5c390e8",
    });
  });

  it("addresses the alerts page, its kind and its run in the URL (RM-330)", () => {
    expect(parseRoute("/alerts")).toEqual({ view: "alerts", filters: { kind: "", run: "" } });
    expect(parseRoute("/alerts?kind=resolved&run=run-7f3a")).toEqual({
      view: "alerts",
      filters: { kind: "resolved", run: "run-7f3a" },
    });
    expect(parseRoute("/alerts?kind=nonsense")).toEqual({
      view: "alerts",
      filters: { kind: "", run: "" },
    });
  });

  it("never nests deeper than view → detail", () => {
    const routes: Route[] = [
      { view: "overview" },
      { view: "runs", filters: emptyRunsFilters() },
      { view: "run", runId: "run-7f3a" },
      { view: "repo", repo: "acme/widgets", from: "", to: "" },
      { view: "agentType", agentType: "fix-ci", from: "", to: "" },
      { view: "verify", commit: "", repo: "" },
      { view: "alerts", filters: { kind: "all", run: "run-7f3a" } },
      { view: "alert", eventId: "01a077c2-eff1-7762-8a61-91a3a5c390e8" },
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
    "/runs?repo=acme%2Fwidgets&agent_type=fix-ci&status=lapsed&q=flake&from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z&cursor=4821&limit=25",
    "/runs/run-7f3a",
    "/repos/acme%2Fwidgets",
    "/repos/acme%2Fwidgets?from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z",
    "/agent-types/fix-ci",
    "/verify",
    "/verify?commit=9d4e1f0c",
    "/verify?commit=9d4e1f0c&repo=acme%2Fwidgets",
    "/alerts",
    "/alerts?kind=resolved",
    "/alerts?kind=all&run=run-7f3a",
    "/alerts/01a077c2-eff1-7762-8a61-91a3a5c390e8",
  ];

  it.each(canonical)("round-trips %s byte for byte", (path) => {
    expect(routeToPath(parseRoute(path))).toBe(path);
  });

  it("restores every runs filter from a copied link", () => {
    const route = parseRoute(
      "/runs?repo=acme%2Fwidgets&agent_type=fix-ci&status=lapsed&q=flake&from=2026-08-01T00%3A00%3A00Z&to=2026-08-30T00%3A00%3A00Z&cursor=4821&limit=25",
    );
    expect(route).toEqual({
      view: "runs",
      filters: {
        repo: "acme/widgets",
        agentType: "fix-ci",
        status: "lapsed",
        search: "flake",
        from: "2026-08-01T00:00:00Z",
        to: "2026-08-30T00:00:00Z",
        cursor: "4821",
        limit: "25",
        order: "",
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
        order: "",
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

describe("#445: /setup and /account, deliberately outside VIEWS/Route", () => {
  it("parseRoute sends /setup and /account to notFound — AuthGate and App.tsx decide them off the path directly", () => {
    expect(parseRoute("/setup").view).toBe("notFound");
    expect(parseRoute("/setup?code=abc").view).toBe("notFound");
    expect(parseRoute("/account").view).toBe("notFound");
  });

  it("isSetupPath matches only /setup, query string or not", () => {
    expect(isSetupPath("/setup")).toBe(true);
    expect(isSetupPath("/setup?code=the-one-time-code")).toBe(true);
    expect(isSetupPath("/")).toBe(false);
    expect(isSetupPath("/account")).toBe(false);
    expect(isSetupPath("/setup/extra")).toBe(false);
  });

  it("setupCodeFrom reads the ?code= off a /setup address, or \"\" if absent", () => {
    expect(setupCodeFrom("/setup?code=the-one-time-code")).toBe("the-one-time-code");
    expect(setupCodeFrom("/setup")).toBe("");
    expect(setupCodeFrom("/setup?code=")).toBe("");
  });

  it("isAccountPath matches only /account", () => {
    expect(isAccountPath("/account")).toBe(true);
    expect(isAccountPath("/account?notice=recovery-signin")).toBe(true);
    expect(isAccountPath("/")).toBe(false);
    expect(isAccountPath("/setup")).toBe(false);
  });
});
