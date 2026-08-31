// SPDX-License-Identifier: Apache-2.0

/*
 * FE-043 and the repo view's pure machinery (NEW — proposed for doc 07 TC-FE;
 * see the report for #55).
 *
 *   FE-043 | U | Repo-host link-out is derived from the `repo` field's own
 *     `host/org/name` grammar, and is absent for any value that does not parse
 *     as one | A link only for a value doc 02 §5 sanctions; null for a URL, a
 *     bare name, a query string, an uppercase host or a traversal | FD §3.4,
 *     P4; doc 02 §5
 *
 * The window and the completeness rule are here too, because both are the
 * arithmetic that keeps FD §8's anti-pattern 10 out of the view: a count with
 * no window is a vanity number, and a group count taken over a page that is
 * not the whole set is a wrong number stated confidently.
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_WINDOW_DAYS,
  groupByIdentity,
  hostUrlOf,
  isComplete,
  resolveWindow,
} from "./repo";
import { runsPath } from "./query";
import type { RunPage, RunSummary } from "./query";

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = new Date("2026-08-31T12:00:00Z");

function run(over: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: "run-7f3a2c",
    spiffe_id: "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c",
    agent_type: "fix-ci",
    task_ref: "task-1481",
    status: "retired",
    repos: ["github.com/acme/api"],
    commits: 3,
    chain_position: 91,
    registered_at: "2026-08-20T09:00:00Z",
    last_event_at: "2026-08-20T09:20:00Z",
    ...over,
  };
}

function page(runs: readonly RunSummary[], total: number, nextCursor = ""): RunPage {
  return {
    runs,
    total,
    limit: 200,
    ...(nextCursor === "" ? {} : { next_cursor: nextCursor }),
    data_as_of: "2026-08-31T12:00:00Z",
  };
}

describe("FE-043 the link-out follows doc 02 §5's repo grammar", () => {
  it("links a host/org/name value over https", () => {
    expect(hostUrlOf("github.com/acme/api")).toBe("https://github.com/acme/api");
  });

  it("keeps every segment of a nested group path", () => {
    expect(hostUrlOf("gitlab.example.co.uk/org/team/name")).toBe(
      "https://gitlab.example.co.uk/org/team/name",
    );
  });

  it.each([
    ["", "an empty value names no repository"],
    ["acme/api", "no host segment, so no host to link to"],
    ["github.com/acme", "doc 02 §5 spells the grammar host/org/name"],
    ["https://github.com/acme/api", "already a URL, which is not what is recorded"],
    ["GitHub.com/acme/api", "doc 02 §5 says lowercase host"],
    ["github.com/acme/api?next=x", "a query string is not part of the grammar"],
    ["github.com/acme/api#frag", "nor is a fragment"],
    ["github.com/acme/../../etc", "nor is a traversal"],
    ["evil.com@github.com/a/b", "userinfo would move the host"],
    ["github.com/acme/ api", "whitespace is not a segment character"],
  ])("refuses %j — %s", (value) => {
    expect(hostUrlOf(value)).toBeNull();
  });
});

describe("FE-040 every window the view uses is a stated one", () => {
  it("takes both bounds from the address when both are RFC 3339", () => {
    const w = resolveWindow("2026-08-01T00:00:00Z", "2026-08-15T00:00:00Z", NOW);
    expect(w.source).toBe("url");
    expect(w.from.toISOString()).toBe("2026-08-01T00:00:00.000Z");
    expect(w.to.toISOString()).toBe("2026-08-15T00:00:00.000Z");
  });

  it.each([
    ["", ""],
    ["2026-08-01T00:00:00Z", ""],
    ["", "2026-08-15T00:00:00Z"],
    ["yesterday", "today"],
    ["2026-08-15T00:00:00Z", "2026-08-01T00:00:00Z"],
    ["2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z"],
  ])("falls back to a stated default for (%j, %j)", (from, to) => {
    const w = resolveWindow(from, to, NOW);
    expect(w.source).toBe("default");
    expect(w.to.getTime()).toBe(NOW.getTime());
    expect(w.from.getTime()).toBe(NOW.getTime() - DEFAULT_WINDOW_DAYS * DAY_MS);
  });

  it("never returns a window that is not a positive interval", () => {
    for (const [from, to] of [
      ["", ""],
      ["2026-08-15T00:00:00Z", "2026-08-01T00:00:00Z"],
      ["2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z"],
      ["2026-08-01T00:00:00Z", "2026-08-15T00:00:00Z"],
    ]) {
      const w = resolveWindow(from as string, to as string, NOW);
      expect(w.to.getTime()).toBeGreaterThan(w.from.getTime());
    }
  });
});

describe("FE-042 the page knows whether it is the whole set", () => {
  it("is complete when the server's total is on the page and no cursor follows", () => {
    expect(isComplete(page([run(), run({ run_id: "b" })], 2))).toBe(true);
  });

  it("is not complete when the server counted more than it served", () => {
    expect(isComplete(page([run()], 4))).toBe(false);
  });

  it("is not complete when the server offered a next page", () => {
    expect(isComplete(page([run()], 1, "90"))).toBe(false);
  });
});

describe("FE-042 runs group by the identity that made them", () => {
  it("puts two runs of one identity in one group, in first-seen order", () => {
    const a = "spiffe://innsegl.dev/agent/fix-ci/task-1/run-a";
    const b = "spiffe://innsegl.dev/agent/dep-bump/task-2/run-b";
    const groups = groupByIdentity([
      run({ run_id: "1", spiffe_id: a }),
      run({ run_id: "2", spiffe_id: b }),
      run({ run_id: "3", spiffe_id: a }),
    ]);
    expect(groups.map((g) => g.identity)).toEqual([a, b]);
    expect(groups[0]?.runs.map((r) => r.run_id)).toEqual(["1", "3"]);
    expect(groups[1]?.runs.map((r) => r.run_id)).toEqual(["2"]);
  });

  it("groups nothing out of nothing", () => {
    expect(groupByIdentity([])).toEqual([]);
  });
});

describe("FE-040 the request carries internal/api's own parameter names", () => {
  it("spells them as server.go's runFilterFrom reads them", () => {
    const url = new URL(
      runsPath({
        repo: "github.com/acme/api",
        agentType: "fix-ci",
        from: new Date("2026-08-01T00:00:00Z"),
        to: new Date("2026-08-15T00:00:00Z"),
        limit: 200,
      }),
      "http://dashboard.invalid",
    );
    expect(url.pathname).toBe("/api/v1/runs");
    expect(url.searchParams.get("repo")).toBe("github.com/acme/api");
    expect(url.searchParams.get("agent_type")).toBe("fix-ci");
    expect(url.searchParams.get("from")).toBe("2026-08-01T00:00:00.000Z");
    expect(url.searchParams.get("to")).toBe("2026-08-15T00:00:00.000Z");
    expect(url.searchParams.get("limit")).toBe("200");
  });

  it("carries no parameter it was not given, so an unbounded read is visible", () => {
    expect(runsPath({})).toBe("/api/v1/runs");
    expect(runsPath({ repo: "" })).toBe("/api/v1/runs");
  });
});
