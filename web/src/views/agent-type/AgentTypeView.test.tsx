// SPDX-License-Identifier: Apache-2.0

/*
 * FE-044 (rendered), FE-045 and FE-046 (NEW — proposed for doc 07 TC-FE; see
 * the report for #55).
 *
 *   FE-044 | U | Run frequency across time is a set of server-side windowed
 *     counts | One request per bucket boundary, each carrying the window's own
 *     start; every rendered bucket shows both of its bounds and its count |
 *     FD §3.5, §7, §8 anti-pattern 10
 *
 *   FE-045 | U | Aggregate verification status is rendered as not verified
 *     live, and never as a verdict | No verdict, no rate, no green, no
 *     verification badge; the refusal names why a stored answer would be a
 *     database-only verdict and points at the per-commit page that does check |
 *     FD §3.5, P2, §5.3, §8 anti-patterns 1, 3 and 10; IP §6.11
 *
 *   FE-046 | U | Repositories touched are labelled by the completeness of the
 *     set they were derived from | Complete: stated as the window's whole set.
 *     Truncated: stated as the repositories named by the runs drawn, and no
 *     count of repositories is offered | FD §3.5, §7
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StalenessProvider } from "../../components/common";
import { parseRoute } from "../../app/routes";
import { AgentTypeView } from "./AgentTypeView";
import { FREQUENCY_BUCKETS } from "./frequency";
import { strings } from "./strings";
import type { LoadRuns, RunPage, RunSummary, RunsQuery } from "./query";

const NOW = new Date("2026-08-31T12:00:00Z");
const TYPE = "fix-ci";
const TYPE_PATH = `/agent-types/${TYPE}`;
const WINDOWED = `${TYPE_PATH}?from=2026-08-01T00:00:00Z&to=2026-08-31T00:00:00Z`;

function run(over: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: "run-7f3a2c",
    spiffe_id: "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c",
    agent_type: TYPE,
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

function page(runs: readonly RunSummary[], total = runs.length): RunPage {
  return { runs, total, limit: 200, data_as_of: "2026-08-31T12:00:00Z" };
}

const RUNS = page([
  run({ run_id: "run-7f3a2c", repos: ["github.com/acme/api"] }),
  run({ run_id: "run-0e91bd", chain_position: 90, repos: ["github.com/acme/web"] }),
  run({ run_id: "run-115fac", chain_position: 88, repos: ["github.com/acme/api"] }),
]);

/**
 * A loader that answers the page query with `full` and every cumulative query
 * with the next number in `cumulative`, in the order the view asks.
 */
function loader(full: RunPage | Error, cumulative: readonly number[] = []) {
  const calls: RunsQuery[] = [];
  let taken = 0;
  const load: LoadRuns = (query) => {
    calls.push(query);
    if (query.limit === 1) {
      const total = cumulative[taken] ?? 0;
      taken += 1;
      return Promise.resolve(page([], total));
    }
    return full instanceof Error ? Promise.reject(full) : Promise.resolve(full);
  };
  return { load, calls };
}

function renderType(path: string, full: RunPage | Error, cumulative: readonly number[] = []) {
  const { load, calls } = loader(full, cumulative);
  const { container } = render(<AgentTypeView route={parseRoute(path)} load={load} now={NOW} />);
  return { calls, container };
}

describe("FE-044 run frequency is asked of the server, bucket by bucket", () => {
  it("issues one cumulative query per interior boundary, all from the window's start", async () => {
    const { calls } = renderType(WINDOWED, page(RUNS.runs, 11), [2, 2, 5, 9, 9]);
    await screen.findByText(strings.labels.frequency);

    const cumulative = calls.filter((c) => c.limit === 1);
    expect(cumulative).toHaveLength(FREQUENCY_BUCKETS - 1);
    for (const call of cumulative) {
      expect(call.agentType).toBe(TYPE);
      expect(call.from?.toISOString()).toBe("2026-08-01T00:00:00.000Z");
    }
    expect(cumulative.map((c) => c.to?.toISOString())).toEqual([
      "2026-08-06T00:00:00.000Z",
      "2026-08-11T00:00:00.000Z",
      "2026-08-16T00:00:00.000Z",
      "2026-08-21T00:00:00.000Z",
      "2026-08-26T00:00:00.000Z",
    ]);
  });

  it("renders every bucket with both of its bounds and its own count", async () => {
    renderType(WINDOWED, page(RUNS.runs, 11), [2, 2, 5, 9, 9]);
    const table = await screen.findByRole("table", { name: strings.labels.frequency });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(FREQUENCY_BUCKETS);

    expect(rows[0]?.textContent).toContain("2026-08-01 00:00:00 UTC");
    expect(rows[0]?.textContent).toContain("2026-08-06 00:00:00 UTC");
    expect(
      rows.map((row) => within(row).getAllByRole("cell")[2]?.textContent),
    ).toEqual(["2", "0", "3", "4", "0", "2"]);
  });

  it("shows the window's own total, which is what the buckets sum to", async () => {
    renderType(WINDOWED, page(RUNS.runs, 11), [2, 2, 5, 9, 9]);
    const summary = await screen.findByRole("group", { name: strings.labels.summary });
    expect(within(summary).getByText(strings.labels.runsInWindow).nextElementSibling)
      .toHaveTextContent("11");
  });

  it("states the default window when the address carries none, and bounds every query with it", async () => {
    const { calls } = renderType(TYPE_PATH, RUNS, [0, 0, 0, 0, 0]);
    await screen.findByText(strings.sentences.defaultWindow);
    for (const call of calls) {
      expect(call.from?.toISOString()).toBe("2026-08-01T12:00:00.000Z");
    }
    const summary = screen.getByRole("group", { name: strings.labels.summary });
    expect(
      within(summary).getByText("2026-08-01 12:00:00 UTC", { selector: "time" }),
    ).toBeInTheDocument();
  });
});

describe("FE-045 aggregate verification status is not a verdict", () => {
  it("says it was not verified live, and why a stored answer would not do", async () => {
    renderType(WINDOWED, RUNS, [0, 0, 0, 0, 0]);
    expect(await screen.findByText(strings.labels.aggregateVerification)).toBeInTheDocument();
    expect(screen.getByText(strings.sentences.verificationNotLive)).toBeInTheDocument();
    expect(screen.getByText(strings.sentences.verificationNoAggregate)).toBeInTheDocument();
    expect(screen.getByText(strings.sentences.verificationDatabaseOnly)).toBeInTheDocument();
  });

  it("sends the reader to the page that does check, one commit at a time", async () => {
    renderType(WINDOWED, RUNS, [0, 0, 0, 0, 0]);
    const link = await screen.findByRole("link", { name: strings.labels.verifyACommit });
    expect(link).toHaveAttribute("href", "/verify");
  });

  it("spends no green, shows no badge and states no rate", async () => {
    const { container } = renderType(WINDOWED, RUNS, [0, 0, 0, 0, 0]);
    const block = await screen.findByRole("group", {
      name: strings.labels.aggregateVerification,
    });
    expect(container.innerHTML).not.toContain("proof-verified");
    expect(container.querySelector("[data-verdict]")).toBeNull();
    expect(container.textContent ?? "").not.toContain("%");
    // The strongest form of "this is not a metric": the block carries no
    // number at all. A rate, a tally or a count of verified commits would each
    // have to put a digit here, and any of the three would be a verdict read
    // out of the database (IP §6.11, FD P2).
    expect(block.textContent ?? "").not.toMatch(/\d/);
    expect(block.querySelector("svg")?.getAttribute("data-icon")).not.toBe(
      "verification-mark",
    );
  });
});

describe("FE-046 repositories touched are labelled by what they were derived from", () => {
  it("names the window's whole set when the page is the whole set", async () => {
    renderType(WINDOWED, page(RUNS.runs, 3), [0, 0, 0, 0, 0]);
    const repos = await screen.findByRole("group", { name: strings.labels.reposTouched });
    expect(within(repos).getByText(strings.sentences.reposComplete)).toBeInTheDocument();
    expect(within(repos).queryByText(strings.sentences.reposFromPage)).toBeNull();
    expect(within(repos).getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual([
      "/repos/github.com%2Facme%2Fapi",
      "/repos/github.com%2Facme%2Fweb",
    ]);
  });

  it("says the list came from the rows it drew when the server counted more", async () => {
    renderType(WINDOWED, page(RUNS.runs, 41), [0, 0, 0, 0, 0]);
    const repos = await screen.findByRole("group", { name: strings.labels.reposTouched });
    expect(within(repos).getByText(strings.sentences.reposFromPage)).toBeInTheDocument();
    expect(within(repos).queryByText(strings.sentences.reposComplete)).toBeNull();
  });

  it("offers no count of repositories, which the query API does not aggregate", async () => {
    renderType(WINDOWED, page(RUNS.runs, 41), [0, 0, 0, 0, 0]);
    const repos = await screen.findByRole("group", { name: strings.labels.reposTouched });
    expect(repos.textContent ?? "").not.toMatch(/\b2\b/);
  });
});

describe("the agent-type view's honest states (FD §4.6)", () => {
  it("says what it is loading", () => {
    const pending: LoadRuns = () => new Promise<RunPage>(() => {});
    render(<AgentTypeView route={parseRoute(TYPE_PATH)} load={pending} now={NOW} />);
    expect(screen.getByRole("status")).toHaveTextContent(strings.nouns.runs);
  });

  it("shows nothing rather than guessing when the ledger did not answer", async () => {
    renderType(WINDOWED, new Error("dial tcp: connection refused"));
    expect(await screen.findByRole("alert")).toHaveTextContent("dial tcp: connection refused");
    expect(screen.queryByText(strings.labels.frequency)).toBeNull();
  });

  it("says the window holds no runs rather than drawing an empty table", async () => {
    renderType(WINDOWED, page([], 0), [0, 0, 0, 0, 0]);
    expect(await screen.findByText(strings.sentences.empty)).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: strings.labels.runs })).toBeNull();
  });

  it("carries the staleness marker when the read path is degraded (FD §4.4)", async () => {
    const { load } = loader(RUNS, [0, 0, 0, 0, 0]);
    render(
      <StalenessProvider degraded asOf={new Date("2026-08-31T11:00:00Z")} now={NOW}>
        <AgentTypeView route={parseRoute(WINDOWED)} load={load} now={NOW} />
      </StalenessProvider>,
    );
    await screen.findByText(strings.labels.frequency);
    expect(screen.getByText("2026-08-31 11:00:00 UTC", { selector: "time" })).toBeInTheDocument();
  });

  it("refuses a route that is not an agent type rather than rendering a blank panel", () => {
    render(<AgentTypeView route={parseRoute("/nowhere/at/all")} now={NOW} />);
    expect(screen.getByRole("alert")).toHaveTextContent(strings.labels.wrongRoute);
  });
});

describe("the agent-type view links on", () => {
  it("links every run to its detail view and every repository to its own", async () => {
    renderType(WINDOWED, RUNS, [0, 0, 0, 0, 0]);
    await screen.findByText(strings.labels.frequency);
    expect(screen.getByRole("link", { name: "run-0e91bd" })).toHaveAttribute(
      "href",
      "/runs/run-0e91bd",
    );
  });
});
