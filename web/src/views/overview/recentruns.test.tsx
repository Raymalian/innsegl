// SPDX-License-Identifier: Apache-2.0

/*
 * FE-118 — the overview's recent runs are a real table.
 *
 * doc 06 §3.1 asks for a "recent runs list (last ~10)" and the approved
 * artboard settles what that list looks like: five columns — status, run,
 * agent, task, commits — under a header row, in the same treatment as the
 * runs table two clicks away (FE-121).
 *
 * It was a stack of wrapped rows: a badge, a chip, an agent type and a commit
 * count, all flowing inline. Four facts per run with nothing naming which is
 * which, no way to compare the same fact down the page, and — the part doc 06
 * §6.4 governs — nothing a screen reader can navigate as tabular data:
 *
 *   "Screen-reader semantics: tables are real tables."
 *
 * So this asserts the structure, not the pixels: `table`, `caption`, `thead`,
 * `th[scope=col]` per column, and a `th[scope=row]` per run, which is what
 * tells a reader who has landed on a commit count which run it belongs to.
 *
 * The two non-rows are asserted too, because they are different things and
 * doc 06 P2 forbids rendering either as the other: a list that did not answer
 * is absent, and a list that answered with nothing is empty.
 */

import { render, screen, within } from "@testing-library/react";

import { RecentRuns } from "./RecentRuns";
import type { RunSummary } from "./types";

const RUNS: readonly RunSummary[] = [
  {
    run_id: "run-45a24f66c4e57d281dc280bee5d2671f",
    spiffe_id: "spiffe://innsegl.dev/agent/general-purpose/apts-se-005/run-45a24f66",
    agent_type: "general-purpose",
    task_ref: "apts-se-005",
    status: "active",
    repos: ["github.com/acme/api"],
    commits: 0,
    chain_position: 8402,
    registered_at: "2026-08-30T14:10:05Z",
    last_event_at: "2026-08-30T14:40:05Z",
  },
  {
    run_id: "run-b43fa508fd703f0f303b7e44fdda55cb",
    spiffe_id: "spiffe://innsegl.dev/agent/orchestrator/fix-rebase-report/run-b43fa508",
    agent_type: "orchestrator",
    task_ref: "fix-rebase-report",
    status: "retired",
    repos: [],
    commits: 1,
    chain_position: 8410,
    registered_at: "2026-08-30T13:10:05Z",
    last_event_at: "2026-08-30T14:41:05Z",
  },
];

describe("FE-118 the overview's recent runs are a real table", () => {
  it("renders a table with a caption, not a stack of rows", () => {
    render(<RecentRuns runs={RUNS} />);
    const table = screen.getByRole("table");
    expect(table.tagName).toEqual("TABLE");
    expect(table.querySelector("caption")?.textContent ?? "").not.toEqual("");
  });

  it("names its five columns in the order the design sets them", () => {
    render(<RecentRuns runs={RUNS} />);
    const headers = screen
      .getAllByRole("columnheader")
      .map((cell) => (cell.textContent ?? "").trim());
    expect(headers).toEqual(["Status", "Run", "Agent", "Task", "Commits"]);
    for (const cell of screen.getAllByRole("columnheader")) {
      expect(cell.getAttribute("scope")).toEqual("col");
    }
  });

  it("makes the run id each row's header, so every cell says whose it is", () => {
    render(<RecentRuns runs={RUNS} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(RUNS.length);
    const header = within(rows[0] as HTMLElement).getByRole("rowheader");
    expect(header.getAttribute("scope")).toEqual("row");
    expect(header.textContent ?? "").toContain("run-45a24f66");
  });

  it("carries the agent, the task and the commit count on the row", () => {
    render(<RecentRuns runs={RUNS} />);
    const row = screen.getAllByRole("row")[2] as HTMLElement;
    expect(within(row).getByText("orchestrator")).toBeInTheDocument();
    expect(within(row).getByText("fix-rebase-report")).toBeInTheDocument();
    expect(within(row).getByText("1")).toBeInTheDocument();
    // The badge names the status for the eye and again for assistive
    // technology (doc 06 §6.4); both are the point.
    expect(within(row).getAllByText(/retired/i).length).toBeGreaterThan(0);
  });

  it("renders nothing at all when the runs index did not answer (P2)", () => {
    const { container } = render(<RecentRuns runs={null} />);
    expect(container.querySelector("table")).toBeNull();
    expect(container.textContent).toEqual("");
  });

  it("says the ledger holds none rather than drawing an empty table (§4.6)", () => {
    render(<RecentRuns runs={[]} />);
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByText(/no runs yet/i)).toBeInTheDocument();
  });
});
