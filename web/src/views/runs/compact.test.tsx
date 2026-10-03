// SPDX-License-Identifier: Apache-2.0

/*
 * RM-331 (#507) — a better runs list: seven plain columns, one note instead of
 * one per row, repository offered as a choice, and plain paging.
 */

import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runPage, runSummary, threeRuns } from "./fixtures";
import { RunsTable } from "./RunsTable";
import { RunsView } from "./RunsView";
import type { RunPage } from "./api";

afterEach(cleanup);
beforeEach(() => window.history.replaceState(null, "", "/runs"));

const source = (page: RunPage) => () => Promise.resolve(page);

describe("RM-331 the runs table", () => {
  it("has the columns Status, Repository, Agent type, Task, Started, Last seen, Commits", () => {
    render(<RunsTable runs={threeRuns()} total={3} />);
    expect(
      screen.getAllByRole("columnheader").map((h) => h.textContent?.replace(/\s*Sort.*$/, "").trim()),
    ).toEqual([
      "Status",
      "Repository",
      "Agent type",
      "Task",
      "Started",
      "Last seen",
      "Commits",
    ]);
  });

  it("shows the repository, the agent type and a commit count on each row", () => {
    render(<RunsTable runs={[runSummary()]} total={1} />);
    const row = screen.getAllByRole("row")[1] as HTMLElement;
    expect(within(row).getByRole("link", { name: "innsegl.dev/core" })).toBeInTheDocument();
    expect(row).toHaveTextContent("fix-ci");
    expect(row).toHaveTextContent("2 commits");
  });

  it("repeats no note on any row", () => {
    render(<RunsTable runs={threeRuns()} total={3} />);
    expect(screen.queryByText(/no live check ran/i)).toBeNull();
    expect(screen.queryByText(/live checks against/i)).toBeNull();
  });

  it("does not call the repository column 'Signed in'", () => {
    render(<RunsTable runs={threeRuns()} total={3} />);
    expect(screen.queryByText(/signed in/i)).toBeNull();
  });

  it("links the task to the run", () => {
    render(<RunsTable runs={[runSummary()]} total={1} />);
    expect(screen.getByRole("link", { name: /task-1481/ })).toHaveAttribute(
      "href",
      "/runs/run-7f3a2c",
    );
  });

  it("marks the sort on the Started column, which is what the ledger sorts", () => {
    render(<RunsTable runs={threeRuns()} total={3} filters={{
      repo: "", agentType: "", status: "", search: "", from: "", to: "", cursor: "", limit: "", order: "",
    }} />);
    const started = screen.getByRole("columnheader", { name: /started/i });
    expect(started).toHaveAttribute("aria-sort", "descending");
  });
});

describe("RM-331 the runs view", () => {
  it("says once, above the table, that the list runs no live verification", async () => {
    render(<RunsView source={source(runPage())} />);
    const table = await screen.findByRole("table");
    const note = screen.getByTestId("runs-note");
    expect(note).toHaveTextContent(/no live verification/i);
    expect(
      note.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(screen.getAllByText(/no live verification/i)).toHaveLength(1);
  });

  it("offers the repositories the API returned as choices, and still accepts any", async () => {
    render(<RunsView source={source(runPage())} />);
    await screen.findByRole("table");
    const input = screen.getByLabelText("Repository") as HTMLInputElement;
    const list = document.getElementById(input.getAttribute("list") ?? "");
    expect(list?.tagName).toBe("DATALIST");
    expect([...(list?.querySelectorAll("option") ?? [])].map((o) => o.getAttribute("value"))).toEqual([
      "innsegl.dev/core",
      "innsegl.dev/docs",
    ]);
  });

  it("keeps status a select", async () => {
    render(<RunsView source={source(runPage())} />);
    await screen.findByRole("table");
    expect(screen.getByLabelText("Status").tagName).toBe("SELECT");
  });

  it("pages plainly: 'Next 200 runs', and no talk of cursors", async () => {
    render(
      <RunsView source={source(runPage({ total: 900, limit: 200, next_cursor: "4102" }))} />,
    );
    await screen.findByRole("table");
    expect(screen.getByRole("link", { name: "Next 200 runs" })).toHaveAttribute(
      "href",
      expect.stringContaining("cursor=4102"),
    );
    expect(screen.queryByText(/keyset|cursor/i)).toBeNull();
    expect(screen.queryByText(/at most/i)).toBeNull();
  });
});
