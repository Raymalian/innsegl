// SPDX-License-Identifier: Apache-2.0

/*
 * FE-121 — the runs table and the overview's recent runs are one treatment.
 *
 * doc 06 §5.4 puts the density of a table in the token sheet ("compact rows in
 * tables"), and §5.1 puts every value behind a token so "a downstream
 * deployment can rebrand without touching components". Two tables that reached
 * for the same tokens independently still drift: one of them grows a header
 * background, the other keeps a plain rule, and a reader two clicks apart is
 * looking at two products.
 *
 * The overview's recent runs became a real table in FE-118. This is what stops
 * the two from being maintained as twins by hand: the classes come from ONE
 * module, and a rendered header cell and a rendered body cell in either table
 * carry byte-identical class strings. Restyling a table means editing the
 * shared module, which restyles both.
 *
 * Rendered rather than read off the source, deliberately. An import is easy to
 * satisfy and easy to defeat — a view can import the shared string and then
 * append a class of its own. Comparing the rendered attribute is the assertion
 * that actually holds.
 */

import { render, screen } from "@testing-library/react";

import { RecentRuns } from "../overview/RecentRuns";
import type { RunSummary as OverviewRun } from "../overview/types";
import { RunsTable } from "./RunsTable";
import { threeRuns } from "./fixtures";

const OVERVIEW_RUNS: readonly OverviewRun[] = [
  {
    run_id: "run-7f3a2c",
    spiffe_id: "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c",
    agent_type: "fix-ci",
    task_ref: "task-1481",
    status: "active",
    repos: ["innsegl.dev/core"],
    commits: 2,
    chain_position: 4181,
    registered_at: "2026-08-30T11:02:41Z",
    last_event_at: "2026-08-30T11:12:04Z",
  },
];

function classesOf(): { header: string; cell: string; rowHeader: string } {
  const header = screen.getAllByRole("columnheader")[0] as HTMLElement;
  const rowHeader = screen.getAllByRole("rowheader")[0] as HTMLElement;
  const cell = screen.getAllByRole("cell")[0] as HTMLElement;
  return {
    header: header.className,
    cell: cell.className,
    rowHeader: rowHeader.className,
  };
}

describe("FE-121 one table treatment, two tables", () => {
  it("draws the same column header in both", () => {
    const overview = render(<RecentRuns runs={OVERVIEW_RUNS} />);
    const fromOverview = classesOf();
    overview.unmount();

    render(<RunsTable runs={threeRuns()} total={3} />);
    const fromRuns = classesOf();

    expect(fromRuns.header).toEqual(fromOverview.header);
  });

  it("draws the same body cell and the same row header in both", () => {
    const overview = render(<RecentRuns runs={OVERVIEW_RUNS} />);
    const fromOverview = classesOf();
    overview.unmount();

    render(<RunsTable runs={threeRuns()} total={3} />);
    const fromRuns = classesOf();

    expect(fromRuns.cell).toEqual(fromOverview.cell);
    expect(fromRuns.rowHeader).toEqual(fromOverview.rowHeader);
  });

  it("wraps both in the same scrolling shell, so neither can overflow alone", () => {
    const overview = render(<RecentRuns runs={OVERVIEW_RUNS} />);
    const fromOverview = (
      screen.getByRole("table").parentElement as HTMLElement
    ).className;
    overview.unmount();

    render(<RunsTable runs={threeRuns()} total={3} />);
    expect((screen.getByRole("table").parentElement as HTMLElement).className).toEqual(
      fromOverview,
    );
  });
});
