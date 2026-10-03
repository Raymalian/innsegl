// SPDX-License-Identifier: Apache-2.0

/* The runs table says how long each run was active, and marks an active
 * run that has recorded nothing lately as idle. */

import { render, screen } from "@testing-library/react";

import { runSummary } from "./fixtures";
import { RunsTable } from "./RunsTable";

describe("the runs table's activity", () => {
  it("has an Active for column", () => {
    const run = runSummary({
      registered_at: "2026-10-03T08:43:03Z",
      last_event_at: "2026-10-03T10:58:03Z",
    });
    render(<RunsTable runs={[run]} total={1} />);
    expect(screen.getByRole("columnheader", { name: /active for/i })).toBeInTheDocument();
    expect(screen.getByText("2 h 15 min")).toBeInTheDocument();
  });

  it("marks an active run silent for hours as idle", () => {
    const run = runSummary({ status: "active", last_event_at: "2026-10-03T08:00:00Z" });
    render(<RunsTable runs={[run]} total={1} now={new Date("2026-10-03T17:00:00Z")} />);
    expect(screen.getByText("Idle")).toBeInTheDocument();
  });
});
