// SPDX-License-Identifier: Apache-2.0

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { RunsTable } from "./RunsTable";
import { runSummary } from "./fixtures";

/**
 * FE-058 (proposed for doc 06's test list; doc 06 is not modified here).
 *
 * The rendered half of FE-057: a stale row must SAY it is stale, in the table,
 * where the reader is.
 *
 * ── THE ROW THIS EXISTS FOR ────────────────────────────────────────────────
 *
 * Measured on this project's deployment on 2026-09-10 — six runs badged
 * Active, five of them dead. The operator's question was the only one that
 * matters about a dashboard: "how can I trust the page?" A badge that reads
 * the same for a run working now and a run that died yesterday afternoon has
 * no answer to that.
 */
afterEach(cleanup);

describe("FE-058 a stale run says so in the table", () => {
  it("annotates a run that has been quiet, and leaves a working one alone", () => {
    const now = new Date();
    const runs = [
      runSummary({ run_id: "run-alive", last_event_at: now.toISOString() }),
      runSummary({
        run_id: "run-dead",
        last_event_at: new Date(now.getTime() - 17 * 3600_000).toISOString(),
      }),
    ];
    render(<RunsTable runs={runs} total={runs.length} />);

    // RM-331: the age is the Last seen column's value, on every row.
    // The dead one carries its age; the working one says it was just seen.
    expect(screen.getByText("17 hours ago")).toBeTruthy();
    expect(screen.getByText("Just now")).toBeTruthy();
  });

  it("says it is unknown when the ledger recorded no time, rather than inventing one", () => {
    const runs = [runSummary({ run_id: "run-unknown", last_event_at: "" })];
    render(<RunsTable runs={runs} total={runs.length} />);
    expect(screen.queryAllByText(/ago|just now/i)).toHaveLength(0);
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
  });
});
