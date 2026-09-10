// SPDX-License-Identifier: Apache-2.0

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { RunsTable } from "./RunsTable";
import { runSummary } from "./fixtures";

/**
 * FE-061 (proposed for doc 06's test list; doc 06 is not modified here).
 *
 * The rendered half of FE-060: a stale row must SAY it is stale, in the table,
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

describe("FE-061 a stale run says so in the table", () => {
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

    // The dead one carries its age.
    expect(screen.getByText("last seen 17 hours ago")).toBeTruthy();

    // The live one carries nothing: an annotation on every healthy row is one
    // a reader learns to skip, and then skips on the row that mattered.
    expect(screen.queryByText(/last seen 0 minutes ago/)).toBeNull();
    expect(screen.queryAllByText(/last seen/)).toHaveLength(1);
  });

  it("says nothing when the ledger recorded no time, rather than inventing one", () => {
    const runs = [runSummary({ run_id: "run-unknown", last_event_at: "" })];
    render(<RunsTable runs={runs} total={runs.length} />);
    expect(screen.queryAllByText(/last seen/)).toHaveLength(0);
  });
});
