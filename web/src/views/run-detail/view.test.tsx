// SPDX-License-Identifier: Apache-2.0

/*
 * FE-087 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Run detail's read has four states and never fewer | A bounded loading
 *     state; a run that does not exist rendered as absent and not as a fault;
 *     a read that failed rendered as degraded with a retry; the loaded view;
 *     and the staleness marker carried whenever the read path is degraded |
 *     FD §4.4, §4.6, P2, §8 anti-patterns 7 and 8
 *
 * The two states that get collapsed are "no such run" and "the ledger did not
 * answer". They look the same on screen if nobody separates them, and they
 * mean opposite things to an auditor: one says the link is wrong, the other
 * says the system is not answering. doc 06 P2 exists for this.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { StalenessProvider } from "../../components/common/StalenessIndicator";
import { RunDetailView, RunNotFound } from "./RunDetailView";
import type { FetchRun } from "./RunDetailView";
import { NOW, SPIFFE_ID, runDetail } from "./fixtures";
import type { RunDetail } from "./types";

const ROUTE = { view: "run", runId: "run-7f3a2c" } as const;

function view(read: () => Promise<RunDetail>) {
  return render(<RunDetailView route={ROUTE} fetchRun={read} now={NOW} />);
}

describe("FE-087 the four read states", () => {
  it("says what it is loading while it loads", () => {
    view(() => new Promise<RunDetail>(() => undefined));
    expect(screen.getByRole("status")).toHaveTextContent("Loading the run…");
  });

  it("renders the run once it arrives", async () => {
    view(async () => runDetail());
    expect(await screen.findByText(SPIFFE_ID)).toBeInTheDocument();
    expect(screen.getByText("Timeline")).toBeInTheDocument();
  });

  it("passes the run id from the route to the read, and nothing else", async () => {
    const read = vi.fn<FetchRun>(async () => runDetail());
    render(<RunDetailView route={ROUTE} fetchRun={read} now={NOW} />);
    await screen.findByText("Timeline");
    expect(read.mock.calls[0]?.[0]).toEqual("run-7f3a2c");
  });

  it("calls a run that does not exist absent, not broken", async () => {
    view(async () => {
      throw new RunNotFound("run-7f3a2c");
    });
    expect(await screen.findByText("No run with this identifier")).toBeInTheDocument();
    // A missing run is not a fault, so it raises nothing (doc 06 P2, P3).
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("calls a read that failed a failure, says what failed, and offers a retry", async () => {
    let attempt = 0;
    view(async () => {
      attempt += 1;
      if (attempt === 1) throw new Error("502 Bad Gateway");
      return runDetail();
    });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Can't reach the ledger");
    expect(alert).toHaveTextContent("502 Bad Gateway");

    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
  });

  it("carries the staleness marker when the read path is degraded", async () => {
    render(
      <StalenessProvider
        degraded
        asOf={new Date("2026-08-31T11:30:00.000Z")}
        now={NOW}
      >
        <RunDetailView route={ROUTE} fetchRun={async () => runDetail()} now={NOW} />
      </StalenessProvider>,
    );
    await screen.findByText("Timeline");
    expect(screen.getByText(/Data as of/)).toBeInTheDocument();
    expect(screen.getByText("2026-08-31 11:30:00 UTC")).toBeInTheDocument();
  });

  it("carries no staleness marker when the read path is healthy", async () => {
    view(async () => runDetail());
    await screen.findByText("Timeline");
    expect(screen.queryByText(/Data as of/)).not.toBeInTheDocument();
  });
});
