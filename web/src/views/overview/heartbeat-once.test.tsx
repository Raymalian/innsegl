// SPDX-License-Identifier: Apache-2.0

/*
 * FE-114 — the anchoring heartbeat is rendered once.
 *
 * doc 06 §3.1 puts the pulse in one place and says which:
 *
 *   "Anchoring heartbeat in the persistent header (all views): 'Ledger segment
 *    N anchored M min ago.' ... it is the system's public tamper-evidence
 *    pulse and is never hidden."
 *
 * The shell owns that header and takes the pulse as a prop (App.tsx), and
 * `OverviewHeartbeat` is what fills the slot. The overview BODY rendered a
 * second `AnchoringPulse` of its own, so a reader on "/" saw the same sentence
 * twice — once in the chrome and once in the page. Two renderings of one fact
 * is not redundancy here, it is a second place the fact can be wrong: they
 * read the same endpoint through two independent hooks, so a slow or failing
 * second read puts "Ledger segment 8421 anchored 3 min ago" above
 * "Couldn't read the anchoring heartbeat" on the same screen.
 *
 * `AnchoringEvidence` is NOT the pulse and stays where it is: the chain
 * positions, the segment digest and the Rekor index are the material behind
 * the claim (doc 06 P1), they appear nowhere else, and the header is a single
 * line that cannot carry them.
 */

import { render, screen } from "@testing-library/react";

import { App } from "../../app/App";
import { Overview } from "./Overview";
import { AnchoringPulse } from "./AnchoringPulse";
import type { OverviewData } from "./types";

const NOW = new Date("2026-08-30T14:44:05Z");

const DATA: OverviewData = {
  active_runs: 7,
  retired_runs: 41,
  expired_runs: 2,
  commits_recorded: 1284573,
  open_alerts: 0,
  anchor: {
    present: true,
    segment_id: "sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f",
    first_position: 8001,
    last_position: 8421,
    sealed_at: "2026-08-30T14:41:05Z",
    anchored: true,
    rekor_log_index: 82914,
  },
  data_as_of: "2026-08-30T14:44:05Z",
};

describe("FE-114 the anchoring heartbeat is rendered once", () => {
  it("is absent from the overview body: §3.1 puts it in the header", () => {
    const { container } = render(
      <Overview data={DATA} now={NOW} apiBase="/api/v1" />,
    );
    expect(container.querySelectorAll("[data-testid='overview-heartbeat']")).toHaveLength(
      0,
    );
    expect(screen.queryByText(/anchored 3 min ago/i)).toBeNull();
  });

  it("keeps the material behind the pulse, which is not the pulse (P1, P4)", () => {
    render(<Overview data={DATA} now={NOW} apiBase="/api/v1" />);
    expect(screen.getByText(/chain positions 8001 to 8421/i)).toBeInTheDocument();
    expect(screen.getAllByText(/82914/).length).toBeGreaterThan(0);
  });

  it("appears exactly once on a rendered overview, in the shell's header", () => {
    window.history.replaceState(null, "", "/");
    const { container } = render(
      <App
        views={{ overview: () => <Overview data={DATA} now={NOW} apiBase="/api/v1" /> }}
        heartbeat={<AnchoringPulse anchor={DATA.anchor} lagBoundMs={900_000} now={NOW} />}
      />,
    );
    expect(container.querySelectorAll("[data-testid='overview-heartbeat']")).toHaveLength(
      1,
    );
    expect(screen.getAllByText(/ledger segment 8421 anchored/i)).toHaveLength(1);
  });
});
