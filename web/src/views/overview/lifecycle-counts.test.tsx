// SPDX-License-Identifier: Apache-2.0

/*
 * FE-131 (NEW — proposed for doc 07 TC-FE; see the report for #256).
 *
 *   U | The overview counts Lapsed and Abandoned, and counts neither as
 *     active | Both numbers render beside the active count, labelled, with
 *     the horizon that split them; the active figure is unchanged by either |
 *     #256, FD §3.1, §6.2, §8 anti-pattern 10
 *
 * ── WHY THEY SIT BESIDE THE ACTIVE COUNT ───────────────────────────────────
 *
 * "Active agents" is the first number an operator reads, and the question it
 * has to survive is "and the rest?". Before this there was one other bucket
 * and its name implied the agents in it were gone. Two buckets, named for what
 * the SYSTEM will and will not do — restore an identity, or refuse to — answer
 * that question without answering a question nobody can: whether an agent is
 * still there.
 *
 * MetricCard's `children` slot exists for exactly this ("a breakdown, a link
 * to the material"), so this is the design system's own affordance and not a
 * new one.
 */

import { render, screen, within } from "@testing-library/react";

import { Overview } from "./Overview";
import type { OverviewData } from "./types";

const NOW = new Date("2026-08-30T14:44:05Z");

const DATA: OverviewData = {
  active_runs: 7,
  lapsed_runs: 3,
  abandoned_runs: 2,
  retired_runs: 41,
  commits_recorded: 1284573,
  open_alerts: 0,
  restore_horizon_seconds: 30 * 24 * 60 * 60,
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

function view(over: Partial<OverviewData> = {}) {
  return render(
    <Overview data={{ ...DATA, ...over }} now={NOW} apiBase="/api/v1" />,
  );
}

function activeCard(): HTMLElement {
  return screen.getByTestId("metric-active-agents");
}

describe("FE-131 the overview counts lapsed and abandoned", () => {
  it("renders both numbers, each named", () => {
    view();
    const card = within(activeCard());
    expect(card.getByText(/\b3 lapsed\b/)).toBeInTheDocument();
    expect(card.getByText(/\b2 abandoned\b/)).toBeInTheDocument();
  });

  it("counts neither of them as active", () => {
    const { rerender } = view();
    // The headline figure is `active_runs` and nothing else. 7, not 10, not 12.
    expect(within(activeCard()).getByText("7")).toBeInTheDocument();

    rerender(
      <Overview
        data={{ ...DATA, lapsed_runs: 900, abandoned_runs: 900 }}
        now={NOW}
        apiBase="/api/v1"
      />,
    );
    expect(within(activeCard()).getByText("7")).toBeInTheDocument();
  });

  it("states the horizon the two were split with", () => {
    view();
    expect(within(activeCard()).getByText(/30 d/)).toBeInTheDocument();
  });

  it("says when the deployment set no horizon, rather than showing a number", () => {
    view({ restore_horizon_seconds: 0, abandoned_runs: 0 });
    expect(within(activeCard()).getByText(/no restore horizon/i)).toBeInTheDocument();
  });

  it("says nothing about either when there are none of both", () => {
    // doc 06 P3: the calm state is what is left over. A breakdown reading
    // "0 lapsed, 0 abandoned" on every healthy deployment is a line readers
    // learn to skip, and then skip on the day it is not zero.
    view({ lapsed_runs: 0, abandoned_runs: 0 });
    expect(within(activeCard()).queryByText(/lapsed/i)).toBeNull();
  });

  it("makes no claim about the agents behind either number", () => {
    const { container } = view();
    expect(container.textContent ?? "").not.toMatch(
      /\b(?:dead|died|death|dying|killed)\b/i,
    );
  });
});
