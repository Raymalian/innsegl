// SPDX-License-Identifier: Apache-2.0

/*
 * The overview page — doc 06 §3.1, §4.4, §4.5, §5.3, P2, P3.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-074 | U | Drift and reconciler alerts on the overview | Pinned above
 *          |   | every metric, banner-level, linked to their material | FD §3.1, P3
 *   FE-075 | U | The overview asserts no verification verdict | No green, no
 *          |   | verification tri-state anywhere on the view | FD §5.3, P2, IP §6.11
 */

import { render, screen, within } from "@testing-library/react";

import { StalenessProvider } from "../../components/common";
import { Overview } from "./Overview";
import type { OverviewData, RunSummary } from "./types";

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

const RUN: RunSummary = {
  run_id: "run-42",
  spiffe_id: "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
  agent_type: "fix-ci",
  task_ref: "JIRA-118",
  status: "active",
  repos: ["github.com/acme/api"],
  commits: 3,
  chain_position: 8402,
  registered_at: "2026-08-30T14:10:05Z",
  last_event_at: "2026-08-30T14:40:05Z",
};

function view(over: Partial<OverviewData> = {}, props: Record<string, unknown> = {}) {
  return render(
    <Overview data={{ ...DATA, ...over }} now={NOW} apiBase="/api/v1" {...props} />,
  );
}

describe("FE-074 alerts pin to the top", () => {
  it("puts an open drift alert above every metric, in the P3 style", () => {
    view({ open_alerts: 3 });
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/3 open integrity alerts/);
    const firstCard = screen.getByTestId("metric-active-agents");
    expect(
      alert.compareDocumentPosition(firstCard) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("says one alert in the singular, and states exactly what it counts", () => {
    view({ open_alerts: 1 });
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/1 open integrity alert/);
    expect(alert).toHaveTextContent(/could not attribute/i);
  });

  it("links the alert to the material the count came from (P1)", () => {
    view({ open_alerts: 1 });
    expect(
      within(screen.getByRole("alert")).getByRole("link"),
    ).toHaveAttribute("href", "/api/v1/overview");
  });

  it("raises no alarm when the ledger holds none (P3: the calm state is quiet)", () => {
    view({ open_alerts: 0 });
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("the overview's metrics", () => {
  it("states the counts exactly, as the query API returned them", () => {
    view();
    expect(screen.getByTestId("metric-active-agents")).toHaveTextContent("7");
    expect(screen.getByTestId("metric-commits")).toHaveTextContent("1,284,573");
  });

  it("names the window a windowed count was taken over (§8 anti-pattern 10)", () => {
    view({}, {
      runsToday: { count: 12, since: new Date("2026-08-30T00:00:00Z") },
    });
    const card = screen.getByTestId("metric-runs-today");
    expect(card).toHaveTextContent("12");
    expect(card).toHaveTextContent(/2026-08-30 00:00:00 UTC/);
  });

  it("shows no number at all when the runs index did not answer (P2)", () => {
    view();
    const card = screen.getByTestId("metric-runs-today");
    expect(card).toHaveTextContent(/not counted/i);
    expect(card).toHaveTextContent(/rather than a guess/i);
  });

  it("carries the pass-rate card, in its unmeasured state", () => {
    view();
    expect(screen.getByTestId("metric-pass-rate")).toHaveTextContent(/not measured/i);
  });
});

describe("FE-075 the overview asserts no verification verdict", () => {
  it("spends no green anywhere on the page (§5.3, §8 anti-pattern 3)", () => {
    const { container } = view({ open_alerts: 2 });
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });

  it("renders no verification tri-state at all: it ran no check (IP §6.11)", () => {
    const { container } = view();
    expect(container.innerHTML).not.toMatch(/proof-failed|proof-unavailable/);
    expect(screen.queryByText(/rekor inclusion proven/i)).toBeNull();
    expect(screen.queryByText(/fulcio certificate chain valid/i)).toBeNull();
  });
});

describe("the overview's heartbeat and staleness", () => {
  it("shows the anchoring pulse on the page, never hidden (§3.1)", () => {
    view();
    expect(screen.getByTestId("overview-heartbeat")).toHaveTextContent(
      /ledger segment 8421 anchored 3 min ago/i,
    );
  });

  it("puts the segment's own material beside the pulse (P1, P4)", () => {
    view();
    expect(screen.getByText(/chain positions 8001 to 8421/i)).toBeInTheDocument();
    // The chip renders the value twice: once for the eye, once for assistive
    // technology. Both are the Rekor entry index, and both are the point.
    expect(screen.getAllByText(/82914/).length).toBeGreaterThan(0);
  });

  it("carries the staleness marker when the read path is degraded (§4.4)", () => {
    render(
      <StalenessProvider
        degraded
        asOf={new Date("2026-08-30T14:30:05Z")}
        now={NOW}
      >
        <Overview data={DATA} now={NOW} apiBase="/api/v1" />
      </StalenessProvider>,
    );
    // The timestamp sits inside a <time> element, so the marker's own text
    // nodes are matched first and the whole string is asserted on the element.
    expect(screen.getByText(/data as of/i).textContent).toMatch(
      /data as of 2026-08-30 14:30:05 UTC/i,
    );
  });

  it("carries no staleness marker when the read path is healthy (P3)", () => {
    view();
    expect(screen.queryByText(/data as of/i)).toBeNull();
  });
});

describe("the overview's recent runs", () => {
  it("lists the runs it was given, with status and commit count", () => {
    view({}, { recentRuns: [RUN] });
    const row = screen.getByRole("listitem");
    expect(row).toHaveTextContent(/fix-ci/);
    expect(row).toHaveTextContent(/active/i);
    expect(row).toHaveTextContent(/3 commits/);
  });

  it("says the ledger is empty rather than rendering a blank panel (§4.6)", () => {
    view({}, { recentRuns: [] });
    expect(screen.getByText(/no runs yet/i)).toBeInTheDocument();
  });
});
