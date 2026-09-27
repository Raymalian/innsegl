// SPDX-License-Identifier: Apache-2.0

/*
 * The overview page — doc 06 §3.1, §4.4, §4.5, §5.3, P2, P3.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-074, FE-110 and FE-111 held the stacked alert banners this page used
 *          to carry. ADR-0054 moved open alerts to the header's notification
 *          menu; their successors are FE-134 to FE-137 in views/alerts.
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
  lapsed_runs: 2,
  abandoned_runs: 0,
  restore_horizon_seconds: 30 * 24 * 60 * 60,
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

describe("FE-137 open alerts are not a banner on this page (ADR-0054)", () => {
  it("raises no page banner even with alerts open: the header menu carries them", () => {
    const { container } = view({ open_alerts: 3 });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(container.querySelector("[data-alert-kind]")).toBeNull();
  });

  it("leaves the metrics as the first thing under the heading", () => {
    view({ open_alerts: 3 });
    const heading = screen.getByRole("heading", { level: 1 });
    const firstCard = screen.getByTestId("metric-active-agents");
    expect(
      heading.compareDocumentPosition(firstCard) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
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
  it("renders no pulse of its own: §3.1 puts it in the persistent header", () => {
    // FE-114. This page rendered a SECOND AnchoringPulse under the header's,
    // reading the same endpoint through a second hook — so a slow or failing
    // second read put "anchored 3 min ago" above "couldn't read the anchoring
    // heartbeat" on one screen. The shell owns the pulse; heartbeat-once.test
    // .tsx holds the whole argument.
    const { container } = view();
    expect(container.querySelector("[data-testid='overview-heartbeat']")).toBeNull();
  });

  it("puts the segment's own material on the page (P1, P4)", () => {
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
  it("tables the runs it was given, with status, agent, task and commits", () => {
    // A table since FE-118 — doc 06 §6.4, "tables are real tables". The
    // structure has its own test in recentruns.test.tsx; what this asserts is
    // that the overview still puts the runs it was handed on the page.
    view({}, { recentRuns: [RUN] });
    const row = screen.getAllByRole("row")[1] as HTMLElement;
    expect(row).toHaveTextContent(/fix-ci/);
    expect(row).toHaveTextContent(/active/i);
    expect(row).toHaveTextContent(/JIRA-118/);
    expect(within(row).getByText("3")).toBeInTheDocument();
  });

  it("says the ledger is empty rather than rendering a blank panel (§4.6)", () => {
    view({}, { recentRuns: [] });
    expect(screen.getByText(/no runs yet/i)).toBeInTheDocument();
  });
});
