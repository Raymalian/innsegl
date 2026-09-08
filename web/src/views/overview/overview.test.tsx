// SPDX-License-Identifier: Apache-2.0

/*
 * The overview page — doc 06 §3.1, §4.4, §4.5, §5.3, P2, P3.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-074 | U | Drift and reconciler alerts on the overview | Pinned above
 *          |   | every metric, banner-level, linked to their material | FD §3.1, P3
 *   FE-075 | U | The overview asserts no verification verdict | No green, no
 *          |   | verification tri-state anywhere on the view | FD §5.3, P2, IP §6.11
 *   FE-110 | U | The alerts feed (RM-102, #167) | One banner per open alert,
 *          |   | type-specific detail, evidence link per type | FD P1, P3
 *   FE-111 | U | The alerts feed degrades honestly | Falls back to the
 *          |   | aggregate count when the list read fails; notes an overflow
 *          |   | when more are open than shown | FD P2, §8 anti-pattern 10
 */

import { render, screen, within } from "@testing-library/react";

import { StalenessProvider } from "../../components/common";
import { Overview } from "./Overview";
import type { AlertRecord, OverviewData, RunSummary } from "./types";

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

const DRIFT_ALERT: AlertRecord = {
  chain_position: 25,
  event_id: "01a077c2-eff1-7762-8a61-91a3a5c390e8",
  event_type: "ledger_drift_detected",
  ts: "2026-09-06T17:27:39.249Z",
  run_id: "run-dd41951f222496a135241a77d1430237",
  subject_event_id: "01a072b2-cdda-774e-a0e2-889ec5ac33fa",
  reason: "commit_recorded claims a Rekor entry that the log does not contain",
  resolved: false,
};

const UNATTRIBUTED_ALERT: AlertRecord = {
  chain_position: 32,
  event_id: "01a077dd-7004-7ef5-befc-b91fe55d3f59",
  event_type: "unattributed_signature_detected",
  ts: "2026-09-06T17:56:35.972Z",
  certificate_identity: "spiffe://innsegl.dev/agent/38830790/831c43f5/run-4d060209a64e0aa508f13e9f1fe193f5",
  rekor_entry_uuid: "628d17d6783490c97e42fb59ab4d3f6d7a1550d945e2bed280f455bca226de78f76205cc0c68c131",
  rekor_log_index: 2,
  resolved: false,
};

function viewWithAlerts(alerts: readonly AlertRecord[] | null, over: Partial<OverviewData> = {}) {
  return render(
    <Overview
      data={{ ...DATA, open_alerts: alerts?.filter((a) => !a.resolved).length ?? 0, ...over }}
      alerts={alerts}
      now={NOW}
      apiBase="/api/v1"
    />,
  );
}

describe("FE-110 the alerts feed lists individual alerts", () => {
  it("renders one banner per open alert rather than a single aggregate count", () => {
    viewWithAlerts([DRIFT_ALERT, UNATTRIBUTED_ALERT]);
    expect(screen.getAllByRole("alert")).toHaveLength(2);
  });

  it("a drift alert carries its reason and subject, and links to the run", () => {
    viewWithAlerts([DRIFT_ALERT]);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/commit_recorded claims a Rekor entry/);
    expect(alert).toHaveTextContent(DRIFT_ALERT.subject_event_id!);
    expect(within(alert).getByRole("link")).toHaveAttribute(
      "href",
      `/runs/${DRIFT_ALERT.run_id}`,
    );
  });

  it("an unattributed alert carries the certificate identity and Rekor entry, with no run to link", () => {
    viewWithAlerts([UNATTRIBUTED_ALERT]);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(UNATTRIBUTED_ALERT.certificate_identity!);
    expect(alert).toHaveTextContent(String(UNATTRIBUTED_ALERT.rekor_log_index));
    expect(within(alert).getByRole("link")).toHaveAttribute(
      "href",
      "/api/v1/alerts?event_type=unattributed_signature_detected",
    );
  });

  it("excludes a resolved alert from the feed", () => {
    viewWithAlerts([DRIFT_ALERT, { ...UNATTRIBUTED_ALERT, resolved: true }], { open_alerts: 1 });
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByRole("alert")).toHaveTextContent(DRIFT_ALERT.subject_event_id!);
  });

  it("raises no alarm when every fetched alert is resolved (P3: the calm state is quiet)", () => {
    viewWithAlerts([{ ...DRIFT_ALERT, resolved: true }], { open_alerts: 0 });
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("FE-111 the alerts feed degrades honestly", () => {
  it("falls back to the aggregate count when the list read did not answer (P2)", () => {
    const { container } = view({ open_alerts: 4 });
    expect(container.querySelector("[data-alert-kind]")).not.toBeNull();
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/4 open integrity alerts/);
    expect(
      within(alert).getByRole("link"),
    ).toHaveAttribute("href", "/api/v1/overview");
  });

  it("notes an overflow when more alerts are open than the feed shows", () => {
    render(
      <Overview
        data={{ ...DATA, open_alerts: 50 }}
        alerts={[DRIFT_ALERT, UNATTRIBUTED_ALERT]}
        now={NOW}
        apiBase="/api/v1"
      />,
    );
    // Two named alerts, plus one note for the rest.
    const alerts = screen.getAllByRole("alert");
    expect(alerts).toHaveLength(3);
    expect(alerts[2]).toHaveTextContent(/48/);
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
