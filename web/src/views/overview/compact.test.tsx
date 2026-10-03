// SPDX-License-Identifier: Apache-2.0

/*
 * RM-331 (#507) — a compact overview: four short cards, definitions on
 * demand, verification as one line, and the repository on every recent run.
 */

import { render, screen, within } from "@testing-library/react";

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
  open_alerts: 3,
  anchor: { present: false, anchored: false },
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

function view() {
  return render(<Overview data={DATA} now={NOW} apiBase="/api/v1" recentRuns={[RUN]} />);
}

const CARDS = ["active-agents", "runs-today", "commits", "open-alerts"];

describe("RM-331 four compact cards", () => {
  it("shows Active agents, Runs today, Commits attributed and Open alerts, in that order", () => {
    view();
    const region = screen.getByRole("region", { name: /system metrics/i });
    const titles = [...region.querySelectorAll("h2")].map((h) => h.textContent);
    expect(titles).toEqual([
      "Active agents",
      "Runs today",
      "Commits attributed",
      "Open alerts",
    ]);
  });

  it.each(CARDS)("%s keeps its full definition behind a disclosure", (id) => {
    view();
    const card = screen.getByTestId(`metric-${id}`);
    const disclosure = card.querySelector("details");
    expect(disclosure).not.toBeNull();
    expect(disclosure).not.toHaveAttribute("open");
    expect(disclosure?.querySelector("summary")?.textContent).toMatch(/how this is counted/i);
  });

  it.each(CARDS)("%s shows one short line of description outside the disclosure", (id) => {
    view();
    const card = screen.getByTestId(`metric-${id}`);
    const line = card.querySelector("[data-description]");
    expect(line).not.toBeNull();
    expect((line?.textContent ?? "").length).toBeLessThan(60);
  });

  it("Open alerts states the count and links to /alerts", () => {
    view();
    const card = screen.getByTestId("metric-open-alerts");
    expect(card).toHaveTextContent("3");
    expect(within(card).getByRole("link", { name: /alerts/i })).toHaveAttribute(
      "href",
      "/alerts",
    );
  });

  it("verification is one line with the Verify a commit link, not a card", () => {
    view();
    const line = screen.getByTestId("metric-pass-rate");
    expect(line.tagName).toBe("P");
    expect(line).toHaveTextContent(/verification pass rate/i);
    expect(line).toHaveTextContent(/not measured/i);
    expect(within(line).getByRole("link", { name: /verify a commit/i })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: /system metrics/i })).not.toContainElement(line);
  });
});

describe("RM-331 recent runs show where the work was", () => {
  it("has a Repository column and shows the repository on the row", () => {
    view();
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent?.trim());
    expect(headers).toContain("Repository");
    expect(screen.getByRole("link", { name: "github.com/acme/api" })).toBeInTheDocument();
  });
});
