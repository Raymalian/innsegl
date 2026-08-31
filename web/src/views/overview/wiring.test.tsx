// SPDX-License-Identifier: Apache-2.0

/*
 * The overview against the query API — doc 06 §3.1, §4.6, §7, P2.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-076 | U | Overview reads | Each of the three reads reported separately;
 *          |   | a failed read never renders as a zero, and the heartbeat
 *          |   | survives a failed read | FD §3.1, §4.6, P2
 *
 * The window in the second read is the assertion worth keeping: doc 06 §8
 * anti-pattern 10 rules out a count with no window, and "runs today" is only
 * exact if the server was asked for one — `from=<midnight UTC>` — rather than
 * counted in the browser out of a page it should never have been sent.
 */

import { render, screen } from "@testing-library/react";

import { OverviewHeartbeat, OverviewView } from "./OverviewView";

const NOW = new Date("2026-08-30T14:44:05Z");

const OVERVIEW = {
  active_runs: 7,
  retired_runs: 41,
  expired_runs: 2,
  commits_recorded: 1284,
  open_alerts: 0,
  anchor: {
    present: true,
    segment_id: "sha256:9f2c",
    first_position: 8001,
    last_position: 8421,
    sealed_at: "2026-08-30T14:41:05Z",
    anchored: true,
    rekor_log_index: 82914,
  },
  data_as_of: "2026-08-30T14:44:05Z",
};

const RUNS = { runs: [], total: 12, limit: 1, data_as_of: "2026-08-30T14:44:05Z" };

function ok(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

function dead(status: number): Response {
  return {
    ok: false,
    status,
    json: async () => ({}),
  } as unknown as Response;
}

let asked: string[] = [];

function api(route: (url: string) => Response) {
  asked = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => {
      const url = String(input);
      asked.push(url);
      return Promise.resolve(route(url));
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const everythingAnswers = (url: string) =>
  url.includes("/overview") ? ok(OVERVIEW) : ok(RUNS);

describe("FE-076 the overview's reads", () => {
  it("shows a loading state before it shows numbers (§4.6)", () => {
    api(everythingAnswers);
    render(<OverviewView now={NOW} />);
    expect(screen.getByText(/loading the overview/i)).toBeInTheDocument();
  });

  it("renders the counts the query API returned", async () => {
    api(everythingAnswers);
    render(<OverviewView now={NOW} />);
    expect(await screen.findByTestId("metric-active-agents")).toHaveTextContent("7");
    expect(screen.getByTestId("metric-commits")).toHaveTextContent("1,284");
  });

  it("asks the SERVER for today's runs, over a stated window (§7, §8/10)", async () => {
    api(everythingAnswers);
    render(<OverviewView now={NOW} />);
    await screen.findByTestId("metric-runs-today");
    expect(asked).toContain(
      "/api/v1/runs?from=2026-08-30T00%3A00%3A00.000Z&limit=1",
    );
    expect(screen.getByTestId("metric-runs-today")).toHaveTextContent("12");
  });

  it("shows nothing rather than guessing when the ledger did not answer (§4.6)", async () => {
    api((url) => (url.includes("/overview") ? dead(503) : ok(RUNS)));
    render(<OverviewView now={NOW} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/can't reach the ledger/i);
    expect(alert).toHaveTextContent(/answered 503/);
    expect(screen.queryByTestId("metric-active-agents")).toBeNull();
  });

  it("keeps the heartbeat visible through a failed read (§3.1)", async () => {
    api((url) => (url.includes("/overview") ? dead(503) : ok(RUNS)));
    render(<OverviewView now={NOW} />);
    await screen.findByRole("alert");
    expect(screen.getByTestId("overview-heartbeat")).toHaveTextContent(
      /couldn't read the anchoring heartbeat/i,
    );
  });

  it("does not let a failed runs read blank the counts that arrived (P2)", async () => {
    api((url) => (url.includes("/overview") ? ok(OVERVIEW) : dead(500)));
    render(<OverviewView now={NOW} />);
    expect(await screen.findByTestId("metric-active-agents")).toHaveTextContent("7");
    const today = screen.getByTestId("metric-runs-today");
    expect(today).toHaveTextContent(/not counted/i);
    expect(today.textContent).not.toMatch(/\b0\b/);
  });
});

describe("the header's heartbeat", () => {
  it("says it is reading before it says anything else (P2)", () => {
    api(everythingAnswers);
    render(<OverviewHeartbeat now={NOW} />);
    expect(screen.getByTestId("overview-heartbeat")).toHaveTextContent(
      /reading the anchoring heartbeat/i,
    );
  });

  it("reads the pulse out of the query API", async () => {
    api(everythingAnswers);
    render(<OverviewHeartbeat now={NOW} />);
    expect(await screen.findByText(/ledger segment 8421/i)).toBeInTheDocument();
  });

  it("renders nothing but the pulse: it is header chrome, not a page", async () => {
    api(everythingAnswers);
    const { container } = render(<OverviewHeartbeat now={NOW} />);
    await screen.findByText(/ledger segment 8421/i);
    expect(container.querySelectorAll("[data-testid='overview-heartbeat']")).toHaveLength(1);
    expect(container.querySelector("h1")).toBeNull();
    expect(screen.queryByTestId("metric-active-agents")).toBeNull();
  });

  it("says it could not read rather than going quiet (never hidden, §3.1)", async () => {
    api(() => dead(502));
    render(<OverviewHeartbeat now={NOW} />);
    expect(
      await screen.findByText(/couldn't read the anchoring heartbeat/i),
    ).toBeInTheDocument();
  });
});
