// SPDX-License-Identifier: Apache-2.0

/*
 * FE-051 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | The runs table never ships the table to the client | Every filter,
 *     search and page is a server request; the client asks for no more than
 *     the API's page cap; no code path materialises the full set or filters,
 *     sorts or searches rows in the browser | FD §3.2, §7
 *
 * doc 06 §7: "Scale posture: server-side pagination, filtering, and search
 * only — never ship-the-table-to-the-client." doc 06 §3.2 wants the table
 * responsive at millions of rows.
 *
 * ── WHAT THIS TEST CAN AND CANNOT SHOW ─────────────────────────────────────
 *
 * It cannot show the three-second budget. That is a measurement against a real
 * deployment, a real hot tier and a real network, and it is not made here or
 * claimed anywhere in this directory.
 *
 * What it CAN show is the property that makes the budget reachable, and it is
 * a property with a sharp edge: the view is indifferent to the rows it is
 * handed. The decisive case below hands the view a page whose rows do not
 * match the filter that was applied and requires the view to render all of
 * them. A client that filtered locally would drop them, and no amount of
 * fixture-shaped data would reveal that; a view that renders whatever the
 * server said is a view that cannot be hiding a local filter.
 *
 * The second half is the page bound: the API caps a page at 200 rows
 * (internal/api/query.go's MaxPageSize) and the client asks for no more, so a
 * link that says `limit=1000000` is rewritten to what will actually be served
 * rather than shared as a query nobody ran.
 */

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { emptyRunsFilters } from "../../app/routes";
import {
  MAX_PAGE_SIZE,
  RUNS_ENDPOINT,
  boundedFilters,
  runsRequestPath,
  type RunPage,
} from "./api";
import { runPage, runSummary, threeRuns } from "./fixtures";
import { strings } from "./strings";
import { RunsView } from "./RunsView";

afterEach(cleanup);
beforeEach(() => window.history.replaceState(null, "", "/runs"));

function recording(page: RunPage = runPage()) {
  const requests: string[] = [];
  return {
    requests,
    source: (request: string): Promise<RunPage> => {
      requests.push(request);
      return Promise.resolve(page);
    },
  };
}

const query = (request: string): URLSearchParams =>
  new URL(request, "http://api.invalid").searchParams;

describe("FE-051 filtering and search happen on the server", () => {
  it("turns a free-text search into a request rather than a local match", async () => {
    const { requests, source } = recording();
    render(<RunsView source={source} />);
    await screen.findByRole("table");
    expect(requests).toHaveLength(1);

    fireEvent.change(screen.getByLabelText(strings.labels.filters.search), {
      target: { value: "task-1481" },
    });
    // Typing alone must not fetch: the search is a query, not a keystroke.
    expect(requests).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: strings.labels.filters.apply }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(query(requests[1] ?? "").get("q")).toBe("task-1481");
  });

  it("renders every row the server returned, even ones the filter would exclude", async () => {
    /* The decisive case. The filter asks for retired runs in one repository;
     * the server answers with three runs, two of which match neither. A client
     * that filtered locally would show one row. */
    window.history.replaceState(
      null,
      "",
      "/runs?repo=innsegl.dev%2Fnowhere&status=retired&q=nothing-matches-this",
    );
    const { requests, source } = recording();
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    expect(requests).toHaveLength(1);
    expect(query(requests[0] ?? "").get("status")).toBe("retired");
    expect(screen.getAllByRole("rowheader")).toHaveLength(threeRuns().length);
    for (const run of threeRuns()) {
      expect(screen.getByText(run.task_ref)).toBeInTheDocument();
    }
  });

  it("fetches one page and one page only, with more to come", async () => {
    const { requests, source } = recording(
      runPage({ total: 4_000_000, next_cursor: "4102" }),
    );
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    // A view that walked the cursor to build the full set would issue more.
    expect(requests).toHaveLength(1);
    expect(screen.getAllByRole("rowheader")).toHaveLength(threeRuns().length);
    // And it says so, with the exact counts doc 06 §6.2 asks for.
    expect(
      screen.getByText(strings.formats.showing(threeRuns().length, 4_000_000)),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: strings.labels.page.next }),
    ).toHaveAttribute("href", expect.stringContaining("cursor=4102"));
  });

  it("pages by following the server's keyset cursor, not by counting rows", async () => {
    window.history.replaceState(null, "", "/runs?cursor=4102");
    const { requests, source } = recording();
    render(<RunsView source={source} />);
    await screen.findByRole("table");
    expect(query(requests[0] ?? "").get("cursor")).toBe("4102");
    // The way back to the start is a link, so it is shareable like the rest.
    expect(
      screen.getByRole("link", { name: strings.labels.page.first }),
    ).toHaveAttribute("href", "/runs");
  });

  it("drops the cursor when the filters change, because it indexed the old set", async () => {
    window.history.replaceState(null, "", "/runs?cursor=4102");
    const { requests, source } = recording();
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    fireEvent.change(screen.getByLabelText(strings.labels.filters.agentType), {
      target: { value: "fix-ci" },
    });
    fireEvent.click(screen.getByRole("button", { name: strings.labels.filters.apply }));
    await waitFor(() => expect(requests).toHaveLength(2));

    expect(query(requests[1] ?? "").get("agent_type")).toBe("fix-ci");
    expect(query(requests[1] ?? "").get("cursor")).toBeNull();
  });
});

describe("FE-051 the client never asks for an unbounded page", () => {
  it.each([
    ["", null],
    ["1", "1"],
    ["50", "50"],
    [String(MAX_PAGE_SIZE), String(MAX_PAGE_SIZE)],
    [String(MAX_PAGE_SIZE + 1), String(MAX_PAGE_SIZE)],
    ["1000000", String(MAX_PAGE_SIZE)],
    ["99999999999999999999", String(MAX_PAGE_SIZE)],
  ])("limit=%s is requested as %s", (asked, served) => {
    const request = runsRequestPath({ ...emptyRunsFilters(), limit: asked });
    expect(query(request).get("limit")).toBe(served);
  });

  it("never produces a request without a bound the server will honour", () => {
    for (const asked of ["0", "-3", "abc", "1e9", " 500", "500.5"]) {
      const limit = query(
        runsRequestPath({ ...emptyRunsFilters(), limit: asked }),
      ).get("limit");
      // Either the client named a number the API will serve, or it named none
      // and internal/api applies DefaultPageSize. There is no third outcome.
      if (limit !== null) {
        expect(Number(limit)).toBeGreaterThan(0);
        expect(Number(limit)).toBeLessThanOrEqual(MAX_PAGE_SIZE);
      }
    }
  });

  it("clamps the address bar too, so a shared link is the query that ran", async () => {
    window.history.replaceState(null, "", "/runs?repo=innsegl.dev%2Fcore&limit=1000000");
    const { requests, source } = recording();
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    await waitFor(() =>
      expect(window.location.search).toBe(
        `?repo=innsegl.dev%2Fcore&limit=${MAX_PAGE_SIZE}`,
      ),
    );
    expect(requests.at(-1)).toBe(
      `${RUNS_ENDPOINT}?repo=innsegl.dev%2Fcore&limit=${MAX_PAGE_SIZE}`,
    );
  });

  it("leaves a limit the API would serve exactly as the reader wrote it", () => {
    const filters = { ...emptyRunsFilters(), limit: "25" };
    expect(boundedFilters(filters)).toEqual(filters);
  });
});

describe("FE-051 an empty answer is an answer, not a blank panel", () => {
  it("says no runs match rather than showing an empty table", async () => {
    const { source } = recording(runPage({ runs: [], total: 0 }));
    render(<RunsView source={source} />);
    expect(await screen.findByText(strings.labels.empty.title)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("renders the row the server sent even when it is the only one", async () => {
    const one = runSummary({ run_id: "run-only" });
    const { source } = recording(runPage({ runs: [one], total: 1 }));
    render(<RunsView source={source} />);
    await screen.findByRole("table");
    expect(screen.getAllByRole("rowheader")).toHaveLength(1);
  });
});
