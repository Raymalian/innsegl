// SPDX-License-Identifier: Apache-2.0

/*
 * FE-052 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | The runs view retains no response | A row is rendered only for the
 *     request the address bar currently describes; a superseded answer is
 *     never shown, not for one frame; the fetch is made with no-store | FD §7,
 *     §8.1
 *
 * doc 06 §8's first anti-pattern is "a 'verified' state rendered from cache
 * while the live check errored". FE-003 already holds the verification panel
 * to that. This is the same rule one level up, at the place it is most likely
 * to be broken: a runs table is the busiest view in the product, its query
 * changes every time a reader applies a filter, and every convenience a data
 * library offers for that — keepPreviousData, stale-while-revalidate, a
 * five-second cache — retains an answer to a question that is no longer on
 * screen, with verification rollups inside it.
 *
 * The dangerous version of that is not visible: old rows under a new filter
 * look like new rows. So the test drives it explicitly — a response is held
 * open while the filter changes, and the previous page must be gone from the
 * document before the next one arrives.
 */

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_TIMEOUT_MS, strings as common } from "../../components/common";
import { fetchRuns } from "./api";
import type { RunPage } from "./api";
import { runPage, runSummary } from "./fixtures";
import { strings } from "./strings";
import { RunsView } from "./RunsView";

afterEach(cleanup);
beforeEach(() => window.history.replaceState(null, "", "/runs"));

/** A source that hands back a promise the test resolves by hand. */
function deferred() {
  const requests: string[] = [];
  const settle: Array<(page: RunPage) => void> = [];
  const source = (request: string): Promise<RunPage> => {
    requests.push(request);
    return new Promise<RunPage>((resolve) => settle.push(resolve));
  };
  return { requests, settle, source };
}

const FIRST = runPage({
  runs: [runSummary({ run_id: "run-first", task_ref: "task-first" })],
  total: 1,
});
const SECOND = runPage({
  runs: [runSummary({ run_id: "run-second", task_ref: "task-second" })],
  total: 1,
});

function applySearch(term: string) {
  fireEvent.change(screen.getByLabelText(strings.labels.filters.search), {
    target: { value: term },
  });
  fireEvent.click(screen.getByRole("button", { name: strings.labels.filters.apply }));
}

describe("FE-052 nothing from a previous query survives on screen", () => {
  it("drops the old page the moment the filter changes", async () => {
    const { requests, settle, source } = deferred();
    render(<RunsView source={source} />);

    settle[0]?.(FIRST);
    expect(await screen.findByText("task-first")).toBeInTheDocument();

    applySearch("second");
    await waitFor(() => expect(requests).toHaveLength(2));

    /* The second answer has not arrived. If anything is retained, this is
     * where it shows: the old row would still be here under the new filter. */
    expect(screen.queryByText("task-first")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");

    settle[1]?.(SECOND);
    expect(await screen.findByText("task-second")).toBeInTheDocument();
    expect(screen.queryByText("task-first")).toBeNull();
  });

  it("never renders an answer to a question that is no longer being asked", async () => {
    const { requests, settle, source } = deferred();
    render(<RunsView source={source} />);
    await waitFor(() => expect(requests).toHaveLength(1));

    applySearch("second");
    await waitFor(() => expect(requests).toHaveLength(2));

    /* The current query answers first; the abandoned one answers LAST, so the
     * defect this test looks for is the one that would win. There are two
     * independent guards against it — the abandoned read stops listening when
     * its effect is torn down, and the render refuses any result whose request
     * is not the one on screen — and this case exercises the first: measured
     * by removing each guard in turn, the case above fails without the second
     * and this one fails without the first. */
    settle[1]?.(SECOND);
    settle[0]?.(FIRST);

    expect(await screen.findByText("task-second")).toBeInTheDocument();
    expect(screen.queryByText("task-first")).toBeNull();
  });

  it("times out into an error rather than spinning, and the retry re-reads", async () => {
    /* doc 06 §4.6: "No blank panels, no infinite spinners: loading states time
     * out into an explicit error." §8 anti-pattern 8 makes it a defect. The
     * bound belongs to LoadingState; what is asserted here is that this view
     * gets it per attempt rather than per lifetime. */
    vi.useFakeTimers();
    try {
      const { requests, source } = deferred();
      render(<RunsView source={source} />);
      expect(requests).toHaveLength(1);
      expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");

      await act(async () => {
        await vi.advanceTimersByTimeAsync(DEFAULT_TIMEOUT_MS + 1);
      });
      expect(screen.queryByRole("status")).toBeNull();
      expect(screen.getByRole("alert")).toBeInTheDocument();

      fireEvent.click(
        screen.getByRole("button", { name: common.error.retry }),
      );
      expect(requests).toHaveLength(2);
      expect(requests[0]).toBe(requests[1]);
      // The retry restarted the read, so the reader is not left looking at
      // the error state of the attempt before it.
      expect(screen.queryByRole("alert")).toBeNull();
      expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    } finally {
      vi.useRealTimers();
    }
  });

  it("asks the browser not to cache the read either", async () => {
    const fetched = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify(FIRST), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetched);
    try {
      const controller = new AbortController();
      await fetchRuns("/api/v1/runs?q=x", controller.signal);
    } finally {
      vi.unstubAllGlobals();
    }
    expect(fetched).toHaveBeenCalledTimes(1);
    const init = fetched.mock.calls[0]?.[1];
    expect(init?.cache).toBe("no-store");
    expect(init?.method).toBe("GET");
  });

  it("reports the ledger's own words when a read fails, and offers a re-read", async () => {
    const requests: string[] = [];
    const source = (request: string): Promise<RunPage> => {
      requests.push(request);
      return Promise.reject(new Error("api: listing runs: connection refused"));
    };
    render(<RunsView source={source} />);
    expect(
      await screen.findByText("api: listing runs: connection refused"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: common.error.retry }));
    await waitFor(() => expect(requests).toHaveLength(2));
  });
});
