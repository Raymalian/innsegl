// SPDX-License-Identifier: Apache-2.0

/*
 * FE-010 — "URL state: filters/selection encoded and restorable | Deep link
 * reproduces exact view | FD §7" (doc 07, TC-FE).
 *
 * doc 06 §7: "Shareability: every view's state (filters, selected run,
 * verification input) lives in the URL." doc 06 §3.2: "Filters are
 * URL-encoded so any filtered view is shareable."
 *
 * ── WHAT "EXACT" IS TAKEN TO MEAN HERE ─────────────────────────────────────
 *
 * The obvious test — set eight filters, read them back, assert equality — is
 * a test of a parser, and this repository already has one in
 * src/app/routes.test.ts. It would pass over a view that dropped a filter on
 * the floor between the URL and the screen.
 *
 * So the assertion below is on RENDERED OUTPUT, and it is byte-for-byte:
 *
 *   A. start on an unfiltered /runs, drive the filter controls by hand,
 *      submit, and let the view fetch and render;
 *   B. tear the whole tree down, put the address bar at exactly the URL A
 *      produced, mount a fresh view, and let it fetch and render;
 *   then innerHTML(A) === innerHTML(B), with NOTHING stripped.
 *
 * Nothing is stripped, and that is deliberate. A prior agent on this project
 * proved two states differed by removing `class` and `style` while leaving a
 * `data-*` attribute in place — an assertion that could not fail. The inverse
 * risk applies to an equality: normalise enough and any two renders are
 * "identical". This test therefore normalises nothing at all, which it can
 * afford to do because every id in the tree is derived from a run id rather
 * than from React's `useId` counter, and because the fixtures hold no clock.
 *
 * Two guards keep the equality from passing vacuously:
 *
 *   - the compared markup must actually contain the filtered material (the
 *     repo, a run id, the task) and a real table row;
 *   - a DIFFERENT deep link must render DIFFERENTLY. Without that, a view
 *     that ignored the URL entirely would pass the equality.
 *
 * The fourth assertion is the property RM-041 built the route table for: the
 * request the table issues and the link a reader copies differ only in path.
 */

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { RUNS_ENDPOINT, type RunPage } from "./api";
import { runPage } from "./fixtures";
import { strings } from "./strings";
import { RunsView } from "./RunsView";

/** The dashboard path the runs table lives at (src/app/routes.ts). */
const RUNS_PATH = "/runs";

afterEach(cleanup);

beforeEach(() => {
  window.history.replaceState(null, "", RUNS_PATH);
});

/** A source that records what was asked for and answers the same page every
 * time. Deterministic on purpose: what varies between A and B must be the
 * route, not the data. */
function recordingSource(page: RunPage = runPage()) {
  const requests: string[] = [];
  const source = (request: string): Promise<RunPage> => {
    requests.push(request);
    return Promise.resolve(page);
  };
  return { requests, source };
}

const here = (): string => `${window.location.pathname}${window.location.search}`;

/** What the six filter controls currently hold. A controlled input's value is
 * a DOM property rather than an attribute, so it does not appear in innerHTML
 * and has to be read separately. */
function controlValues(): Record<string, string> {
  const held = (label: string): string =>
    (screen.getByLabelText(label) as HTMLInputElement | HTMLSelectElement).value;
  return {
    repo: held(strings.labels.filters.repo),
    agentType: held(strings.labels.filters.agentType),
    status: held(strings.labels.filters.status),
    from: held(strings.labels.filters.from),
    to: held(strings.labels.filters.to),
    search: held(strings.labels.filters.search),
  };
}

/** Fill in every filter the table offers and apply them. */
function driveTheFilters(): void {
  fireEvent.change(screen.getByLabelText(strings.labels.filters.repo), {
    target: { value: "innsegl.dev/core" },
  });
  fireEvent.change(screen.getByLabelText(strings.labels.filters.agentType), {
    target: { value: "fix-ci" },
  });
  fireEvent.change(screen.getByLabelText(strings.labels.filters.status), {
    target: { value: "retired" },
  });
  fireEvent.change(screen.getByLabelText(strings.labels.filters.from), {
    target: { value: "2026-08-01" },
  });
  fireEvent.change(screen.getByLabelText(strings.labels.filters.to), {
    target: { value: "2026-08-31" },
  });
  fireEvent.change(screen.getByLabelText(strings.labels.filters.search), {
    target: { value: "task-1481" },
  });
  fireEvent.click(screen.getByRole("button", { name: strings.labels.filters.apply }));
}

describe("FE-010 the runs table's state lives in the URL", () => {
  it("encodes every filter under the query API's own parameter names", async () => {
    const { source } = recordingSource();
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    driveTheFilters();
    await waitFor(() => expect(here()).not.toBe(RUNS_PATH));

    const q = new URL(here(), "http://dashboard.invalid").searchParams;
    expect(q.get("repo")).toBe("innsegl.dev/core");
    expect(q.get("agent_type")).toBe("fix-ci");
    expect(q.get("status")).toBe("retired");
    expect(q.get("q")).toBe("task-1481");
    expect(q.get("from")).toBe("2026-08-01T00:00:00Z");
    expect(q.get("to")).toBe("2026-08-31T23:59:59Z");
  });

  it("reproduces a filtered view exactly from its link, with nothing stripped", async () => {
    const first = recordingSource();
    const a = render(<RunsView source={first.source} />);
    await screen.findByRole("table");
    driveTheFilters();
    await waitFor(() => expect(here()).not.toBe(RUNS_PATH));

    const link = here();
    await waitFor(() =>
      expect(first.requests.at(-1)).toBe(RUNS_ENDPOINT + link.slice(RUNS_PATH.length)),
    );
    await screen.findByRole("table");
    const filtered = a.container.innerHTML;

    // The guard: an equality over an empty or generic page proves nothing.
    expect(filtered).toContain("innsegl.dev/core");
    expect(filtered).toContain("run-7f3a2c");
    expect(filtered).toContain("task-1481");
    expect(a.container.querySelectorAll("tbody tr").length).toBeGreaterThan(0);

    cleanup();

    // B: nothing survives but the link.
    window.history.replaceState(null, "", link);
    const second = recordingSource();
    const b = render(<RunsView source={second.source} />);
    await screen.findByRole("table");

    expect(b.container.innerHTML).toBe(filtered);
    expect(second.requests).toEqual([RUNS_ENDPOINT + link.slice(RUNS_PATH.length)]);

    /* innerHTML does not carry what a controlled input currently holds, so the
     * equality above would survive a form that ignored the URL and rendered
     * six empty boxes in both halves. The controls are therefore read as
     * values, not as markup. */
    expect(controlValues()).toEqual({
      repo: "innsegl.dev/core",
      agentType: "fix-ci",
      status: "retired",
      from: "2026-08-01",
      to: "2026-08-31",
      search: "task-1481",
    });
  });

  it("renders a different deep link differently, so the equality above can fail", async () => {
    window.history.replaceState(null, "", "/runs?repo=innsegl.dev%2Fcore&status=retired");
    const one = recordingSource();
    const a = render(<RunsView source={one.source} />);
    await screen.findByRole("table");
    const first = a.container.innerHTML;
    cleanup();

    window.history.replaceState(null, "", "/runs?repo=innsegl.dev%2Fdocs&status=active");
    const two = recordingSource();
    const b = render(<RunsView source={two.source} />);
    await screen.findByRole("table");

    expect(b.container.innerHTML).not.toBe(first);
    expect(one.requests).not.toEqual(two.requests);
    expect(controlValues()).toMatchObject({
      repo: "innsegl.dev/docs",
      status: "active",
    });
  });

  it("issues a request that differs from the copied link only in its path", async () => {
    const link = "/runs?repo=innsegl.dev%2Fcore&agent_type=fix-ci&status=active&q=task-1481&from=2026-08-01T00%3A00%3A00Z&to=2026-08-31T23%3A59%3A59Z&cursor=4181&limit=25";
    window.history.replaceState(null, "", link);
    const { requests, source } = recordingSource();
    render(<RunsView source={source} />);
    await screen.findByRole("table");

    expect(requests).toHaveLength(1);
    const issued = requests[0] ?? "";
    expect(issued.startsWith(RUNS_ENDPOINT)).toBe(true);
    expect(issued.slice(RUNS_ENDPOINT.length)).toBe(link.slice(RUNS_PATH.length));
    // And the address bar was not quietly rewritten to make that true.
    expect(here()).toBe(link);
  });
});
