// SPDX-License-Identifier: Apache-2.0

/*
 * FE-040, FE-041 and FE-042 (NEW — proposed for doc 07 TC-FE; see the report
 * for #55).
 *
 *   FE-040 | U | Every count the repo view renders is measured over a window
 *     the page states, and that window is what the server was asked for | The
 *     bounds appear on the page; the request carries the same bounds; an
 *     address with no usable window states the default it fell back to |
 *     FD §3.4, §8 anti-pattern 10
 *
 *   FE-041 | U | Attribution coverage is refused rather than computed | No
 *     percentage is rendered; the refusal names the missing denominator AND
 *     the live numerator; nothing green and no verdict appears | FD §3.4, P2,
 *     §5.3; IP §6.11
 *
 *   FE-042 | U | Runs group by agent identity, and the grouping states whether
 *     it is the whole windowed set | Truncated: the shortfall is stated and no
 *     per-identity count is rendered. Complete: it says so and the counts
 *     hold. The two renders differ with every imperceptible attribute
 *     stripped | FD §3.4, §7
 *
 * ── ON THE STRIPPER ────────────────────────────────────────────────────────
 *
 * `perceivable` below removes every screen-reader-only element and then every
 * attribute a sighted reader cannot see — class, style, id, title, and the
 * whole of aria-* and data-*. This project has already had a test that proved
 * two states "differ" by leaving a data-* attribute in place, which made the
 * assertion impossible to fail. What survives here is tag structure, text and
 * href, and nothing else.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StalenessProvider } from "../../components/common";
import { parseRoute } from "../../app/routes";
import { RepoView } from "./RepoView";
import { strings } from "./strings";
import type { LoadRuns, RunPage, RunSummary, RunsQuery } from "./query";

const NOW = new Date("2026-08-31T12:00:00Z");
const REPO = "github.com/acme/api";
const REPO_PATH = `/repos/${encodeURIComponent(REPO)}`;
const FIX_CI = "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c";
const DEP_BUMP = "spiffe://innsegl.dev/agent/dep-bump/task-0042/run-0e91bd";

function run(over: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: "run-7f3a2c",
    spiffe_id: FIX_CI,
    agent_type: "fix-ci",
    task_ref: "task-1481",
    status: "retired",
    repos: [REPO],
    commits: 3,
    chain_position: 91,
    registered_at: "2026-08-20T09:00:00Z",
    last_event_at: "2026-08-20T09:20:00Z",
    ...over,
  };
}

function page(runs: readonly RunSummary[], total = runs.length): RunPage {
  return { runs, total, limit: 200, data_as_of: "2026-08-31T12:00:00Z" };
}

const THREE_RUNS = page([
  run({ run_id: "run-7f3a2c", spiffe_id: FIX_CI }),
  run({
    run_id: "run-0e91bd",
    spiffe_id: DEP_BUMP,
    agent_type: "dep-bump",
    task_ref: "task-0042",
    chain_position: 90,
  }),
  run({ run_id: "run-115fac", spiffe_id: FIX_CI, chain_position: 88 }),
]);

function loader(result: RunPage | Error): { load: LoadRuns; calls: RunsQuery[] } {
  const calls: RunsQuery[] = [];
  const load: LoadRuns = (query) => {
    calls.push(query);
    return result instanceof Error ? Promise.reject(result) : Promise.resolve(result);
  };
  return { load, calls };
}

function renderRepo(path: string, result: RunPage | Error) {
  const { load, calls } = loader(result);
  const { container } = render(<RepoView route={parseRoute(path)} load={load} now={NOW} />);
  return { calls, container };
}

/** Everything a sighted reader can perceive, and nothing else. */
function perceivable(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of Array.from(clone.querySelectorAll('[class~="sr-only"]'))) {
    hidden.remove();
  }
  for (const element of [clone, ...Array.from(clone.querySelectorAll("*"))]) {
    for (const name of Array.from(element.getAttributeNames())) {
      if (/^(class|style|id|title)$/.test(name) || /^(aria|data)-/.test(name)) {
        element.removeAttribute(name);
      }
    }
  }
  return clone.innerHTML;
}

describe("FE-040 the window is stated and it is what the server was asked for", () => {
  it("uses the window in the address and prints both of its bounds", async () => {
    const { calls } = renderRepo(
      `${REPO_PATH}?from=2026-08-01T00:00:00Z&to=2026-08-15T00:00:00Z`,
      THREE_RUNS,
    );
    await screen.findByText(strings.labels.runsTable);

    expect(calls[0]?.from?.toISOString()).toBe("2026-08-01T00:00:00.000Z");
    expect(calls[0]?.to?.toISOString()).toBe("2026-08-15T00:00:00.000Z");
    expect(screen.getByText("2026-08-01 00:00:00 UTC", { selector: "time" })).toBeInTheDocument();
    expect(screen.getByText("2026-08-15 00:00:00 UTC", { selector: "time" })).toBeInTheDocument();
  });

  it("states the default window when the address carries none, and still bounds the query", async () => {
    const { calls } = renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByText(strings.sentences.defaultWindow);

    expect(calls[0]?.to?.toISOString()).toBe(NOW.toISOString());
    expect(calls[0]?.from?.toISOString()).toBe("2026-08-01T12:00:00.000Z");
    expect(screen.getByText("2026-08-01 12:00:00 UTC", { selector: "time" })).toBeInTheDocument();
    expect(screen.getByText("2026-08-31 12:00:00 UTC", { selector: "time" })).toBeInTheDocument();
  });

  it("asks the server for this repository, once, and for no more than one page", async () => {
    const { calls } = renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByText(strings.labels.runsTable);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.repo).toBe(REPO);
    expect(calls[0]?.limit).toBe(200);
  });
});

describe("FE-041 attribution coverage is refused, not computed", () => {
  it("renders no percentage anywhere on the page", async () => {
    const { container } = renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByText(strings.labels.coverage);
    expect(container.textContent ?? "").not.toContain("%");
    expect(container.textContent ?? "").not.toMatch(/\d\s*(percent|pct)\b/i);
  });

  it("keeps the explanation in a collapsed note, after the data", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    const note = (await screen.findByText(strings.labels.coverage)).closest("details");
    expect(note).not.toBeNull();
    expect(note).not.toHaveAttribute("open");
    const table = screen.getByRole("table");
    // The note follows the table in document order: data first.
    expect(
      table.compareDocumentPosition(note as HTMLElement) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("names the missing denominator and the live numerator, both", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    expect(await screen.findByText(strings.sentences.coverageDenominator)).toBeInTheDocument();
    expect(screen.getByText(strings.sentences.coverageNumerator)).toBeInTheDocument();
    expect(screen.getByText(strings.sentences.coverageRefusal)).toBeInTheDocument();
  });

  it("spends no green and asserts no verdict", async () => {
    const { container } = renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByText(strings.labels.coverage);
    expect(container.innerHTML).not.toContain("proof-verified");
    expect(container.querySelector("[data-verdict]")).toBeNull();
  });
});

describe("FE-042 one table of runs, and the summary says whether it is the whole set", () => {
  it("leads with the summary and one table, with no repeated section headings", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByRole("table");
    expect(screen.getAllByRole("table")).toHaveLength(1);
    // header row plus three runs
    expect(screen.getAllByRole("row")).toHaveLength(4);
    expect(screen.queryByText("Agent identity")).toBeNull();
    expect(screen.queryByText(/Runs by this identity/)).toBeNull();
  });

  it("keeps the agent identity of each run on its row", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    const row = (await screen.findByRole("link", { name: "dep-bump" })).closest("tr");
    expect(row?.textContent ?? "").toContain(DEP_BUMP);
  });

  it("keeps the server's order", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByRole("table");
    const ids = screen
      .getAllByRole("link")
      .map((l) => l.textContent)
      .filter((t) => t?.startsWith("run-"));
    expect(ids).toEqual(["run-7f3a2c", "run-0e91bd", "run-115fac"]);
  });

  it("says nothing about truncation when the page is the whole set", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByRole("table");
    expect(screen.queryByText(strings.sentences.setIsTruncated)).toBeNull();
  });

  it("states the shortfall when the server counted more than it served", async () => {
    renderRepo(REPO_PATH, page(THREE_RUNS.runs, 41));
    expect(await screen.findByText(strings.sentences.setIsTruncated)).toBeInTheDocument();
  });

  it("differs perceivably between the complete and the truncated render", async () => {
    const complete = renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByRole("table");
    const before = perceivable(complete.container);
    const truncated = renderRepo(REPO_PATH, page(THREE_RUNS.runs, 41));
    await screen.findByText(strings.sentences.setIsTruncated);
    expect(before).not.toBe("");
    expect(perceivable(truncated.container)).not.toBe(before);
  });

  it("shows the server's total as the run count", async () => {
    renderRepo(REPO_PATH, page(THREE_RUNS.runs, 41));
    const summary = await screen.findByRole("group", { name: strings.labels.summary });
    expect(within(summary).getByText(strings.labels.runsInWindow).nextElementSibling)
      .toHaveTextContent("41");
  });

  it("totals commits only when the whole set is here and each run touched this repository alone", async () => {
    renderRepo(REPO_PATH, page([run({ commits: 3 }), run({ run_id: "b", commits: 4 })]));
    const summary = await screen.findByRole("group", { name: strings.labels.summary });
    expect(within(summary).getByText(strings.labels.commitsInWindow).nextElementSibling)
      .toHaveTextContent("7");
  });

  it("sums no commit count over a page that is not the whole set", async () => {
    renderRepo(REPO_PATH, page([run({ commits: 3 }), run({ run_id: "b", commits: 4 })], 41));
    const summary = await screen.findByRole("group", { name: strings.labels.summary });
    expect(within(summary).queryByText(strings.labels.commitsInWindow)).toBeNull();
    expect(summary.textContent ?? "").not.toMatch(/\b7\b/);
  });

  it("sums no commit count when a run touched other repositories too", async () => {
    renderRepo(REPO_PATH, page([run({ commits: 3, repos: [REPO, "github.com/acme/web"] })]));
    const summary = await screen.findByRole("group", { name: strings.labels.summary });
    expect(within(summary).queryByText(strings.labels.commitsInWindow)).toBeNull();
  });
});

describe("the repo view links out, and links on", () => {
  it("links to the repository host over https", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    const out = await screen.findByRole("link", { name: strings.labels.openOnHost });
    expect(out).toHaveAttribute("href", "https://github.com/acme/api");
  });

  it("says so, rather than guessing, when the recorded value is not host/org/name", async () => {
    renderRepo("/repos/api", THREE_RUNS);
    expect(await screen.findByText(strings.sentences.noHostLink)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: strings.labels.openOnHost })).toBeNull();
  });

  it("links every run to its detail view and every agent type to its own", async () => {
    renderRepo(REPO_PATH, THREE_RUNS);
    await screen.findByText(strings.labels.runsTable);
    expect(screen.getByRole("link", { name: "run-7f3a2c" })).toHaveAttribute(
      "href",
      "/runs/run-7f3a2c",
    );
    expect(screen.getByRole("link", { name: "dep-bump" })).toHaveAttribute(
      "href",
      "/agent-types/dep-bump",
    );
  });
});

describe("the repo view's honest states (FD §4.6)", () => {
  it("says what it is loading", () => {
    const pending: LoadRuns = () => new Promise<RunPage>(() => {});
    render(<RepoView route={parseRoute(REPO_PATH)} load={pending} now={NOW} />);
    expect(screen.getByRole("status")).toHaveTextContent(strings.nouns.runs);
  });

  it("shows nothing rather than guessing when the ledger did not answer", async () => {
    renderRepo(REPO_PATH, new Error("dial tcp: connection refused"));
    expect(await screen.findByRole("alert")).toHaveTextContent("dial tcp: connection refused");
    expect(screen.queryByText(strings.labels.runsTable)).toBeNull();
  });

  it("says the window holds no runs rather than drawing an empty table", async () => {
    renderRepo(REPO_PATH, page([], 0));
    expect(await screen.findByText(strings.sentences.empty)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("carries the staleness marker when the read path is degraded (FD §4.4)", async () => {
    const { load } = loader(THREE_RUNS);
    render(
      <StalenessProvider degraded asOf={new Date("2026-08-31T11:00:00Z")} now={NOW}>
        <RepoView route={parseRoute(REPO_PATH)} load={load} now={NOW} />
      </StalenessProvider>,
    );
    await screen.findByText(strings.labels.runsTable);
    expect(screen.getByText("2026-08-31 11:00:00 UTC", { selector: "time" })).toBeInTheDocument();
  });

  it("refuses a route that is not a repository rather than rendering a blank panel", () => {
    render(<RepoView route={parseRoute("/nowhere/at/all")} now={NOW} />);
    expect(screen.getByRole("alert")).toHaveTextContent(strings.labels.wrongRoute);
  });
});

describe("the per-run commit count says what it counts", () => {
  it("marks a run whose commits are not all this repository's", async () => {
    renderRepo(REPO_PATH, page([run({ repos: [REPO, "github.com/acme/web"] })]));
    expect(await screen.findByText(strings.sentences.commitsSpanRepos)).toBeInTheDocument();
  });

  it("does not mark a run that touched this repository alone", async () => {
    renderRepo(REPO_PATH, page([run()]));
    await screen.findByText(strings.labels.runsTable);
    expect(screen.queryByText(strings.sentences.commitsSpanRepos)).toBeNull();
  });
});
