// SPDX-License-Identifier: Apache-2.0

/*
 * The run page's own tests (#443, RM-278): one agent at a time, by task,
 * with its lineage. Driven against the two approved boards' own fixtures
 * (agent-record.json ↔ Agent.dc.html, session-record.json ↔ Session.dc.html)
 * plus the two pre-existing gateway-run fixtures (record.json,
 * states-record.json), which now render through the session board's own
 * layout — a plain root run is a session by the contract (`parent_run_id ===
 * ""`), even one that predates the session/subagent split.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifiedProof } from "../../components/verification/fixtures";
import type { Proof } from "../../components/verification";
import { RunPage } from "./RunPage";
import type { FetchProof, FetchRunRecord, FetchStepDiff } from "./api";
import {
  AGENT_NOW,
  AGENT_RUN_ID,
  NOW,
  RUN_ID,
  SESSION_NOW,
  SESSION_RUN_ID,
  agentRecord,
  record,
  statesDiff,
  statesRecord,
  stepOneDiff,
  sessionRecord,
  STATES_NOW,
  STATES_RUN_ID,
} from "./fixtures";
import type { StepDiff } from "./types";

const AGENT_ROUTE = { view: "run", runId: AGENT_RUN_ID } as const;
const SESSION_ROUTE = { view: "run", runId: SESSION_RUN_ID } as const;
const ROUTE = { view: "run", runId: RUN_ID } as const;
const STATES_ROUTE = { view: "run", runId: STATES_RUN_ID } as const;

function stubs(overrides: { readonly diff?: () => Promise<StepDiff>; readonly proof?: () => Promise<Proof> } = {}) {
  const readDiff: FetchStepDiff = overrides.diff ?? (async () => stepOneDiff());
  const readProof: FetchProof = overrides.proof ?? (async () => verifiedProof());
  return { readDiff, readProof };
}

beforeEach(() => {
  window.history.pushState(null, "", "/runs/" + AGENT_RUN_ID);
});

afterEach(() => {
  window.history.pushState(null, "", "/");
});

describe("the subagent page (agent-record.json ↔ Agent.dc.html)", () => {
  function renderAgent() {
    const { readDiff, readProof } = stubs();
    const readRecord: FetchRunRecord = async () => agentRecord();
    render(<RunPage route={AGENT_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={AGENT_NOW} />);
  }

  it("renders the lineage nav: the session pill, spawned-at-step link, this-agent pill", async () => {
    renderAgent();
    const nav = await screen.findByRole("navigation", { name: "Where this agent came from" });
    const inNav = within(nav);
    expect(inNav.getByRole("link", { name: /Session/ })).toHaveAttribute("href", "/runs/run-bf9a1e9bc86c64de3347eb83887c4ce2");
    const spawnedLink = inNav.getByRole("link", { name: "spawned at step 662" });
    expect(spawnedLink).toHaveAttribute("href", "/runs/run-bf9a1e9bc86c64de3347eb83887c4ce2#step-662");
    expect(inNav.getByText("this agent")).toBeInTheDocument();
  });

  it("renders the kicker, heading and status pill", async () => {
    renderAgent();
    expect(await screen.findByText("SUBAGENT · general-purpose")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "RM-189 health stops naming repos" })).toBeInTheDocument();
    expect(screen.getByText("Lapsed")).toBeInTheDocument();
    expect(screen.getByText(/ran 26 Sep 18:00–18:02 UTC/)).toBeInTheDocument();
  });

  it("renders the four fact cards exactly as the board: Started by, Worked in, Did, Identity", async () => {
    renderAgent();
    const startedBy = (await screen.findByText("Started by")).closest("div") as HTMLElement;
    expect(within(startedBy).getByRole("link", { name: "Session" })).toHaveAttribute(
      "href",
      "/runs/run-bf9a1e9bc86c64de3347eb83887c4ce2",
    );
    expect(startedBy).toHaveTextContent("at step 662 · 26 Sep 18:00 UTC");

    const workedIn = screen.getByText("Worked in").closest("div") as HTMLElement;
    expect(workedIn).toHaveTextContent("Raymalian/innsegl · own worktree");

    const did = screen.getByText("Did").closest("div") as HTMLElement;
    expect(did).toHaveTextContent("15 steps · 2 files written · 0 commits · no subagents");

    const identity = screen.getByText("Identity").closest("div") as HTMLElement;
    expect(within(identity).getByText("run-26c7818c…41ef")).toBeInTheDocument();
  });

  it('shows "Asked to" first, as text: a heading without its markers', async () => {
    renderAgent();
    const asked = (await screen.findByText("Asked to")).closest("section") as HTMLElement;
    expect(within(asked).getByText("the instructions its parent's spawn carried")).toBeInTheDocument();
    expect(within(asked).getByText("The problem")).toBeInTheDocument();
    expect(within(asked).queryByText(/##/)).not.toBeInTheDocument();
    // Three lines of text: all shown, so no toggle (AskedReported.test.tsx covers the toggle).
    expect(within(asked).queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument();
  });

  it('renders "Reported back" in full, bolding **x** and marking `code` monospace, nothing else', async () => {
    renderAgent();
    const reported = (await screen.findByText("Reported back")).closest("section") as HTMLElement;
    expect(within(reported).getByText("its final message to the session · step 15")).toBeInTheDocument();
    const bold = within(reported).getByText("#309 is fixed and tested but not committed.");
    expect(bold.tagName).toBe("STRONG");
    const code = within(reported).getByText("web/src");
    expect(code.tagName).toBe("CODE");
    expect(within(reported).queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument();
  });

  it('"What it ran" states the step count and defaults to the Commands toggle', async () => {
    renderAgent();
    expect(await screen.findByText("What it ran · 15 steps")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Commands" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "With output" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByText("#")).toBeInTheDocument();
    expect(screen.getByText("Tool")).toBeInTheDocument();
    expect(screen.getByText("Command or file")).toBeInTheDocument();
    expect(screen.getByText("Result")).toBeInTheDocument();
    expect(screen.getByText("Time")).toBeInTheDocument();
  });

  it("collapses a run of ordinary rows and expands it on \"show\"", async () => {
    renderAgent();
    await screen.findByText("What it ran · 15 steps");
    // As the board: steps 1-3 show, 4-9 collapse.
    expect(document.querySelector('[data-step="3"]')).not.toBeNull();
    const group = screen.getByText(/Steps 4–9/);
    expect(group).toHaveTextContent("6 more commands");
    expect(document.querySelector('[data-step="4"]')).toBeNull();

    await userEvent.click(within(group.closest("div") as HTMLElement).getByRole("button", { name: "show" }));
    expect(document.querySelector('[data-step="4"]')).not.toBeNull();
  });

  it("opens a file-write step by default, showing its output", async () => {
    renderAgent();
    await screen.findByText("What it ran · 15 steps");
    const step10 = document.querySelector('[data-step="10"]') as HTMLElement;
    expect(step10).not.toBeNull();
    // As the board: the content it wrote, as a new file, not the tool's own sentence.
    const preview = within(step10).getByTestId("written-preview");
    expect(within(preview).getByText("internal/api/health_test.go")).toBeInTheDocument();
    expect(within(preview).getByText("new file")).toBeInTheDocument();
    expect(within(preview).getByText("package api")).toBeInTheDocument();
    expect(within(step10).queryByText("File created successfully at: internal/api/health_test.go")).toBeNull();
  });

  it('a report row shows tool "Report" and hands back to the session', async () => {
    renderAgent();
    const step15 = (await screen.findByText("What it ran · 15 steps")) && (document.querySelector('[data-step="15"]') as HTMLElement);
    expect(within(step15).getByText("Report")).toBeInTheDocument();
    expect(within(step15).getByText("Handed its report back to the session · shown above")).toBeInTheDocument();
  });

  it('"With output" opens every row and removes the collapsed group', async () => {
    renderAgent();
    await screen.findByText("What it ran · 15 steps");
    await userEvent.click(screen.getByRole("button", { name: "With output" }));
    expect(screen.queryByText(/more commands/)).toBeNull();
    for (let n = 1; n <= 9; n++) {
      expect(document.querySelector(`[data-step="${n}"]`)).not.toBeNull();
    }
  });

  it('"Where it sits" names the parent and its other agents, highlights this agent, and states no subagents', async () => {
    renderAgent();
    const sits = (await screen.findByText("Where it sits")).closest("section") as HTMLElement;
    const inSits = within(sits);
    expect(inSits.getByRole("link", { name: /Session/ })).toHaveTextContent("72 other agents");
    expect(inSits.getByText("RM-189 health stops naming repos")).toBeInTheDocument();
    expect(inSits.getByText("Started no subagents of its own.")).toBeInTheDocument();
    expect(
      screen.getByText("Matched to step 662 by the agent id its spawn returned and its own steps carry."),
    ).toBeInTheDocument();
  });

  it('"Files it wrote" lists both written files with their badges and steps', async () => {
    renderAgent();
    const files = (await screen.findByText("Files it wrote")).closest("section") as HTMLElement;
    const inFiles = within(files);
    expect(inFiles.getByText("internal/api/health_test.go")).toBeInTheDocument();
    expect(inFiles.getByText("internal/api/server.go")).toBeInTheDocument();
    expect(inFiles.getByText("step 10")).toBeInTheDocument();
    expect(inFiles.getByText("step 12")).toBeInTheDocument();
  });

  it('"Commits" says None, and "Witnesses" states the hook-recorded sentence', async () => {
    renderAgent();
    const commits = (await screen.findByText("Commits")).closest("section") as HTMLElement;
    expect(within(commits).getByText("None.")).toBeInTheDocument();

    const witnesses = screen.getByText("Witnesses").closest("section") as HTMLElement;
    expect(
      within(witnesses).getByText(
        "Recorded by the hook before the gateway existed: no snapshots or telemetry for this agent. Every step's body is stored and its digest verifies.",
      ),
    ).toBeInTheDocument();
  });
});

describe("the session page (session-record.json ↔ Session.dc.html)", () => {
  function renderSession() {
    const { readDiff, readProof } = stubs();
    const readRecord: FetchRunRecord = async () => sessionRecord();
    window.history.pushState(null, "", "/runs/" + SESSION_RUN_ID);
    render(<RunPage route={SESSION_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={SESSION_NOW} />);
  }

  it('renders "this session" in the nav, the session kicker and heading, and an Active pill', async () => {
    renderSession();
    const nav = await screen.findByRole("navigation", { name: "Where this agent came from" });
    expect(within(nav).getByText("this session")).toBeInTheDocument();
    expect(within(nav).getByText("started by you · nothing above it")).toBeInTheDocument();
    expect(screen.getByText("SESSION · the agent you talk to")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Session on Raymalian/innsegl" })).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText(/since 23 Sep 08:16 UTC/)).toBeInTheDocument();
  });

  it("renders the four session fact cards: Did, Started, Committed, Repository", async () => {
    renderSession();
    const record = sessionRecord();
    const did = (await screen.findByText("Did")).closest("div") as HTMLElement;
    expect(did).toHaveTextContent(`${record.steps.length} steps over 8 days`);
    const started = screen.getByText("Started", { selector: "dt" }).closest("div") as HTMLElement;
    expect(started).toHaveTextContent("8 subagents · 0 running now");
    const committed = screen.getByText("Committed").closest("div") as HTMLElement;
    expect(committed).toHaveTextContent("3 signed commits");
    const repository = screen.getByText("Repository").closest("div") as HTMLElement;
    expect(repository).toHaveTextContent("Raymalian/innsegl");
  });

  it('"Agents it started" lists all 8 children, newest first, with Kind/Steps/Commits/Ended', async () => {
    renderSession();
    await screen.findByText("Agents it started");
    const table = screen.getByRole("region", { name: "Agents it started" });
    const rows = within(table);
    expect(rows.getByText("Baseline snapshot before first step")).toBeInTheDocument();
    expect(rows.getByText("spawned at step 2802")).toBeInTheDocument();
    expect(rows.getAllByText("general-purpose · sonnet").length).toBeGreaterThan(0);
    expect(rows.getByText("1 Oct 07:45")).toBeInTheDocument();
    // The lapsed child (no model on record) names its status in the Ended
    // cell instead, lowercase, with no time (#443's own rule for a child
    // that is not retired).
    expect(rows.getByText("RM-189 health stops naming repos")).toBeInTheDocument();
    expect(rows.getByText("general-purpose", { selector: "span" })).toBeInTheDocument();
    expect(rows.getByText("lapsed 26 Sep")).toBeInTheDocument();
    expect(rows.getByText("Showing 8 of 8")).toBeInTheDocument();
    expect(rows.queryByRole("button", { name: "Show more agents" })).toBeNull();

    const firstLink = rows.getAllByRole("link")[0] as HTMLElement;
    expect(firstLink).toHaveAttribute("href", "/runs/run-6f3e38cf7e807075bb34c62c01899b7b");
  });

  it("the search box filters agents by title", async () => {
    renderSession();
    await screen.findByText("Agents it started");
    const table = screen.getByRole("region", { name: "Agents it started" });
    const search = screen.getByRole("searchbox", { name: "Find an agent by task" });
    await userEvent.type(search, "E19");
    expect(within(table).getByText("Showing 3 of 3")).toBeInTheDocument();
    expect(within(table).getByText("E19 passkey login and gate")).toBeInTheDocument();
    expect(within(table).queryByText("Baseline snapshot before first step")).not.toBeInTheDocument();
  });

  it('"What it ran" reads newest first and offers the All / Agents started / Commits / Failed filter', async () => {
    renderSession();
    const record = sessionRecord();
    expect(await screen.findByText(`What it ran · ${record.steps.length} steps, newest first`)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");

    const rows = document.querySelectorAll("[data-step]");
    const numbers = [...rows].map((r) => Number(r.getAttribute("data-step")));
    expect(numbers).toEqual([...numbers].sort((a, b) => b - a));

    await userEvent.click(screen.getByRole("button", { name: "Agents started" }));
    expect(document.querySelectorAll("[data-step]")).toHaveLength(2);
    expect(document.querySelector('[data-step="2802"]')).toHaveTextContent("Baseline snapshot before first step");
  });

  it('a spawn row shows "Started <link to the child>"', async () => {
    renderSession();
    await screen.findByText(/What it ran/);
    const step2802 = document.querySelector('[data-step="2802"]') as HTMLElement;
    const link = within(step2802).getByRole("link", { name: "Baseline snapshot before first step" });
    expect(link).toHaveAttribute("href", "/runs/run-6f3e38cf7e807075bb34c62c01899b7b");
  });

  it("a step with a commit shows a commit chip and opens by default", async () => {
    renderSession();
    await screen.findByText(/What it ran/);
    const step2799 = document.querySelector('[data-step="2799"]') as HTMLElement;
    expect(within(step2799).getByText("innsegl-commit: signed 8619ee7")).toBeInTheDocument();
    expect(await within(step2799).findByText("Commit")).toBeInTheDocument();
  });

  it('"Where it sits" highlights this session and breaks down what it started by agent type', async () => {
    renderSession();
    const sits = (await screen.findByText("Where it sits")).closest("section") as HTMLElement;
    expect(within(sits).getByText("This session")).toBeInTheDocument();
    expect(within(sits).getByText("8 general-purpose")).toBeInTheDocument();
  });

  it('"Commits" states the one-commit-identity sentence, the first 3 shas, and "All N commits"', async () => {
    renderSession();
    await screen.findByText("Agents it started");
    const commits = screen.getByRole("heading", { name: "Commits" }).closest("section") as HTMLElement;
    const inCommits = within(commits);
    expect(
      inCommits.getByText(
        "3 commits, each signed under its own one-commit identity. They are commits, not agents, and are listed here rather than in the agents table.",
      ),
    ).toBeInTheDocument();
    expect(inCommits.getByText("8619ee7")).toBeInTheDocument();
    expect(inCommits.getByText("bd845eb")).toBeInTheDocument();
    expect(inCommits.getByText("0cc4680")).toBeInTheDocument();
    expect(inCommits.getByText("All 3 commits")).toBeInTheDocument();
    // No separate "Witnesses" or "Files it wrote" panel for a session.
    expect(screen.queryByText("Witnesses")).toBeNull();
    expect(screen.queryByText("Files it wrote")).toBeNull();
  });
});

describe("a plain root run (record.json) renders through the session layout", () => {
  it("shows a plain commit list (self-signed) rather than the one-commit-identity sentence", async () => {
    const { readDiff, readProof } = stubs();
    const readRecord: FetchRunRecord = async () => record();
    window.history.pushState(null, "", "/runs/" + RUN_ID);
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    expect(await screen.findByText("SESSION · the agent you talk to")).toBeInTheDocument();
    const commits = screen.getByRole("heading", { name: "Commits" }).closest("section") as HTMLElement;
    expect(within(commits).getByText("c906a8c")).toBeInTheDocument();
    expect(within(commits).getByText("e18 end to end")).toBeInTheDocument();
    expect(within(commits).queryByText(/one-commit identity/)).not.toBeInTheDocument();
  });
});

describe("witness disagreement and dark mode survive the redesign (states-record.json)", () => {
  it("raises the page-level banner and opens step 7 with the witness grid inside it", async () => {
    const readRecord: FetchRunRecord = async () => statesRecord();
    const readDiff: FetchStepDiff = async () => statesDiff();
    const readProof: FetchProof = async () => verifiedProof();
    window.history.pushState(null, "", "/runs/" + STATES_RUN_ID);
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Witnesses disagree on step 7");

    const step7 = document.querySelector('[data-step="7"]') as HTMLElement;
    expect(step7).not.toBeNull();
    const grid = step7.querySelector("[data-witness-grid]");
    expect(grid).not.toBeNull();
    expect(within(grid as HTMLElement).getByText(/Harness telemetry/)).toBeInTheDocument();
  });

  it("a failed step opens by default with no red anywhere in its outcome", async () => {
    const readRecord: FetchRunRecord = async () => statesRecord();
    const readDiff: FetchStepDiff = async () => statesDiff();
    const readProof: FetchProof = async () => verifiedProof();
    window.history.pushState(null, "", "/runs/" + STATES_RUN_ID);
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    await screen.findByText(/What it ran/);
    const step4 = document.querySelector('[data-step="4"]') as HTMLElement;
    const outcome = within(step4).getByText("failed · exit 1");
    expect(outcome.className).not.toMatch(/integrity-alert/);
    expect(outcome.className).not.toMatch(/proof-failed/);
  });
});

describe("#440 kept: a clipped step's full output on request, and paging 100 at a time", () => {
  it("loads a clipped step's full output on request", async () => {
    const base = sessionRecord();
    const target = base.steps[1]!;
    const clipped = {
      ...base,
      steps: base.steps.map((s) => (s.n === target.n ? { ...s, output: "first part only", clipped: true } : s)),
    };
    const readStep = vi.fn(async () => ({ ...target, output: "first part only, and the rest", clipped: false }));
    const { readDiff, readProof } = stubs();
    window.history.pushState(null, "", "/runs/" + SESSION_RUN_ID);
    render(
      <RunPage
        route={SESSION_ROUTE}
        fetchRunRecord={async () => clipped}
        fetchStepDiff={readDiff}
        fetchProof={readProof}
        fetchStep={readStep}
        now={SESSION_NOW}
      />,
    );
    await screen.findByText(/What it ran/);
    const row = document.querySelector(`[data-step="${target.n}"]`) as HTMLElement;
    expect(within(row).getByText("first part only")).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Show full output" }));
    expect(await within(row).findByText("first part only, and the rest")).toBeInTheDocument();
    expect(readStep).toHaveBeenCalledWith(SESSION_RUN_ID, target.n, expect.anything());
  });

  it("draws the step table 100 at a time", async () => {
    const base = agentRecord();
    const one = base.steps[0]!;
    const many = {
      ...base,
      written: [],
      commits: [],
      steps: Array.from({ length: 250 }, (_, i) => ({ ...one, n: i + 1, event_id: `e${i + 1}`, commit_sha: "", kind: "tool" as const })),
    };
    const { readDiff, readProof } = stubs();
    render(<RunPage route={AGENT_ROUTE} fetchRunRecord={async () => many} fetchStepDiff={readDiff} fetchProof={readProof} now={AGENT_NOW} />);
    await screen.findByText(/What it ran/);
    expect(document.querySelectorAll("[data-step]")).toHaveLength(3); // the first 3 show, the next 97 collapse
    expect(screen.getByText(/Steps 4–100/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show 100 more steps (150 left)" }));
    expect(screen.getByText(/Steps 4–200/)).toBeInTheDocument();
  });
});

describe("#435 a run with nothing recorded", () => {
  it("says no steps were recorded", async () => {
    const base = agentRecord();
    const bare = { ...base, steps: [], written: [], commits: [], witness: { steps: 0, agree: 0, disagree: 0, unchecked: 0, bodies_stored: 0, bodies_verified: 0 } };
    const { readDiff, readProof } = stubs();
    render(<RunPage route={AGENT_ROUTE} fetchRunRecord={async () => bare} fetchStepDiff={readDiff} fetchProof={readProof} now={AGENT_NOW} />);
    expect((await screen.findAllByText(/No steps were recorded for this run/)).length).toBeGreaterThan(0);
  });
});

describe("#442 off-screen steps are not drawn until scrolled near", () => {
  it("marks a long run's step rows for the browser to skip while off screen", async () => {
    const base = record();
    const one = base.steps[2]!;
    // Failed steps each stay their own open row, so all 40 are drawn.
    const long = {
      ...base,
      steps: Array.from({ length: 40 }, (_, i) => ({ ...one, n: i + 1, event_id: `e${i + 1}`, commit_sha: "", outcome: { kind: "error" as const, exit_code: 1 } })),
    };
    render(
      <RunPage route={ROUTE} fetchRunRecord={async () => long} fetchStepDiff={async () => stepOneDiff()} fetchProof={async () => verifiedProof()} now={NOW} />,
    );
    await screen.findByText(/What it ran/);
    const cards = Array.from(document.querySelectorAll("[data-step]"));
    expect(cards).toHaveLength(40);
    for (const card of cards) {
      expect(card.className).toContain("[content-visibility:auto]");
    }
  });

  it("draws a short run's step rows in full, as screenshots and print need", async () => {
    const { readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={async () => record()} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);
    await screen.findByText(/What it ran/);
    for (const card of Array.from(document.querySelectorAll("[data-step]"))) {
      expect(card.className).not.toContain("content-visibility");
    }
  });
});

describe("#443 the diff layout toggle shows only where there is a diff", () => {
  it("is absent for a run whose steps have no snapshot diff", async () => {
    const { readDiff, readProof } = stubs();
    render(<RunPage route={AGENT_ROUTE} fetchRunRecord={async () => agentRecord()} fetchStepDiff={readDiff} fetchProof={readProof} now={AGENT_NOW} />);
    await screen.findByText("What it ran · 15 steps");
    expect(screen.queryByRole("button", { name: "Side by side" })).toBeNull();
  });
});

describe("#443 a child not linked to a spawn", () => {
  it("is named by its kind and says it was not matched, never 'step 0'", async () => {
    const base = sessionRecord();
    const unmatched = {
      ...base,
      children: [{ ...base.children[0]!, title: "", agent_type: "fork", model: "", spawned_at_step: 0 }],
    };
    const { readDiff, readProof } = stubs();
    render(<RunPage route={SESSION_ROUTE} fetchRunRecord={async () => unmatched} fetchStepDiff={readDiff} fetchProof={readProof} now={SESSION_NOW} />);
    await screen.findByText("Agents it started");
    expect(screen.getAllByText("fork agent").length).toBeGreaterThan(0);
    expect(screen.getByText("not matched to a step")).toBeInTheDocument();
    expect(screen.queryByText("spawned at step 0")).toBeNull();
  });
});
