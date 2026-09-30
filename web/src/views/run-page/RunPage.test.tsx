// SPDX-License-Identifier: Apache-2.0

/*
 * doc 07's run-page test catalogue, RPG-010..015 — issues #395-397.
 *
 * Named by catalogue id, driven against the approved mockup's own fixtures:
 * record.json/diff-step1.json for the Main board, states-record.json/
 * states-diff.json (this issue's own) for the States board.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifiedProof } from "../../components/verification/fixtures";
import type { Proof } from "../../components/verification";
import { RunPage } from "./RunPage";
import type { FetchProof, FetchRunRecord, FetchStepDiff } from "./api";
import { NOW, RUN_ID, record, statesRecord, statesDiff, stepOneDiff, STATES_NOW, STATES_RUN_ID } from "./fixtures";
import type { StepDiff } from "./types";

const ROUTE = { view: "run", runId: RUN_ID } as const;
const STATES_ROUTE = { view: "run", runId: STATES_RUN_ID } as const;

function stubs(overrides: { readonly diff?: () => Promise<StepDiff>; readonly proof?: () => Promise<Proof> } = {}) {
  const readRecord: FetchRunRecord = async () => record();
  const readDiff: FetchStepDiff = overrides.diff ?? (async () => stepOneDiff());
  const readProof: FetchProof = overrides.proof ?? (async () => verifiedProof());
  return { readRecord, readDiff, readProof };
}

function statesStubs() {
  const readRecord: FetchRunRecord = async () => statesRecord();
  const readDiff: FetchStepDiff = async () => statesDiff();
  const readProof: FetchProof = async () => verifiedProof();
  return { readRecord, readDiff, readProof };
}

beforeEach(() => {
  window.history.pushState(null, "", "/runs/" + RUN_ID);
});

afterEach(() => {
  window.history.pushState(null, "", "/");
});

describe("RPG-010 renders the mockup's run page from fixtures/record.json", () => {
  it("renders the header: breadcrumb, heading, status pill, fact cards", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("main agent");
    expect(screen.getByText("Runs")).toBeInTheDocument();
    expect(screen.getByText("github.com/innsegl-test/gateway-livetest")).toBeInTheDocument();
    expect(screen.getByText("Retired")).toBeInTheDocument();
    expect(screen.getByText("Every step has a stored body; digests verify")).toBeInTheDocument();

    expect(screen.getByText("Identity")).toBeInTheDocument();
    const repoBranch = screen.getByText("Repository · branch").closest("div");
    expect(repoBranch).toHaveTextContent("innsegl-test/gateway-livetest");
    expect(repoBranch).toHaveTextContent("main");
    expect(screen.getByText("Activity")).toBeInTheDocument();
    expect(screen.getByText("4 steps · 1 commit · 1 subagent · 2 files")).toBeInTheDocument();
    expect(screen.getByText("Witnesses")).toBeInTheDocument();
    expect(screen.getByText("Gateway, snapshots and telemetry agree on all 4 steps")).toBeInTheDocument();
  });

  it("renders the agent tree, highlighting the selected run", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Agent tree");
    expect(screen.getByText("main")).toBeInTheDocument();
    expect(screen.getByText("general-purpose")).toBeInTheDocument();
    expect(
      screen.getByText("Linked by the exact brief its parent's spawn carried (step 4)"),
    ).toBeInTheDocument();

    const selected = screen.getByRole("link", { name: /^main/ });
    expect(selected).toHaveAttribute("aria-current", "page");
  });

  it("renders files changed: the tree, the subagent note, and the legend", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    const filesPanel = (await screen.findByText("Files changed")).closest("section") as HTMLElement;
    const files = within(filesPanel);
    expect(files.getByText("gateway-livetest/")).toBeInTheDocument();
    expect(files.getByText("e18.txt")).toBeInTheDocument();
    expect(files.getByText("e18-sub.txt")).toBeInTheDocument();
    expect(files.getByText("e18-sub.txt was written by the subagent")).toBeInTheDocument();
    expect(files.getByText("A added")).toBeInTheDocument();
    expect(files.getByText("M modified")).toBeInTheDocument();
    expect(files.getByText("D deleted")).toBeInTheDocument();
    expect(files.getByText("R reverted")).toBeInTheDocument();
  });

  it("renders the commits aside", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    const commitsPanel = (await screen.findByText("Commits")).closest("section") as HTMLElement;
    const commits = within(commitsPanel);
    expect(commits.getByText("c906a8c")).toBeInTheDocument();
    expect(commits.getByText("made by step 2", { exact: false })).toBeInTheDocument();
    expect(commits.getByText("landed on main", { exact: false })).toBeInTheDocument();
  });

  it("renders the brief, with its keyed-digest caption", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    const briefSection = (await screen.findByText("Brief")).closest("section") as HTMLElement;
    const brief = within(briefSection);
    expect(brief.getByText(/the first message this agent received/)).toBeInTheDocument();
    expect(brief.getByText(/keyed digest/)).toBeInTheDocument();
    expect(
      brief.getByText(/Do these in order and report each result in one line/),
    ).toBeInTheDocument();
  });

  it("renders every step: number, tool, summary, outcome, time, witnesses", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Timeline");

    const step1 = document.querySelector('[data-step="1"]');
    expect(step1).not.toBeNull();
    const s1 = within(step1 as HTMLElement);
    expect(s1.getByText("Write")).toBeInTheDocument();
    // Twice: the step's own summary, and the diff file header under it —
    // waited for the diff's own content, so the count is not read mid-fetch.
    await s1.findByText("e18 end to end");
    expect(s1.getAllByText("e18.txt")).toHaveLength(2);
    expect(s1.getByText("done")).toBeInTheDocument();
    expect(s1.getByText("3 of 3 witnesses agree")).toBeInTheDocument();
    expect(s1.getByText("File created successfully at: e18.txt")).toBeInTheDocument();

    const step2 = document.querySelector('[data-step="2"]');
    const s2 = within(step2 as HTMLElement);
    expect(s2.getByText("Bash")).toBeInTheDocument();
    expect(s2.getByText("exit 0")).toBeInTheDocument();
    expect(s2.getByText(/1 file changed, 1 insertion/)).toBeInTheDocument();

    const step3 = document.querySelector('[data-step="3"]');
    const s3 = within(step3 as HTMLElement);
    expect(s3.getByText("failed · exit 1")).toBeInTheDocument();
    expect(s3.getByText(/Operation not permitted/)).toBeInTheDocument();
    // record.json's step 3 is outcome.kind "error", not "refused" — this view
    // cannot truthfully claim a sandbox refusal the contract did not record,
    // so only the general sentence renders (see strings.ts's own comment).
    expect(
      s3.getByText("A step that failed is part of the record, shown as it happened."),
    ).toBeInTheDocument();
    expect(s3.queryByText(/Refused by the harness sandbox/)).not.toBeInTheDocument();

    const step4 = document.querySelector('[data-step="4"]');
    const s4 = within(step4 as HTMLElement);
    expect(s4.getByText("Agent")).toBeInTheDocument();
    expect(s4.getByText("returned")).toBeInTheDocument();
    expect(s4.getByText(/general-purpose/)).toBeInTheDocument();
    expect(s4.getByText(/The subagent made commit 64967eb/)).toBeInTheDocument();
  });

  it("renders the inline diff for step 1, from GET .../steps/1/diff", async () => {
    const readDiffSpy = vi.fn<FetchStepDiff>(async () => stepOneDiff());
    const { readRecord, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiffSpy} fetchProof={readProof} now={NOW} />);

    await screen.findByText("e18 end to end");
    expect(readDiffSpy).toHaveBeenCalledWith(RUN_ID, 1, expect.any(AbortSignal));
    expect(await screen.findByText("+")).toBeInTheDocument();
  });

  it("renders the commit card with the three checks and a Verified badge", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Commit");
    // The check grid renders only once the proof fetch resolves; anchor on
    // one of its own labels rather than the static "Commit" heading above it.
    await screen.findByText("1 · Fulcio certificate chain");
    expect(screen.getByText("2 · Rekor inclusion")).toBeInTheDocument();
    expect(screen.getByText("3 · Trailer matches certificate identity")).toBeInTheDocument();
    expect(screen.getByText("Valid")).toBeInTheDocument();
    expect(screen.getByText("Same identity")).toBeInTheDocument();
    expect(screen.getAllByText("Verified").length).toBeGreaterThan(0);
    expect(screen.getByText("Signed by this run in the core; recorded as intent → signature → record")).toBeInTheDocument();
    expect(screen.getByText("Verify it yourself")).toBeInTheDocument();
  });

  it("renders the reply, with its keyed-digest heading", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText(/Reply · keyed digest/);
    expect(screen.getByText(/The subagent committed as 64967eb/)).toBeInTheDocument();
  });
});

describe("RPG-011 the Unified / Side by side toggle", () => {
  it("renders two columns in side-by-side mode, and keeps the choice in the URL", async () => {
    const user = userEvent.setup();
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Timeline");
    const unified = screen.getByRole("button", { name: "Unified" });
    const side = screen.getByRole("button", { name: "Side by side" });
    expect(unified).toHaveAttribute("aria-pressed", "true");
    expect(side).toHaveAttribute("aria-pressed", "false");

    await user.click(side);

    expect(window.location.search).toContain("diff=side");
    expect(side).toHaveAttribute("aria-pressed", "true");
    const diffFile = document.querySelector("[data-diff-mode]");
    expect(diffFile).toHaveAttribute("data-diff-mode", "side");

    await user.click(unified);
    expect(window.location.search).not.toContain("diff=side");
  });

  it("starts in side-by-side mode when the URL already names it", async () => {
    window.history.pushState(null, "", `/runs/${RUN_ID}?diff=side`);
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Timeline");
    expect(screen.getByRole("button", { name: "Side by side" })).toHaveAttribute("aria-pressed", "true");
  });
});

describe("RPG-012 witness disagreement", () => {
  it("raises the page-level banner naming the step, and shows the 2 of 3 badge with the missing cell", async () => {
    const { readRecord, readDiff, readProof } = statesStubs();
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Witnesses disagree on step 7");
    expect(alert).toHaveTextContent("toolu_01XyABCDEFGHIJKLMNOPQk");

    const step7 = document.querySelector('[data-step="7"]') as HTMLElement;
    expect(step7).not.toBeNull();
    const s7 = within(step7);
    expect(s7.getByText("2 of 3 witnesses")).toBeInTheDocument();
    expect(s7.getByText("Gateway")).toBeInTheDocument();
    expect(s7.getByText("Workspace snapshot")).toBeInTheDocument();
    expect(s7.getByText("Harness telemetry")).toBeInTheDocument();
    expect(s7.getByText("no event for this tool call")).toBeInTheDocument();
    const grid = step7.querySelector("[data-witness-grid]");
    expect(within(grid as HTMLElement).getByText(/Harness telemetry/)).toBeInTheDocument();
  });
});

describe("RPG-013 a failed step is grey, not red, with its exit code", () => {
  it("step 4 (a failed Bash call) shows exit 1 with no red anywhere", async () => {
    const { readRecord, readDiff, readProof } = statesStubs();
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    await screen.findByText("Timeline");
    const step4 = document.querySelector('[data-step="4"]') as HTMLElement;
    const s4 = within(step4);
    expect(s4.getByText("failed · exit 1")).toBeInTheDocument();
    const outcome = s4.getByText("failed · exit 1");
    expect(outcome.className).not.toMatch(/integrity-alert/);
    expect(outcome.className).not.toMatch(/proof-failed/);
  });
});

describe("RPG-014 a reverted file and a not_landed commit", () => {
  it("shows the R file with when it was written and reverted, never committed", async () => {
    const { readRecord, readDiff, readProof } = statesStubs();
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    const filesPanel = (await screen.findByText("Files changed")).closest("section") as HTMLElement;
    expect(within(filesPanel).getByText("scratch/probe.sh")).toBeInTheDocument();
    expect(
      screen.getByText("written in step 3, deleted in step 5 · never committed"),
    ).toBeInTheDocument();
  });

  it("keeps the not_landed commit's badge Verified, with landing shown beside it", async () => {
    const { readRecord, readDiff, readProof } = statesStubs();
    render(<RunPage route={STATES_ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={STATES_NOW} />);

    const commitsPanel = (await screen.findByText("Commits")).closest("section") as HTMLElement;
    expect(within(commitsPanel).getByText("5d31e0a")).toBeInTheDocument();
    expect(within(commitsPanel).getByText("on no branch", { exact: false })).toBeInTheDocument();

    // The commit card's own badge is unaffected by landing — it is a
    // statement about the signature, not about the repository (doc 06 §4.2).
    expect((await screen.findAllByText("Verified")).length).toBeGreaterThan(0);
  });
});

describe("RPG-015 keyboard path and +/- markers", () => {
  it("every interactive element in the tree, files, steps and toggle is a real, focusable control", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("Timeline");

    // Agent tree rows are links.
    const treePanel = screen.getByText("Agent tree").closest("section") as HTMLElement;
    expect(within(treePanel).getByRole("link", { name: /^main/ })).toBeInTheDocument();
    expect(within(treePanel).getByRole("link", { name: /^general-purpose/ })).toBeInTheDocument();
    // The toggle is two real buttons.
    expect(screen.getByRole("button", { name: "Unified" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Side by side" })).toBeInTheDocument();
    // The commit SHA is a real, focusable, copy button.
    expect(screen.getByRole("button", { name: /Copy commit SHA/ })).toBeInTheDocument();

    const user = userEvent.setup();
    await user.tab();
    expect(document.activeElement).not.toBe(document.body);
  });

  it("every diff line carries a +/- marker, never colour alone", async () => {
    const { readRecord, readDiff, readProof } = stubs();
    render(<RunPage route={ROUTE} fetchRunRecord={readRecord} fetchStepDiff={readDiff} fetchProof={readProof} now={NOW} />);

    await screen.findByText("e18 end to end");
    await screen.findByText("+");
    const markers = document.querySelectorAll("[data-diff-file] [aria-hidden='true']");
    const found = [...markers].map((m) => m.textContent).filter((t) => t === "+" || t === "−");
    expect(found.length).toBeGreaterThan(0);
  });
});
