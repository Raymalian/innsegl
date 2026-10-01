// SPDX-License-Identifier: Apache-2.0

/*
 * Unit tests for derive.ts's own pure functions (#443, RM-278) — the ones
 * dense enough to deserve a test that does not involve mounting a page:
 * date formatting, the fact-card sentences, the inline markdown lexer, and
 * the step-row open/collapse plan.
 */

import { describe, expect, it } from "vitest";

import {
  dayMonthTimeUtc,
  dayMonthUtc,
  daysBetween,
  endedColumnText,
  filterSteps,
  groupRange,
  hhmmUtc,
  linesOf,
  toolDisplayName,
  countText,
  parseInlineMarkdown,
  planStepRows,
  sessionCommittedText,
  sessionDidText,
  sessionStartedText,
  statusRangeText,
  stepOpensByDefault,
  subagentDidText,
} from "./derive";
import { agentRecord, sessionRecord } from "./fixtures";
import type { RecordStep, RunRecord } from "./types";

describe("date formatting", () => {
  it("dayMonthUtc reads a UTC day and month with no year", () => {
    expect(dayMonthUtc("2026-09-26T18:02:31.000Z")).toBe("26 Sep");
  });
  it("hhmmUtc zero-pads", () => {
    expect(hhmmUtc("2026-10-01T07:05:00.000Z")).toBe("07:05");
  });
  it("dayMonthTimeUtc combines both", () => {
    expect(dayMonthTimeUtc("2026-10-01T07:45:18Z")).toBe("1 Oct 07:45");
  });
  it("daysBetween floors and never goes negative", () => {
    const start = new Date("2026-09-23T08:16:57.000Z");
    const end = new Date("2026-10-01T12:47:29.000Z");
    expect(daysBetween(start, end)).toBe(8);
    expect(daysBetween(end, start)).toBe(0);
  });
});

describe("statusRangeText", () => {
  it("names when a lapsed agent worked, from its own steps, not when it was marked lapsed", () => {
    expect(
      statusRangeText("lapsed", "2026-09-26T18:00:52.000Z", "2026-09-27T06:06:22.000Z", "2026-09-26T18:02:31.000Z"),
    ).toBe("ran 26 Sep 18:00–18:02 UTC");
  });

  it("an active run states when it started", () => {
    expect(statusRangeText("active", "2026-09-23T08:16:57.000Z", null)).toBe("since 23 Sep 08:16 UTC");
  });
  it("a run that ended the same day states the one day once", () => {
    expect(statusRangeText("lapsed", "2026-09-26T18:00:52.000Z", "2026-09-26T18:02:31.000Z")).toBe(
      "ran 26 Sep 18:00–18:02 UTC",
    );
  });
  it("a run that crossed midnight states both days", () => {
    expect(statusRangeText("retired", "2026-09-26T23:50:00.000Z", "2026-09-27T00:10:00.000Z")).toBe(
      "ran 26 Sep 23:50 – 27 Sep 00:10 UTC",
    );
  });
});

describe("endedColumnText", () => {
  it("a retired child names the full moment", () => {
    expect(endedColumnText("retired", "2026-10-01T07:45:18Z")).toBe("1 Oct 07:45");
  });
  it("anything else names its status and the day, lowercase", () => {
    expect(endedColumnText("lapsed", "2026-09-26T18:02:31Z")).toBe("lapsed 26 Sep");
  });
});

describe("fact-card sentences", () => {
  it("subagentDidText says no subagents, not 0, and pluralises correctly", () => {
    const record = agentRecord();
    expect(subagentDidText(record)).toBe("15 steps · 2 files written · 0 commits · no subagents");
  });

  it("sessionDidText reads steps over N days from `now`", () => {
    const record = sessionRecord();
    const now = new Date("2026-10-01T12:47:29.000Z");
    expect(sessionDidText(record, now)).toBe(`${record.steps.length} steps over 8 days`);
  });

  it("sessionStartedText counts children and how many are still active", () => {
    const record = sessionRecord();
    expect(sessionStartedText(record)).toBe("8 subagents · 0 running now");
  });

  it("sessionCommittedText counts the record's own commits", () => {
    const record = sessionRecord();
    expect(sessionCommittedText(record)).toBe("3 signed commits");
  });
});

describe("linesOf", () => {
  it("splits on literal newlines and counts the lines that carry text", () => {
    const { lines, total } = linesOf("a\n\nb\nc");
    expect(lines).toEqual(["a", "", "b", "c"]);
    expect(total).toBe(3);
  });
});

describe("parseInlineMarkdown", () => {
  it("renders **bold** and `code` and leaves everything else as text", () => {
    const tokens = parseInlineMarkdown("**#309 is fixed.** See `web/src` for it.");
    expect(tokens).toEqual([
      { kind: "bold", value: "#309 is fixed." },
      { kind: "text", value: " See " },
      { kind: "code", value: "web/src" },
      { kind: "text", value: " for it." },
    ]);
  });

  it("a lone unmatched delimiter is plain text", () => {
    expect(parseInlineMarkdown("a * b")).toEqual([{ kind: "text", value: "a * b" }]);
  });
});

function step(overrides: Partial<RecordStep>): RecordStep {
  return {
    n: 1,
    tool_use_id: "t",
    event_id: "e",
    chain_position: 1,
    at: "2026-09-26T18:00:00.000Z",
    tool: "Bash",
    summary: "echo hi",
    input: "{}",
    output: "",
    truncated: false,
    clipped: false,
    outcome: { kind: "ok", exit_code: null },
    tree_before: "",
    tree_after: "",
    files: [],
    spawned_run_id: "",
    spawned_commits: [],
    kind: "tool",
    commit_sha: "",
    witnesses: { gateway: "present", snapshot: "inactive", telemetry: "inactive" },
    ...overrides,
  };
}

function bareRecord(steps: RecordStep[]): RunRecord {
  const base = agentRecord();
  return { ...base, steps, written: [], commits: [] };
}

describe("stepOpensByDefault", () => {
  it("opens a failed step, a file write, a commit, and a disagreement; nothing else", () => {
    const record = bareRecord([]);
    expect(stepOpensByDefault(record, step({ outcome: { kind: "error", exit_code: 1 } }))).toBe(true);
    expect(stepOpensByDefault(record, step({ commit_sha: "abc" }))).toBe(true);
    expect(
      stepOpensByDefault(
        record,
        step({ witnesses: { gateway: "present", snapshot: "unchanged", telemetry: "missing" } }),
      ),
    ).toBe(true);
    expect(stepOpensByDefault(record, step({}))).toBe(false);
  });

  it("opens a step the run's own `written` list names", () => {
    const record = { ...bareRecord([]), written: [{ path: "a.go", status: "A" as const, step: 3 }] };
    expect(stepOpensByDefault(record, step({ n: 3 }))).toBe(true);
    expect(stepOpensByDefault(record, step({ n: 4 }))).toBe(false);
  });
});

describe("planStepRows", () => {
  it("shows the first 3 of a run of ordinary rows and collapses the rest, as the board does (steps 4-9)", () => {
    const steps = [1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => step({ n, at: `2026-09-26T18:0${n}:00.000Z` }));
    const record = bareRecord(steps);
    const plan = planStepRows(record, steps);
    expect(plan).toEqual([
      { kind: "row", step: steps[0], open: false },
      { kind: "row", step: steps[1], open: false },
      { kind: "row", step: steps[2], open: false },
      { kind: "group", steps: steps.slice(3) },
    ]);
  });

  it("never collapses a single leftover row: 4 ordinary rows all show", () => {
    const steps = [1, 2, 3, 4].map((n) => step({ n }));
    const plan = planStepRows(bareRecord(steps), steps);
    expect(plan.every((item) => item.kind === "row")).toBe(true);
    expect(plan).toHaveLength(4);
  });

  it("leaves a run of fewer than 3 as ordinary closed rows", () => {
    const steps = [1, 2].map((n) => step({ n }));
    const record = bareRecord(steps);
    const plan = planStepRows(record, steps);
    expect(plan).toEqual([
      { kind: "row", step: steps[0], open: false },
      { kind: "row", step: steps[1], open: false },
    ]);
  });

  it("never folds a spawn or report row into a group, even mid-run — it stays its own row, closed by default", () => {
    const steps = [
      step({ n: 1 }),
      step({ n: 2 }),
      step({ n: 3, kind: "spawn", spawned_run_id: "run-x" }),
      step({ n: 4 }),
      step({ n: 5 }),
    ];
    const record = bareRecord(steps);
    const plan = planStepRows(record, steps);
    expect(plan.find((item) => item.kind === "row" && item.step.kind === "spawn")).toEqual({
      kind: "row",
      step: steps[2],
      open: false,
    });
  });

  it("a failed step among ordinary ones breaks the run and opens on its own", () => {
    const steps = [
      step({ n: 1 }),
      step({ n: 2, outcome: { kind: "error", exit_code: 1 } }),
      step({ n: 3 }),
    ];
    const record = bareRecord(steps);
    const plan = planStepRows(record, steps);
    expect(plan).toEqual([
      { kind: "row", step: steps[0], open: false },
      { kind: "row", step: steps[1], open: true },
      { kind: "row", step: steps[2], open: false },
    ]);
  });

  it("allOpen disables both collapsing and the closed default", () => {
    const steps = [1, 2, 3, 4].map((n) => step({ n }));
    const record = bareRecord(steps);
    const plan = planStepRows(record, steps, true);
    expect(plan).toEqual(steps.map((s) => ({ kind: "row", step: s, open: true })));
  });
});

describe("groupRange", () => {
  it("names the ascending step range and each end's own time, regardless of input order", () => {
    const steps = [step({ n: 9, at: "2026-09-26T18:01:27.000Z" }), step({ n: 4, at: "2026-09-26T18:01:04.000Z" })];
    expect(groupRange(steps)).toEqual({
      a: 4,
      b: 9,
      atA: "2026-09-26T18:01:04.000Z",
      atB: "2026-09-26T18:01:27.000Z",
    });
  });
});

describe("filterSteps", () => {
  const steps = [
    step({ n: 1, kind: "spawn", spawned_run_id: "run-a" }),
    step({ n: 2, commit_sha: "deadbeef" }),
    step({ n: 3, outcome: { kind: "error", exit_code: 1 } }),
    step({ n: 4 }),
  ];
  it("spawned filters to Agent steps only", () => {
    expect(filterSteps(steps, "spawned").map((s) => s.n)).toEqual([1]);
  });
  it("commits filters to steps that made one", () => {
    expect(filterSteps(steps, "commits").map((s) => s.n)).toEqual([2]);
  });
  it("failed filters to a non-ok outcome", () => {
    expect(filterSteps(steps, "failed").map((s) => s.n)).toEqual([3]);
  });
  it("all keeps every step, in order", () => {
    expect(filterSteps(steps, "all").map((s) => s.n)).toEqual([1, 2, 3, 4]);
  });
});

describe("#443 session page details", () => {
  it("names a tool by its own name, not its server prefix", () => {
    expect(toolDisplayName("mcp__claude-in-chrome__browser_batch")).toBe("browser_batch");
    expect(toolDisplayName("Bash")).toBe("Bash");
  });

  it("formats a step count the same way everywhere", () => {
    expect(countText(3103)).toBe("3,103");
  });
});
