// SPDX-License-Identifier: Apache-2.0

/*
 * FE-130 (NEW — proposed for doc 07 TC-FE; see the report for #256).
 *
 *   U | The run page states the evidence for the state it names | Last
 *     activity, withdrawal instant, restorable-until, parent run and the
 *     horizon the answer was computed with are all on the page; an absent
 *     fact is stated as absent and never rendered as an instant | #256,
 *     FD P1, P2, §3.3
 *
 * ── THE RULE ───────────────────────────────────────────────────────────────
 *
 * A page that states a conclusion must be able to state its evidence. "Lapsed"
 * and "Abandoned" are the same run seen against two different horizons, so a
 * page that shows the word without the horizon has handed the reader a verdict
 * they cannot check — which is doc 06 P1 exactly, one level up from a
 * verification.
 *
 * ── AND THE ABSENCES ───────────────────────────────────────────────────────
 *
 * A run that was never withdrawn has no withdrawal instant, and the zero time
 * marshals as "0001-01-01T00:00:00Z", which a reader has every right to read
 * as a timestamp. `internal/api` omits the member; this asserts the page does
 * the same rather than rendering a year nobody recorded.
 */

import { render } from "@testing-library/react";

import { RunHeader } from "./RunHeader";
import { EVENT_TYPES } from "./types";
import type { RunDetail } from "./types";
import { NOW, ledgerEvent, runDetail } from "./fixtures";

const WITHDRAWN_AT = "2026-08-31T11:44:00.000Z";
const LAST_ACTIVITY = "2026-08-31T11:43:00.000Z";
const PARENT_RUN = "run-0dd8f0f0f52a4a6c9f6c9e4c1a2b3c4d";
const THIRTY_DAYS = 30 * 24 * 60 * 60;

/** A run whose newest fact is the reaper's withdrawal. */
function withdrawnTimeline() {
  return [
    ledgerEvent(EVENT_TYPES.runRegistered, 1, {
      canonical: { agent_type: "fix-ci", task_ref: "JIRA-118" },
    }),
    ledgerEvent(EVENT_TYPES.toolCall, 3, {
      ts: LAST_ACTIVITY,
      canonical: { tool_name: "edit_file" },
    }),
    ledgerEvent(EVENT_TYPES.runExpired, 4, {
      ts: WITHDRAWN_AT,
      source: "reaper",
    }),
  ];
}

function withdrawnRun(status: string, over: Partial<RunDetail> = {}): RunDetail {
  return runDetail(withdrawnTimeline(), status, {
    last_activity_at: LAST_ACTIVITY,
    withdrawn_at: WITHDRAWN_AT,
    restorable_until: "2026-09-30T11:44:00.000Z",
    parent_run_id: PARENT_RUN,
    restore_horizon_seconds: THIRTY_DAYS,
    ...over,
  });
}

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderRun(detail: RunDetail): string {
  const { container } = render(
    <RunHeader run={detail} events={detail.timeline ?? []} now={NOW} />,
  );
  return visibleText(container);
}

describe("FE-130 the run page states its evidence", () => {
  it("shows every fact a lapsed state was derived from", () => {
    const text = renderRun(withdrawnRun("lapsed"));

    // The four instants and the parent, each under its own label.
    expect(text).toContain("Last activity");
    expect(text).toContain("Credential withdrawn");
    expect(text).toContain("Restorable until");
    expect(text).toContain("Parent run");
    expect(text).toContain(PARENT_RUN);

    // And the number that decided which of the two withdrawn states this is.
    expect(text).toContain("Restore horizon");
    expect(text).toContain("30 d");
  });

  it("says in a sentence what it concluded, and from when", () => {
    const text = renderRun(withdrawnRun("lapsed"));
    expect(text).toMatch(/Nothing heard since 2026-08-31 11:43:00 UTC/);
    // "Lapsed" means restorable for now, so the sentence says until when.
    expect(text).toMatch(/can be restored/i);
    expect(text).toContain("2026-09-30 11:44:00 UTC");
  });

  it("reads abandonment as an end to restoring, never as an agent ending", () => {
    const text = renderRun(
      withdrawnRun("abandoned", { restorable_until: "2026-08-31T11:45:00.000Z" }),
    );
    expect(text).toMatch(/Nothing heard since 2026-08-31 11:43:00 UTC/);
    expect(text).toMatch(/can no longer be restored/i);
    // The claim it must not make. FE-132 holds this across the whole product;
    // it is asserted here too because this is the page that would make it.
    expect(text).not.toMatch(/\b(?:dead|died|death|dying|killed)\b/i);
  });

  it("keeps a resumed run's lapse visible while reading active", () => {
    const text = renderRun(withdrawnRun("active"));
    // The run is active because its newest fact is its own, but the
    // withdrawal happened and erasing it would be a second kind of lie.
    expect(text).toContain("Credential withdrawn");
    expect(text).toContain("2026-08-31 11:44:00 UTC");
  });

  it("states an absent fact as absent rather than as an instant", () => {
    const detail = runDetail(
      [ledgerEvent(EVENT_TYPES.runRegistered, 1)],
      "active",
      { last_activity_at: "2026-08-31T11:41:00.000Z", restore_horizon_seconds: THIRTY_DAYS },
    );
    const text = renderRun(detail);
    // The zero time, which is what a struct with no `omitempty` would have
    // produced on the wire and what a careless render would print.
    expect(text).not.toContain("0001-01-01");
    expect(text).not.toContain("Restorable until");
    expect(text).not.toContain("Parent run");
    expect(text).toMatch(/never withdrawn|no withdrawal/i);
  });

  it("does not invent a horizon the query API did not report", () => {
    const text = renderRun(
      withdrawnRun("lapsed", { restore_horizon_seconds: undefined }),
    );
    // P2: "we were not told" and "no horizon is set" are different facts.
    expect(text).not.toContain("30 d");
    expect(text).toMatch(/did not report/i);
  });

  it("says so when the deployment set no horizon at all", () => {
    const text = renderRun(
      withdrawnRun("lapsed", {
        restore_horizon_seconds: 0,
        restorable_until: undefined,
      }),
    );
    expect(text).toMatch(/no restore horizon/i);
    expect(text).not.toContain("Restorable until");
  });
});
