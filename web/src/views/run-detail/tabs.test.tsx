// SPDX-License-Identifier: Apache-2.0

/*
 * FE-113 (NEW — proposed for doc 07 TC-FE by this change).
 *
 *   U | Run detail's timeline and activity log are one tab control | Timeline
 *     selected by default; both tabs carry their own count (timeline events,
 *     tool calls); the integrity alert banner renders outside both panels and
 *     stays visible whichever tab is open; `tablist`/`tab`/`tabpanel` with
 *     `aria-selected`, `aria-controls` and Left/Right arrow navigation |
 *     FD P3, §3.3, §6.4
 *
 * ── WHAT THIS IS PROTECTING ────────────────────────────────────────────────
 *
 * The two halves of this page were stacked, and the stacking order was right:
 * doc 06 P3 puts the strongest claim first, and the timeline is the evidence
 * chain. What was wrong was the consequence. MEASURED on a real run: 1220 tool
 * calls, so "below the timeline" meant several hundred screens below it, and
 * the activity log was in practice unreachable. A tab control keeps the
 * ordering — Timeline is first and selected — and makes the second half one
 * key away instead of one scroll-to-the-bottom away.
 *
 * Three of the assertions below are the ones that would be quietly lost if
 * somebody rewrote this as a row of buttons swapping a div:
 *
 *   - THE ALARM IS OUTSIDE BOTH PANELS. doc 06 §4.5 makes the banner
 *     "page-level, persistent until the underlying condition clears". A tab
 *     control is a place to hide a condition behind an unselected tab, and a
 *     hidden alarm is worse than the scroll it replaced. The fixture below is
 *     a run whose tool-call event does not name the hash before it, and the
 *     banner it raises has to be on screen with EITHER tab open.
 *   - BOTH TABS CARRY THEIR COUNT. A reader must be able to see what is behind
 *     the tab they are not looking at. Exact, never rounded (§6.2).
 *   - ARROW KEYS MOVE BETWEEN THE TABS. doc 06 §6.4 is gating, and
 *     `role="tab"` is a promise to a screen-reader user about which keys work.
 *     A control that announces itself as a tablist and then ignores Left and
 *     Right has told them something untrue.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RunDetailView } from "./RunDetailView";
import { NOW, RUN_ID, healthyTimeline, runDetail } from "./fixtures";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

const ROUTE = { view: "run", runId: RUN_ID } as const;

/** The run log the activity panel reads. Fixed, so a count is a constant. */
const RUN_LOG = {
  run_id: RUN_ID,
  retention_days: 90,
  entries: [
    {
      chain_position: 3,
      tool_name: "edit_file",
      ts: "2026-08-31T11:43:00.000Z",
      payload_digest:
        "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      integrity: "verified" as const,
      body: { tool_input: { file_path: "internal/ledger/append.go" } },
    },
  ],
  verified: 1,
  altered: 0,
  expired: 0,
};

beforeEach(() => {
  // The activity panel fetches its own detail. Stubbed rather than left to
  // reach the network, so which tab is open is the only variable in this file.
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => RUN_LOG })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The healthy run, with the tool call no longer naming the hash before it —
 * doc 02 §4's chain check failing on a consecutive pair, which is the one
 * condition a single response can actually establish (see events.ts). */
function chainBrokenAtToolCall(): readonly TimelineEvent[] {
  return healthyTimeline().map((event) =>
    event.event_type === EVENT_TYPES.toolCall
      ? { ...event, prev_event_hash: `sha256:${"0".repeat(64)}` }
      : event,
  );
}

function view(timeline: readonly TimelineEvent[] = healthyTimeline()) {
  return render(
    <RunDetailView route={ROUTE} fetchRun={async () => runDetail(timeline)} now={NOW} />,
  );
}

/** The tabs, in document order. */
async function tabs(): Promise<HTMLElement[]> {
  await screen.findByRole("tablist");
  return screen.getAllByRole("tab");
}

describe("FE-113 the two halves are one tab control", () => {
  it("offers exactly two tabs inside one named tablist", async () => {
    view();
    const list = await screen.findByRole("tablist");
    expect(list).toHaveAccessibleName();
    expect(within(list).getAllByRole("tab")).toHaveLength(2);
  });

  it("selects the timeline by default, because P3 still puts the chain first", async () => {
    view();
    const [timeline, activity] = await tabs();
    expect(timeline).toHaveTextContent("Timeline");
    expect(timeline).toHaveAttribute("aria-selected", "true");
    expect(activity).toHaveAttribute("aria-selected", "false");
    // Only the selected panel is in the accessibility tree.
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
  });

  it("names each tab's panel, and labels each panel with its tab", async () => {
    const { container } = view();
    for (const tab of await tabs()) {
      const id = tab.getAttribute("aria-controls");
      expect(id, "a tab controls nothing").toBeTruthy();
      const panel = container.querySelector(`[id="${id}"]`);
      expect(panel, `no panel with id ${String(id)}`).not.toBeNull();
      expect(panel).toHaveAttribute("role", "tabpanel");
      expect(panel).toHaveAttribute("aria-labelledby", tab.id);
    }
  });

  it("shows the timeline and hides the activity log until it is asked for", async () => {
    const { container } = view();
    const [, activity] = await tabs();
    const activityPanel = container.querySelector(
      `[id="${activity?.getAttribute("aria-controls") ?? ""}"]`,
    );
    expect(activityPanel).not.toBeVisible();
    expect(screen.getByRole("tabpanel")).toHaveTextContent("Run registered");
  });

  it("swaps which panel is shown when the other tab is chosen", async () => {
    view();
    const [timeline, activity] = await tabs();
    await userEvent.click(activity as HTMLElement);

    expect(activity).toHaveAttribute("aria-selected", "true");
    expect(timeline).toHaveAttribute("aria-selected", "false");
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveTextContent("What this agent did");
    expect(panel).not.toHaveTextContent("Run registered");
  });
});

describe("FE-113 each tab says what is behind it", () => {
  it("counts the timeline's events on the timeline tab", async () => {
    view();
    const [timeline] = await tabs();
    // healthyTimeline() is six events. Exact, never rounded (doc 06 §6.2).
    expect(timeline).toHaveTextContent("6 events");
  });

  it("counts the tool calls on the activity tab", async () => {
    view();
    const [, activity] = await tabs();
    expect(activity).toHaveTextContent("1 tool call");
  });

  it("says one event rather than 1 events", async () => {
    view([healthyTimeline()[0] as TimelineEvent]);
    const [timeline] = await tabs();
    expect(timeline).toHaveTextContent("1 event");
    expect(timeline).not.toHaveTextContent("1 events");
  });

  it("keeps the counts readable from the tab that is NOT open", async () => {
    view();
    const [timeline, activity] = await tabs();
    await userEvent.click(activity as HTMLElement);
    expect(timeline).toHaveTextContent("6 events");
    expect(activity).toHaveTextContent("1 tool call");
  });
});

describe("FE-113 the integrity alarm is outside the tabs", () => {
  it("raises the banner for a tool call whose chain link does not hold", async () => {
    view(chainBrokenAtToolCall());
    // The precondition the two assertions below rest on, stated where it can
    // fail: the fixture really does raise the alarm, and it does so on a page
    // that really does have the tab control on it.
    const [timeline] = await tabs();
    expect(timeline).toHaveAttribute("aria-selected", "true");
    const alarm = await screen.findByRole("alert");
    expect(alarm).toHaveTextContent("A chain link in this run does not hold");
  });

  it("renders the banner in neither panel", async () => {
    const { container } = view(chainBrokenAtToolCall());
    const alarm = await screen.findByRole("alert");
    for (const panel of Array.from(container.querySelectorAll('[role="tabpanel"]'))) {
      expect(panel.contains(alarm), "the alarm is inside a tab panel").toBe(false);
    }
    // And above the control, not merely beside it (doc 06 P3).
    const list = screen.getByRole("tablist");
    expect(
      alarm.compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("keeps the banner on screen with the activity tab open", async () => {
    view(chainBrokenAtToolCall());
    const [, activity] = await tabs();
    await userEvent.click(activity as HTMLElement);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "A chain link in this run does not hold",
    );
    expect(screen.getByRole("alert")).toBeVisible();
  });
});

describe("FE-113 the tab control is operable from the keyboard", () => {
  it("puts exactly one tab in the tab order (a roving tabindex)", async () => {
    view();
    const [timeline, activity] = await tabs();
    expect(timeline).toHaveAttribute("tabindex", "0");
    expect(activity).toHaveAttribute("tabindex", "-1");
  });

  it("moves selection and focus to the right on ArrowRight", async () => {
    view();
    const [timeline, activity] = await tabs();
    (timeline as HTMLElement).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(activity).toHaveFocus();
    expect(activity).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveTextContent("What this agent did");
  });

  it("moves back to the left on ArrowLeft", async () => {
    view();
    const [timeline, activity] = await tabs();
    (timeline as HTMLElement).focus();
    await userEvent.keyboard("{ArrowRight}{ArrowLeft}");
    expect(timeline).toHaveFocus();
    expect(timeline).toHaveAttribute("aria-selected", "true");
    expect(activity).toHaveAttribute("aria-selected", "false");
  });

  it("wraps at both ends rather than stopping dead", async () => {
    view();
    const [timeline, activity] = await tabs();
    (timeline as HTMLElement).focus();
    await userEvent.keyboard("{ArrowLeft}");
    expect(activity).toHaveFocus();
    await userEvent.keyboard("{ArrowRight}");
    expect(timeline).toHaveFocus();
  });

  it("goes to the first and last tab on Home and End", async () => {
    view();
    const [timeline, activity] = await tabs();
    (timeline as HTMLElement).focus();
    await userEvent.keyboard("{End}");
    expect(activity).toHaveFocus();
    await userEvent.keyboard("{Home}");
    expect(timeline).toHaveFocus();
  });

  it("reaches the selected tab by Tab, and does not trap the reader in the strip", async () => {
    view();
    const [timeline, activity] = await tabs();
    (timeline as HTMLElement).focus();
    await userEvent.tab();
    // The next Tab leaves the tablist entirely — that is what the roving
    // tabindex buys, and it is the behaviour a keyboard reader expects of a
    // tab control rather than of a toolbar.
    expect(timeline).not.toHaveFocus();
    expect(activity).not.toHaveFocus();
  });
});
