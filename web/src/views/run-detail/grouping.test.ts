// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { groupTimeline, toolCallRunThreshold } from "./events";
import type { TimelineEvent } from "./types";

function ev(position: number, type: string): TimelineEvent {
  return {
    chain_position: position,
    event_id: `e${position}`,
    event_type: type,
    source: "mcp",
    ts: "2026-09-10T12:00:00.000Z",
  } as unknown as TimelineEvent;
}

describe("groupTimeline", () => {
  it("folds a long run of tool calls into one row", () => {
    const events = [
      ev(1, "run_registered"),
      ...Array.from({ length: 200 }, (_, n) => ev(2 + n, "tool_call")),
      ev(202, "run_retired"),
    ];
    const rows = groupTimeline(events);
    expect(rows).toHaveLength(3);
    expect(rows[0]?.kind).toBe("event");
    expect(rows[1]?.kind).toBe("tool-calls");
    expect(rows[2]?.kind).toBe("event");
    if (rows[1]?.kind === "tool-calls") expect(rows[1].events).toHaveLength(200);
  });

  it("never folds across another event, because the order is the evidence", () => {
    const events = [
      ...Array.from({ length: 10 }, (_, n) => ev(1 + n, "tool_call")),
      ev(11, "commit_recorded"),
      ...Array.from({ length: 10 }, (_, n) => ev(12 + n, "tool_call")),
    ];
    const rows = groupTimeline(events);
    expect(rows.map((r) => r.kind)).toEqual(["tool-calls", "event", "tool-calls"]);
  });

  it("leaves a short run as ordinary nodes, because a disclosure would cost a click and save nothing", () => {
    const events = Array.from({ length: toolCallRunThreshold - 1 }, (_, n) =>
      ev(1 + n, "tool_call"),
    );
    const rows = groupTimeline(events);
    expect(rows).toHaveLength(toolCallRunThreshold - 1);
    expect(rows.every((r) => r.kind === "event")).toBe(true);
  });

  it("keeps every event exactly once and in the ledger's order", () => {
    const events = [
      ev(1, "run_registered"),
      ...Array.from({ length: 30 }, (_, n) => ev(2 + n, "tool_call")),
      ev(32, "commit_recorded"),
      ev(33, "run_retired"),
    ];
    const flat = groupTimeline(events).flatMap((r) =>
      r.kind === "event" ? [r.event] : [...r.events],
    );
    expect(flat.map((e) => e.chain_position)).toEqual(events.map((e) => e.chain_position));
  });

  it("returns nothing for no events", () => {
    expect(groupTimeline([])).toHaveLength(0);
  });
});
