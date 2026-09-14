// SPDX-License-Identifier: Apache-2.0

/*
 * FE-125 — doc 07's new row, verbatim:
 *
 *   U | The writer is shown where it is informative and kept where it is not |
 *     An event type doc 02 §3 permits more than one writer carries
 *     `source: <value>` on the rail; a type with a single legal writer carries
 *     the same label inside the event's own evidence disclosure instead of on
 *     every row; a writer doc 02 §3 does not permit for that type is on the
 *     rail whatever the type; the repaired-history mark is unchanged and still
 *     visible without opening anything | FD §3.3, P1, P3
 *
 * ── THE RULE, AND WHY IT IS NOT "HIDE THE MCP ONE" ─────────────────────────
 *
 * doc 06 §3.3 asks for reconciler-sourced events to be "labelled `source:
 * reconciler` so repaired history is visible as repaired". FE-012 holds that,
 * and nothing here weakens it. What this adds is the observation that the same
 * label on every one of a thousand rows is what makes the exceptional one
 * unreadable — the eye cannot find the repair when every row carries a writer
 * and a sentence explaining who that writer is.
 *
 * The rule is therefore about INFORMATION, not about the value `mcp`:
 *
 *   doc 02 §3's "Emitted by" column gives eleven of the twelve event types
 *   exactly one legal writer. For those, `source:` restates the event type and
 *   tells a reader nothing they did not already have. `commit_recorded` is the
 *   one row with two — "mcp or reconciler ... `source: reconciler` when
 *   repaired" — and there the writer is a fact about the world.
 *
 * So: more than one legal writer, or a writer the type does not permit at all,
 * goes on the rail. Everything else keeps the label in the event's own evidence
 * disclosure, where it is still rendered, still the ledger's own enum value,
 * and one click from anyone auditing a specific event.
 *
 * `railText` below strips the body of any CLOSED `<details>`, which is what
 * makes the negative assertions mean something: `textContent` happily returns
 * the contents of a disclosure nobody has opened, so a test that did not strip
 * them would pass whether the label moved or not.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { strings } from "./strings";
import { Timeline } from "./Timeline";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

const NOW = new Date("2026-08-31T12:00:00.000Z");

function event(eventType: string, source: string): TimelineEvent {
  return {
    chain_position: 41,
    event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V1W",
    event_type: eventType,
    source,
    ts: "2026-08-31T11:52:00.000Z",
    event_hash: "sha256:9f2b1c8d7e6a5f4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a09",
    prev_event_hash:
      "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
    canonical: {
      commit_sha: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
      repo: "innsegl",
      rekor_log_index: 82914,
    },
  };
}

/** What a reader sees on the rail, before opening anything. */
function railText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  for (const details of Array.from(clone.querySelectorAll("details"))) {
    if (details.hasAttribute("open")) continue;
    for (const child of Array.from(details.children)) {
      if (child.tagName !== "SUMMARY") child.remove();
    }
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function rail(events: readonly TimelineEvent[]): string {
  const { container } = render(<Timeline events={events} now={NOW} />);
  return railText(container);
}

describe("FE-125 the ordinary writer is not repeated on every row", () => {
  it("keeps `source: mcp` off the rail for a type only the MCP can write", () => {
    // doc 02 §3 names the MCP as `run_registered`'s only emitter, so the label
    // restates the event type and the sentence explaining the MCP is the noise
    // this rule removes.
    const text = rail([event(EVENT_TYPES.runRegistered, "mcp")]);
    expect(text).toContain("Run registered");
    expect(text).not.toContain("source: mcp");
    expect(text).not.toContain(strings.event.writer.mcp);
  });

  it("keeps the reaper off the rail on the one event only the reaper writes", () => {
    const text = rail([event(EVENT_TYPES.runExpired, "reaper")]);
    expect(text).not.toContain("source: reaper");
  });

  it("still renders the label, one click away, in the event's own evidence", async () => {
    // P1: the evidence sits next to the claim. Moved, not dropped — and the
    // value is still the ledger's own, not a word this dashboard chose.
    const { container } = render(
      <Timeline events={[event(EVENT_TYPES.runRegistered, "mcp")]} now={NOW} />,
    );
    expect(railText(container)).not.toContain("source: mcp");
    await userEvent.click(container.querySelector("summary") as HTMLElement);
    expect(screen.getByText("source: mcp")).toBeInTheDocument();
    expect(screen.getByText(strings.event.writer.mcp)).toBeInTheDocument();
  });
});

describe("FE-125 the writer stays on the rail where it is a fact", () => {
  it("shows it on the one event type doc 02 §3 gives two legal writers", () => {
    expect(rail([event(EVENT_TYPES.commitRecorded, "mcp")])).toContain("source: mcp");
    expect(rail([event(EVENT_TYPES.commitRecorded, "reconciler")])).toContain(
      "source: reconciler",
    );
  });

  it("keeps repaired history visible as repaired, without opening anything", () => {
    const text = rail([event(EVENT_TYPES.commitRecorded, "reconciler")]);
    expect(text).toContain("source: reconciler");
    expect(text).toContain("Repaired history");
    expect(text).toContain(strings.event.repairedDetail);
  });

  it("does not call an original commit repaired", () => {
    expect(rail([event(EVENT_TYPES.commitRecorded, "mcp")])).not.toContain(
      "Repaired history",
    );
  });

  it("shows a writer the event type does not permit, whatever the type", () => {
    // doc 02 §3 gives `run_registered` one emitter and it is not the
    // reconciler. A value outside that column is the ledger saying something
    // the schema does not sanction, and doc 06 P2 forbids rendering it as the
    // ordinary case.
    expect(rail([event(EVENT_TYPES.runRegistered, "reconciler")])).toContain(
      "source: reconciler",
    );
    expect(rail([event(EVENT_TYPES.runRetired, "system")])).toContain("source: system");
    // Including a value outside doc 02 §2's enum entirely.
    expect(rail([event(EVENT_TYPES.runRegistered, "somebody-else")])).toContain(
      "source: somebody-else",
    );
  });

  it("marks an unexpected writer as unexpected, in words", () => {
    const text = rail([event(EVENT_TYPES.runRegistered, "reconciler")]);
    expect(text).toContain(strings.event.unexpectedWriter);
  });

  it("does not call the reconciler's own event a repair, or an unexpected writer", () => {
    // doc 02 §3 names the reconciler as `commit_intent_expired`'s ONLY emitter.
    // Expected, so no warning; single-emitter, so the label is in the evidence.
    const text = rail([event(EVENT_TYPES.commitIntentExpired, "reconciler")]);
    expect(text).not.toContain("Repaired history");
    expect(text).not.toContain(strings.event.unexpectedWriter);
    expect(text).not.toContain("source: reconciler");
  });
});
