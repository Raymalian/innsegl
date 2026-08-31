// SPDX-License-Identifier: Apache-2.0

/*
 * FE-012 — doc 07's own row, verbatim:
 *
 *   | FE-012 | U | Reconciler-sourced timeline events | Labelled
 *     `source: reconciler` in run detail | FD §3.3 |
 *
 * and doc 06 §3.3's sentence it is drawn from:
 *
 *   "reconciler-sourced events are labelled `source: reconciler` so repaired
 *    history is visible as repaired, per P1."
 *
 * ── WHY THE ASSERTION IS SHAPED THE WAY IT IS ──────────────────────────────
 *
 * The label is the letter of the requirement. The sentence after it is the
 * point: *repaired history is visible as repaired*. A repair that renders
 * identically to an original event is a silent claim that the system never
 * lost anything — which is the opposite of what IP §6.10 and the reconciler's
 * drift work exist to surface.
 *
 * So this file does not assert that a string is somewhere in the markup. It
 * renders the SAME event twice, changing only `source`, and requires that what
 * a SIGHTED reader can read differs between the two. `visibleText` strips
 * everything a sighted reader cannot perceive — every class and style
 * attribute is gone because textContent never carried them, `sr-only` subtrees
 * are removed because they are announced and not shown, and every `<svg>` is
 * removed so that an icon cannot be the thing carrying the difference. What is
 * left is words on a screen.
 *
 * That shape is deliberate and it is this project's own history: a prior agent
 * proved two states differed by stripping `class` and `style` while leaving a
 * `data-*` attribute in place, which made the assertion impossible to fail.
 * Text content cannot hold a `data-*` attribute, so there is nothing here to
 * leave in by accident.
 */

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { strings } from "./strings";
import { Timeline } from "./Timeline";
import type { TimelineEvent } from "./types";

const NOW = new Date("2026-08-31T12:00:00.000Z");

/**
 * One `commit_recorded` event, varying only in who appended it. doc 02 §3
 * gives this event type two legal emitters — "mcp or reconciler | Phase C;
 * `source: reconciler` when repaired" — so it is the one type where the same
 * fact can arrive by either route, and therefore the only honest fixture for
 * this test.
 */
function commitRecorded(source: string): TimelineEvent {
  return event("commit_recorded", source);
}

/**
 * `commit_intent_expired` is the control. doc 02 §3 names the reconciler as
 * its ONLY emitter, so a reconciler-sourced one is the reconciler doing its
 * job and not the ledger recovering from a loss. It must carry the label and
 * must NOT be called repaired — otherwise "repaired" degrades into a synonym
 * for "reconciler", and the word stops distinguishing anything.
 */
function intentExpired(source: string): TimelineEvent {
  return event("commit_intent_expired", source);
}

function event(eventType: string, source: string): TimelineEvent {
  return {
    chain_position: 41,
    event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V1W",
    event_type: eventType,
    source,
    ts: "2026-08-31T11:52:00.000Z",
    event_hash: "sha256:9f2b1c8d7e6a5f4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a09",
    prev_event_hash: "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
    canonical: {
      commit_sha: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
      intent_event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V1V",
      rekor_entry_uuid: "24296fb24b8ad77a1c9f6d3e5b4a2f1908e7d6c5b4a39281706f5e4d3c2b1a09",
      rekor_log_index: 82914,
      repo: "innsegl",
      tree_hash: "9a8b7c6d5e4f302918273645afbecd0192837465",
    },
  };
}

/** What a sighted reader can actually read. */
function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderTimeline(events: readonly TimelineEvent[]): string {
  const { container } = render(<Timeline events={events} now={NOW} />);
  return visibleText(container);
}

describe("FE-012 reconciler-sourced timeline events", () => {
  it("labels a reconciler-sourced event `source: reconciler`", () => {
    expect(renderTimeline([commitRecorded("reconciler")])).toContain(
      "source: reconciler",
    );
  });

  it("labels an agent-sourced event `source: mcp`, and never as the reconciler", () => {
    const text = renderTimeline([commitRecorded("mcp")]);
    expect(text).toContain("source: mcp");
    expect(text).not.toContain("source: reconciler");
  });

  it("labels every source the ledger can carry, so no event is unattributed to a writer", () => {
    // doc 02 §2's source enum. An event whose writer is not stated reads as
    // having come from the agent, which for a reaper or system event is false.
    for (const source of ["mcp", "reconciler", "reaper", "system"]) {
      expect(renderTimeline([commitRecorded(source)])).toContain(`source: ${source}`);
    }
  });

  it("renders repaired history differently from original history, in words", () => {
    const original = renderTimeline([commitRecorded("mcp")]);
    const repaired = renderTimeline([commitRecorded("reconciler")]);
    expect(repaired).not.toEqual(original);
  });

  /*
   * The three assertions below exist because the one above is not enough, and
   * that was measured rather than reasoned: with `isRepairedHistory` mutated
   * to `return false` — every repair marker gone — the difference test above
   * still passed, because the two renders differ in the source line anyway.
   * A test that a mutation survives is a test that is not testing what its
   * name says. These pin the marker itself.
   */
  it("says in words that the repaired event is repaired history", () => {
    const repaired = renderTimeline([commitRecorded("reconciler")]);
    // The claim, quoted rather than imported: a catalogue edited to the empty
    // string would satisfy `toContain` against itself and assert nothing.
    expect(repaired).toContain("Repaired history");
    expect(strings.event.repairedDetail.length).toBeGreaterThan(40);
    expect(repaired).toContain(strings.event.repairedDetail);
  });

  it("does not call an original event repaired", () => {
    const original = renderTimeline([commitRecorded("mcp")]);
    expect(original).not.toContain("Repaired history");
    expect(original).not.toContain(strings.event.repairedDetail);
  });

  it("labels the reconciler's own events without calling them repairs", () => {
    // doc 02 §3: `commit_intent_expired` is emitted by the reconciler and by
    // nothing else. Labelled, yes. Repaired, no — nothing was lost.
    const own = renderTimeline([intentExpired("reconciler")]);
    expect(own).toContain("source: reconciler");
    expect(own).not.toContain("Repaired history");
  });
});
