// SPDX-License-Identifier: Apache-2.0

/*
 * FE-080 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Every run-detail timeline node shows its chain position, and what can
 *     be said about its link to the preceding event is stated rather than
 *     assumed | Position rendered on every node; a checkable link that holds
 *     reads as holding, a checkable link that does not is an integrity alert
 *     and raises the page banner, and a link that cannot be checked from this
 *     response says so | FD §3.3, P1, P2, §4.5
 *
 * ── WHY THE THIRD STATE IS THE POINT ───────────────────────────────────────
 *
 * `internal/api`'s timelineSQL is `WHERE run_id = $1 ORDER BY chain_position`,
 * so a run's events are not adjacent in the ledger: every other run's events
 * sit between them, and `prev_event_hash` usually names an event this response
 * does not contain. A view that rendered a tick beside every node would be
 * asserting a hash chain nobody followed — doc 06 P1 in reverse. A view that
 * rendered a break would be crying wolf on the component whose whole job is to
 * be believed (P3).
 *
 * So the honest majority case is "not checkable here", and this test exists to
 * stop it quietly becoming either of the other two.
 */

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Timeline } from "./Timeline";
import { chainLinkAt } from "./events";
import { NOW, healthyTimeline, ledgerEvent } from "./fixtures";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderTimeline(events: readonly TimelineEvent[]) {
  const { container } = render(<Timeline events={events} now={NOW} />);
  return { container, text: visibleText(container) };
}

describe("FE-080 chain position", () => {
  it("shows the chain position of every node, exactly as the ledger holds it", () => {
    const events = healthyTimeline();
    const { text } = renderTimeline(events);
    for (const event of events) {
      expect(text).toContain(`Chain position ${event.chain_position}`);
    }
  });

  it("shows a position the ledger actually returned, not the index in the list", () => {
    // A run's events are sparse in the chain. Rendering 1, 2, 3 down the side
    // would be a number the reader cannot check against anything.
    const events = [
      ledgerEvent(EVENT_TYPES.runRegistered, 7),
      ledgerEvent(EVENT_TYPES.runRetired, 214),
    ];
    const { text } = renderTimeline(events);
    expect(text).toContain("Chain position 7");
    expect(text).toContain("Chain position 214");
    expect(text).not.toContain("Chain position 0");
    expect(text).not.toContain("Chain position 1 ");
  });
});

describe("FE-080 what can be said about a chain link", () => {
  const linked: readonly TimelineEvent[] = [
    ledgerEvent(EVENT_TYPES.runRegistered, 1),
    ledgerEvent(EVENT_TYPES.runRetired, 2),
  ];

  it("calls consecutive positions with matching hashes linked", () => {
    expect(chainLinkAt(linked, 1)).toEqual("linked");
    expect(renderTimeline(linked).text).toContain("Chain link holds");
  });

  it("refuses to call a non-consecutive pair either linked or broken", () => {
    const sparse: readonly TimelineEvent[] = [
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.runRetired, 9),
    ];
    expect(chainLinkAt(sparse, 1)).toEqual("unchecked");
    const { text } = renderTimeline(sparse);
    expect(text).toContain("Chain link not checkable here");
    // The claim it must never make about a pair it did not check.
    expect(text).not.toContain("Chain link holds");
  });

  it("calls a consecutive pair whose hashes disagree broken, and says so loudly", () => {
    const broken: readonly TimelineEvent[] = [
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.runRetired, 2, {
        prev_event_hash:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      }),
    ];
    expect(chainLinkAt(broken, 1)).toEqual("broken");
    const { container, text } = renderTimeline(broken);
    expect(text).toContain("Chain link broken");
    // doc 06 §6.4: never colour alone. The node carries an icon beside the
    // words, and the words are what this asserts.
    expect(container.querySelectorAll("[data-icon]").length).toBeGreaterThan(0);
  });

  it("says of the first event that there is nothing here to link it to", () => {
    expect(chainLinkAt(linked, 0)).toEqual("first");
    expect(renderTimeline(linked).text).toContain("First event in this response");
  });

  it("puts the two hashes on the page, so the link is checkable by hand", () => {
    const { text } = renderTimeline(linked);
    expect(text).toContain(linked[1]?.event_hash.slice(0, 12) ?? "");
    expect(text).toContain(linked[1]?.prev_event_hash.slice(0, 12) ?? "");
  });
});
