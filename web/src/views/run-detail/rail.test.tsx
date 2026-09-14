// SPDX-License-Identifier: Apache-2.0

/*
 * FE-123, FE-124 and FE-126 — doc 07's new rows.
 *
 *   FE-123 | U | The timeline is a rail, and only an exception is boxed |
 *     Every node draws a marker in a shared rail gutter with its content beside
 *     it, and the connector runs between markers and stops at the last; an
 *     ordinary event carries no panel, no ground and no border; a degraded
 *     event takes the amber band, an integrity alert the red one, and a
 *     recorded commit its own bordered card | FD §3.3, §5.3, §5.4, P3
 *
 *   FE-124 | U | A folded run of tool calls is one disclosure that says what it
 *     folds | ... | FD §3.3, §6.2
 *
 *   FE-126 | U | A run that expired reads as degraded, not as an ordinary
 *     ending | ... | FD §3.2, §5.3, P2
 *
 * ── WHY "NOT BOXED" IS THE ASSERTION WITH TEETH ────────────────────────────
 *
 * doc 06 P3 designs the alarm first, and everything that follows from that is
 * about what the CALM state costs. A timeline that draws every event as a panel
 * on its own ground spends the whole of its visual vocabulary on the ordinary
 * case, and then has nothing left with which to say "this one is different" —
 * the amber band and the red fill land on a page where every row already has a
 * border, and the eye has nowhere to go.
 *
 * So the falsifiable half of FE-123 is the negative one: an ordinary node's
 * content carries no ground and no border at all. It is asserted from the
 * rendered class attribute rather than from a data attribute, because this
 * project has already shipped one assertion that could not fail — a test that
 * stripped `class` and `style` from markup while leaving a `data-*` in place.
 * The class attribute is the thing that actually decides what is on screen.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Timeline } from "./Timeline";
import { severityOf, toolCallRunThreshold } from "./events";
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

/** The rows of the rail: one `<li>` per node or per fold, top level only. */
function rows(container: HTMLElement): HTMLElement[] {
  const list = container.querySelector("ol");
  return Array.from(list?.children ?? []).filter(
    (child): child is HTMLElement => child.tagName === "LI",
  );
}

const gutterOf = (row: HTMLElement) =>
  row.querySelector("[data-rail-gutter]") as HTMLElement | null;
const bodyOf = (row: HTMLElement) =>
  row.querySelector("[data-node-body]") as HTMLElement | null;

const ordinary = ledgerEvent(EVENT_TYPES.runRegistered, 1, {
  canonical: { agent_type: "fix-ci", task_ref: "JIRA-118" },
});
const intentExpired = ledgerEvent(EVENT_TYPES.commitIntentExpired, 5, {
  source: "reconciler",
  canonical: { intent_event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V04" },
});
const drift = ledgerEvent(EVENT_TYPES.ledgerDriftDetected, 5, {
  source: "reconciler",
  canonical: { reason: "no Rekor entry for a recorded commit" },
});
const commitRecorded = ledgerEvent(EVENT_TYPES.commitRecorded, 5, {
  canonical: {
    commit_sha: "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291",
    repo: "innsegl",
    rekor_log_index: 82914,
  },
});
const runExpired = ledgerEvent(EVENT_TYPES.runExpired, 9, { source: "reaper" });

describe("FE-123 every node sits on a rail", () => {
  it("gives each row a marker in a gutter and its content beside it", () => {
    const { container } = renderTimeline(healthyTimeline());
    const list = rows(container);
    expect(list.length).toBeGreaterThan(1);
    for (const row of list) {
      const gutter = gutterOf(row);
      expect(gutter, "a row with no rail gutter").not.toBeNull();
      // The marker is an icon, so the rail reads without colour (doc 06 §6.4).
      expect(gutter?.querySelector("[data-icon]")).not.toBeNull();
      expect(bodyOf(row), "a row with no content beside the rail").not.toBeNull();
      // Gutter first, content second: the rail is a column, not a prefix.
      expect(
        (gutterOf(row) as HTMLElement).compareDocumentPosition(
          bodyOf(row) as HTMLElement,
        ) & Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }
  });

  it("connects the markers, and stops the connector at the last one", () => {
    const { container } = renderTimeline(healthyTimeline());
    const list = rows(container);
    const connected = list.filter((row) => row.querySelector("[data-rail-line]") !== null);
    // A line after the last marker would draw the chain continuing past the
    // last event this response holds, which is a claim about events not here.
    expect(connected).toHaveLength(list.length - 1);
    expect(list[list.length - 1]?.querySelector("[data-rail-line]")).toBeNull();
  });

  it("draws one rail for one event too, without a connector", () => {
    const { container } = renderTimeline([ordinary]);
    const list = rows(container);
    expect(list).toHaveLength(1);
    expect(gutterOf(list[0] as HTMLElement)).not.toBeNull();
    expect(list[0]?.querySelector("[data-rail-line]")).toBeNull();
  });
});

describe("FE-123 only an exception is boxed", () => {
  it("leaves an ordinary event with no ground and no border at all", () => {
    const { container } = renderTimeline([ordinary]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).not.toMatch(/\bbg-/);
    expect(body.className).not.toMatch(/\bborder/);
  });

  it("gives a degraded event the amber band", () => {
    const { container } = renderTimeline([intentExpired]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).toMatch(/\bbg-degraded-surface\b/);
  });

  it("gives an integrity alert the red one, and never the amber", () => {
    const { container } = renderTimeline([drift]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).toMatch(/\bbg-integrity-alert-surface\b/);
    expect(body.className).not.toMatch(/\bbg-degraded-surface\b/);
  });

  it("gives a recorded commit a card of its own, neutral and outlined", () => {
    // doc 06 §5.3: a commit the ledger holds is not a verification, so the card
    // is neutral. The green lives behind "Verify this commit" and nowhere else.
    const { container } = renderTimeline([commitRecorded]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).toMatch(/\bbg-surface\b/);
    expect(body.className).toMatch(/\bborder-line\b/);
    expect(body.className).not.toMatch(/\bbg-degraded-surface\b/);
    expect(body.className).not.toMatch(/\bbg-integrity-alert-surface\b/);
  });

  it("renders the four treatments as four different class strings", () => {
    const drawn = [ordinary, intentExpired, drift, commitRecorded].map((event) => {
      const { container } = renderTimeline([event]);
      return (bodyOf(rows(container)[0] as HTMLElement) as HTMLElement).className;
    });
    expect(new Set(drawn).size).toEqual(4);
  });
});

describe("FE-124 a run of tool calls folds into one disclosure", () => {
  const many = (n: number): readonly TimelineEvent[] => [
    ledgerEvent(EVENT_TYPES.runRegistered, 1),
    ...Array.from({ length: n }, (_, i) =>
      ledgerEvent(EVENT_TYPES.toolCall, 2 + i, {
        canonical: { tool_name: "edit_file" },
      }),
    ),
    ledgerEvent(EVENT_TYPES.runRetired, 2 + n),
  ];

  /** The fold's own disclosure.
   *
   * Found as the row that is not an event — every node carries its own
   * chain-link disclosure, so `querySelector("details")` would return the FIRST
   * node's evidence panel and the assertions below would be about the wrong
   * element entirely. The fold row is the one with no `data-event-type` on it. */
  function foldOf(container: HTMLElement): HTMLDetailsElement {
    const row = rows(container).find(
      (r) => bodyOf(r)?.hasAttribute("data-event-type") === false,
    );
    expect(row, "no folded row in this timeline").toBeDefined();
    return row?.querySelector("details") as HTMLDetailsElement;
  }

  it("folds closed, and says how many calls and which positions it covers", () => {
    const { container } = renderTimeline(many(toolCallRunThreshold + 2));
    const fold = foldOf(container);
    expect(fold, "no disclosure for the folded run").not.toBeNull();
    expect(fold.open, "the fold starts open, so the reader arrives at noise").toBe(
      false,
    );
    const summary = fold.querySelector("summary") as HTMLElement;
    const said = (summary.textContent ?? "").replace(/\s+/g, " ");
    expect(said).toContain(`${toolCallRunThreshold + 2} tool calls`);
    // The first and last chain position it covers, exactly (doc 06 §6.2).
    expect(said).toContain("2");
    expect(said).toContain(String(toolCallRunThreshold + 3));
  });

  it("keeps the fold on the rail like any other row", () => {
    const { container } = renderTimeline(many(toolCallRunThreshold + 2));
    const fold = rows(container).find(
      (row) => bodyOf(row)?.hasAttribute("data-event-type") === false,
    );
    expect(fold, "the fold is not a row of the rail").toBeDefined();
    expect(gutterOf(fold as HTMLElement)).not.toBeNull();
  });

  it("reveals every call, each with its own chain position, when opened", async () => {
    const n = toolCallRunThreshold + 2;
    const { container } = renderTimeline(many(n));
    await userEvent.click(foldOf(container).querySelector("summary") as HTMLElement);
    for (let position = 2; position < 2 + n; position += 1) {
      expect(screen.getByText(`Chain position ${position}`)).toBeInTheDocument();
    }
  });
});

describe("FE-126 a run that expired reads as degraded", () => {
  it("calls run_expired degraded rather than neutral", () => {
    // doc 06 §3.2: expired "means an agent died unretired". A credential that
    // ran out while the agent was still working is a degradation of the
    // guarantee, which doc 06 §5.3 gives amber — never green, never red.
    expect(severityOf(runExpired)).toEqual("degraded");
  });

  it("bands it amber and says in words what happened", () => {
    const { container, text } = renderTimeline([runExpired]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).toMatch(/\bbg-degraded-surface\b/);
    expect(text).toContain("Credential ran out");
  });

  it("keeps the dashed outline that tells expired from retired without a hue", () => {
    const { container } = renderTimeline([runExpired]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).toContain("--innsegl-border-style-status-expired");
  });

  it("is not an integrity alert, and not the words an expired intent uses", () => {
    const { text } = renderTimeline([runExpired]);
    expect(text).not.toContain("Integrity alert");
    // P2: two different degradations are two different facts. An expired
    // commit intent is a promise nobody kept; an expired run is an identity
    // that ran out underneath an agent that was still working.
    expect(text).not.toContain("Ended without completing");
  });

  it("still leaves a retired run calm", () => {
    const { container, text } = renderTimeline([
      ledgerEvent(EVENT_TYPES.runRetired, 9),
    ]);
    const body = bodyOf(rows(container)[0] as HTMLElement) as HTMLElement;
    expect(body.className).not.toMatch(/\bbg-/);
    expect(text).not.toContain("Credential ran out");
  });
});
