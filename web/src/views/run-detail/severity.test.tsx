// SPDX-License-Identifier: Apache-2.0

/*
 * FE-043 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | A run-detail timeline node whose event is a failure never renders as
 *     merely informational, and a failure is never collapsed into a
 *     degradation | The two alert event types of doc 02 §3 carry the words
 *     "Integrity alert" and an icon and raise the page-level banner;
 *     `commit_intent_expired` carries its own distinct words and does not;
 *     an ordinary event carries neither | FD §8 anti-patterns 2 and 4, P2, P3,
 *     §4.5
 *
 * doc 06 §8's anti-pattern 2 is "any collapse of failed and unavailable into
 * one visual state", and this view has a third thing to keep apart from both:
 * an ordinary event. Three states, so the test asserts all three and asserts
 * each is NOT the other two — a test that only checked the alarm would pass a
 * view that raised the alarm on everything.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RunDetailView } from "./RunDetailView";
import { Timeline } from "./Timeline";
import { NOW, healthyTimeline, ledgerEvent, runDetail } from "./fixtures";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderNode(event: TimelineEvent) {
  const { container } = render(<Timeline events={[event]} now={NOW} />);
  return { container, text: visibleText(container) };
}

const drift = ledgerEvent(EVENT_TYPES.ledgerDriftDetected, 5, {
  source: "reconciler",
  canonical: {
    reason: "no Rekor entry for a recorded commit",
    subject_event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V04",
  },
});

const unattributed = ledgerEvent(EVENT_TYPES.unattributedSignatureDetected, 5, {
  source: "reconciler",
  canonical: {
    certificate_identity: "spiffe://innsegl.dev/agent/unknown/task-0/run-0",
    rekor_entry_uuid: "24296fb24b8ad77a1c9f6d3e5b4a2f1908e7d6c5b4a39281706f5e4d3c2b1a09",
    rekor_log_index: 91002,
  },
});

const intentExpired = ledgerEvent(EVENT_TYPES.commitIntentExpired, 5, {
  source: "reconciler",
  canonical: { intent_event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V04" },
});

const ordinary = ledgerEvent(EVENT_TYPES.toolCall, 5, {
  canonical: { tool_name: "edit_file" },
});

describe("FE-043 a failure never renders as merely informational", () => {
  it("calls ledger drift an integrity alert, in words and with an icon", () => {
    const { text, container } = renderNode(drift);
    expect(text).toContain("Integrity alert");
    expect(container.querySelectorAll("[data-icon]").length).toBeGreaterThan(0);
  });

  it("calls an unattributed signature an integrity alert too", () => {
    expect(renderNode(unattributed).text).toContain("Integrity alert");
  });

  it("does not call an expired commit intent an integrity alert", () => {
    // Nothing was violated: a promised commit never arrived. doc 06 §5.3 gives
    // that amber, and P2 forbids it being reported as the stronger claim.
    const { text } = renderNode(intentExpired);
    expect(text).toContain("Ended without completing");
    expect(text).not.toContain("Integrity alert");
  });

  it("leaves an ordinary event calm, with neither marking", () => {
    const { text } = renderNode(ordinary);
    expect(text).not.toContain("Integrity alert");
    expect(text).not.toContain("Ended without completing");
  });

  it("gives the three states three different renders, in words alone", () => {
    const renders = [drift, intentExpired, ordinary].map(
      (event) => renderNode(event).text,
    );
    expect(new Set(renders).size).toEqual(3);
  });
});

describe("FE-043 the page-level banner", () => {
  const view = (timeline: readonly TimelineEvent[]) =>
    render(
      <RunDetailView
        route={{ view: "run", runId: "run-7f3a2c" }}
        fetchRun={async () => runDetail(timeline)}
        now={NOW}
      />,
    );

  it("raises a banner for drift, linking to the event that established it", async () => {
    view([...healthyTimeline(), drift]);
    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent("Ledger drift detected in this run");
    expect(screen.getByRole("link", { name: "Go to the event" })).toHaveAttribute(
      "href",
      "#run-event-5",
    );
  });

  it("raises a banner when a checkable chain link does not hold", async () => {
    view([
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.runRetired, 2, {
        prev_event_hash:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      }),
    ]);
    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent("A chain link in this run does not hold");
  });

  it("raises nothing at all on a healthy run — the calm state is quiet", async () => {
    view(healthyTimeline());
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
