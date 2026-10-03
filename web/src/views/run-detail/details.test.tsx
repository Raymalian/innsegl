// SPDX-License-Identifier: Apache-2.0

/*
 * Each timeline node leads with plain facts and keeps its technical fields
 * behind one "Details" disclosure, a native <details> and so keyboard-operable.
 * A broken chain link is the exception: it stays on the surface, because a
 * condition doc 06 §4.5 raises must not hide inside a closed panel.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Timeline } from "./Timeline";
import { NOW, ledgerEvent } from "./fixtures";
import { strings } from "./strings";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

/** What a reader sees before opening anything. */
function surface(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) hidden.remove();
  for (const details of Array.from(clone.querySelectorAll("details"))) {
    if (details.hasAttribute("open")) continue;
    for (const child of Array.from(details.children)) {
      if (child.tagName !== "SUMMARY") child.remove();
    }
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderEvents(events: readonly TimelineEvent[]) {
  return render(<Timeline events={events} now={NOW} />);
}

const COMMIT = ledgerEvent(EVENT_TYPES.commitRecorded, 4);
const TOOL = ledgerEvent(EVENT_TYPES.toolCall, 3, {
  canonical: { tool_name: "edit_file", payload_digest: "sha256:aabb" },
});

describe("RM-332 a node's technical fields sit behind Details", () => {
  it("shows no hash, id or raw record before Details is opened", () => {
    const { container } = renderEvents([COMMIT]);
    const text = surface(container);
    expect(text).toContain(strings.event.commitRecorded);
    expect(text).toContain(strings.details.summary);
    for (const hidden of [
      strings.timeline.eventHash,
      strings.timeline.prevEventHash,
      strings.timeline.eventId,
      strings.canonical.heading,
      strings.detail.treeHash,
      strings.detail.rekorLogIndex,
    ]) {
      expect(text, hidden).not.toContain(hidden);
    }
    expect(text).not.toContain(COMMIT.event_hash);
  });

  it("has one Details disclosure per node, closed", () => {
    const { container } = renderEvents([TOOL, COMMIT]);
    const summaries = Array.from(container.querySelectorAll("summary")).filter(
      (s) => s.textContent === strings.details.summary,
    );
    expect(summaries).toHaveLength(2);
    for (const summary of summaries) {
      expect(summary.closest("details")).not.toHaveAttribute("open");
    }
  });

  it("keeps every fact: opening Details shows the hashes, link, raw record and digests", async () => {
    renderEvents([TOOL]);
    await userEvent.click(screen.getByText(strings.details.summary));
    expect(screen.getByText(strings.timeline.eventHash)).toBeVisible();
    expect(screen.getByText(strings.timeline.prevEventHash)).toBeVisible();
    expect(screen.getByText(strings.timeline.eventId)).toBeVisible();
    expect(screen.getByText(strings.chain.first)).toBeVisible();
    expect(screen.getByText(strings.canonical.heading)).toBeVisible();
    expect(screen.getByText(strings.toolCall.bodyNotStored)).toBeVisible();
  });

  it("is a native disclosure, so the keyboard operates it", () => {
    // jsdom does not model <summary> focus; the browser suite tabs to it.
    const { container } = renderEvents([COMMIT]);
    const summary = Array.from(container.querySelectorAll("summary")).find(
      (s) => s.textContent === strings.details.summary,
    );
    expect(summary?.parentElement?.tagName).toBe("DETAILS");
    expect(summary).not.toHaveAttribute("tabindex", "-1");
  });

  it("keeps a broken chain link on the surface", () => {
    const broken = ledgerEvent(EVENT_TYPES.toolCall, 4, { prev_event_hash: "sha256:wrong" });
    const { container } = renderEvents([ledgerEvent(EVENT_TYPES.runRegistered, 3), broken]);
    expect(surface(container)).toContain(strings.chain.broken);
  });

  it("says nothing of the chain on the surface when the link holds or cannot be checked", () => {
    const { container } = renderEvents([COMMIT]);
    const text = surface(container);
    expect(text).not.toContain(strings.chain.linked);
    expect(text).not.toContain(strings.chain.unchecked);
    expect(text).not.toContain(strings.chain.first);
  });
});
