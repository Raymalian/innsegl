// SPDX-License-Identifier: Apache-2.0

/*
 * FE-122 — doc 07's new row, verbatim:
 *
 *   U | Run detail's facts read as one strip, and the identity sits under the
 *     heading | Agent, task, tool calls and commits render as one bordered
 *     strip of labelled columns; the uppercase field label is one class string
 *     shared with the runs view's filter labels; the full SPIFFE ID sits
 *     directly under the heading in mono with no label of its own;
 *     registered/ended instants, latest chain position, repositories and the
 *     whole credential expiry history are all still rendered |
 *     FD §3.3, §5.2, §5.4
 *
 * ── THE HALF THAT IS EASY TO LOSE ──────────────────────────────────────────
 *
 * The strip is a presentation change and presentation changes drop facts. doc
 * 06 §3.3 names five things the header carries and the credential expiry
 * history is the one with no column of its own, so it is the one a four-column
 * strip quietly leaves behind. Half of this file is therefore not about the
 * strip at all: it is the same list of fields FE-082 already asserts, asserted
 * again after the treatment changed, because a test that only checked the new
 * shape would go green on a header that had lost half its content.
 *
 * The label assertion is rendered rather than read off the source, for the
 * reason FE-121 gives about the two tables: an import is easy to satisfy and
 * easy to defeat — a view can import the shared string and append a class of
 * its own. Comparing the rendered attribute is the assertion that holds.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RunsFilterForm } from "../runs/RunsFilterForm";
import { emptyRunsFilters } from "../../app/routes";
import { RunHeader } from "./RunHeader";
import { ELLIPSIS } from "../../components/common/identifier";
import { NOW, SPIFFE_ID, healthyTimeline, ledgerEvent, runDetail } from "./fixtures";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderHeader(
  events: readonly TimelineEvent[] = healthyTimeline(),
  status = "retired",
): { text: string; container: HTMLElement } {
  const detail = runDetail(events, status);
  const { container } = render(<RunHeader run={detail} events={events} now={NOW} />);
  return { text: visibleText(container), container };
}

/** The strip's own cells: a label and the value under it. */
function facts(container: HTMLElement): Record<string, string> {
  const found: Record<string, string> = {};
  for (const cell of Array.from(container.querySelectorAll("[data-fact]"))) {
    const label = cell.querySelector("dt");
    const value = cell.querySelector("dd");
    found[(label?.textContent ?? "").trim()] = (value?.textContent ?? "")
      .replace(/\s+/g, " ")
      .trim();
  }
  return found;
}

describe("FE-122 the facts are one strip", () => {
  it("carries agent, task, tool calls and commits as four labelled columns", () => {
    const { container } = renderHeader();
    const strip = facts(container);
    expect(strip["Agent"]).toEqual("fix-ci");
    expect(strip["Task"]).toEqual("JIRA-118");
    // healthyTimeline() makes one tool call, and doc 06 §6.2 wants it exact.
    expect(strip["Tool calls"]).toEqual("1");
    expect(strip["Commits"]).toEqual("1");
  });

  it("counts the tool calls the ledger actually returned, not a fixed number", () => {
    const events = [
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.toolCall, 2),
      ledgerEvent(EVENT_TYPES.toolCall, 3),
      ledgerEvent(EVENT_TYPES.toolCall, 4),
    ];
    expect(facts(renderHeader(events, "active").container)["Tool calls"]).toEqual("3");
  });

  it("sits every cell in ONE strip, so the four cannot be styled apart", () => {
    const { container } = renderHeader();
    const strips = new Set(
      Array.from(container.querySelectorAll("[data-fact]")).map(
        (cell) => cell.parentElement,
      ),
    );
    expect(strips.size).toEqual(1);
    const [strip] = [...strips];
    // A strip, not a loose grid: it has a ground and an outline of its own.
    expect((strip as HTMLElement).className).toMatch(/\bbg-surface\b/);
    expect((strip as HTMLElement).className).toMatch(/\bborder-line\b/);
  });

  it("draws its field label with the same class string the runs view uses", () => {
    // FE-121's argument, applied to labels: two views that reached for the same
    // tokens independently drift, and a reader two clicks apart is looking at
    // two products.
    const header = renderHeader();
    const fromHeader = (
      header.container.querySelector("[data-fact] dt") as HTMLElement
    ).className;
    const runs = render(<RunsFilterForm filters={emptyRunsFilters()} />);
    const fromRuns = (runs.container.querySelector("label") as HTMLElement).className;
    expect(fromRuns).toEqual(fromHeader);
  });
});

describe("FE-122 the identity sits under the heading", () => {
  it("renders the SPIFFE ID in full, in mono, with no label of its own", () => {
    const { container, text } = renderHeader();
    expect(text).toContain(SPIFFE_ID);
    expect(text).not.toContain(ELLIPSIS);
    // doc 06 §3.3 asks for the identity, not for a form field. The word that
    // used to label it is gone; the value is what a reader reads.
    expect(text).not.toContain("Agent identity");
    const identity = container.querySelector("[data-run-identity]");
    expect(identity, "the identity is not a block of its own").not.toBeNull();
    // And it comes before the strip, which is what "under the heading" means.
    const strip = container.querySelector("[data-fact]");
    expect(
      (identity as HTMLElement).compareDocumentPosition(strip as HTMLElement) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("keeps the identity copyable and hands the full value to assistive tech", () => {
    renderHeader();
    expect(
      screen.getByRole("button", { name: `SPIFFE ID: ${SPIFFE_ID}. Copy` }),
    ).toBeInTheDocument();
  });
});

describe("FE-122 the strip drops nothing doc 06 §3.3 names", () => {
  it("still labels the end of the run with the event that ended it", () => {
    expect(renderHeader().text).toContain("Retired");
  });

  it("still distinguishes a withdrawn run from a retired one", () => {
    const events = [
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.runExpired, 2, { source: "reaper" }),
    ];
    const { text } = renderHeader(events, "lapsed");
    // #256: a withdrawal is not an ending, so it is no longer filed beside a
    // retirement — it has its own cell, under the reaper's own verb.
    expect(text).toContain("Credential withdrawn");
    expect(text).not.toContain("Retired");
  });

  it("still says in a sentence that a running run has not ended", () => {
    const { text } = renderHeader([ledgerEvent(EVENT_TYPES.runRegistered, 1)], "active");
    expect(text).toContain("This run has no retirement event in the ledger.");
  });

  it("still lists the credential expiry history, every issue of it", () => {
    const events = [
      ...healthyTimeline(),
      ledgerEvent(EVENT_TYPES.credentialIssued, 7, {
        canonical: {
          audience: "innsegl.dev",
          credential_expiry: "2026-08-31T13:12:00.000Z",
        },
      }),
    ];
    const { text } = renderHeader(events);
    expect(text).toContain("Credential expiry history");
    expect(text).toContain("in 42 min");
    expect(text).toContain("in 1 h 12 min");
  });

  it("still says so when no credential was ever issued", () => {
    const { text } = renderHeader([ledgerEvent(EVENT_TYPES.runRegistered, 1)], "active");
    expect(text).toContain("No credential was issued to this run.");
  });

  it("still carries the registered instant, the chain position and the repos", () => {
    const { text } = renderHeader();
    expect(text).toContain("Registered");
    expect(text).toContain("Latest chain position");
    expect(text).toContain("46");
    expect(text).toContain("innsegl");
  });
});
