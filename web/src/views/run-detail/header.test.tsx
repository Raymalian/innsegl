// SPDX-License-Identifier: Apache-2.0

/*
 * FE-082 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Run-detail header carries every field doc 06 §3.3 names | Full SPIFFE
 *     ID, untruncated and copyable; agent type; task ref; registered
 *     timestamp; the end of the run labelled with the event that ended it, or
 *     a sentence saying there is none; the whole credential expiry history |
 *     FD §3.3, P4, P2, §8 anti-pattern 6
 *
 * The "full" in "full SPIFFE ID" is the assertion that matters. `IdentifierChip`
 * middle-truncates by default, which is right in a table and is doc 06 §8's
 * anti-pattern 6 here — "identifiers ... truncated so the trust domain is
 * lost". A test that only asked whether a chip was present would pass over an
 * abbreviated one.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RunHeader } from "./RunHeader";
import { ELLIPSIS } from "../../components/common/identifier";
import { EVENT_TYPES } from "./types";
import { NOW, SPIFFE_ID, healthyTimeline, ledgerEvent, runDetail } from "./fixtures";

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderHeader(
  events = healthyTimeline(),
  status = "retired",
): { text: string; container: HTMLElement } {
  const detail = runDetail(events, status);
  const { container } = render(
    <RunHeader run={detail} events={events} now={NOW} />,
  );
  return { text: visibleText(container), container };
}

describe("FE-082 the run-detail header", () => {
  it("renders the SPIFFE ID in full, with no ellipsis anywhere in it", () => {
    const { text } = renderHeader();
    expect(text).toContain(SPIFFE_ID);
    expect(text).not.toContain(ELLIPSIS);
  });

  it("keeps the identity copyable, and hands the full value to assistive tech", () => {
    renderHeader();
    // The chip's own contract (FE-008): the accessible name is the whole
    // value, whatever the glyphs on screen say.
    expect(
      screen.getByRole("button", { name: `SPIFFE ID: ${SPIFFE_ID}. Copy` }),
    ).toBeInTheDocument();
  });

  it("names the agent type and the task the run was started for", () => {
    const { text } = renderHeader();
    expect(text).toContain("fix-ci");
    expect(text).toContain("JIRA-118");
  });

  it("labels the end of the run with the event that ended it", () => {
    const { text } = renderHeader();
    expect(text).toContain("Retired");
  });

  it("distinguishes a run that expired from one that was retired", () => {
    // doc 06 §3.2: expired "means an agent died unretired", which is a
    // different fact and must not read as a tidy ending.
    const events = [
      ledgerEvent(EVENT_TYPES.runRegistered, 1),
      ledgerEvent(EVENT_TYPES.runExpired, 2, { source: "reaper" }),
    ];
    const { text } = renderHeader(events, "expired");
    expect(text).toContain("Expired");
    expect(text).not.toContain("Retired");
  });

  it("says in a sentence that a running run has not ended, rather than blanking", () => {
    const events = [ledgerEvent(EVENT_TYPES.runRegistered, 1)];
    const { text } = renderHeader(events, "active");
    expect(text).toContain("This run has no retirement or expiry event in the ledger.");
  });

  it("lists the credential expiry history, every issue of it", () => {
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
    // Two issues, so two expiries, each with its own instant. A view showing
    // only the newest would answer a different question.
    expect(text).toContain("in 42 min");
    expect(text).toContain("in 1 h 12 min");
  });

  it("says so when no credential was ever issued", () => {
    const events = [ledgerEvent(EVENT_TYPES.runRegistered, 1)];
    const { text } = renderHeader(events, "active");
    expect(text).toContain("No credential was issued to this run.");
  });
});
