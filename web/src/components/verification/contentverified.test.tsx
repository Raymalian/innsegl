// SPDX-License-Identifier: Apache-2.0

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { VerificationBadge } from "./VerificationBadge";
import { strings } from "./strings";

/**
 * FE-062 (proposed for doc 06's test list; doc 06 is not modified here) —
 * RM-124, #196.
 *
 * ── THE ANSWER THE PAGE COULD NOT GIVE ─────────────────────────────────────
 *
 * Both the proof API and this dashboard said "the commit's signature is not
 * PEM", which describes machinery and reads as an accusation. A reader could
 * not tell a rebased commit from a forged one — and every merge strategy
 * GitHub offers rewrites the commit object, so the rebased case is the
 * ORDINARY state of an agent's commit once it reaches a default branch.
 *
 * doc 06 §4.2, amended for ADR-0047 on 2026-09-10, adds a fourth badge:
 * `content verified` — the object was rewritten and its signature is gone, and
 * the change the commit makes is one a signed run recorded. It is deliberately
 * NOT `verified`: that would overstate, because the message, the parent and
 * the author belong to whoever merged it. And deliberately not `failed`: that
 * would accuse a genuine signature.
 */
afterEach(cleanup);

describe("FE-062 the fourth verdict", () => {
  it("renders with its own label, distinct from verified and failed", () => {
    render(<VerificationBadge verdict="content-verified" />);
    const label = strings.verdict["content-verified"].label;

    expect(screen.getByText(label)).toBeTruthy();
    expect(label).not.toBe(strings.verdict.verified.label);
    expect(label).not.toBe(strings.verdict.failed.label);
  });

  it("says what it does and does not prove, for a screen reader", () => {
    render(<VerificationBadge verdict="content-verified" />);
    const meaning = strings.verdict["content-verified"].meaning;

    // doc 06 §4.2: "the panel must say which claim it is making". A badge
    // whose spoken meaning did not distinguish the change from the commit
    // would be the overstatement the fourth badge exists to avoid.
    expect(meaning.toLowerCase()).toContain("change");
    expect(screen.getByText(meaning)).toBeTruthy();
  });

  it("carries its own data-verdict, so colour is never the only signal", () => {
    // doc 06 §6.4: colour + icon + label, never colour alone.
    const { container } = render(<VerificationBadge verdict="content-verified" />);
    const badge = container.querySelector('[data-verdict="content-verified"]');
    expect(badge).toBeTruthy();
  });
});
