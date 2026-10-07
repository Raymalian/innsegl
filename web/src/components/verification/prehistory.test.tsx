// SPDX-License-Identifier: Apache-2.0

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { VerificationBadge } from "./VerificationBadge";
import { strings } from "./strings";

/**
 * ADR-0073 — a commit signed before the deployment's trust history began.
 *
 * Its CA and its transparency log were lost before anything recorded them, so
 * nothing can prove it, and nothing in it was found wrong either. It is not a
 * pass and it is not a failure, and the badge must read as neither.
 */
afterEach(cleanup);

describe("the pre-history verdict", () => {
  it("renders with its own label, distinct from every other verdict", () => {
    render(<VerificationBadge verdict="pre-history" />);
    const label = strings.verdict["pre-history"].label;

    expect(screen.getByText(label)).toBeTruthy();
    for (const other of ["verified", "failed", "unavailable", "content-verified", "unattributed"] as const) {
      expect(label).not.toBe(strings.verdict[other].label);
    }
  });

  it("says it cannot be verified, for a screen reader", () => {
    render(<VerificationBadge verdict="pre-history" />);
    const meaning = strings.verdict["pre-history"].meaning;

    expect(meaning.toLowerCase()).toContain("signed before this deployment's trust history began");
    expect(meaning).toContain("cannot be verified");
    expect(screen.getByText(meaning)).toBeTruthy();
  });

  it("is never drawn with the verification mark or the verified tone", () => {
    const { container } = render(<VerificationBadge verdict="pre-history" />);
    const badge = container.querySelector('[data-verdict="pre-history"]');
    expect(badge).toBeTruthy();
    expect(container.querySelector('[data-icon="verification-mark"]')).toBeNull();
    expect(container.querySelector('[data-icon="content-mark"]')).toBeNull();
  });
});
