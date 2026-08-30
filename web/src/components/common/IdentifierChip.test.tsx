// SPDX-License-Identifier: Apache-2.0

/*
 * FE-008 (doc 07, TC-FE) — identifier chip, rendered half.
 *
 *   "Mono, middle truncation preserves trust domain + last segment, copy
 *    works, full value accessible to AT"  — proves FD P4, §4.3
 *
 * doc 06 §4.3: "One component for SPIFFE IDs, SHAs, run IDs, Rekor indices:
 * monospace, middle-truncation preserving trust domain and final segment,
 * copy-on-click with confirmation, full value on hover/focus and in an
 * accessible tooltip." doc 06 §6.4: "Truncated identifiers expose their full
 * value to assistive tech."
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IdentifierChip } from "./IdentifierChip";

const SPIFFE =
  "spiffe://innsegl.dev/agent/fix-ci/run/01HQ8Z9K2MJT4V6XR3B7YN5PDC";
const SHA = "9f2c1a4e7b60d38f5c91ae02d746b8130fca5e29";

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The element carrying the visible, possibly-truncated glyphs. */
function visibleValue(container: HTMLElement): HTMLElement {
  const el = container.querySelector<HTMLElement>("[data-identifier-display]");
  if (el === null) throw new Error("no visible value element rendered");
  return el;
}

describe("FE-008 IdentifierChip", () => {
  it("renders the identifier in monospace (P4, §5.2)", () => {
    const { container } = render(
      <IdentifierChip kind="spiffe" value={SPIFFE} />,
    );
    expect(visibleValue(container).className).toMatch(/(^|\s)font-mono(\s|$)/);
  });

  it("truncates in the middle, keeping the trust domain and the final segment", () => {
    const { container } = render(
      <IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />,
    );
    const shown = visibleValue(container).textContent ?? "";
    expect(shown).not.toBe(SPIFFE);
    expect(shown.startsWith("spiffe://innsegl.dev")).toBe(true);
    expect(shown.endsWith("01HQ8Z9K2MJT4V6XR3B7YN5PDC")).toBe(true);
  });

  it("keeps both ends of a 40-character commit SHA", () => {
    const { container } = render(
      <IdentifierChip kind="sha" value={SHA} maxLength={16} />,
    );
    const shown = visibleValue(container).textContent ?? "";
    expect(shown).not.toBe(SHA);
    expect(SHA.startsWith(shown.split("…")[0]!)).toBe(true);
    expect(SHA.endsWith(shown.split("…")[1]!)).toBe(true);
  });

  it("hides the truncated glyphs from assistive technology", () => {
    const { container } = render(
      <IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />,
    );
    expect(visibleValue(container)).toHaveAttribute("aria-hidden", "true");
  });

  it("puts the FULL value in the control's accessible name", () => {
    render(<IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />);
    expect(screen.getByRole("button")).toHaveAccessibleName(
      new RegExp(escapeRegExp(SPIFFE)),
    );
  });

  it("names what kind of identifier it is, so the value is not bare (§6.1)", () => {
    render(<IdentifierChip kind="sha" value={SHA} maxLength={16} />);
    expect(screen.getByRole("button")).toHaveAccessibleName(/commit sha/i);
  });

  it("exposes the full value on hover and on keyboard focus (§4.3)", async () => {
    const user = userEvent.setup();
    render(<IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />);
    const button = screen.getByRole("button");

    expect(button).toHaveAttribute("title", SPIFFE);

    expect(screen.queryByRole("tooltip")).toBeNull();
    await user.tab();
    expect(button).toHaveFocus();
    expect(screen.getByRole("tooltip")).toHaveTextContent(SPIFFE);
  });

  it("copies the full value on click, never the truncated one", async () => {
    const user = userEvent.setup();
    render(<IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />);
    await user.click(screen.getByRole("button"));
    await expect(navigator.clipboard.readText()).resolves.toBe(SPIFFE);
  });

  it("confirms the copy in a live region (§4.3 'with confirmation')", async () => {
    const user = userEvent.setup();
    render(<IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />);
    await user.click(screen.getByRole("button"));
    expect(await screen.findByRole("status")).toHaveTextContent(/copied/i);
  });

  it("says the copy failed rather than claiming it worked (P2)", async () => {
    const user = userEvent.setup();
    render(<IdentifierChip kind="spiffe" value={SPIFFE} maxLength={40} />);
    const failing = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockRejectedValue(new Error("denied"));
    await user.click(screen.getByRole("button"));
    expect(await screen.findByRole("status")).toHaveTextContent(
      /couldn't copy/i,
    );
    failing.mockRestore();
  });

  it("links to the canonical view when one is given (P4)", () => {
    render(
      <IdentifierChip kind="spiffe" value={SPIFFE} href="/runs/01HQ8Z9K" />,
    );
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/runs/01HQ8Z9K");
    expect(link).toHaveAccessibleName(new RegExp(escapeRegExp(SPIFFE)));
  });

  it("carries no mutating affordance (P6)", () => {
    render(<IdentifierChip kind="spiffe" value={SPIFFE} />);
    for (const control of screen.getAllByRole("button")) {
      expect(control).toHaveAccessibleName(/copy/i);
    }
  });
});
