// SPDX-License-Identifier: Apache-2.0

/*
 * FE-032 (NEW — proposed for doc 07 TC-FE; see the report for #50).
 *
 *   U | Per-view empty and dependency-error states | Both render explicit
 *     copy, an icon and a label; neither is a blank panel; the error is amber,
 *     not a failed verdict | FD §4.6, §5.3, §6.1
 *
 * doc 06 §4.6: "Every view specifies its empty state ('No runs match these
 * filters') and its dependency-error state ('Can't reach the ledger — showing
 * nothing rather than guessing'). No blank panels, no infinite spinners."
 *
 * The two are deliberately different components rather than one with a flag.
 * An empty result is not a problem — the query worked and the answer is none —
 * and doc 06 P2 is exactly about not collapsing "nothing matched" into "we
 * could not check". One renders neutral, the other renders degraded.
 */

import { render, screen } from "@testing-library/react";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";

describe("FE-032 EmptyState", () => {
  it("says what is empty, in the view's own words", () => {
    render(<EmptyState title="No runs match these filters" />);
    expect(
      screen.getByText("No runs match these filters"),
    ).toBeInTheDocument();
  });

  it("is never a blank panel (§4.6)", () => {
    const { container } = render(<EmptyState />);
    expect((container.textContent ?? "").trim().length).toBeGreaterThan(0);
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
  });

  it("is neutral — an empty result is not a fault (P2, §5.3)", () => {
    const { container } = render(<EmptyState title="No runs" />);
    expect(container.innerHTML).not.toMatch(
      /degraded|integrity-alert|proof-verified|proof-failed/,
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("carries the detail a view gives it", () => {
    render(
      <EmptyState title="No runs" detail="Widen the date range to see more." />,
    );
    expect(
      screen.getByText("Widen the date range to see more."),
    ).toBeInTheDocument();
  });
});

describe("FE-032 ErrorState", () => {
  it("names the dependency and what it is doing instead (§4.6, §6.1)", () => {
    render(
      <ErrorState
        title="Can't reach the ledger"
        detail="Showing nothing rather than guessing."
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/can't reach the ledger/i);
    expect(alert).toHaveTextContent(/rather than guessing/i);
  });

  it("is degraded-amber, not a failed verification (§5.3, P2)", () => {
    const { container } = render(<ErrorState />);
    expect(container.innerHTML).toMatch(/degraded/);
    expect(container.innerHTML).not.toMatch(/proof-failed|proof-verified/);
  });

  it("pairs the colour with an icon and a label (§6.4)", () => {
    const { container } = render(<ErrorState />);
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
    expect((container.textContent ?? "").trim().length).toBeGreaterThan(0);
  });

  it("offers a read-only retry when the caller can retry (P6)", () => {
    const onRetry = vi.fn();
    render(<ErrorState onRetry={onRetry} />);
    screen.getByRole("button", { name: /retry/i }).click();
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("offers no control at all when the caller cannot retry", () => {
    render(<ErrorState />);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("links to the evidence when there is any (P1)", () => {
    render(<ErrorState evidenceHref="/health" />);
    expect(screen.getByRole("link")).toHaveAttribute("href", "/health");
  });

  it("uses no reassuring or celebratory copy (§6.1, §8.9)", () => {
    render(<ErrorState />);
    const text = screen.getByRole("alert").textContent ?? "";
    expect(text).not.toMatch(/successfully|seamless|trusted by|all set|!/i);
  });
});
