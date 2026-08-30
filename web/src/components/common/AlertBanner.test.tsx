// SPDX-License-Identifier: Apache-2.0

/*
 * FE-031 (NEW — proposed for doc 07 TC-FE; see the report for #50).
 *
 *   U | Page-level alert banner for drift, chain failure and anchoring-lag
 *     breach | Announced, dominant, linked to its evidence, and impossible to
 *     dismiss while the condition holds | FD P1, P3, §4.5, §6.4
 *
 * doc 06 §4.5: "For drift detection, chain-verification failure, and
 * anchoring-lag breach. Page-level, persistent until the underlying condition
 * clears, links directly to the evidence."
 *
 * "Persistent until the underlying condition clears" is a statement about who
 * is allowed to remove it, so the test that matters is the absence of a close
 * button: the banner takes the current alerts and renders them, and the ONLY
 * thing that makes one go away is that it stops being an alert. A dismissable
 * banner would let a reader clear a drift alert without clearing the drift.
 *
 * doc 06 P1 supplies the link: "Every claim the UI makes must be visually
 * adjacent to the evidence behind it."
 */

import { render, screen } from "@testing-library/react";
import type { Alert } from "./AlertBanner";
import { AlertBanner } from "./AlertBanner";

const DRIFT: Alert = {
  id: "drift-1",
  kind: "integrity",
  title: "Unattributed signature detected",
  detail:
    "Commit 9f2c1a4 in innsegl/innsegl carries a signature with no matching ledger intent.",
  evidenceHref: "/runs?alert=drift-1",
};

const LAG: Alert = {
  id: "lag-1",
  kind: "degraded",
  title: "Anchoring lag beyond bound",
  detail: "Ledger segment 412 was anchored 47 min ago, 17 min beyond the bound.",
  evidenceHref: "/overview#anchoring",
};

describe("FE-031 AlertBanner", () => {
  it("announces itself in a live region (§6.4)", () => {
    render(<AlertBanner alerts={[DRIFT]} />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      /unattributed signature detected/i,
    );
  });

  it("links directly to the evidence (P1, §4.5)", () => {
    render(<AlertBanner alerts={[DRIFT]} />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/runs?alert=drift-1");
    expect(link).toHaveAccessibleName(/evidence/i);
  });

  it("offers no way to dismiss it — the condition clears it, not the reader", () => {
    render(<AlertBanner alerts={[DRIFT]} />);
    for (const control of screen.queryAllByRole("button")) {
      expect(control).not.toHaveAccessibleName(/dismiss|close|hide|ignore|ok/i);
    }
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("persists across re-renders while the condition holds", () => {
    const view = render(<AlertBanner alerts={[DRIFT]} />);
    view.rerender(<AlertBanner alerts={[DRIFT]} />);
    view.rerender(<AlertBanner alerts={[DRIFT]} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("disappears only when the condition clears", () => {
    const view = render(<AlertBanner alerts={[DRIFT]} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    view.rerender(<AlertBanner alerts={[]} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("is the loudest thing on the page for an integrity alert (P3, §5.3)", () => {
    const { container } = render(<AlertBanner alerts={[DRIFT]} />);
    expect(container.innerHTML).toMatch(/integrity-alert/);
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });

  it("uses amber for an anchoring-lag breach, not the red alarm (§5.3)", () => {
    const { container } = render(<AlertBanner alerts={[LAG]} />);
    expect(container.innerHTML).toMatch(/degraded/);
    expect(container.innerHTML).not.toMatch(/integrity-alert/);
  });

  it("carries an icon and a text label in both kinds, never colour alone", () => {
    for (const alert of [DRIFT, LAG]) {
      const { container, unmount } = render(<AlertBanner alerts={[alert]} />);
      expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
      expect((container.textContent ?? "").trim().length).toBeGreaterThan(0);
      unmount();
    }
  });

  it("uses different icons for an integrity alert and a degradation", () => {
    const iconFor = (alert: Alert): string | null => {
      const { container, unmount } = render(<AlertBanner alerts={[alert]} />);
      const name =
        container.querySelector("svg[data-icon]")?.getAttribute("data-icon") ??
        null;
      unmount();
      return name;
    };
    expect(iconFor(DRIFT)).not.toBe(iconFor(LAG));
  });

  it("pins every current alert, each with its own evidence (§3.1)", () => {
    render(<AlertBanner alerts={[DRIFT, LAG]} />);
    expect(screen.getAllByRole("alert")).toHaveLength(2);
    expect(
      screen.getAllByRole("link").map((a) => a.getAttribute("href")),
    ).toEqual(["/runs?alert=drift-1", "/overview#anchoring"]);
  });

  it("renders nothing when there is nothing wrong (P3: success is quiet)", () => {
    const { container } = render(<AlertBanner alerts={[]} />);
    expect(container.innerHTML).toBe("");
  });

  it("states what happened without reassurance (§6.1)", () => {
    render(<AlertBanner alerts={[DRIFT]} />);
    const text = screen.getByRole("alert").textContent ?? "";
    expect(text).not.toMatch(/successfully|seamless|trusted by|!/i);
  });
});
