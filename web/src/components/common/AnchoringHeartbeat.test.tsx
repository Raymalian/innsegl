// SPDX-License-Identifier: Apache-2.0

/*
 * FE-005 (doc 07, TC-FE) — anchoring heartbeat beyond the lag bound.
 *
 *   "Header turns amber with lag duration"  — proves FD §3.1
 *
 * doc 06 §3.1: "Anchoring heartbeat in the persistent header (all views):
 * 'Ledger segment N anchored M min ago.' Exceeding the configured
 * anchoring-lag bound turns this amber with the lag duration; it is the
 * system's public tamper-evidence pulse and is never hidden."
 *
 * The header chrome belongs to RM-041 (#49); this is the shared component the
 * header renders, and the amber-with-lag behaviour lives here.
 */

import { render, screen } from "@testing-library/react";
import { AnchoringHeartbeat } from "./AnchoringHeartbeat";

const NOW = new Date("2026-08-30T14:44:05Z");
const RECENT = new Date("2026-08-30T14:41:05Z"); // 3 min ago
const LATE = new Date("2026-08-30T13:57:05Z"); // 47 min ago
const BOUND_MS = 30 * 60 * 1000; // 30 min

describe("FE-005 AnchoringHeartbeat", () => {
  it("reads the pulse plainly when the lag is inside the bound", () => {
    render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={RECENT}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    const pulse = screen.getByTestId("anchoring-heartbeat");
    expect(pulse).toHaveAttribute("data-state", "within-bound");
    expect(pulse).toHaveTextContent(/ledger segment 412 anchored 3 min ago/i);
  });

  it("stays calm inside the bound — no degraded colour, no alarm (P3)", () => {
    const { container } = render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={RECENT}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(container.innerHTML).not.toMatch(/degraded/);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("turns amber beyond the bound", () => {
    const { container } = render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={LATE}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("anchoring-heartbeat")).toHaveAttribute(
      "data-state",
      "beyond-bound",
    );
    // Amber is reachable only through the degraded group (ADR-0038, §5.3).
    expect(container.innerHTML).toMatch(/degraded/);
    expect(container.innerHTML).not.toMatch(/proof-verified|proof-failed/);
  });

  it("states the lag duration and the bound it broke", () => {
    render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={LATE}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    const pulse = screen.getByTestId("anchoring-heartbeat");
    expect(pulse).toHaveTextContent(/47 min/); // how long since the anchor
    expect(pulse).toHaveTextContent(/17 min/); // how far beyond the bound
    expect(pulse).toHaveTextContent(/30 min/); // the bound itself
  });

  it("is never hidden: it renders in both states", () => {
    const inside = render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={RECENT}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(inside.getByTestId("anchoring-heartbeat")).toBeVisible();
    inside.unmount();

    const outside = render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={LATE}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(outside.getByTestId("anchoring-heartbeat")).toBeVisible();
  });

  it("pairs the amber with an icon and a text label, never colour alone (§6.4)", () => {
    const { container } = render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={LATE}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
    expect(
      screen.getByTestId("anchoring-heartbeat").textContent,
    ).toBeTruthy();
  });

  it("exposes the anchor time absolutely, with its timezone (§6.2)", () => {
    render(
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={LATE}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    const time = screen.getByText(/3 min ago|47 min ago/);
    expect(time).toHaveAttribute("datetime", "2026-08-30T13:57:05.000Z");
    expect(time).toHaveAttribute("title", "2026-08-30 13:57:05 UTC");
  });

  it("says so rather than guessing when nothing has been anchored yet (P2)", () => {
    render(
      <AnchoringHeartbeat segment={null} anchoredAt={null} lagBoundMs={BOUND_MS} now={NOW} />,
    );
    const pulse = screen.getByTestId("anchoring-heartbeat");
    expect(pulse).toHaveAttribute("data-state", "unknown");
    expect(pulse).toHaveTextContent(/no segment anchored yet/i);
  });
});
