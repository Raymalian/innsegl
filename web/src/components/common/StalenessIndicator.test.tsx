// SPDX-License-Identifier: Apache-2.0

/*
 * FE-006 (doc 07, TC-FE) — degraded ledger read path.
 *
 *   "Staleness marker with timestamp on every affected view"  — proves FD §4.4
 *
 * doc 06 §4.4: "Whenever the dashboard serves data while the ledger read path
 * is degraded, every affected view carries a visible 'data as of {timestamp}'
 * marker. Silent staleness violates P2." doc 06 §8 anti-pattern 7 makes silent
 * staleness a defect.
 *
 * "Every affected view" is a property of the mechanism, not of any one view:
 * a marker each view has to remember to render is a marker some view will
 * forget. So the read-path state is provided once and the marker is derived
 * from it, and this file tests that derivation across several views at once.
 */

import { render, screen } from "@testing-library/react";
import {
  StalenessIndicator,
  StalenessProvider,
  useReadPath,
} from "./StalenessIndicator";

const AS_OF = new Date("2026-08-30T14:32:05Z");
const NOW = new Date("2026-08-30T14:44:05Z"); // 12 minutes later

/* Three stand-ins for three of doc 06 §3's views. Each renders the marker the
 * way a real view would: unconditionally, letting the provider decide. */
function View({ name }: { name: string }) {
  return (
    <section aria-label={name}>
      <StalenessIndicator />
      <p>rows</p>
    </section>
  );
}

function ThreeViews() {
  return (
    <>
      <View name="Overview" />
      <View name="Runs" />
      <View name="Run detail" />
    </>
  );
}

describe("FE-006 staleness marker", () => {
  it("marks EVERY affected view when the read path is degraded", () => {
    render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <ThreeViews />
      </StalenessProvider>,
    );
    expect(screen.getAllByText(/data as of/i)).toHaveLength(3);
  });

  it("shows the timestamp, absolute and with its timezone (§4.4, §6.2)", () => {
    render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <View name="Runs" />
      </StalenessProvider>,
    );
    const marker = screen.getByRole("status");
    expect(marker).toHaveTextContent("2026-08-30 14:32:05 UTC");
    expect(screen.getByText(/2026-08-30 14:32:05 UTC/)).toHaveAttribute(
      "datetime",
      "2026-08-30T14:32:05.000Z",
    );
  });

  it("says how stale, in exact units (§6.2)", () => {
    render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <View name="Runs" />
      </StalenessProvider>,
    );
    expect(screen.getByRole("status")).toHaveTextContent(/12 min/);
  });

  it("renders nothing at all when the read path is healthy (P3: success is quiet)", () => {
    render(
      <StalenessProvider degraded={false} asOf={AS_OF} now={NOW}>
        <ThreeViews />
      </StalenessProvider>,
    );
    expect(screen.queryByText(/data as of/i)).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("carries an icon and a text label, never colour alone (§6.4)", () => {
    const { container } = render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <View name="Runs" />
      </StalenessProvider>,
    );
    const marker = screen.getByRole("status");
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
    expect((marker.textContent ?? "").trim().length).toBeGreaterThan(0);
  });

  it("is degraded-amber, not a verdict colour (§5.3)", () => {
    const { container } = render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <View name="Runs" />
      </StalenessProvider>,
    );
    const markup = container.innerHTML;
    expect(markup).toMatch(/degraded/);
    expect(markup).not.toMatch(/proof-verified/);
    expect(markup).not.toMatch(/proof-failed/);
  });

  it("reports the read path to any view that needs to decide for itself", () => {
    function Probe() {
      const readPath = useReadPath();
      return <span data-testid="probe">{String(readPath.degraded)}</span>;
    }
    render(
      <StalenessProvider degraded asOf={AS_OF} now={NOW}>
        <Probe />
      </StalenessProvider>,
    );
    expect(screen.getByTestId("probe")).toHaveTextContent("true");
  });

  it("defaults to healthy when no provider is present, and says so silently", () => {
    render(<StalenessIndicator />);
    expect(screen.queryByRole("status")).toBeNull();
  });
});
