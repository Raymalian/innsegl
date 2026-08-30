// SPDX-License-Identifier: Apache-2.0

/*
 * FE-011 (doc 07, TC-FE) — loading timeout.
 *
 *   "Spinner times out into explicit error state"  — proves FD §4.6
 *
 * doc 06 §4.6: "No blank panels, no infinite spinners: loading states time out
 * into an explicit error." doc 06 §8 anti-pattern 8: "Spinners without
 * timeout-to-error." The bound is the load-bearing part — a component that
 * merely *can* show an error still spins forever if nothing ever tells it to.
 */

import { act, render, screen } from "@testing-library/react";
import { LoadingState } from "./LoadingState";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

function advance(ms: number) {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

describe("FE-011 LoadingState", () => {
  it("announces that it is loading, and what", () => {
    render(<LoadingState what="runs" timeoutMs={10_000} />);
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(/loading runs/i);
    expect(status).toHaveAttribute("aria-busy", "true");
  });

  it("is still loading one millisecond before the bound", () => {
    render(<LoadingState what="runs" timeoutMs={10_000} />);
    advance(9_999);
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("times out into an EXPLICIT error, and stops claiming to be busy", () => {
    render(<LoadingState what="runs" timeoutMs={10_000} />);
    advance(10_000);

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/timed out/i);
    // Explicit means it says what did not answer and how long it waited.
    expect(alert).toHaveTextContent(/runs/i);
    expect(alert).toHaveTextContent(/10 s/);
    expect(document.querySelector("[aria-busy='true']")).toBeNull();
  });

  it("never returns to loading once it has timed out", () => {
    render(<LoadingState what="runs" timeoutMs={5_000} />);
    advance(5_000);
    advance(60_000);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText(/loading runs/i)).toBeNull();
  });

  it("tells its caller it timed out, exactly once", () => {
    const onTimeout = vi.fn();
    render(
      <LoadingState what="runs" timeoutMs={1_000} onTimeout={onTimeout} />,
    );
    advance(10_000);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it("offers a read-only retry, never a mutating one (P6)", () => {
    const onRetry = vi.fn();
    render(<LoadingState what="runs" timeoutMs={1_000} onRetry={onRetry} />);
    advance(1_000);
    const retry = screen.getByRole("button", { name: /retry/i });
    act(() => {
      retry.click();
    });
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("has a bound even when the caller names none", () => {
    render(<LoadingState what="runs" />);
    advance(120_000);
    expect(screen.getByRole("alert")).toHaveTextContent(/timed out/i);
  });

  it("carries an icon and a label in the timed-out state, not colour alone (§6.4)", () => {
    const { container } = render(<LoadingState what="runs" timeoutMs={1_000} />);
    advance(1_000);
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
    expect(screen.getByRole("alert").textContent).toBeTruthy();
  });

  it("times out as degraded, not as a failed verification (§5.3)", () => {
    const { container } = render(<LoadingState what="runs" timeoutMs={1_000} />);
    advance(1_000);
    expect(container.innerHTML).toMatch(/degraded/);
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });

  it("drops its timer when unmounted", () => {
    const onTimeout = vi.fn();
    const view = render(
      <LoadingState what="runs" timeoutMs={1_000} onTimeout={onTimeout} />,
    );
    view.unmount();
    advance(10_000);
    expect(onTimeout).not.toHaveBeenCalled();
  });
});
