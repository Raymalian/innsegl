// SPDX-License-Identifier: Apache-2.0

/*
 * The metric cards — doc 06 §3.1, §6.2, §8 anti-patterns 2, 3 and 10.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-072 | U | Overview metric counts | Exact: never abbreviated, never
 *          |   | rounded; every windowed count states its window | FD §6.2, §8/10
 *   FE-073 | U | Verification pass rate on the overview | States that it was
 *          |   | not measured and why; a measured rate keeps failed and
 *          |   | unavailable apart; 100% is never green | FD §3.1, §5.3, P2,
 *          |   | §8/2, IP §6.11
 *
 * FE-073 is the test for the decision this issue could not make on its own.
 * doc 06 §3.1 asks for a "verification pass rate" and says a rate below 100%
 * renders as a warning. `internal/api` deliberately does not serve one, and
 * says why in `Overview`'s own comment: a rate counted from the ledger is a
 * database-only verdict, which IP §6.11 and doc 06 P2 forbid in terms. These
 * tests pin the reading this view shipped — the card says it was not measured
 * and why — so that a human ruling changes a test rather than a habit.
 */

import { render, screen } from "@testing-library/react";

import { formatCount, formatRate } from "./format";
import { MetricCard } from "./MetricCard";
import { PassRateCard } from "./PassRateCard";
import { perceptible } from "./perceptible";
import type { PassRate } from "./types";

const NOW = new Date("2026-08-30T14:44:05Z");
const COMMITS = 1284;

function rate(over: Partial<PassRate> = {}): PassRate {
  return {
    verified: 1284,
    failed: 0,
    unavailable: 0,
    checked: 1284,
    measuredAt: new Date("2026-08-30T14:41:05Z"),
    liveness: { source: "live" },
    ...over,
  };
}

function passRate(over: Partial<PassRate> | undefined) {
  return render(
    <PassRateCard
      commitsRecorded={COMMITS}
      rate={over === undefined ? undefined : rate(over)}
      now={NOW}
      verifyHref="/verify"
    />,
  );
}

describe("FE-072 counts are exact", () => {
  it("never abbreviates and never rounds", () => {
    expect(formatCount(1284)).toBe("1,284");
    expect(formatCount(1284573)).toBe("1,284,573");
    expect(formatCount(999)).toBe("999");
    expect(formatCount(0)).toBe("0");
    expect(formatCount(1000)).toBe("1,000");
    for (const shown of [formatCount(1284573), formatCount(1500)]) {
      expect(shown).not.toMatch(/[kKmMbB]/);
      expect(shown).not.toMatch(/\./);
    }
  });

  it("renders the whole number in the card, not a shortened one", () => {
    render(
      <MetricCard
        id="commits"
        label="Commits attributed"
        value={formatCount(1284573)}
        meaning="Commits the ledger holds a record for."
      />,
    );
    expect(screen.getByTestId("metric-commits")).toHaveTextContent("1,284,573");
  });

  it("carries the meaning of the number with it (P1, §8/10)", () => {
    render(
      <MetricCard
        id="runs-today"
        label="Runs today"
        value="12"
        meaning="Runs registered since 2026-08-30 00:00:00 UTC."
      />,
    );
    expect(screen.getByTestId("metric-runs-today")).toHaveTextContent(
      /since 2026-08-30 00:00:00 UTC/,
    );
  });

  it("spends no green on a count (§5.3)", () => {
    const { container } = render(
      <MetricCard id="active" label="Active agents" value="7" meaning="Runs registered." />,
    );
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });
});

describe("FE-073 the verification pass rate asserts nothing that was not checked", () => {
  it("says it was not measured, rather than counting one out of the ledger", () => {
    passRate(undefined);
    const card = screen.getByTestId("metric-pass-rate");
    expect(card).toHaveTextContent(/not measured/i);
    expect(card).toHaveTextContent(/no live check has run/i);
    expect(card.textContent).not.toMatch(/\d+(\.\d+)?%/);
  });

  it("shows numerator over denominator on hover, even with no numerator (§6.2)", () => {
    passRate(undefined);
    const card = screen.getByTestId("metric-pass-rate");
    expect(card).toHaveTextContent(/0 of 1,284 commits checked live/);
    expect(screen.getByTitle(/0 of 1,284 commits checked live/)).toBeInTheDocument();
  });

  it("renders unavailable rather than calm: it is amber, with an icon (§5.3, §6.4)", () => {
    const { container } = passRate(undefined);
    expect(container.innerHTML).toMatch(/degraded/);
    expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });

  it("offers the reader the live check the dashboard did not run (P1, §6.1)", () => {
    passRate(undefined);
    expect(screen.getByRole("link", { name: /verify a commit/i })).toHaveAttribute(
      "href",
      "/verify",
    );
  });

  it("refuses a retained rate: a cached verdict is not a live one (anti-pattern 1)", () => {
    passRate({ liveness: { source: "cache" } });
    const card = screen.getByTestId("metric-pass-rate");
    expect(card).toHaveTextContent(/not measured/i);
    expect(card).toHaveTextContent(/retained from an earlier check/i);
    expect(card.textContent).not.toMatch(/\d+(\.\d+)?%/);
  });

  it("states a live rate as a rate, with its numerator over denominator on hover", () => {
    passRate({ verified: 1240, failed: 30, unavailable: 14, checked: 1284 });
    const card = screen.getByTestId("metric-pass-rate");
    expect(card).toHaveTextContent("96.5%");
    expect(screen.getByTitle(/1,240 of 1,284 commits verified live/)).toBeInTheDocument();
  });

  it("keeps failed and unavailable apart (§8 anti-pattern 2)", () => {
    passRate({ verified: 1240, failed: 30, unavailable: 14, checked: 1284 });
    expect(screen.getByTestId("metric-pass-rate")).toHaveTextContent(
      /30 failed, 14 could not be checked/,
    );
  });

  it("renders below 100% as a warning, not a neutral number (§3.1)", () => {
    const warned = passRate({ verified: 1240, failed: 30, unavailable: 14, checked: 1284 });
    expect(warned.container.innerHTML).toMatch(/integrity-alert|degraded/);
    warned.unmount();

    const clean = passRate({});
    expect(clean.container.innerHTML).not.toMatch(/integrity-alert|degraded/);
  });

  it("distinguishes a failed commit from one it could not check", () => {
    const failed = perceptible(
      passRate({ verified: 1283, failed: 1, unavailable: 0, checked: 1284 }).container
        .innerHTML,
    );
    const unavailable = perceptible(
      passRate({ verified: 1283, failed: 0, unavailable: 1, checked: 1284 }).container
        .innerHTML,
    );
    expect(failed).not.toEqual(unavailable);
    expect(failed).toMatch(/integrity-alert/);
    expect(unavailable).not.toMatch(/integrity-alert/);
    expect(unavailable).toMatch(/degraded/);
  });

  it("never renders 100% while a commit is unverified (§8 anti-pattern 10)", () => {
    expect(formatRate(999, 1000)).toBe("99.9%");
    expect(formatRate(9999, 10000)).toBe("99.9%");
    expect(formatRate(1284, 1284)).toBe("100%");
    passRate({ verified: 999, failed: 1, unavailable: 0, checked: 1000 });
    expect(screen.getByTestId("metric-pass-rate")).not.toHaveTextContent("100%");
  });

  it("is never green, not even at 100% (§5.3, §8 anti-pattern 3)", () => {
    const { container } = passRate({});
    expect(container.innerHTML).toMatch(/100%/);
    expect(container.innerHTML).not.toMatch(/proof-verified/);
  });

  it("says when the measurement was taken, because a rate has an age (P2)", () => {
    passRate({});
    expect(screen.getByTestId("metric-pass-rate")).toHaveTextContent(/measured 3 min ago/i);
  });
});
