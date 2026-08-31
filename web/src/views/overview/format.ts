// SPDX-License-Identifier: Apache-2.0

/*
 * Numbers, exactly — doc 06 §6.2.
 *
 *   "Counts are exact, never rounded vanity numbers. Verification pass rate
 *    shows numerator/denominator on hover."
 *
 * and doc 06 §8 anti-pattern 10: "Metrics chosen to look good rather than to
 * inform (e.g., cumulative counts with no window, hiding a failing pass rate)."
 *
 * Two rules follow, and both are enforced here rather than remembered by each
 * card:
 *
 * 1. A COUNT IS NEVER ABBREVIATED AND NEVER ROUNDED. There is no "1.2k" in
 *    this file and no place for one. Digit grouping is the only thing done to
 *    a count, and grouping does not change a value.
 *
 * 2. A RATE BELOW 100% NEVER RENDERS AS 100%. A rate is a ratio and cannot be
 *    exact at one decimal place, so the rounding is chosen to fail in the
 *    direction that cannot hide a defect: it floors, and it refuses to print
 *    100 for anything short of every commit verified. 999 of 1000 is 99.9%,
 *    not "100%", and 9,999 of 10,000 is 99.9% too — the digit that is lost is
 *    lost downward, into the reader's suspicion rather than out of it. The
 *    numerator and denominator are always available beside it.
 *
 * `Intl.NumberFormat` is deliberately not used: its grouping depends on the
 * runtime's locale data, which makes a rendered count non-deterministic across
 * machines and a test of it non-deterministic with it. The separator is
 * English-first and lives in the string catalogue.
 */

import { GROUP_SEPARATOR } from "./strings";

/**
 * A whole count, grouped and complete. `1284` → `1,284`; `1000000` → `1,000,000`.
 * Never abbreviated, never rounded, never scaled.
 */
export function formatCount(value: number): string {
  if (!Number.isFinite(value)) return "";
  const whole = Math.trunc(value);
  const sign = whole < 0 ? "-" : "";
  const digits = Math.abs(whole).toString();
  let grouped = "";
  for (let i = 0; i < digits.length; i += 1) {
    const fromEnd = digits.length - i;
    grouped += digits[i];
    if (fromEnd > 1 && fromEnd % 3 === 1) grouped += GROUP_SEPARATOR;
  }
  return `${sign}${grouped}`;
}

/**
 * A pass rate as a percentage, floored to one decimal, and capped below 100
 * unless every checked commit verified.
 */
export function formatRate(verified: number, checked: number): string {
  if (checked <= 0) return "";
  if (verified >= checked) return "100%";
  const floored = Math.floor((verified / checked) * 1000) / 10;
  const shown = Math.min(floored, 99.9);
  return `${shown}%`;
}

/**
 * Midnight UTC of the day `now` falls in.
 *
 * The window for "runs today", and it is UTC for the same reason
 * `components/common/time.ts` renders every absolute timestamp in UTC: a
 * number whose window depends on who is reading it is not evidence. The card
 * renders the boundary, so "today" is never a word the reader has to trust.
 */
export function startOfUtcDay(now: Date): Date {
  return new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
  );
}
