// SPDX-License-Identifier: Apache-2.0

/*
 * FE-044's arithmetic (NEW — proposed for doc 07 TC-FE; see the report for
 * #55).
 *
 *   FE-044 | U | Run frequency across time is a set of server-side windowed
 *     counts, and the buckets neither double-count nor drop a run | Buckets
 *     tile the window exactly; each count is a difference of two cumulative
 *     server totals; the counts sum to the window's own total | FD §3.5, §7,
 *     §8 anti-pattern 10
 *
 * ── WHY CUMULATIVE DIFFERENCES ─────────────────────────────────────────────
 *
 * internal/api's run filter is `registered_at >= from AND registered_at <= to`
 * — closed at BOTH ends. Six adjacent bucket queries sharing their boundaries
 * would therefore count a run registered exactly on a boundary twice, and six
 * queries that backed the boundary off by a second would lose it. Neither is a
 * frequency.
 *
 * So the view asks a different question: how many runs fall between the
 * window's start and each boundary. Those answers are closed-closed too, but
 * the DIFFERENCE of two of them is a half-open interval, which is exactly a
 * bucket. Nothing is counted twice and nothing falls between the buckets.
 */

import { describe, expect, it } from "vitest";

import { FREQUENCY_BUCKETS, bucketCounts, bucketsOf } from "./frequency";

const FROM = new Date("2026-08-01T00:00:00Z");
const TO = new Date("2026-08-31T00:00:00Z");

describe("FE-044 the buckets tile the window exactly", () => {
  it("starts at the window's start and ends at its end", () => {
    const buckets = bucketsOf(FROM, TO, FREQUENCY_BUCKETS);
    expect(buckets).toHaveLength(FREQUENCY_BUCKETS);
    expect(buckets[0]?.from.getTime()).toBe(FROM.getTime());
    expect(buckets[FREQUENCY_BUCKETS - 1]?.to.getTime()).toBe(TO.getTime());
  });

  it("leaves no gap and no overlap between adjacent buckets", () => {
    const buckets = bucketsOf(FROM, TO, FREQUENCY_BUCKETS);
    for (let i = 1; i < buckets.length; i += 1) {
      expect(buckets[i]?.from.getTime()).toBe(buckets[i - 1]?.to.getTime());
    }
  });

  it("still ends exactly at the window's end when the span does not divide", () => {
    const odd = new Date(FROM.getTime() + 7 * 24 * 60 * 60 * 1000 + 1);
    const buckets = bucketsOf(FROM, odd, 6);
    expect(buckets[5]?.to.getTime()).toBe(odd.getTime());
    for (let i = 1; i < buckets.length; i += 1) {
      expect(buckets[i]?.from.getTime()).toBe(buckets[i - 1]?.to.getTime());
    }
  });

  it("refuses a window that is not a positive interval", () => {
    expect(bucketsOf(TO, FROM, 6)).toEqual([]);
    expect(bucketsOf(FROM, FROM, 6)).toEqual([]);
    expect(bucketsOf(FROM, TO, 0)).toEqual([]);
  });
});

describe("FE-044 a bucket's count is a difference of two server totals", () => {
  it("differences the cumulative answers in order", () => {
    expect(bucketCounts([2, 2, 5, 9, 9, 11])).toEqual([2, 0, 3, 4, 0, 2]);
  });

  it("sums back to the last cumulative answer, which is the window's total", () => {
    const cumulative = [2, 2, 5, 9, 9, 11];
    const counts = bucketCounts(cumulative);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(cumulative[cumulative.length - 1]);
  });

  it("never renders a negative count when the window moved between requests", () => {
    // The last bucket ends at "now" for a default window, so a run appended
    // between two of the requests can make a later cumulative smaller than an
    // earlier one. A negative frequency is not a fact; zero is.
    expect(bucketCounts([5, 3, 7])).toEqual([5, 0, 4]);
  });

  it("counts nothing out of nothing", () => {
    expect(bucketCounts([])).toEqual([]);
    expect(bucketCounts([0, 0, 0])).toEqual([0, 0, 0]);
  });
});
