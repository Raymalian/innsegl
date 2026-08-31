// SPDX-License-Identifier: Apache-2.0

/*
 * The window "runs today" is counted over — doc 06 §8 anti-pattern 10.
 *
 * "Today" is a word, and a count behind a word is a count a reader has to
 * trust. The boundary is UTC and it is rendered, so the reader can check it
 * against the timestamps everywhere else in the product, which are UTC too.
 */

import { formatCount, formatRate, startOfUtcDay } from "./format";

describe("the metric window and the numbers in it", () => {
  it("starts the day at midnight UTC, whatever the hour", () => {
    expect(startOfUtcDay(new Date("2026-08-30T14:44:05Z")).toISOString()).toBe(
      "2026-08-30T00:00:00.000Z",
    );
    expect(startOfUtcDay(new Date("2026-08-30T00:00:00Z")).toISOString()).toBe(
      "2026-08-30T00:00:00.000Z",
    );
    expect(startOfUtcDay(new Date("2026-08-30T23:59:59.999Z")).toISOString()).toBe(
      "2026-08-30T00:00:00.000Z",
    );
  });

  it("does not shift the day across a month boundary", () => {
    expect(startOfUtcDay(new Date("2026-09-01T00:30:00Z")).toISOString()).toBe(
      "2026-09-01T00:00:00.000Z",
    );
  });

  it("refuses to render a rate nothing was counted over", () => {
    expect(formatRate(0, 0)).toBe("");
    expect(formatCount(Number.NaN)).toBe("");
  });

  it("floors a rate rather than rounding it up", () => {
    // 2 of 3 is 66.66…%, and the digit that is lost is lost downward.
    expect(formatRate(2, 3)).toBe("66.6%");
    expect(formatRate(1, 3)).toBe("33.3%");
    expect(formatRate(0, 1000)).toBe("0%");
  });
});
