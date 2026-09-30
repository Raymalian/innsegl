// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { formatAbsoluteUtcShort } from "./time";

describe("formatAbsoluteUtcShort", () => {
  const now = new Date("2026-09-30T14:35:00Z");

  it("gives only the time of day, UTC named, when the instant was today", () => {
    expect(formatAbsoluteUtcShort(new Date("2026-09-30T14:31:58Z"), now)).toBe("14:31:58 UTC");
  });

  it("gives the full date on any other day", () => {
    expect(formatAbsoluteUtcShort(new Date("2026-09-29T23:59:59Z"), now)).toBe("2026-09-29 23:59:59 UTC");
  });
});
