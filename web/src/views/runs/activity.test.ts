// SPDX-License-Identifier: Apache-2.0

/*
 * How long a run was active, and whether an active run is idle. "Active" is
 * the ledger's word; a session killed without its end hook stays active
 * until the backstop retires it, days later. Idle is how a reader tells it
 * from an agent working now.
 */

import { activeFor, isIdle, IDLE_AFTER_MS } from "./activity";

const NOW = new Date("2026-10-03T17:00:00Z");

describe("activeFor", () => {
  it("is the time from registration to the newest activity", () => {
    expect(activeFor("2026-10-03T08:43:03Z", "2026-10-03T10:58:03Z")).toBe("2 h 15 min");
  });

  it("is nothing when either time is unreadable", () => {
    expect(activeFor("", "2026-10-03T10:58:03Z")).toBeNull();
    expect(activeFor("2026-10-03T08:43:03Z", "not a time")).toBeNull();
  });
});

describe("isIdle", () => {
  it("is an active run with nothing recorded for the idle bound", () => {
    const quiet = new Date(NOW.getTime() - IDLE_AFTER_MS).toISOString();
    expect(isIdle("active", quiet, NOW)).toBe(true);
  });

  it("is not an active run that did something inside the bound", () => {
    const recent = new Date(NOW.getTime() - IDLE_AFTER_MS + 60_000).toISOString();
    expect(isIdle("active", recent, NOW)).toBe(false);
  });

  it("is never a run that is not active", () => {
    expect(isIdle("retired", "2026-10-01T00:00:00Z", NOW)).toBe(false);
  });
});
