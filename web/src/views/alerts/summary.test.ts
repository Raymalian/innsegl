// SPDX-License-Identifier: Apache-2.0

/*
 * RM-203 (#326): the sealer's own drift reason, said in plain words.
 *
 * Measured live: an anchoring failure showed in the menu as "Segment
 * sha256:7cab25be… (positions 33552..33613) is sealed but has no transparency
 * log entry: anchoring…" -- a log line cut short, not a sentence an operator
 * can act on. It is the drift the sealer raises most, and its shape is fixed
 * (internal/segment AnchorAlert), so it is matched like the reconciler's five.
 */

import { describe, expect, it } from "vitest";

import type { AlertRecord } from "../overview/types";
import { alertSummary } from "./summary";

function drift(reason: string): AlertRecord {
  return {
    chain_position: 1,
    event_id: "01a0e1f3-7187-7c98-9dad-9893da9b1c8a",
    event_type: "ledger_drift_detected",
    ts: "2026-09-27T08:20:23Z",
    reason,
    resolved: false,
  } as AlertRecord;
}

describe("RM-203 the sealer's anchoring alert reads as a sentence", () => {
  it("names the positions and says what failed, with no hash", () => {
    const got = alertSummary(
      drift(
        "segment sha256:7cab25be30802767d00722f86f527c0ca08b00dc7814c68dcb402cf643538a7d (positions 33552..33613) is sealed but has no transparency log entry: anchoring segment sha256:7cab25be gave up after 5 attempts: transparency log unavailable",
      ),
    );
    expect(got).toBe("Positions 33552–33613 are sealed but could not be anchored in the transparency log.");
  });

  it("leaves any other reason as it was", () => {
    expect(alertSummary(drift("the object store did not answer"))).toBe("The object store did not answer.");
  });
});
