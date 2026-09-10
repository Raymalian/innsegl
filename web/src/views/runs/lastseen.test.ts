// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { lastSeen } from "./lastseen";

/**
 * FE-060 (proposed for doc 06's test list; doc 06 is not modified here).
 *
 * ── WHY A STATUS BADGE ALONE IS NOT AN HONEST ANSWER ───────────────────────
 *
 * "Active" is a fact about the LEDGER: no `run_retired` and no `run_expired`
 * for this run. It reads as a fact about the WORLD: this agent is working.
 * Those are the same thing only while something retires finished runs and
 * expires crashed ones.
 *
 * Measured on this project's own deployment on 2026-09-10: six runs showing
 * Active, five of them dead — three silent for seventeen hours. The operator's
 * question on seeing it was the right one: "how can I trust the page?"
 *
 * doc 06 P2 forbids exactly this. A view may not present something it does not
 * know, and it does not know that a run with no activity since yesterday is
 * working. So the badge keeps saying what the ledger says, and the cell says
 * how old that claim is. The reader is then never misled by a stale row,
 * whether or not a reaper is running.
 *
 * The value is already on the wire — `last_event_at` is in the runs response
 * and was simply not rendered.
 */
describe("lastSeen", () => {
  const now = new Date("2026-09-10T12:00:00Z");

  it("says nothing for a run that is doing something now", () => {
    // A live agent needs no annotation: the badge is true and an age beside it
    // would be noise on every healthy row.
    expect(lastSeen("2026-09-10T11:59:30Z", now)).toBeNull();
  });

  it("names the age once a run has been quiet long enough to doubt", () => {
    expect(lastSeen("2026-09-10T11:20:00Z", now)).toBe("last seen 40 minutes ago");
    expect(lastSeen("2026-09-10T09:00:00Z", now)).toBe("last seen 3 hours ago");
    expect(lastSeen("2026-09-09T14:11:00Z", now)).toBe("last seen 21 hours ago");
    expect(lastSeen("2026-09-07T12:00:00Z", now)).toBe("last seen 3 days ago");
  });

  it("reads the singular as a person would", () => {
    expect(lastSeen("2026-09-10T11:00:00Z", now)).toBe("last seen 1 hour ago");
    expect(lastSeen("2026-09-09T12:00:00Z", now)).toBe("last seen 1 day ago");
  });

  it("says nothing when the ledger recorded no time", () => {
    // Absent, not zero. A missing timestamp is not "last seen in 1970", and
    // rendering it as an age would be inventing a fact (doc 06 P2).
    expect(lastSeen("", now)).toBeNull();
    expect(lastSeen("not a timestamp", now)).toBeNull();
  });

  it("says nothing about a future timestamp rather than counting backwards", () => {
    // Clock skew between the ledger and the browser. "last seen -2 minutes
    // ago" is worse than silence.
    expect(lastSeen("2026-09-10T12:05:00Z", now)).toBeNull();
  });
});
