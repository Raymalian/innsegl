// SPDX-License-Identifier: Apache-2.0

/*
 * The pass rate is measured live by the query API
 * (GET /api/v1/verification/recent): the ledger names the most recent
 * commits, and each verdict is the three checks' own. While it measures,
 * the card says so rather than "Not measured".
 */

import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PassRateCard } from "./PassRateCard";
import { fetchRecentVerification } from "./data";
import { strings } from "./strings";

afterEach(() => vi.unstubAllGlobals());

describe("the live pass rate", () => {
  it("reads the API's measurement as a live rate", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            checked: 20, verified: 18, failed: 0, unavailable: 2,
            measured_at: "2026-10-04T10:00:00Z", commits: [],
          }),
        ),
      ),
    );
    const rate = await fetchRecentVerification("/api/v1", new AbortController().signal);
    expect(rate).toMatchObject({ checked: 20, verified: 18, failed: 0, unavailable: 2 });
    expect(rate?.liveness.source).toBe("live");
    expect(rate?.measuredAt.toISOString()).toBe("2026-10-04T10:00:00.000Z");
  });

  it("has nothing to show when there are no recorded commits", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ checked: 0, verified: 0, failed: 0, unavailable: 0, measured_at: "2026-10-04T10:00:00Z", commits: [] })),
      ),
    );
    expect(await fetchRecentVerification("/api/v1", new AbortController().signal)).toBeUndefined();
  });

  it("says it is checking while the measurement runs", () => {
    render(<PassRateCard commitsRecorded={30} measuring now={new Date()} verifyHref="/verify" />);
    expect(screen.getByText(strings.passRate.measuring)).toBeInTheDocument();
    expect(screen.queryByText(strings.passRate.notMeasured)).not.toBeInTheDocument();
  });
});
