// SPDX-License-Identifier: Apache-2.0

/*
 * FE-002 and FE-003 — the rollup rule, and the rule that outranks it.
 *
 * doc 07:
 *   FE-002 | U | Rollup logic: one check failed vs one check errored |
 *     Failed → rollup failed; errored → rollup unavailable; never verified |
 *     FD §4.1
 *   FE-003 | U | Live check errors while cache says verified |
 *     UI renders unavailable, not cached verified | FD anti-pattern 1
 *
 * doc 06 §4.1 states the rule this file tests:
 *
 *   "Any single check failing makes the rollup failed. Any check erroring
 *    (not failing) makes the rollup verification unavailable, never
 *    'verified.'"
 *
 * The rule is three lines of code and it is the most consequential three lines
 * in the dashboard, so it is tested exhaustively rather than by example: all
 * 27 assignments of three results to three checks, each one asserted against
 * the rule restated independently of the implementation.
 *
 * FE-003 is the second half, and it is a different claim. §4.1's rule is about
 * what the checks say; anti-pattern 1 is about whether anybody asked them:
 *
 *   "1. A 'verified' state rendered from cache while the live check errored."
 *
 * A cached green is the most damaging thing this dashboard can do, because it
 * asserts a cryptographic fact the system cannot currently confirm. So the
 * downgrade is not a rendering nicety applied in a component — it is in the
 * one function that decides the verdict, it is tested here, and every render
 * path goes through it.
 */

import { describe, expect, it } from "vitest";

import { forgedTrailerProof, proofWithResults, verifiedProof } from "./fixtures";
import { rollupChecks, verdictOf } from "./rollup";
import type { CheckResult } from "./types";

const RESULTS: readonly CheckResult[] = ["verified", "failed", "unavailable"];

/** doc 06 §4.1, restated here so the test does not consult the code it tests. */
function ruleOf(results: readonly CheckResult[]) {
  if (results.includes("failed")) return "failed";
  if (results.includes("unavailable")) return "unavailable";
  return "verified";
}

const everyAssignment: (readonly [CheckResult, CheckResult, CheckResult])[] = [];
for (const a of RESULTS) {
  for (const b of RESULTS) {
    for (const c of RESULTS) everyAssignment.push([a, b, c]);
  }
}

describe("FE-002 the rollup of three checks", () => {
  it("covers every assignment of three results to three checks", () => {
    expect(everyAssignment).toHaveLength(27);
  });

  it.each(everyAssignment)("[%s, %s, %s] rolls up by doc 06 §4.1", (a, b, c) => {
    const proof = proofWithResults([a, b, c]);
    expect(rollupChecks(proof.checks)).toBe(ruleOf([a, b, c]));
  });

  it("says verified for exactly one of the 27, and only for all three verified", () => {
    const verified = everyAssignment.filter(
      (results) => rollupChecks(proofWithResults(results).checks) === "verified",
    );
    expect(verified).toEqual([["verified", "verified", "verified"]]);
  });

  it("a check that failed outranks a check that errored", () => {
    // Both are present. doc 06 §4.1 gives failure the answer: "any single
    // check failing makes the rollup failed."
    expect(rollupChecks(proofWithResults(["failed", "unavailable", "verified"]).checks))
      .toBe("failed");
    expect(rollupChecks(proofWithResults(["unavailable", "failed", "verified"]).checks))
      .toBe("failed");
  });

  it("never reads verified when a check errored", () => {
    for (const results of everyAssignment) {
      if (!results.includes("unavailable")) continue;
      expect(rollupChecks(proofWithResults(results).checks)).not.toBe("verified");
    }
  });

  it("rolls up no checks as unavailable, never as verified", () => {
    // An empty list is not three passing checks. Go's rollup is only ever
    // called with the three, so it can return verified over an empty slice;
    // a panel handed an empty list must not.
    expect(rollupChecks([])).toBe("unavailable");
  });

  it("refuses to say verified unless all three named checks are present", () => {
    const proof = verifiedProof();
    const missing = { ...proof, checks: proof.checks.slice(0, 2) };
    expect(verdictOf(missing, { source: "live" }).verdict).toBe("unavailable");
    const renamed = {
      ...proof,
      checks: [
        { ...proof.checks[0], name: "chain ok" },
        proof.checks[1],
        proof.checks[2],
      ],
    } as typeof proof;
    expect(verdictOf(renamed, { source: "live" }).verdict).toBe("unavailable");
  });

  it("ignores the verdict the response reports and rolls up the checks itself", () => {
    // A server asserting a verdict its own checks contradict is exactly what
    // doc 06 P1 means by "evidence over assertion".
    const lying = proofWithResults(["failed", "verified", "verified"], {
      verdict: "verified",
    });
    expect(lying.verdict).toBe("verified");
    expect(verdictOf(lying, { source: "live" }).verdict).toBe("failed");
  });

  it("keeps unattributed distinct from failed (doc 06 §8 anti-pattern 2)", () => {
    const unattributed = { ...verifiedProof(), verdict: "unattributed" as const, checks: [] };
    expect(verdictOf(unattributed, { source: "live" }).verdict).toBe("unattributed");
  });
});

describe("FE-003 a live check that errored outranks a cached verdict", () => {
  it("renders unavailable when the live check errored, cache notwithstanding", () => {
    const cached = verifiedProof();
    expect(rollupChecks(cached.checks)).toBe("verified");

    const rolled = verdictOf(cached, {
      source: "cache",
      liveError: "dial tcp: connection refused",
    });
    expect(rolled.verdict).toBe("unavailable");
    expect(rolled.derived).toBe("verified");
    expect(rolled.reasons).toContain("live-check-errored");
  });

  it("renders unavailable for a cached verdict even with no error reported", () => {
    // A proof nobody re-checked is not a proof that just passed. The panel is
    // the only component entitled to a green and it spends one only on a live
    // verification.
    const rolled = verdictOf(verifiedProof(), { source: "cache" });
    expect(rolled.verdict).toBe("unavailable");
    expect(rolled.reasons).toContain("not-a-live-check");
  });

  it("renders unavailable when an upstream the check needed was unreachable", () => {
    const proof = proofWithResults(["verified", "verified", "verified"], {
      upstreamsReachable: false,
    });
    expect(rollupChecks(proof.checks)).toBe("verified");
    expect(verdictOf(proof, { source: "live" }).verdict).toBe("unavailable");
    expect(verdictOf(proof, { source: "live" }).reasons).toContain("upstream-unreachable");
  });

  it("renders unavailable when the response contradicts its own material", () => {
    // Live, deliberately: the point of this case is that a contradiction in the
    // response's own material withholds the verdict even when the check was
    // genuinely live. Passing a cache here would prove the weaker thing.
    const rolled = verdictOf(verifiedProof(), { source: "live" }, [
      { name: "the log index is the one the response reports", result: "contradicts" },
    ]);
    expect(rolled.verdict).toBe("unavailable");
    expect(rolled.reasons).toContain("material-contradicted");
  });

  it("leaves a finding that could not be re-derived alone", () => {
    // Underivable is not contradiction. Reading it as one would make every
    // degraded response look like a lying server.
    const rolled = verdictOf(verifiedProof(), { source: "live" }, [
      { name: "the log entry is this commit's artifact", result: "underivable" },
      { name: "the verdict is the rollup of the reported checks", result: "agrees" },
    ]);
    expect(rolled.verdict).toBe("verified");
    expect(rolled.reasons).toEqual([]);
  });

  it("does not launder a failure into unavailable when the live check errored", () => {
    // The downgrade runs one way only. doc 06 §8 anti-pattern 2 forbids
    // collapsing failed into unavailable as firmly as anti-pattern 1 forbids
    // the reverse, and a mismatch that stopped being loud because the network
    // went down is a mismatch nobody acts on.
    const rolled = verdictOf(forgedTrailerProof(), {
      source: "cache",
      liveError: "dial tcp: connection refused",
    });
    expect(rolled.verdict).toBe("failed");
  });

  it("has no default: the caller states the source or does not compile", () => {
    // This case used to assert the opposite — that a caller saying nothing was
    // reporting a live check, because internal/api's Prover holds no cache.
    // That is true of the Prover and irrelevant to the caller: the only thing
    // that knows a proof was retained is the code retaining it, and a default
    // let it report a cache by saying nothing.
    //
    // RM-050's anti-pattern review found the residue. The prop had been made
    // required, but `Liveness.source` was still optional and this function
    // still defaulted its parameter to `{}`, so `liveness={{}}` compiled and
    // painted green. Both are closed now; FE-039 holds the type-level half.
    expect(verdictOf(verifiedProof(), { source: "live" }).verdict).toBe("verified");
    expect(verdictOf(verifiedProof(), { source: "cache" }).verdict).toBe(
      "unavailable",
    );
  });
});
