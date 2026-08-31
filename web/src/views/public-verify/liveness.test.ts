// SPDX-License-Identifier: Apache-2.0

/*
 * FE-060 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   U | The public page's liveness gate over a proof response | An upstream
 *     the response never mentions withholds the verdict exactly as an
 *     unreachable one does; a response that names both leaves the rollup to
 *     the panel | FD §3.6, P2; IP I5, §6.11
 *
 * ── THE HOLE THIS CLOSES, AND WHY IT IS NOT THE PANEL'S ────────────────────
 *
 * `verdictOf` in components/verification already withholds a green when an
 * upstream is UNREACHABLE, and that covers every response an honest BFF
 * produces: internal/api/proof.go's `collect` reports both upstreams on every
 * answer, reachable or not.
 *
 * It does not cover a response that reports NO upstream at all, because that
 * response contains nothing for `verdictOf` to iterate over — an empty
 * `upstreams` array adds no downgrade reason, and three checks reading
 * "verified" then roll up to a green. That is the database-only verdict in its
 * purest form: a badge asserting a cryptographic fact with no record that
 * anything outside the deployment was ever asked.
 *
 * On a dashboard view the gap is theoretical, because the API and the view
 * ship together. On THIS page it is the whole threat model: doc 06 §1's third
 * audience "trusts nothing about this deployment", and a deployment that
 * wanted to look verified would not send `reachable: false` — it would send
 * nothing and let silence read as assent.
 *
 * So the rule is: ABSENCE IS NOT AN ANSWER. An upstream doc 06 §3.6 names,
 * missing from the response, is treated exactly as one that did not answer.
 * The gate cannot invent a green — it only ever withholds one — so the worst a
 * false positive costs is an honest "verification unavailable", which is the
 * side of P2 this project errs on by design.
 */

import { describe, expect, it } from "vitest";

import type { Proof, Upstream } from "../../components/verification";
import { verdictOf } from "../../components/verification";
import { readProofResponse } from "./response";
import { REQUIRED_UPSTREAMS, livenessOf } from "./liveness";
import { strings, upstreamName } from "./strings";
import { silentUpstreamsProof, wireProof } from "./fixtures";

function proofOf(body: unknown): Proof {
  const reading = readProofResponse(body);
  if (!reading.ok) throw new Error(`fixture is not a proof: ${reading.reason}`);
  return reading.proof;
}

describe("FE-060 the two upstreams doc 06 §3.6 names", () => {
  it("are Fulcio and Rekor, and the spelling is internal/api's", () => {
    expect([...REQUIRED_UPSTREAMS]).toEqual(["fulcio", "rekor"]);
  });
});

describe("FE-060 a response that names both upstreams", () => {
  it("is live, and adds no reason of its own", () => {
    expect(livenessOf(proofOf(wireProof()))).toEqual({ source: "live" });
  });

  it("is still live when an upstream answered that it could not help", () => {
    // Unreachable is the PANEL's downgrade to make, and it makes it. A second
    // reason here would report the same fact twice to the reader.
    const proof = proofOf(wireProof({ fulcioReachable: false, rekorReachable: false }));
    expect(livenessOf(proof)).toEqual({ source: "live" });
    expect(verdictOf(proof, livenessOf(proof)).reasons).toContain("upstream-unreachable");
  });
});

describe("FE-060 a response that does not name an upstream", () => {
  it.each(REQUIRED_UPSTREAMS)("withholds the verdict when %s is absent", (name) => {
    const proof = proofOf(wireProof({ omitUpstreams: [name] }));
    const liveness = livenessOf(proof);
    expect(liveness.source).toBe("live");
    expect(liveness.liveError).toBe(strings.blocked.silent(upstreamName(name)));
  });

  it("names every absent upstream, not the first one", () => {
    const proof = proofOf(silentUpstreamsProof());
    expect(livenessOf(proof).liveError).toBe(strings.blocked.silent("Fulcio, Rekor"));
  });

  it("turns three passing checks into unavailable rather than verified", () => {
    const proof = proofOf(silentUpstreamsProof());
    const rollup = verdictOf(proof, livenessOf(proof));
    expect(rollup.derived).toBe("verified");
    expect(rollup.verdict).toBe("unavailable");
    expect(rollup.reasons).toContain("live-check-errored");
  });

  it("does the same when the array is present and empty", () => {
    const proof: Proof = { ...proofOf(wireProof()), upstreams: [] as readonly Upstream[] };
    expect(verdictOf(proof, livenessOf(proof)).verdict).toBe("unavailable");
  });
});

describe("FE-060 the gate withholds and never grants", () => {
  it("cannot turn a failed verdict into anything else", () => {
    const proof = proofOf(
      wireProof({
        results: ["verified", "verified", "failed"],
        verdict: "failed",
        omitUpstreams: ["fulcio", "rekor"],
      }),
    );
    // doc 06 §8 anti-pattern 2: a mismatch that stopped being loud because the
    // upstream record went missing is a mismatch nobody acts on.
    expect(verdictOf(proof, livenessOf(proof)).verdict).toBe("failed");
  });

  it("leaves a commit that claims nothing unattributed", () => {
    const proof = proofOf({
      ...(wireProof({ verdict: "unattributed" }) as Record<string, unknown>),
      checks: [],
      upstreams: [],
    });
    // VER-006 and E7: a pre-adoption commit is not a failure and not an
    // unavailable check, and collapsing it into either would make every commit
    // from before adoption look like an attack.
    expect(verdictOf(proof, livenessOf(proof)).verdict).toBe("unattributed");
  });
});
