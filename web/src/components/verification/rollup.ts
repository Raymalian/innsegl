// SPDX-License-Identifier: Apache-2.0

/*
 * The verdict the panel renders, and the one function that decides it.
 *
 * doc 06 §4.1 states the rule:
 *
 *   "Any single check failing makes the rollup failed. Any check erroring
 *    (not failing) makes the rollup verification unavailable, never
 *    'verified.'"
 *
 * `rollupChecks` is that rule and nothing else, and it agrees with
 * `internal/verify`'s `rollup` on every input that function can receive. It
 * differs on one input that function cannot: an EMPTY list of checks. Go's
 * rollup is only ever called with the three, so its loop-with-no-iterations
 * returning `verified` is unreachable there; a panel can be handed anything an
 * HTTP response contains, and "no checks ran" is not "three checks passed".
 *
 * ── WHY THERE IS A SECOND FUNCTION ─────────────────────────────────────────
 *
 * §4.1's rule answers "what did the checks say". It does not answer "did
 * anybody ask them", and that is the question doc 06 §8's first anti-pattern
 * is about:
 *
 *   "1. A 'verified' state rendered from cache while the live check errored."
 *
 * A cached green is the most damaging thing this dashboard can do. It asserts
 * a cryptographic fact the system cannot currently confirm, to a reader whose
 * entire reason for being on the page is that they should not have to trust
 * us. So `verdictOf` puts five separate conditions between a set of passing
 * checks and a green, and any one of them alone is enough to withhold it:
 *
 *   not-a-live-check       the proof came from a cache, so nothing was asked
 *   live-check-errored     the live attempt failed, whatever the cache holds
 *   upstream-unreachable   Fulcio or Rekor was not there to answer
 *   material-contradicted  the response disagrees with its own evidence
 *   checks-missing         one of the three named checks is not in the response
 *
 * The downgrade runs ONE WAY. It can only turn `verified` into `unavailable`;
 * it never turns `failed` into anything. doc 06 §8's second anti-pattern
 * forbids collapsing failed and unavailable, and a mismatch that stopped being
 * loud because the network went down is a mismatch nobody acts on (P3).
 *
 * Everything that renders a verdict in this component goes through here. There
 * is no second path by which a badge could reach a colour.
 */

import type { Check, CheckResult, Finding, Proof, Verdict } from "./types";
import { CHECK_IDS, CHECK_NAMES } from "./types";

/** Where the proof in hand came from, and what the live attempt did. */
export interface Liveness {
  /**
   * `live` — this proof is the result of a check that just ran.
   * `cache`  — it is a retained earlier answer.
   *
   * Defaulting to `live` is not optimism: `internal/api`'s Prover runs
   * `internal/verify` on every request and neither of them holds a cache, so a
   * caller with a proof and nothing to say about it has a live one. A caller
   * holding a retained answer has to say so, and the whole of FE-003 is what
   * happens when it does.
   */
  readonly source?: "live" | "cache";
  /** What the live attempt said when it failed. Rendered verbatim (P1). */
  readonly liveError?: string;
}

export type DowngradeReason =
  | "not-a-live-check"
  | "live-check-errored"
  | "upstream-unreachable"
  | "material-contradicted"
  | "checks-missing";

export interface Rollup {
  /** What the panel renders. */
  readonly verdict: Verdict;
  /** What the checks alone said, before liveness was considered. Kept so the
   * panel can explain a downgrade rather than merely perform one. */
  readonly derived: Verdict;
  readonly downgraded: boolean;
  readonly reasons: readonly DowngradeReason[];
  /** The upstream errors and the live error, for the reader. */
  readonly errors: readonly string[];
}

/** doc 06 §4.1's rule over a list of checks, and nothing else. */
export function rollupChecks(checks: readonly Check[]): Verdict {
  if (checks.length === 0) return "unavailable";
  let verdict: CheckResult = "verified";
  for (const check of checks) {
    if (check.result === "failed") return "failed";
    if (check.result === "unavailable") verdict = "unavailable";
  }
  return verdict;
}

/** Whether all three of doc 06 §4.1's named checks are present. */
function allThreePresent(checks: readonly Check[]): boolean {
  const names = new Set(checks.map((check) => check.name));
  return CHECK_IDS.every((id) => names.has(CHECK_NAMES[id]));
}

/**
 * The verdict to render for this proof, given where it came from and what its
 * own material says about it.
 *
 * The proof's own `verdict` field is deliberately NOT consulted, except for
 * `unattributed`, which describes the commit rather than a check and cannot be
 * derived from checks that do not exist. Everything else is rolled up here
 * from the checks in front of the reader — doc 06 P1, evidence over assertion.
 * A server that asserts a verdict its own checks contradict is answered with
 * the checks.
 */
export function verdictOf(
  proof: Proof,
  liveness: Liveness = {},
  findings: readonly Finding[] = [],
): Rollup {
  if (proof.verdict === "unattributed" && proof.checks.length === 0) {
    return {
      verdict: "unattributed",
      derived: "unattributed",
      downgraded: false,
      reasons: [],
      errors: [],
    };
  }

  const derived = rollupChecks(proof.checks);
  const reasons: DowngradeReason[] = [];
  const errors: string[] = [];

  if (liveness.liveError !== undefined && liveness.liveError !== "") {
    reasons.push("live-check-errored");
    errors.push(liveness.liveError);
  }
  if (liveness.source === "cache") reasons.push("not-a-live-check");
  for (const upstream of proof.upstreams) {
    if (upstream.reachable) continue;
    if (!reasons.includes("upstream-unreachable")) reasons.push("upstream-unreachable");
    errors.push(upstream.error ?? upstream.name);
  }
  if (findings.some((finding) => finding.result === "contradicts")) {
    reasons.push("material-contradicted");
    for (const finding of findings) {
      if (finding.result === "contradicts") errors.push(finding.detail ?? finding.name);
    }
  }
  if (!allThreePresent(proof.checks)) reasons.push("checks-missing");

  // One direction only: a green becomes an amber, and nothing becomes a green.
  const verdict: Verdict = derived === "verified" && reasons.length > 0 ? "unavailable" : derived;
  return {
    verdict,
    derived,
    downgraded: verdict !== derived,
    reasons,
    errors,
  };
}
