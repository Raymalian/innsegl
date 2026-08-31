// SPDX-License-Identifier: Apache-2.0

/*
 * The liveness gate — the fourth thing standing between this page and a
 * database-only verdict, and the only one the three-check panel cannot supply.
 *
 * doc 06 §3.6: the page "performs LIVE checks against Fulcio/Rekor. If they
 * are unreachable, it says exactly that (P2) and offers nothing database-only
 * in their place." IP I5: "Verification never trusts this system."
 *
 * `verdictOf` in components/verification already withholds a green when a
 * reported upstream is UNREACHABLE. It cannot withhold one for an upstream the
 * response never reported, because there is nothing in the response to iterate
 * over: an empty `upstreams` array produces no downgrade reason, and three
 * checks reading "verified" then roll up to a green with no record that
 * anything outside the deployment was consulted.
 *
 * Every response internal/api produces names both upstreams, so on a dashboard
 * view — where the API and the view ship together — the gap is theoretical.
 * On this page it is the threat model. doc 06 §1's third audience "trusts
 * nothing about this deployment", and a deployment that wanted to look
 * verified would not send `reachable: false`; it would send nothing, and let
 * silence be read as assent.
 *
 * THE RULE: absence is not an answer. An upstream doc 06 §3.6 names, missing
 * from the response, is treated exactly as an upstream that did not answer.
 *
 * The gate runs ONE WAY, like the panel's own downgrade: it can only withhold
 * a verdict, never grant one, so a false positive costs an honest
 * "verification unavailable" rather than a false green. FE-060 asserts both
 * directions, including that a `failed` stays failed (doc 06 §8 anti-pattern
 * 2) and that an `unattributed` commit stays unattributed (VER-006, E7).
 *
 * `source` is always `"live"` here, and that is a statement about the client
 * rather than a default: this view holds no cache, and its rendered phase is
 * keyed on the request and reset during render, so the proof in hand was
 * produced by the request currently on screen. `liveness` is required by
 * components/verification precisely so that a view which DID retain a response
 * has to say so; if this page ever gains a cache, this is the function that
 * has to change and FE-060 is what will notice.
 */

import type { Liveness, Proof } from "../../components/verification";
import { strings, upstreamName } from "./strings";

/** The two upstreams doc 06 §3.6 names by hand. Spelled as
 * `internal/api/proof.go`'s UpstreamFulcio and UpstreamRekor spell them. */
export const REQUIRED_UPSTREAMS = ["fulcio", "rekor"] as const;

/** The named upstreams this response says nothing at all about. */
export function unreportedUpstreams(proof: Proof): readonly string[] {
  const reported = new Set(proof.upstreams.map((upstream) => upstream.name));
  return REQUIRED_UPSTREAMS.filter((name) => !reported.has(name));
}

/**
 * Where the proof in hand came from, and what the live attempt did.
 *
 * A response missing a named upstream carries a `liveError`, which is one of
 * the five conditions `verdictOf` puts between a set of passing checks and a
 * green. The sentence is the one the reader sees, so it comes from the
 * catalogue rather than being assembled here.
 */
export function livenessOf(proof: Proof): Liveness {
  const unreported = unreportedUpstreams(proof);
  if (unreported.length === 0) return { source: "live" };
  return {
    source: "live",
    liveError: strings.blocked.silent(unreported.map(upstreamName).join(", ")),
  };
}
