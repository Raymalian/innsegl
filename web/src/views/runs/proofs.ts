// SPDX-License-Identifier: Apache-2.0

/*
 * How a verification reaches a row of the runs table.
 *
 * ── WHY THE TABLE DOES NOT VERIFY ──────────────────────────────────────────
 *
 * doc 06 §3.2 asks the commits column to carry "per-run verification rollup".
 * A verification in this product is three LIVE checks against Fulcio and Rekor
 * per commit (doc 06 §4.1, IP §6.11), and internal/api's runs endpoint returns
 * no verdict at all — deliberately, because a verdict read out of the database
 * is the thing IP §6.11 and doc 06 P2 forbid. So a page of 50 runs cannot be
 * rolled up without 50 runs' worth of commits' worth of live round trips,
 * which doc 06 §7's three-second budget does not have room for.
 *
 * This view therefore performs no verification and invents no verdict. A
 * caller that HAS proofs — the run detail view, a future BFF that batches
 * them — hands them in through `RunProofSource`; a row with none says in as
 * many words that no check ran for it, and shows no badge at all. doc 06 P2's
 * three states are verified, failed and unavailable, and "nobody asked" is
 * none of the three: rendering it as one would be a claim about a check that
 * never happened.
 *
 * ── LIVENESS IS STATED, NOT ASSUMED ────────────────────────────────────────
 *
 * `VerificationPanel` and `VerificationSummary` already require a `liveness`
 * prop with no default (FE-039), which stops a view that caches from staying
 * silent. `Liveness.source` itself is still optional, so `{}` compiles and
 * means live.
 *
 * A runs table is the most likely thing in this product to end up behind a
 * cache, and its rollups are the densest place a stale green can hide. So this
 * directory narrows the contract: a proof handed to a row must state its
 * source explicitly. `{}` does not compile here. A caller that retains
 * responses has to write `{ source: "cache" }`, and the downgrade in
 * `verdictOf` does the rest — doc 06 §8 anti-pattern 1, made a type error
 * rather than a review item.
 */

import type {
  Finding,
  Liveness,
  Proof,
} from "../../components/verification";
import type { RunSummary } from "./api";

/** `Liveness` with the source spelled out. There is no default and no silence. */
export interface StatedLiveness extends Liveness {
  readonly source: "live" | "cache";
}

/** One commit's proof, and where it came from. */
export interface CommitProof {
  readonly proof: Proof;
  readonly liveness: StatedLiveness;
  /** internal/api's re-derivation against the response's own material. */
  readonly findings?: readonly Finding[];
}

/**
 * The proofs a caller holds for one run's commits, if it holds any.
 *
 * Synchronous on purpose: this view does not fetch verifications, so there is
 * nothing here for a promise to be waiting on. A caller that wants to fetch
 * them owns that fetch, and owns saying whether what it hands over is live.
 */
export type RunProofSource = (run: RunSummary) => readonly CommitProof[];
