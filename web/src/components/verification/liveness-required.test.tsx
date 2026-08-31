// SPDX-License-Identifier: Apache-2.0

// FE-039 — the panel cannot be rendered without saying where the proof came
// from.
//
// `liveness` was optional and defaulted to live. The reasoning was that
// `internal/api`'s Prover holds no cache, so a caller with nothing to say has
// a live proof. That is true of the BFF and false of the caller: the Proof
// type carries no cache signal, so a VIEW that retains a response is the only
// thing that knows it did, and under a default it reports a cache by saying
// nothing at all.
//
// The consequence is the failure this panel exists to prevent. doc 06
// anti-pattern 1 and FE-003: a green that no live check confirmed. It is
// silent, it is invisible in review, and no runtime test can find it, because
// the view that forgot is indistinguishable from the view that is genuinely
// live.
//
// So it is required, and this file is what keeps it required. The assertions
// below are type-level: they fail at `tsc --noEmit`, before any of them runs.
// Same move as ADR-0038 decision 3 — a mode that exists in one arm and not the
// other is not something a checker finds, it is something the sheet cannot
// express.

import { describe, expect, it } from "vitest";
import { VerificationPanel } from "./VerificationPanel";
import { VerificationSummary } from "./VerificationSummary";
import { verifiedProof } from "./fixtures";

describe("FE-039 liveness is required, not defaulted", () => {
  it("refuses a panel that will not say where its proof came from", () => {
    const proof = verifiedProof();

    // @ts-expect-error liveness is required: a view that caches and stays
    // quiet must not compile. If this line stops erroring, the prop has been
    // made optional again and FE-003's protection is opt-in.
    const withoutLiveness = <VerificationPanel proof={proof} id="p" />;

    // @ts-expect-error same contract on the summary, which is what a table
    // row renders — the densest place for a stale green to hide.
    const summaryWithout = <VerificationSummary proof={proof} id="p" />;

    // The elements are constructed but never rendered; the assertion above is
    // the compiler's. These keep the bindings used.
    expect(withoutLiveness).toBeDefined();
    expect(summaryWithout).toBeDefined();
  });

  it("accepts both sources when they are stated", () => {
    const proof = verifiedProof();
    expect(
      <VerificationPanel proof={proof} liveness={{ source: "live" }} id="p" />,
    ).toBeDefined();
    expect(
      <VerificationPanel proof={proof} liveness={{ source: "cache" }} id="p" />,
    ).toBeDefined();
  });
});
