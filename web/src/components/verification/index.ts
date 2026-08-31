// SPDX-License-Identifier: Apache-2.0

/*
 * The three-check verification panel — doc 06 §4.1, issue #51.
 *
 * Everything the five remaining views need in order to render a verification,
 * and nothing they need in order to render one badly: there is no exported
 * badge that skips the panel except `VerificationBadge`, which
 * `VerificationSummary` uses and which a table should not reach for on its own
 * (doc 06 §8 anti-pattern 4).
 *
 * This is the only directory in the product that spends a green, and
 * `styles.ts` is the only file in it that names one.
 */

export { VerificationPanel } from "./VerificationPanel";
export type { VerificationPanelProps } from "./VerificationPanel";

export { VerificationSummary } from "./VerificationSummary";
export type { VerificationSummaryProps } from "./VerificationSummary";

export { VerificationBadge } from "./VerificationBadge";
export type { VerificationBadgeProps } from "./VerificationBadge";

export { IdentityComparison } from "./IdentityComparison";
export type { IdentityComparisonProps } from "./IdentityComparison";

export { ProofIcon } from "./ProofIcon";
export type { ProofIconProps } from "./ProofIcon";

export { rollupChecks, verdictOf } from "./rollup";
export type { DowngradeReason, Liveness, Rollup } from "./rollup";

export { SPIFFE_SEGMENT_NAMES, diffIdentity, segmentsOf, splitSPIFFEID } from "./identity";
export type { IdentityDiff, Segment, SegmentName } from "./identity";

export { CHECK_IDS, CHECK_NAMES, checkIdOf } from "./types";
export type {
  Agreement,
  CertificateInfo,
  Check,
  CheckId,
  CheckResult,
  Claim,
  EntryInfo,
  Fact,
  Finding,
  Gap,
  Material,
  Proof,
  Recovered,
  Upstream,
  Verdict,
} from "./types";

export { strings } from "./strings";
export type { VerificationStrings } from "./strings";
