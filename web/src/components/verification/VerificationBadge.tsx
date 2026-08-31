// SPDX-License-Identifier: Apache-2.0

/*
 * The verification badge — doc 06 §4.2's second half.
 *
 *   "Verification: Verified / Failed / Verification unavailable — three
 *    distinct visual treatments (color + icon + label; never color alone)."
 *
 * It lives here rather than in components/common because it carries the one
 * green in the product, and ADR-0038 decision 4 keeps that reachable from one
 * directory. A badge is a rollup and doc 06 §4.1 permits one only where it
 * expands: use `VerificationSummary` in a table, never this on its own.
 *
 * A badge is a fact, not a control (P6). Nothing here is focusable.
 */

import { ProofIcon } from "./ProofIcon";
import { strings } from "./strings";
import {
  badgeBase,
  hairline,
  proofFailed,
  proofNeutral,
  proofUnavailable,
  proofVerified,
  srOnly,
} from "./styles";
import type { Verdict } from "./types";

const TONE: Record<Verdict, string> = {
  verified: proofVerified,
  failed: proofFailed,
  unavailable: proofUnavailable,
  // Not a verdict about cryptography, so not one of the three hues (§5.3).
  unattributed: proofNeutral,
};

export interface VerificationBadgeProps {
  readonly verdict: Verdict;
}

export function VerificationBadge({ verdict }: VerificationBadgeProps) {
  const { label, meaning } = strings.verdict[verdict];
  return (
    <span
      data-verdict={verdict}
      title={meaning}
      className={`${badgeBase} ${hairline} ${TONE[verdict]}`}
    >
      <ProofIcon verdict={verdict} className="shrink-0" />
      <span>{label}</span>
      {/* The word alone does not distinguish "we checked and it is wrong"
       * from "we could not check", which is the distinction doc 06 P2 exists
       * to protect. The meaning is spoken. */}
      <span className={srOnly}>{meaning}</span>
    </span>
  );
}
