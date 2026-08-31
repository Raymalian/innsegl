// SPDX-License-Identifier: Apache-2.0

/*
 * The rollup badge a table shows, and the panel behind it.
 *
 * doc 06 §4.1: "a summary badge may roll them up in tables but always expands
 * to the panel." doc 06 §8's anti-pattern 4 is the same sentence read as a
 * defect: "A verification summary that cannot be expanded to the three checks
 * and their inputs."
 *
 * So this component exists to make the expansion structural rather than
 * remembered. There is no prop that turns the panel off and no variant that
 * renders the badge alone: a table author who reaches for a summary gets the
 * three checks with it, and the only way to ship anti-pattern 4 is to write a
 * different component on purpose.
 *
 * It is a native <details>. doc 06 §6.4 requires expandable panels to be
 * keyboard-operable with visible focus, and a disclosure the browser
 * implements needs no JavaScript to satisfy that — which also keeps doc 06
 * §7's payload budget for the public verification page.
 */

import { VerificationPanel } from "./VerificationPanel";
import type { VerificationPanelProps } from "./VerificationPanel";
import { VerificationBadge } from "./VerificationBadge";
import { verdictOf } from "./rollup";
import { focusRing, hairline } from "./styles";

export type VerificationSummaryProps = VerificationPanelProps;

export function VerificationSummary({
  proof,
  liveness,
  findings,
  id,
}: VerificationSummaryProps) {
  const rollup = verdictOf(proof, liveness, findings);
  return (
    <details className={`${hairline} rounded-md`}>
      <summary className={`${focusRing} cursor-pointer list-none p-2`}>
        <VerificationBadge verdict={rollup.verdict} />
      </summary>
      <VerificationPanel proof={proof} liveness={liveness} findings={findings} id={id} />
    </details>
  );
}
