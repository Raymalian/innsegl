// SPDX-License-Identifier: Apache-2.0

/*
 * The shape beside every verdict — doc 06 §5.3, §6.4.
 *
 *   "Every semantic color is paired with an icon and a text label."
 *   "Never color alone."
 *
 * Three of the four shapes already exist in components/common's icon set and
 * are used from there rather than redrawn: the triangle for a failure, the
 * questioned ring for a check that could not run, and the ruled block for a
 * commit that claims nothing. The fourth does not exist, because the shared
 * set deliberately contains no mark of approval — nothing in that directory is
 * a cryptographic verification, and RM-042 said so in as many words. So it is
 * drawn here, in the one component entitled to render one.
 *
 * It follows every convention of the shared set: inline, `currentColor`,
 * `aria-hidden`, one 16x16 viewBox, and a silhouette that differs from the
 * other three with no colour at all — a ring with a tick inside it, against a
 * triangle, a questioned ring and a set of rules.
 */

import { Icon } from "../common/Icon";
import type { IconName } from "../common/Icon";
import type { Verdict } from "./types";

const SHARED: Record<Exclude<Verdict, "verified">, IconName> = {
  failed: "integrity-alert",
  unavailable: "unknown",
  unattributed: "empty",
};

export interface ProofIconProps {
  readonly verdict: Verdict;
  /** Size and spacing only. Colour arrives through `currentColor`. */
  readonly className?: string;
}

export function ProofIcon({ verdict, className }: ProofIconProps) {
  if (verdict !== "verified") {
    return <Icon name={SHARED[verdict]} className={className} />;
  }
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      data-icon="verification-mark"
      viewBox="0 0 16 16"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <circle cx="8" cy="8" r="5.5" />
      <path d="M5.25 8.25 7.25 10.25 10.75 5.75" />
    </svg>
  );
}
