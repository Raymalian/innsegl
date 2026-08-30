// SPDX-License-Identifier: Apache-2.0

/*
 * Run status badge — doc 06 §3.2, §4.2, §5.3, §6.4. Driven by FE-030.
 *
 *   §3.2: "status badge (Active / Retired / Expired — expired styled
 *   distinctly from retired, since it means an agent died unretired)."
 *
 * Retired and Expired are the pair this component exists to keep apart. They
 * are two different facts — one run ended because something retired it, the
 * other ended because its credential ran out while nothing was watching — and
 * a reader who confuses them draws the wrong conclusion about whether the
 * system is working.
 *
 * doc 06 §5.3 assigns run status to "neutral grays" and reserves colour for
 * verdicts, so the distinction could not have been carried by hue even if that
 * had been the easy route. It is carried by four things a greyscale printout
 * keeps:
 *
 *   - a different word;
 *   - a different icon silhouette (a dashed ring with a clock hand past the
 *     hour, against a closed ring crossed by a bar);
 *   - a dashed outline against a solid one, from
 *     --innsegl-border-style-status-expired;
 *   - a different stated meaning, in the title and to assistive technology.
 *
 * FE-030 asserts this by stripping every class and inline style attribute from
 * both renders and requiring the markup still to differ.
 *
 * A badge is a fact, not a control (P6): no element here is focusable.
 */

import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { strings } from "./strings";
import {
  badgeBase,
  expiredOutline,
  hairline,
  srOnly,
  statusActive,
  statusExpired,
  statusRetired,
} from "./styles";

export type RunStatus = "active" | "retired" | "expired";

const PRESENTATION: Record<
  RunStatus,
  { readonly icon: IconName; readonly tone: string; readonly outline: string }
> = {
  active: { icon: "status-active", tone: statusActive, outline: hairline },
  retired: { icon: "status-retired", tone: statusRetired, outline: hairline },
  expired: { icon: "status-expired", tone: statusExpired, outline: expiredOutline },
};

export interface StatusBadgeProps {
  readonly status: RunStatus;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const { icon, tone, outline } = PRESENTATION[status];
  const { label, meaning } = strings.status[status];

  return (
    <span
      data-status={status}
      title={meaning}
      className={`${badgeBase} ${outline} ${tone}`}
    >
      <Icon name={icon} className="shrink-0" />
      <span>{label}</span>
      {/* The word alone does not tell Retired from Expired for someone who has
       * not read doc 06 §3.2. The meaning does, and it is spoken. */}
      <span className={srOnly}>{meaning}</span>
    </span>
  );
}
