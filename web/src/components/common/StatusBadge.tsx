// SPDX-License-Identifier: Apache-2.0

/*
 * The run's lifecycle state — doc 06 §3.2, §4.2, §5.3, §6.4. FE-030, FE-129.
 *
 * ── FOUR STATES, AND WHY DOC 06 NAMES THREE ────────────────────────────────
 *
 * doc 06 §3.2 says "Active / Retired / Expired — expired styled distinctly
 * from retired, since it means an agent died unretired". #256 keeps the first
 * half of that sentence and refuses the second: the system cannot observe an
 * agent ending. An agent waiting on a provider usage limit, running a long
 * build, or on a sleeping machine is silent and alive, and the reaper
 * withdrawing a credential is this system acting on silence rather than a
 * death it witnessed. The conflict with §3.2 is reported to the human, not
 * resolved by editing the specification.
 *
 * So the one word becomes two, and the three become four:
 *
 *   Active     the newest fact recorded for this run is not a withdrawal.
 *   Lapsed     it is a withdrawal, and the identity can still be restored.
 *   Abandoned  it is a withdrawal, and the restore horizon has passed.
 *   Retired    something ended the run. Someone said stop.
 *
 * Every one of the four is a consequence of recorded facts and their order —
 * see internal/api/query.go. None is a guess with better manners.
 *
 * ── NONE OF IT IS CARRIED BY HUE ───────────────────────────────────────────
 *
 * doc 06 §5.3 assigns run state to "neutral grays" and reserves colour for
 * verdicts, so the distinction could not have been carried by hue even if that
 * had been the easy route. It is carried by three things a greyscale printout
 * keeps:
 *
 *   - a different word;
 *   - a different icon silhouette (a filled disc, a closed ring crossed by a
 *     bar, a dashed ring with a clock hand, that same ring with the horizon
 *     drawn through it);
 *   - a dashed outline on the two withdrawn states against a solid one on the
 *     two that were not, from --innsegl-border-style-status-expired;
 *
 * and by a fourth a screen reader keeps: a different stated meaning, in the
 * title and in the description spoken after the word.
 *
 * FE-129 asserts this by stripping every perceptible presentation attribute
 * from all four renders and requiring the markup still to differ four ways.
 *
 * A badge is a fact, not a control (P6): no element here is focusable.
 */

import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { strings } from "./strings";
import {
  badgeBase,
  hairline,
  srOnly,
  statusActive,
  statusRetired,
  statusWithdrawn,
  withdrawnOutline,
} from "./styles";

/** The four, spelled as internal/api spells them. `app/routes.ts` holds the
 * same set for the URL; FE-129 asserts the two are one list. */
export type RunStatus = "active" | "lapsed" | "abandoned" | "retired";

const PRESENTATION: Record<
  RunStatus,
  { readonly icon: IconName; readonly tone: string; readonly outline: string }
> = {
  active: { icon: "status-active", tone: statusActive, outline: hairline },
  lapsed: {
    icon: "status-lapsed",
    tone: statusWithdrawn,
    outline: withdrawnOutline,
  },
  /* The quieter tone of Retired, because there is nothing further to expect
   * from either; the dashed outline of Lapsed, because the reaper wrote this
   * one and nobody said stop. It is told from both by its word and its icon. */
  abandoned: {
    icon: "status-abandoned",
    tone: statusRetired,
    outline: withdrawnOutline,
  },
  retired: { icon: "status-retired", tone: statusRetired, outline: hairline },
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
      {/* The word alone does not tell Lapsed from Abandoned for someone who
       * has not read #256. The meaning does, and it is spoken. */}
      <span className={srOnly}>{meaning}</span>
    </span>
  );
}
