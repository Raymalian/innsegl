// SPDX-License-Identifier: Apache-2.0

/*
 * One metric card — doc 06 §3.1, §5.3, §5.4, §6.2, §6.4.
 *
 * Three properties, and the second and third are the ones that matter.
 *
 * THE NUMBER ARRIVES FORMATTED. This component never touches a value: it takes
 * a string a caller produced through `format.ts`, so there is no arithmetic
 * here that could round, scale or abbreviate one. doc 06 §6.2 asks for exact
 * counts and §8's tenth anti-pattern is about metrics that flatter; both are
 * properties of the number, so both are governed where the number is made.
 *
 * THE MEANING TRAVELS WITH THE CLAIM. `meaning` is not optional. doc 06 §8
 * anti-pattern 10 names "cumulative counts with no window" as a defect, and a
 * card that cannot say what it counted over is that defect by construction. P1
 * says the same thing more generally: a number with no statement of what it
 * measures is an assertion.
 *
 * COLOUR IS NEVER ALONE. A tone that carries a claim carries an icon with it
 * (doc 06 §6.4), and the icon is derived from the tone rather than passed in,
 * so there is no call site that can spend the colour and forget the icon.
 *
 * There is no `verified` tone and no way to add one by accident: doc 06 §5.3
 * gives green to cryptographic verification, this view performs none, and
 * `styles.ts` names no green for this file to reach.
 */

import type { ReactNode } from "react";

import { Icon } from "../../components/common";
import type { IconName } from "../../components/common";
import {
  cardBase,
  cardLabel,
  cardMeaning,
  cardValue,
  degraded,
  hairline,
  integrityAlert,
  mutedText,
  neutralSurface,
  secondaryText,
  srOnly,
} from "./styles";

/** What the card is claiming, in doc 06 §5.3's vocabulary. */
export type MetricTone = "neutral" | "degraded" | "alert";

const PRESENTATION: Record<
  MetricTone,
  {
    readonly surface: string;
    readonly label: string;
    readonly meaning: string;
    readonly icon?: IconName;
  }
> = {
  /* A count of rows in a ledger is not a verdict about anything. */
  neutral: { surface: neutralSurface, label: secondaryText, meaning: mutedText },
  /* Amber: unavailable, lagging or stale (doc 06 §5.3). */
  degraded: {
    surface: degraded,
    label: "",
    meaning: "",
    icon: "unknown",
  },
  /* Red, filled: the P3 alarm. */
  alert: {
    surface: integrityAlert,
    label: "",
    meaning: "",
    icon: "integrity-alert",
  },
};

export interface MetricCardProps {
  /** Stable, and the test hook. Not rendered. */
  readonly id: string;
  readonly label: string;
  /** Already formatted (see `format.ts`). */
  readonly value: string;
  /** What the number counts, and over what window. Required. */
  readonly meaning: string;
  /** doc 06 §6.2's hover. Announced as well as shown, because a fact only a
   * mouse can reach is a fact some readers do not have. */
  readonly hover?: string;
  readonly tone?: MetricTone;
  /** Further evidence lines: a breakdown, a link to the material. */
  readonly children?: ReactNode;
}

export function MetricCard({
  id,
  label,
  value,
  meaning,
  hover,
  tone = "neutral",
  children,
}: MetricCardProps) {
  const skin = PRESENTATION[tone];
  return (
    <article
      data-testid={`metric-${id}`}
      data-tone={tone}
      className={`${cardBase} ${hairline} ${skin.surface}`}
    >
      <h2 className={`${cardLabel} ${skin.label}`}>{label}</h2>
      <p className={cardValue} title={hover}>
        {skin.icon === undefined ? null : (
          <Icon name={skin.icon} className="mr-2 inline-block shrink-0 align-baseline" />
        )}
        {value}
        {hover === undefined ? null : <span className={srOnly}>{hover}</span>}
      </p>
      <p className={`${cardMeaning} ${skin.meaning}`}>{meaning}</p>
      {children}
    </article>
  );
}
