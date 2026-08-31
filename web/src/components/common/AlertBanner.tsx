// SPDX-License-Identifier: Apache-2.0

/*
 * Alert banner — doc 06 §4.5, §3.1, P1, P3, §6.4. Driven by FE-031.
 *
 *   §4.5: "For drift detection, chain-verification failure, and anchoring-lag
 *   breach. Page-level, persistent until the underlying condition clears,
 *   links directly to the evidence."
 *   P3: "Failure is loud... Design the alarm first; the calm state is what's
 *   left."
 *
 * "Persistent until the underlying condition clears" is a statement about who
 * may remove the banner, and the shape of this component is the enforcement:
 * it takes the alerts that currently hold and renders them. There is no
 * dismiss control, no `onClose`, and no internal open/closed state — so the
 * only thing that can make a drift alert disappear is the drift being gone.
 * A close button would let a reader clear the alarm without clearing the
 * condition, which is the failure mode P3 is written against.
 *
 * Two kinds, because doc 06 §5.3 gives two different colours to the three
 * conditions §4.5 lists:
 *
 *   integrity — drift detection and chain-verification failure. Red, filled,
 *               the most dominant thing on the page.
 *   degraded  — anchoring-lag breach. Amber: the system is behind, not broken,
 *               and calling it red would overstate what is known (P2).
 *
 * P1 supplies the link: every alert points at the material behind the claim.
 */

import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { strings } from "./strings";
import {
  degraded,
  hairline,
  integrityAlert,
  linkOnFill,
  noticeBase,
  noticeBody,
  noticeTitle,
} from "./styles";

export type AlertKind = "integrity" | "degraded";

export interface Alert {
  /** Stable across re-renders while the condition holds. */
  readonly id: string;
  readonly kind: AlertKind;
  readonly title: string;
  readonly detail: string;
  /** P1: the material behind the claim. Required — an alert with no evidence
   * is an assertion, which is what P1 exists to forbid. */
  readonly evidenceHref: string;
  readonly evidenceLabel?: string;
}

const PRESENTATION: Record<
  AlertKind,
  { readonly icon: IconName; readonly tone: string }
> = {
  integrity: { icon: "integrity-alert", tone: integrityAlert },
  degraded: { icon: "anchor-lag", tone: degraded },
};

export interface AlertBannerProps {
  /** Every condition that currently holds. Empty renders nothing. */
  readonly alerts: readonly Alert[];
}

export function AlertBanner({ alerts }: AlertBannerProps) {
  if (alerts.length === 0) return null;
  return (
    <div className="flex flex-col gap-2" aria-label={strings.alert.regionLabel}>
      {alerts.map((alert) => (
        <Banner key={alert.id} alert={alert} />
      ))}
    </div>
  );
}

function Banner({ alert }: { readonly alert: Alert }) {
  const { icon, tone } = PRESENTATION[alert.kind];
  return (
    <div
      role="alert"
      data-alert-kind={alert.kind}
      className={`${noticeBase} ${hairline} ${tone}`}
    >
      <Icon name={icon} className="mt-[0.3em] shrink-0" />
      <span className={noticeBody}>
        <span className={noticeTitle}>{alert.title}</span>
        <span>{alert.detail}</span>
        <a href={alert.evidenceHref} className={linkOnFill}>
          {alert.evidenceLabel ?? strings.alert.evidence}
        </a>
      </span>
    </div>
  );
}
