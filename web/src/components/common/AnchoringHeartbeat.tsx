// SPDX-License-Identifier: Apache-2.0

/*
 * Anchoring heartbeat — doc 06 §3.1, §5.3, P3. Driven by FE-005.
 *
 *   §3.1: "Anchoring heartbeat in the persistent header (all views): 'Ledger
 *   segment N anchored M min ago.' Exceeding the configured anchoring-lag
 *   bound turns this amber with the lag duration; it is the system's public
 *   tamper-evidence pulse and is never hidden."
 *
 * The header chrome belongs to RM-041 (#49); this is the shared component the
 * header renders, and the amber-with-lag behaviour is here so that every place
 * the pulse appears agrees about when the bound is broken.
 *
 * Three properties are the whole component:
 *
 *   - It always renders. There is no branch that returns null, no prop that
 *     suppresses it, and no state in which it collapses to an icon. "Never
 *     hidden" is a promise about tamper evidence: a heartbeat that can be
 *     turned off is not a heartbeat.
 *   - Beyond the bound it states three numbers, not one — how long since the
 *     anchor, how far past the bound that is, and what the bound was. A reader
 *     who sees only "47 min" cannot tell whether that is a breach.
 *   - Inside the bound it is quiet: neutral secondary text, no amber, no
 *     alert role. P3 — "the healthy state is calm and neutral".
 *
 * Colour: the breach is amber, from the degraded group (doc 06 §5.3, "anchoring
 * lag"). It is never red — red is reserved for verification failure and
 * integrity alerts, and a late anchor is neither — and the calm state is never
 * green, because a segment anchoring on time is not a cryptographic
 * verification (ADR-0038 decision 4).
 */

import type { ReactNode } from "react";
import { Icon } from "./Icon";
import { strings } from "./strings";
import { degraded, hairline, secondaryText } from "./styles";
import {
  elapsedSince,
  formatAbsoluteUtc,
  formatDuration,
  toDateTimeAttribute,
} from "./time";

export interface AnchoringHeartbeatProps {
  /** The most recently anchored segment, or null if none has been. */
  readonly segment: number | null;
  readonly anchoredAt: Date | null;
  /** The configured anchoring-lag bound (doc 06 §3.1). */
  readonly lagBoundMs: number;
  /** Injected for determinism; defaults to the wall clock. */
  readonly now?: Date;
}

type HeartbeatState = "within-bound" | "beyond-bound" | "unknown";

export function AnchoringHeartbeat({
  segment,
  anchoredAt,
  lagBoundMs,
  now,
}: AnchoringHeartbeatProps) {
  const at = now ?? new Date();

  /* Nothing anchored yet is neither healthy nor a breach, and P2 forbids
   * collapsing it into either. It is reported as the fact it is, in neutral
   * text: on a fresh deployment there is genuinely nothing to be late. */
  if (anchoredAt === null || segment === null) {
    return (
      <Shell state="unknown" tone={secondaryText}>
        <Icon name="unknown" className="shrink-0" />
        <span>{strings.heartbeat.unknown}</span>
      </Shell>
    );
  }

  const lagMs = at.getTime() - anchoredAt.getTime();
  const beyond = lagMs > lagBoundMs;
  const ago = elapsedSince(anchoredAt, at);

  const timestamp = (
    <time
      dateTime={toDateTimeAttribute(anchoredAt)}
      title={formatAbsoluteUtc(anchoredAt)}
      className="font-mono"
    >
      {`${ago} ago`}
    </time>
  );

  if (!beyond) {
    return (
      <Shell state="within-bound" tone={secondaryText}>
        <Icon name="anchor-pulse" className="shrink-0" />
        <span>
          {`Ledger segment ${segment} anchored `}
          {timestamp}
        </span>
      </Shell>
    );
  }

  const over = formatDuration(lagMs - lagBoundMs);
  const bound = formatDuration(lagBoundMs);
  return (
    <Shell state="beyond-bound" tone={`${degraded} ${hairline} px-2`}>
      <Icon name="anchor-lag" className="shrink-0" />
      <span>
        {`Ledger segment ${segment} anchored `}
        {timestamp}
        {` — ${over} beyond the ${bound} anchoring-lag bound`}
      </span>
    </Shell>
  );
}

function Shell({
  state,
  tone,
  children,
}: {
  readonly state: HeartbeatState;
  readonly tone: string;
  readonly children: ReactNode;
}) {
  return (
    <p
      data-testid="anchoring-heartbeat"
      data-state={state}
      aria-label={strings.heartbeat.regionLabel}
      className={`inline-flex items-center gap-2 rounded-md py-1 text-body leading-tight ${tone}`}
    >
      {children}
    </p>
  );
}
