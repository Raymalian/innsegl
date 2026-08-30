// SPDX-License-Identifier: Apache-2.0

/*
 * Dependency-error state — doc 06 §4.6, §5.3, §6.1, P2. Driven by FE-032.
 *
 *   §4.6: "... its dependency-error state ('Can't reach the ledger — showing
 *   nothing rather than guessing')."
 *
 * Amber, not red. doc 06 §5.3 reserves red for "verification failed or
 * integrity alert" and gives amber to "degraded/unavailable". A ledger that
 * did not answer is the second: rendering it red would tell a reader that
 * something failed verification, which is a far stronger claim than the one
 * the dashboard is in a position to make (P2).
 *
 * Retry is a read. doc 06 P6 forbids mutating controls, and doc 06 §6.1's own
 * model error copy ends "Retry, or verify offline with the material below" —
 * so the button is offered only when the caller can genuinely re-fetch, and it
 * writes nothing.
 */

import { Icon } from "./Icon";
import { strings } from "./strings";
import {
  degraded,
  focusRing,
  hairline,
  link,
  noticeBase,
  noticeBody,
  noticeTitle,
} from "./styles";

export interface ErrorStateProps {
  readonly title?: string;
  readonly detail?: string;
  /** Offered only when the caller can re-run the read. */
  readonly onRetry?: () => void;
  /** P1: put the evidence one click away wherever there is any. */
  readonly evidenceHref?: string;
}

export function ErrorState({
  title,
  detail,
  onRetry,
  evidenceHref,
}: ErrorStateProps) {
  return (
    <div role="alert" className={`${noticeBase} ${hairline} ${degraded}`}>
      <Icon name="unreachable" className="mt-[0.3em] shrink-0" />
      <span className={noticeBody}>
        <span className={noticeTitle}>{title ?? strings.error.title}</span>
        <span>{detail ?? strings.error.detail}</span>
        {onRetry === undefined ? null : (
          <button
            type="button"
            onClick={onRetry}
            className={`rounded-sm underline underline-offset-2 ${focusRing}`}
          >
            {strings.error.retry}
          </button>
        )}
        {evidenceHref === undefined ? null : (
          <a href={evidenceHref} className={link}>
            {strings.error.evidence}
          </a>
        )}
      </span>
    </div>
  );
}
