// SPDX-License-Identifier: Apache-2.0

/*
 * Loading state — doc 06 §4.6, §8 anti-pattern 8. Driven by FE-011.
 *
 *   §4.6: "No blank panels, no infinite spinners: loading states time out into
 *   an explicit error."
 *   §8.8: "Spinners without timeout-to-error." — a defect if found in review.
 *
 * The bound is the component. A loading indicator that *can* show an error is
 * still an infinite spinner if nothing ever tells it to: the timer has to be
 * owned here, so that every caller gets the bound whether or not it thought
 * about one. Hence `timeoutMs` has a default and the timeout fires without any
 * cooperation from the data layer.
 *
 * Two smaller decisions:
 *
 *   - Nothing spins. ADR-0038 decision 4 removed every keyframe animation from
 *     the theme and doc 06 §5.5 allows motion for "state transitions and focus
 *     movement only", so "loading" is carried by a label and three static
 *     dots. The one state transition this component makes is into the error.
 *   - The timed-out state is amber, not red (doc 06 §5.3): a dependency that
 *     did not answer is degraded/unavailable. Red would say a verification
 *     failed, which is a different and much stronger claim (P2).
 *
 * Retry is a read, not a write, so it does not offend P6 — doc 06 §6.1's own
 * example error copy ends "Retry, or verify offline with the material below."
 */

import { useEffect, useState } from "react";
import { Icon } from "./Icon";
import { strings } from "./strings";
import { degraded, focusRing, hairline, mutedText, noticeBase } from "./styles";
import { formatDuration } from "./time";

/** The bound a caller gets for free. Long enough for a cold hot-tier query,
 * short enough that a reader is not left guessing. */
export const DEFAULT_TIMEOUT_MS = 15_000;

export interface LoadingStateProps {
  /** What is being fetched, as a noun phrase: "runs", "the run timeline". */
  readonly what: string;
  readonly timeoutMs?: number;
  /** Told once, when the bound is broken. */
  readonly onTimeout?: () => void;
  /** Offered to the reader only if the caller can actually retry. */
  readonly onRetry?: () => void;
}

export function LoadingState({
  what,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  onTimeout,
  onRetry,
}: LoadingStateProps) {
  const [timedOut, setTimedOut] = useState(false);

  useEffect(() => {
    if (timedOut) return undefined;
    const timer = setTimeout(() => setTimedOut(true), timeoutMs);
    return () => clearTimeout(timer);
  }, [timedOut, timeoutMs]);

  useEffect(() => {
    if (timedOut) onTimeout?.();
  }, [timedOut, onTimeout]);

  if (!timedOut) {
    return (
      <p
        role="status"
        aria-busy="true"
        className={`${noticeBase} ${mutedText}`}
      >
        <Icon name="busy" className="mt-[0.3em] shrink-0" />
        <span>{strings.loading.busy(what)}</span>
      </p>
    );
  }

  return (
    <div role="alert" className={`${noticeBase} ${hairline} ${degraded}`}>
      <Icon name="unreachable" className="mt-[0.15em] shrink-0" />
      <span className="flex flex-col items-start gap-2">
        <span>{strings.loading.timedOut(what, formatDuration(timeoutMs))}</span>
        {onRetry === undefined ? null : (
          <button
            type="button"
            onClick={onRetry}
            className={`rounded-sm px-2 py-1 underline underline-offset-2 ${focusRing}`}
          >
            {strings.loading.retry}
          </button>
        )}
      </span>
    </div>
  );
}
