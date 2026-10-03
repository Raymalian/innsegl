// SPDX-License-Identifier: Apache-2.0

/**
 * How long a run was active, and whether an active run is idle.
 *
 * "Active" is the ledger's word: no retirement and no standing withdrawal. A
 * session killed without its end hook stays active until the silence
 * backstop retires it, days later (ADR-0058 decision 7c). Idle says what the
 * page does know about such a run: nothing has been recorded for it lately.
 * The bound is the query API's own (internal/api DefaultIdleAfter), so the
 * Overview's idle count and these badges agree.
 */

import { formatDuration } from "../../components/common/time";
import type { RunStatus } from "../../components/common/StatusBadge";

/** internal/api's DefaultIdleAfter. */
export const IDLE_AFTER_MS = 15 * 60_000;

/** The time from registration to the newest activity, or null when either
 * time is unreadable. */
export function activeFor(registeredAt: string, lastEventAt: string): string | null {
  const start = Date.parse(registeredAt);
  const last = Date.parse(lastEventAt);
  if (Number.isNaN(start) || Number.isNaN(last)) return null;
  return formatDuration(last - start);
}

/** Whether an active run has recorded nothing for IDLE_AFTER_MS. */
export function isIdle(status: RunStatus, lastEventAt: string, now: Date): boolean {
  if (status !== "active") return false;
  const last = Date.parse(lastEventAt);
  if (Number.isNaN(last)) return false;
  return now.getTime() - last >= IDLE_AFTER_MS;
}
