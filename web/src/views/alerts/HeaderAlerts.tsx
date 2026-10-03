// SPDX-License-Identifier: Apache-2.0

/*
 * The notification menu, wired — ADR-0054.
 *
 * What `App` puts in its header's `alerts` slot. It reads for itself, so the
 * menu works on every view and not only on the one that happens to have read
 * the alerts feed; `useOpenAlerts` says what it reads and how it degrades.
 */

import { DEFAULT_API_BASE } from "../overview/data";
import { DEFAULT_POLL_MS, useOpenAlerts } from "./data";
import { NotificationMenu } from "./NotificationMenu";

export interface HeaderAlertsProps {
  readonly apiBase?: string;
  /** How often to read again; 0 reads once. */
  readonly pollMs?: number;
  /** Injected for determinism; defaults to the wall clock. */
  readonly now?: Date;
}

export function HeaderAlerts({
  apiBase = DEFAULT_API_BASE,
  pollMs = DEFAULT_POLL_MS,
  now,
}: HeaderAlertsProps = {}) {
  const { loading, alerts, openCount } = useOpenAlerts({ base: apiBase, pollMs });
  return (
    <NotificationMenu
      alerts={alerts}
      openCount={openCount}
      loading={loading}
      {...(now === undefined ? {} : { now })}
    />
  );
}
