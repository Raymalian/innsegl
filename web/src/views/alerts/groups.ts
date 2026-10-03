// SPDX-License-Identifier: Apache-2.0

/*
 * How the alerts page groups and filters — RM-330 (#506).
 *
 * A group is the alerts that share a cause (explain.ts). One review usually
 * explains a whole group — a run whose harness telemetry stopped raises one
 * witness alert per tool call — so the page offers to resolve a group's open
 * alerts together. An unexplained reason ("other") groups only with the same
 * reason word for word, so resolving a group never closes an alert nobody
 * looked at.
 *
 * Filtering happens here, in the browser, over every alert the feed served:
 * the feed takes no run or resolved filter of its own (internal/api's
 * AlertFilter is event_type only).
 */

import type { AlertsFilters } from "../../app/routes";
import type { AlertRecord } from "../overview/types";
import { alertCause, type AlertCause } from "./explain";

export interface AlertGroup {
  readonly key: string;
  readonly cause: AlertCause;
  /** The newest alert, which names the group in the page. */
  readonly sample: AlertRecord;
  /** The alerts the current kind filter lists, newest first. */
  readonly alerts: readonly AlertRecord[];
  /** Every open alert in the group for the current run filter, whatever the
   * kind filter — what "resolve these" resolves. */
  readonly open: readonly AlertRecord[];
  readonly resolvedCount: number;
}

export interface GroupedAlerts {
  readonly groups: readonly AlertGroup[];
  /** Every run the alerts name, sorted, for the run filter. */
  readonly runs: readonly string[];
}

function groupKey(alert: AlertRecord, cause: AlertCause): string {
  return cause === "other" ? `other:${(alert.reason ?? "").trim()}` : cause;
}

export function groupAlerts(
  alerts: readonly AlertRecord[],
  filters: AlertsFilters,
): GroupedAlerts {
  const runs = [...new Set(alerts.flatMap((a) => (a.run_id ? [a.run_id] : [])))].sort();
  const inRun = filters.run === "" ? alerts : alerts.filter((a) => a.run_id === filters.run);
  const kind = filters.kind === "" ? "open" : filters.kind;

  const byKey = new Map<string, { cause: AlertCause; members: AlertRecord[] }>();
  for (const alert of inRun) {
    const cause = alertCause(alert);
    const key = groupKey(alert, cause);
    const entry = byKey.get(key) ?? { cause, members: [] };
    entry.members.push(alert);
    byKey.set(key, entry);
  }

  const groups: AlertGroup[] = [];
  for (const [key, { cause, members }] of byKey) {
    const newestFirst = members.slice().sort((a, b) => b.chain_position - a.chain_position);
    const listed = newestFirst.filter((a) =>
      kind === "all" ? true : kind === "open" ? !a.resolved : a.resolved,
    );
    if (listed.length === 0) continue;
    groups.push({
      key,
      cause,
      sample: newestFirst[0] as AlertRecord,
      alerts: listed,
      open: newestFirst.filter((a) => !a.resolved),
      resolvedCount: newestFirst.filter((a) => a.resolved).length,
    });
  }

  groups.sort((a, b) => {
    const openFirst = Number(b.open.length > 0) - Number(a.open.length > 0);
    return openFirst !== 0 ? openFirst : b.sample.chain_position - a.sample.chain_position;
  });
  return { groups, runs };
}
