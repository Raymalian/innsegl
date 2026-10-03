// SPDX-License-Identifier: Apache-2.0

/*
 * The alerts page — RM-330 (#506).
 *
 * Every alert, open and resolved, grouped by what raised it (groups.ts), each
 * group with what it means, what to do, and its counts. The kind and the run
 * are in the URL (FD §7), set with real buttons and a real select. Every row
 * is a link to the alert's own page. A group with open alerts offers to
 * resolve them together, behind a reason and a fresh passkey (ResolveForm),
 * because one review usually explains a whole group.
 *
 * Presentational: it renders what it is given. `AlertsView` reads.
 */

import { useId, useState } from "react";

import { Link, navigate } from "../../app/router";
import { ALERT_KINDS, type AlertKind, type AlertsFilters } from "../../app/routes";
import { Icon } from "../../components/common/Icon";
import { elapsedSince, formatAbsoluteUtc } from "../../components/common/time";
import type { WebAuthnBrowser } from "../auth/client";
import type { AlertRecord } from "../overview/types";
import { explain } from "./explain";
import { groupAlerts, type AlertGroup } from "./groups";
import { ResolveForm } from "./ResolveForm";
import { strings } from "./strings";
import {
  alarmIcon,
  alertList,
  alertRow,
  alertRowRun,
  alertRowRunId,
  alertRowStatus,
  alertRowTime,
  fieldLabel,
  filterBar,
  groupBody,
  groupCard,
  groupCounts,
  groupHeader,
  groupSubheading,
  groupTitle,
  groupTitleRow,
  heading,
  mutedText,
  openCountBadge,
  page,
  runSelect,
  secondaryButton,
  segment,
  segmented,
  summary,
} from "./styles";
import { alertSummary } from "./summary";

export interface AlertsPageProps {
  readonly alerts: readonly AlertRecord[];
  /** False when the read stopped at its bound before the feed ended. */
  readonly complete: boolean;
  readonly filters: AlertsFilters;
  readonly onResolved: () => void;
  readonly now?: Date;
  readonly browser?: WebAuthnBrowser;
  readonly apiBase?: string;
}

export function AlertsPage({
  alerts,
  complete,
  filters,
  onResolved,
  now,
  browser,
  apiBase,
}: AlertsPageProps) {
  const at = now ?? new Date();
  const { groups, runs } = groupAlerts(alerts, filters);
  const kind: AlertKind = filters.kind === "" ? "open" : filters.kind;

  return (
    <article className={page}>
      <header className="flex flex-col gap-2">
        <h1 className={heading}>{strings.page.heading}</h1>
        <p className={summary}>{strings.page.introDetail}</p>
        {complete ? null : (
          <p className={summary}>{strings.page.incompleteDetail(alerts.length)}</p>
        )}
      </header>

      <Filters filters={filters} kind={kind} runs={runs} />

      {groups.length === 0 ? (
        <p className={summary}>{emptyText(kind, filters.run)}</p>
      ) : (
        groups.map((group) => (
          <Group
            key={group.key}
            group={group}
            now={at}
            onResolved={onResolved}
            {...(browser === undefined ? {} : { browser })}
            {...(apiBase === undefined ? {} : { apiBase })}
          />
        ))
      )}
    </article>
  );
}

function emptyText(kind: AlertKind, run: string): string {
  if (run !== "") return strings.page.emptyRunDetail;
  switch (kind) {
    case "open":
      return strings.page.emptyOpenDetail;
    case "resolved":
      return strings.page.emptyResolvedDetail;
    case "all":
      return strings.page.emptyAllDetail;
  }
}

function Filters({
  filters,
  kind,
  runs,
}: {
  readonly filters: AlertsFilters;
  readonly kind: AlertKind;
  readonly runs: readonly string[];
}) {
  const kindLabelId = useId();
  const runId = useId();
  const go = (next: AlertsFilters) => navigate({ view: "alerts", filters: next });
  const options = filters.run !== "" && !runs.includes(filters.run) ? [...runs, filters.run] : runs;

  return (
    <div role="group" aria-label={strings.page.filtersLabel} className={filterBar}>
      <div className="flex flex-col gap-1">
        <span id={kindLabelId} className={fieldLabel}>
          {strings.page.kindLabel}
        </span>
        <div role="group" aria-labelledby={kindLabelId} className={segmented}>
          {ALERT_KINDS.map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={k === kind}
              className={segment}
              onClick={() => go({ ...filters, kind: k === "open" ? "" : k })}
            >
              {strings.page.kinds[k]}
            </button>
          ))}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={runId} className={fieldLabel}>
          {strings.page.runLabel}
        </label>
        <select
          id={runId}
          className={runSelect}
          value={filters.run}
          onChange={(e) => go({ ...filters, run: e.target.value })}
        >
          <option value="">{strings.page.allRuns}</option>
          {options.map((run) => (
            <option key={run} value={run}>
              {run}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function Group({
  group,
  now,
  onResolved,
  browser,
  apiBase,
}: {
  readonly group: AlertGroup;
  readonly now: Date;
  readonly onResolved: () => void;
  readonly browser?: WebAuthnBrowser;
  readonly apiBase?: string;
}) {
  const titleId = useId();
  const [resolving, setResolving] = useState(false);
  const copy = explain(group.cause);
  const title = group.cause === "other" ? alertSummary(group.sample) : copy.title;
  const openIds = group.open.map((a) => a.event_id);

  return (
    <section aria-labelledby={titleId} className={groupCard}>
      <div className={groupHeader}>
        <div className={groupTitleRow}>
          <h2 id={titleId} className={groupTitle}>
            <Icon name="integrity-alert" className={alarmIcon} />
            {title}
          </h2>
          <span className={groupCounts}>
            {group.open.length > 0 ? (
              <span className={openCountBadge}>{strings.page.openCount(group.open.length)}</span>
            ) : null}
            {group.resolvedCount > 0 ? (
              <span>{strings.page.resolvedCount(group.resolvedCount)}</span>
            ) : null}
          </span>
        </div>
        <div className={groupBody}>
          <div className="flex flex-col gap-1">
            <h3 className={groupSubheading}>{strings.explain.whatHeading}</h3>
            <p className={summary}>{copy.whatDetail}</p>
          </div>
          <div className="flex flex-col gap-1">
            <h3 className={groupSubheading}>{strings.explain.todoHeading}</h3>
            <p className={summary}>{copy.todoDetail}</p>
          </div>
          {openIds.length > 0 ? (
            <div className="flex flex-col items-start gap-3">
              <button
                type="button"
                className={secondaryButton}
                aria-expanded={resolving}
                onClick={() => setResolving((was) => !was)}
              >
                {strings.page.resolveGroupLabel(openIds.length)}
              </button>
              {resolving ? (
                <ResolveForm
                  eventIds={openIds}
                  onResolved={onResolved}
                  {...(browser === undefined ? {} : { browser })}
                  {...(apiBase === undefined ? {} : { apiBase })}
                />
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
      <ul aria-label={strings.page.groupListLabel(title)} className={alertList}>
        {group.alerts.map((alert) => (
          <li key={alert.event_id}>
            <Row alert={alert} now={now} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function Row({ alert, now }: { readonly alert: AlertRecord; readonly now: Date }) {
  const ts = new Date(alert.ts);
  return (
    <Link to={{ view: "alert", eventId: alert.event_id }} className={alertRow}>
      <time dateTime={alert.ts} title={formatAbsoluteUtc(ts)} className={alertRowTime}>
        {strings.menu.ago(elapsedSince(ts, now))}
      </time>
      <span className={alertRowRun}>
        {alert.run_id ? (
          <span className={alertRowRunId}>{alert.run_id}</span>
        ) : (
          <span className={mutedText}>{strings.page.noRunLabel}</span>
        )}
      </span>
      <span className={alertRowStatus}>
        {alert.resolved
          ? strings.page.rowResolvedStatus(alert.resolved_by ?? "")
          : strings.page.rowOpenStatus}
      </span>
    </Link>
  );
}
