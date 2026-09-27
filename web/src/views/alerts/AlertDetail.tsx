// SPDX-License-Identifier: Apache-2.0

/*
 * One alert, in full — ADR-0054, doc 06 P1, P4, §4.3.
 *
 * The menu in the header says what happened in one line. This says all of
 * it: every field the alerts feed carries for this event, each in a readable
 * form, the long identifiers in chips that copy the whole value, and the link
 * to the raw record behind it (P1). Presentational; `AlertDetailView` reads.
 *
 * It offers no action. ADR-0044: the dashboard is read-only, and the status
 * line says who can resolve an alert and where, rather than a button that
 * cannot work.
 */

import { useId, type ReactNode } from "react";

import { Link } from "../../app/router";
import { routeToPath } from "../../app/routes";
import { Icon } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import { elapsedSince, formatAbsoluteUtc } from "../../components/common/time";
import type { AlertRecord } from "../overview/types";
import { strings } from "./strings";
import {
  commandBox,
  evidence,
  evidenceHeading,
  factRow,
  factTerm,
  factValue,
  facts,
  heading,
  link,
  mutedText,
  page,
  summary,
} from "./styles";
import { alertSummary, alertTitle } from "./summary";

export interface AlertDetailProps {
  readonly alert: AlertRecord;
  readonly apiBase: string;
  readonly now?: Date;
}

export function AlertDetail({ alert, apiBase, now }: AlertDetailProps) {
  const at = now ?? new Date();
  const ts = new Date(alert.ts);
  const drift = alert.event_type === "ledger_drift_detected";

  return (
    <article className={page}>
      <header className="flex flex-col gap-2">
        <h1 className={heading}>
          <Icon name="integrity-alert" className="shrink-0" />
          {alertTitle(alert)}
        </h1>
        <p className={summary}>{alertSummary(alert)}</p>
      </header>

      <dl aria-label={strings.detail.factsLabel} className={facts}>
        <Fact label={strings.detail.statusLabel}>
          <Status alert={alert} />
        </Fact>
        <Fact label={strings.detail.recordedLabel}>
          <time dateTime={alert.ts}>{formatAbsoluteUtc(ts)}</time>{" "}
          <span className={mutedText}>{strings.menu.ago(elapsedSince(ts, at))}</span>
        </Fact>
        <Fact label={strings.detail.runLabel}>
          {alert.run_id ? (
            <IdentifierChip
              value={alert.run_id}
              kind="run"
              href={routeToPath({ view: "run", runId: alert.run_id })}
            />
          ) : (
            strings.detail.noRun
          )}
        </Fact>
        {drift ? (
          <>
            <Fact label={strings.detail.reasonLabel}>{alert.reason ?? ""}</Fact>
            <Fact label={strings.detail.claimLabel}>
              <IdentifierChip value={alert.subject_event_id ?? ""} />
            </Fact>
          </>
        ) : (
          <>
            <Fact label={strings.detail.identityLabel}>
              <IdentifierChip value={alert.certificate_identity ?? ""} kind="spiffe" />
            </Fact>
            <Fact label={strings.detail.rekorEntryLabel}>
              <IdentifierChip value={alert.rekor_entry_uuid ?? ""} kind="rekor" />
            </Fact>
            <Fact label={strings.detail.rekorIndexLabel}>
              {String(alert.rekor_log_index ?? 0)}
            </Fact>
          </>
        )}
        <Fact label={strings.detail.positionLabel}>{String(alert.chain_position)}</Fact>
        <Fact label={strings.detail.eventLabel}>
          <IdentifierChip value={alert.event_id} />
        </Fact>
      </dl>

      {alert.resolved ? null : <HowToResolve eventId={alert.event_id} />}

      <section className={evidence}>
        <h2 className={evidenceHeading}>{strings.detail.evidenceHeading}</h2>
        <a
          href={`${apiBase}/alerts?event_type=${encodeURIComponent(alert.event_type)}`}
          className={link}
        >
          {strings.detail.rawRecord}
        </a>
        {alert.run_id ? (
          <Link to={{ view: "run", runId: alert.run_id }} className={link}>
            {strings.detail.viewRun}
          </Link>
        ) : null}
      </section>
    </article>
  );
}

function Fact({
  label,
  children,
}: {
  readonly label: string;
  readonly children: ReactNode;
}) {
  return (
    <div className={factRow}>
      <dt className={factTerm}>{label}</dt>
      <dd className={factValue}>{children}</dd>
    </div>
  );
}

/**
 * The command an operator runs to resolve this alert — a thing to copy, not a
 * button (ADR-0044, ADR-0054). The identifier chip is the copy control, given
 * room for the whole command so nothing is abbreviated on screen.
 */
function HowToResolve({ eventId }: { readonly eventId: string }) {
  const headingId = useId();
  const command = strings.detail.resolveCommand(eventId);
  return (
    <section aria-labelledby={headingId} className={evidence}>
      <h2 id={headingId} className={evidenceHeading}>
        {strings.detail.resolveHeading}
      </h2>
      <p className={summary}>{strings.detail.resolveDetail}</p>
      <p className={summary}>{strings.detail.autoClearDetail}</p>
      <div className={commandBox}>
        <IdentifierChip value={command} maxLength={command.length} />
      </div>
    </section>
  );
}

function Status({ alert }: { readonly alert: AlertRecord }) {
  if (!alert.resolved) return <>{strings.detail.openStatus}</>;
  const when = alert.resolved_at ? formatAbsoluteUtc(new Date(alert.resolved_at)) : "";
  return (
    <span className="flex flex-col gap-1">
      <span>{strings.detail.resolvedStatus(alert.resolved_by ?? "", when)}</span>
      {alert.resolved_reason ? (
        <span>{strings.detail.resolvedReason(alert.resolved_reason)}</span>
      ) : null}
    </span>
  );
}
