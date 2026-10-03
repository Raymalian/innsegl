// SPDX-License-Identifier: Apache-2.0

/*
 * One alert, in full — ADR-0054, RM-330, doc 06 P1, P4, §4.3.
 *
 * The menu in the header says what happened in one line. This says all of
 * it: every field the alerts feed carries for this event, each in a readable
 * form, the long identifiers in chips that copy the whole value, the full
 * record behind a toggle (P1), what the alert means and what to do about it.
 * Presentational; `AlertDetailView` reads.
 *
 * An open alert can be resolved here (ADR-0044's 2026-10-03 amendment): a
 * reason and a fresh passkey, which records who, when and why beside the
 * alert and never changes the alert itself. The resolve-alert command stays
 * as the alternative for an operator on the core host.
 */

import { useId, type ReactNode } from "react";

import { Link } from "../../app/router";
import { routeToPath } from "../../app/routes";
import { Icon } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import { elapsedSince, formatAbsoluteUtc } from "../../components/common/time";
import type { WebAuthnBrowser } from "../auth/client";
import type { AlertRecord } from "../overview/types";
import { alertCause, explain } from "./explain";
import { ResolveForm } from "./ResolveForm";
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
  recordPre,
  recordToggle,
  resolveSection,
  summary,
} from "./styles";
import { alertSummary, alertTitle } from "./summary";

export interface AlertDetailProps {
  readonly alert: AlertRecord;
  readonly apiBase: string;
  readonly now?: Date;
  /** Called once a resolution is written, so the view reads again. */
  readonly onResolved?: () => void;
  readonly browser?: WebAuthnBrowser;
}

export function AlertDetail({ alert, apiBase, now, onResolved, browser }: AlertDetailProps) {
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

      <Explanation alert={alert} />

      {alert.resolved ? null : (
        <Resolve
          eventId={alert.event_id}
          apiBase={apiBase}
          onResolved={onResolved ?? (() => undefined)}
          {...(browser === undefined ? {} : { browser })}
        />
      )}

      <section className={evidence}>
        <h2 className={evidenceHeading}>{strings.detail.evidenceHeading}</h2>
        {alert.run_id ? (
          <>
            <Link to={{ view: "run", runId: alert.run_id }} className={link}>
              {strings.detail.viewRun}
            </Link>
            <Link
              to={{ view: "alerts", filters: { kind: "all", run: alert.run_id } }}
              className={link}
            >
              {strings.detail.runAlerts}
            </Link>
          </>
        ) : null}
        <details>
          <summary className={recordToggle}>{strings.detail.recordToggle}</summary>
          <pre className={recordPre}>{JSON.stringify(alert, null, 2)}</pre>
        </details>
      </section>
    </article>
  );
}

/** What this alert means and what to do about it, by its cause. */
function Explanation({ alert }: { readonly alert: AlertRecord }) {
  const whatId = useId();
  const todoId = useId();
  const copy = explain(alertCause(alert));
  return (
    <>
      <section aria-labelledby={whatId} className={evidence}>
        <h2 id={whatId} className={evidenceHeading}>
          {strings.explain.whatHeading}
        </h2>
        <p className={summary}>{copy.whatDetail}</p>
      </section>
      <section aria-labelledby={todoId} className={evidence}>
        <h2 id={todoId} className={evidenceHeading}>
          {strings.explain.todoHeading}
        </h2>
        <p className={summary}>{copy.todoDetail}</p>
      </section>
    </>
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
 * Resolve this alert: a reason and a fresh passkey (RM-330), and the
 * resolve-alert command an operator on the core host can run instead. The
 * identifier chip is the command's copy control, given room for the whole
 * command so nothing is abbreviated on screen.
 */
function Resolve({
  eventId,
  apiBase,
  onResolved,
  browser,
}: {
  readonly eventId: string;
  readonly apiBase: string;
  readonly onResolved: () => void;
  readonly browser?: WebAuthnBrowser;
}) {
  const headingId = useId();
  const cliId = useId();
  const command = strings.detail.resolveCommand(eventId);
  return (
    <section aria-labelledby={headingId} className={resolveSection}>
      <h2 id={headingId} className={evidenceHeading}>
        {strings.resolve.heading}
      </h2>
      <ResolveForm
        eventIds={[eventId]}
        onResolved={onResolved}
        apiBase={apiBase}
        {...(browser === undefined ? {} : { browser })}
      />
      <section aria-labelledby={cliId} className={evidence}>
        <h3 id={cliId} className={evidenceHeading}>
          {strings.resolve.cliHeading}
        </h3>
        <p className={summary}>{strings.resolve.cliDetail}</p>
        <div className={commandBox}>
          <IdentifierChip value={command} maxLength={command.length} />
        </div>
      </section>
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
