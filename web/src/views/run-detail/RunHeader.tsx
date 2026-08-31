// SPDX-License-Identifier: Apache-2.0

/*
 * The run's header — doc 06 §3.3.
 *
 *   "Header: full SPIFFE ID (mono, copyable), agent type, task ref,
 *    registered/retired timestamps, credential expiry history."
 *
 * ── "FULL" IS THE LOAD-BEARING WORD ────────────────────────────────────────
 *
 * `IdentifierChip` middle-truncates by default, which is right in a table
 * cell and wrong here: doc 06 §3.3 asks for the FULL SPIFFE ID, and doc 06 §8
 * makes an identifier "truncated so the trust domain is lost" a defect. So the
 * chip is given a width it cannot exceed, and it returns the value untouched.
 * The copy behaviour, the accessible full value and the tooltip are the chip's
 * and are not reimplemented here — this is a prop, not a second component.
 *
 * ── REGISTERED AND RETIRED ARE NOT THE SAME KIND OF FACT ───────────────────
 *
 * `registered_at` is a column of the run index. The end of a run is not: it is
 * a `run_retired` or a `run_expired` EVENT, and which of the two it is changes
 * what the reader should conclude — doc 06 §3.2, "expired ... means an agent
 * died unretired". So the end is read out of the timeline, labelled with the
 * word that matches the event that ended it, and a run with neither says so in
 * a sentence rather than showing an empty cell (doc 06 P2, §4.6).
 */

import { IdentifierChip } from "../../components/common/IdentifierChip";
import { StatusBadge } from "../../components/common/StatusBadge";
import type { RunStatus } from "../../components/common/StatusBadge";
import { Instant } from "./RelativeTime";
import { strings } from "./strings";
import {
  block,
  factList,
  factRow,
  field,
  fieldGrid,
  fieldLabel,
  pageHeading,
  secondaryText,
  sectionHeading,
} from "./styles";
import { credentialHistory, runEnd } from "./events";
import type { RunSummary, TimelineEvent } from "./types";

/**
 * Wider than any identifier can be, so `truncateIdentifier` returns the value
 * whole. A number rather than a second code path inside the chip: doc 06 §4.3
 * describes one identifier component, and a `full` flag would be a second.
 */
const NEVER_TRUNCATED = Number.MAX_SAFE_INTEGER;

/** The three the API can return (`internal/api/query.go`). Anything else is
 * rendered without a badge rather than mapped to a guess. */
const KNOWN_STATUSES: readonly RunStatus[] = ["active", "retired", "expired"];

export interface RunHeaderProps {
  readonly run: RunSummary;
  readonly events: readonly TimelineEvent[];
  readonly now: Date;
}

export function RunHeader({ run, events, now }: RunHeaderProps) {
  const status = KNOWN_STATUSES.find((known) => known === run.status);
  const end = runEnd(events);
  const credentials = credentialHistory(events);
  const repos = run.repos ?? [];

  return (
    <header className={block}>
      <div className={factRow}>
        <h1 className={pageHeading}>{strings.view.heading}</h1>
        {status === undefined ? null : <StatusBadge status={status} />}
      </div>

      <dl className={fieldGrid}>
        <div className={field}>
          <dt className={fieldLabel}>{strings.header.identity}</dt>
          <dd>
            <IdentifierChip
              value={run.spiffe_id}
              kind="spiffe"
              maxLength={NEVER_TRUNCATED}
            />
          </dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.runId}</dt>
          <dd>
            <IdentifierChip value={run.run_id} kind="run" maxLength={NEVER_TRUNCATED} />
          </dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.agentType}</dt>
          <dd>{run.agent_type}</dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.taskRef}</dt>
          <dd>{run.task_ref}</dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.registered}</dt>
          <dd>
            <Instant
              value={run.registered_at}
              now={now}
              label={strings.header.registered}
            />
          </dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>
            {end === null
              ? strings.header.stillRunning
              : end.kind === "retired"
                ? strings.header.retired
                : strings.header.expired}
          </dt>
          <dd>
            {end === null ? (
              <span className={secondaryText}>{strings.header.noEnd}</span>
            ) : (
              <Instant
                value={end.at}
                now={now}
                label={
                  end.kind === "retired"
                    ? strings.header.retired
                    : strings.header.expired
                }
              />
            )}
          </dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.commits}</dt>
          {/* doc 06 §6.2: counts are exact. */}
          <dd>{String(run.commits)}</dd>
        </div>

        <div className={field}>
          <dt className={fieldLabel}>{strings.header.chainPosition}</dt>
          <dd>{String(run.chain_position)}</dd>
        </div>

        {repos.length === 0 ? null : (
          <div className={field}>
            <dt className={fieldLabel}>{strings.header.repos}</dt>
            <dd className={factRow}>
              {repos.map((repo) => (
                <span key={repo}>{repo}</span>
              ))}
            </dd>
          </div>
        )}
      </dl>

      <section className={factList}>
        <h2 className={sectionHeading}>{strings.header.credentials}</h2>
        {credentials.length === 0 ? (
          <p className={secondaryText}>{strings.header.noCredentials}</p>
        ) : (
          <ol className={factList}>
            {credentials.map((credential) => (
              <li key={credential.eventId} className={factRow}>
                <span className={fieldLabel}>{strings.header.credentialIssued}</span>
                <Instant
                  value={credential.issuedAt}
                  now={now}
                  label={strings.header.credentialIssued}
                />
                <span className={fieldLabel}>{strings.header.credentialExpiry}</span>
                {credential.expiry === undefined ? (
                  <span className={secondaryText}>{strings.canonical.absent}</span>
                ) : (
                  <Instant
                    value={credential.expiry}
                    now={now}
                    label={strings.header.credentialExpiry}
                  />
                )}
                {credential.audience === undefined ? null : (
                  <>
                    <span className={fieldLabel}>
                      {strings.header.credentialAudience}
                    </span>
                    <span>{credential.audience}</span>
                  </>
                )}
                <span className={fieldLabel}>
                  {strings.timeline.chainPosition(credential.chainPosition)}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>
    </header>
  );
}
