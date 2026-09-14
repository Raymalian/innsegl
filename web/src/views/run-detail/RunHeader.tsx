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
 * ── THE IDENTITY IS NOT A FIELD ────────────────────────────────────────────
 *
 * It sits directly under the heading, in mono, carrying no label (FE-122). The
 * word that used to stand above it restated the URI scheme to a reader who can
 * already read one, and it cost a line of a header whose job is to say what
 * this run is in one glance. doc 06 P4 asks for identifiers in mono, which is
 * what makes the line self-describing without the label.
 *
 * ── THE FACTS ARE A STRIP, AND THE STRIP DROPS NOTHING ─────────────────────
 *
 * The four the reader wants first — agent, task, tool calls, commits — lead,
 * and the rest follow in the same strip rather than in a second treatment. The
 * tool-call count is read out of the timeline rather than taken from the run
 * index, because `internal/api`'s RunSummary does not carry one; doc 06 §6.2
 * makes it exact, so it is counted and never estimated.
 *
 * ── REGISTERED AND RETIRED ARE NOT THE SAME KIND OF FACT ───────────────────
 *
 * `registered_at` is a column of the run index. The end of a run is not: it is
 * a `run_retired` or a `run_expired` EVENT, and which of the two it is changes
 * what the reader should conclude — doc 06 §3.2, "expired ... means an agent
 * died unretired". So the end is read out of the timeline, labelled with the
 * word that matches the event that ended it, and a run with neither says so in
 * a sentence rather than showing an empty cell (doc 06 P2, §4.6).
 *
 * ── THE CREDENTIAL HISTORY IS A TABLE ──────────────────────────────────────
 *
 * It is the one fact in this header with more than one row, and every row has
 * the same four members. doc 06 §6.4 wants tables to be real tables, so it is
 * one — drawn from the shared table module (FE-121), which is why restyling a
 * table in this product restyles this one too.
 */

import { IdentifierChip } from "../../components/common/IdentifierChip";
import { StatusBadge } from "../../components/common/StatusBadge";
import type { RunStatus } from "../../components/common/StatusBadge";
import { Instant } from "./RelativeTime";
import { strings } from "./strings";
import {
  cell,
  columnHeader,
  factCell,
  factRow,
  factStrip,
  factValue,
  fieldLabel,
  headerStack,
  identityLine,
  pageHeading,
  secondaryText,
  sectionHeading,
  table,
  tableCaption,
  tablePanel,
  tableScroll,
} from "./styles";
import { credentialHistory, runEnd, toolCallCount } from "./events";
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
  const endLabel =
    end === null
      ? strings.header.stillRunning
      : end.kind === "retired"
        ? strings.header.retired
        : strings.header.expired;

  return (
    <header className={headerStack}>
      <div className={factRow}>
        <h1 className={pageHeading}>{strings.view.heading}</h1>
        {status === undefined ? null : <StatusBadge status={status} />}
      </div>

      <div className={identityLine} data-run-identity>
        <IdentifierChip
          value={run.spiffe_id}
          kind="spiffe"
          maxLength={NEVER_TRUNCATED}
        />
      </div>

      <dl className={factStrip}>
        <Fact label={strings.header.agentType} value={run.agent_type} />
        <Fact label={strings.header.taskRef} value={run.task_ref} />
        {/* doc 06 §6.2: counts are exact, so both are counted rather than
          * rounded or bucketed. */}
        <Fact label={strings.header.toolCalls} value={String(toolCallCount(events))} />
        <Fact label={strings.header.commits} value={String(run.commits)} />

        <Fact label={strings.header.registered}>
          <Instant
            value={run.registered_at}
            now={now}
            label={strings.header.registered}
          />
        </Fact>
        <Fact label={endLabel}>
          {end === null ? (
            <span className={secondaryText}>{strings.header.noEnd}</span>
          ) : (
            <Instant value={end.at} now={now} label={endLabel} />
          )}
        </Fact>
        <Fact
          label={strings.header.chainPosition}
          value={String(run.chain_position)}
        />
        <Fact label={strings.header.runId}>
          <IdentifierChip value={run.run_id} kind="run" maxLength={NEVER_TRUNCATED} />
        </Fact>

        {repos.length === 0 ? null : (
          <Fact label={strings.header.repos}>
            <span className={factRow}>
              {repos.map((repo) => (
                <span key={repo}>{repo}</span>
              ))}
            </span>
          </Fact>
        )}
      </dl>

      <section className={tablePanel}>
        <div className={tableScroll}>
          <table className={table}>
            <caption className={`${tableCaption} ${sectionHeading}`}>
              {strings.header.credentials}
            </caption>
            <thead>
              <tr>
                <th scope="col" className={columnHeader}>
                  {strings.header.credentialIssued}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.header.credentialExpiry}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.header.credentialAudience}
                </th>
                <th scope="col" className={columnHeader}>
                  {strings.header.chainPosition}
                </th>
              </tr>
            </thead>
            <tbody>
              {credentials.length === 0 ? (
                <tr>
                  {/* P2: an empty table is a blank, and a blank is not a fact.
                    * The sentence says which of the two this is. */}
                  <td className={`${cell} ${secondaryText}`} colSpan={4}>
                    {strings.header.noCredentials}
                  </td>
                </tr>
              ) : (
                credentials.map((credential) => (
                  <tr key={credential.eventId}>
                    <td className={cell}>
                      <Instant
                        value={credential.issuedAt}
                        now={now}
                        label={strings.header.credentialIssued}
                      />
                    </td>
                    <td className={cell}>
                      {credential.expiry === undefined ? (
                        <span className={secondaryText}>
                          {strings.canonical.absent}
                        </span>
                      ) : (
                        <Instant
                          value={credential.expiry}
                          now={now}
                          label={strings.header.credentialExpiry}
                        />
                      )}
                    </td>
                    <td className={cell}>
                      {credential.audience === undefined ? (
                        <span className={secondaryText}>
                          {strings.canonical.absent}
                        </span>
                      ) : (
                        credential.audience
                      )}
                    </td>
                    <td className={cell}>
                      {strings.timeline.chainPosition(credential.chainPosition)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </header>
  );
}

/** One cell of the strip: a label, and the value under it. Both halves come
 * from the shared vocabulary, so a fact here and a column header in a table
 * cannot be restyled apart (FE-122). */
function Fact({
  label,
  value,
  children,
}: {
  readonly label: string;
  readonly value?: string;
  readonly children?: React.ReactNode;
}) {
  return (
    <div className={factCell} data-fact>
      <dt className={fieldLabel}>{label}</dt>
      <dd className={factValue}>{value === undefined ? children : value}</dd>
    </div>
  );
}
