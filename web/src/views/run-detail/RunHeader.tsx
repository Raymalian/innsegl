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
 * `registered_at` is a column of the run index. The END of a run is not: it is
 * a `run_retired` EVENT, read out of the timeline, and a run without one says
 * so in a sentence rather than showing an empty cell (doc 06 P2, §4.6).
 *
 * A `run_expired` is NOT an end and is no longer labelled as one (#256). The
 * reaper withdrawing a credential from a run that went quiet is this system
 * acting on silence; the run may be resumed, and the header now says exactly
 * that under `Credential withdrawn` rather than filing it beside a retirement.
 *
 * ── THE STATE CARRIES ITS EVIDENCE, ON THE PAGE ────────────────────────────
 *
 * The badge is one word and the words are close together: Lapsed and Abandoned
 * are the same run seen against two different horizons. A word without the
 * horizon is a verdict a reader cannot check, which is doc 06 P1 one level up
 * from a verification. So the state sentence names the instants it rests on in
 * absolute UTC — on the page, not behind a hover, because a pointer is not
 * something every reader has — and the strip repeats them as relative times
 * with the absolute available four ways (see RelativeTime).
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
import {
  formatAbsoluteUtc,
  formatDuration,
} from "../../components/common/time";
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
import { credentialHistory, parseInstant, runEnd, toolCallCount } from "./events";
import type { RunDetail, TimelineEvent } from "./types";

/**
 * Wider than any identifier can be, so `truncateIdentifier` returns the value
 * whole. A number rather than a second code path inside the chip: doc 06 §4.3
 * describes one identifier component, and a `full` flag would be a second.
 */
const NEVER_TRUNCATED = Number.MAX_SAFE_INTEGER;

/**
 * How many cells the strip always has, before the conditional ones.
 *
 * Agent, Task, Tool calls, Commits, Registered, the end of the run, Last
 * activity, Credential withdrawn, Restore horizon, Latest chain position,
 * Run. Repositories is excluded: it takes the whole row already.
 *
 * It is a constant so the orphan check below can be read against the JSX
 * rather than inferred from it. A count that drifts out of step shows up as a
 * ragged final row in a browser, which is what FE-128 walks every view for.
 */
const FIXED_FACTS = 11;

/** The four the API can return (`internal/api/query.go`). Anything else is
 * rendered without a badge rather than mapped to a guess. */
const KNOWN_STATUSES: readonly RunStatus[] = [
  "active",
  "lapsed",
  "abandoned",
  "retired",
];

export interface RunHeaderProps {
  readonly run: RunDetail;
  readonly events: readonly TimelineEvent[];
  readonly now: Date;
}

export function RunHeader({ run, events, now }: RunHeaderProps) {
  const status = KNOWN_STATUSES.find((known) => known === run.status);
  const end = runEnd(events);
  const retirement = end !== null && end.kind === "retired" ? end : null;
  const credentials = credentialHistory(events);
  const repos = run.repos ?? [];
  const parent =
    run.parent_run_id === undefined || run.parent_run_id === ""
      ? undefined
      : run.parent_run_id;
  /* A fact that lands alone on the final row sits beside three empty cells,
   * which reads as missing data rather than as the end of the strip — the
   * argument `wide` was added for. The strip's length now varies with how much
   * evidence the run has (#256), so the last ordinary cell takes the row when
   * it would otherwise be the only thing on it. MEASURED in a browser: a run
   * with both a restorable-until and a parent left "Run" alone. */
  const factCount =
    FIXED_FACTS +
    (run.restorable_until === undefined ? 0 : 1) +
    (parent === undefined ? 0 : 1);
  const endLabel =
    retirement === null ? strings.header.stillRunning : strings.header.retired;

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

      <p className={secondaryText} data-run-state={run.status}>
        {stateSentence(run)}
      </p>

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
          {retirement === null ? (
            <span className={secondaryText}>{strings.header.noEnd}</span>
          ) : (
            <Instant value={retirement.at} now={now} label={endLabel} />
          )}
        </Fact>

        {/* The evidence for the badge (#256). Five facts, and every one of
          * them is a recorded instant, a recorded id, or arithmetic over the
          * two — nothing here is an inference about an agent. */}
        <Fact label={strings.state.lastActivity}>
          {run.last_activity_at === undefined ? (
            <span className={secondaryText}>{strings.state.noActivity}</span>
          ) : (
            <Instant
              value={run.last_activity_at}
              now={now}
              label={strings.state.lastActivity}
            />
          )}
        </Fact>
        <Fact label={strings.state.withdrawn}>
          {run.withdrawn_at === undefined ? (
            <span className={secondaryText}>{strings.state.noWithdrawal}</span>
          ) : (
            <Instant
              value={run.withdrawn_at}
              now={now}
              label={strings.state.withdrawn}
            />
          )}
        </Fact>
        {run.restorable_until === undefined ? null : (
          <Fact label={strings.state.restorableUntil}>
            <Instant
              value={run.restorable_until}
              now={now}
              label={strings.state.restorableUntil}
            />
          </Fact>
        )}
        <Fact label={strings.state.horizon}>
          {horizonOf(run) === undefined ? (
            <span className={secondaryText}>{horizonSentence(run)}</span>
          ) : (
            horizonOf(run)
          )}
        </Fact>
        {parent === undefined ? null : (
          <Fact label={strings.state.parent}>
            <IdentifierChip value={parent} kind="run" maxLength={NEVER_TRUNCATED} />
          </Fact>
        )}

        <Fact
          label={strings.header.chainPosition}
          value={String(run.chain_position)}
        />
        <Fact label={strings.header.runId} wide={factCount % 4 === 1}>
          <IdentifierChip value={run.run_id} kind="run" maxLength={NEVER_TRUNCATED} />
        </Fact>

        {repos.length === 0 ? null : (
          <Fact label={strings.header.repos} wide>
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

/* ── the state, and the facts under it ──────────────────────────────────────
 *
 * Four functions over data, no JSX between them. They are here rather than in
 * events.ts because every one of them reads the run INDEX rather than the
 * event chain — events.ts is the module that decides things from the timeline,
 * and mixing the two sources in one file is how a view ends up with two
 * answers to the same question.
 */

/** The instant a reader means by "nothing heard since".
 *
 * `last_activity_at` is the newest event the reaper did not write. A run whose
 * whole record is the reaper's has none, and then the honest answer is the
 * moment it registered — which is still a recorded fact and still the last
 * time anything but the reaper said anything about it. */
function heardAt(run: RunDetail): string {
  return formatAbsoluteUtc(
    parseInstant(run.last_activity_at) ??
      parseInstant(run.registered_at) ??
      new Date(0),
  );
}

/** The horizon as a duration, or undefined when there is no number to show —
 * either because the deployment set none or because the query API did not say.
 * The two are different facts and `horizonSentence` tells them apart (P2). */
function horizonOf(run: RunDetail): string | undefined {
  const seconds = run.restore_horizon_seconds;
  if (seconds === undefined || seconds <= 0) return undefined;
  return formatDuration(seconds * 1000);
}

/** Which absence this is. */
function horizonSentence(run: RunDetail): string {
  return run.restore_horizon_seconds === undefined
    ? strings.state.horizonUnknown
    : strings.state.noHorizon;
}

/**
 * What this page concludes, and what it concluded it from.
 *
 * One sentence per state, each naming its instants. The two withdrawn states
 * open the same way — "Nothing heard since X" — because that is the fact they
 * share; they part on what can still be done about it, which is the only thing
 * the horizon decides and the only thing this system is entitled to say.
 */
function stateSentence(run: RunDetail): string {
  const heard = heardAt(run);
  const withdrawn = parseInstant(run.withdrawn_at);
  const until = parseInstant(run.restorable_until);

  switch (run.status) {
    case "active":
      return withdrawn === null
        ? strings.state.active(heard)
        : strings.state.activeAfterWithdrawal(heard, formatAbsoluteUtc(withdrawn));
    case "lapsed":
      return until === null
        ? strings.state.lapsedUnbounded(heard)
        : strings.state.lapsed(heard, formatAbsoluteUtc(until));
    case "abandoned":
      return strings.state.abandoned(heard);
    case "retired":
      return strings.state.retired(
        formatAbsoluteUtc(parseInstant(run.last_event_at) ?? new Date(0)),
      );
    default:
      // A word this build does not know. Said plainly rather than mapped to
      // the nearest one it does (P2).
      return strings.state.unrecognised;
  }
}

/** One cell of the strip: a label, and the value under it. Both halves come
 * from the shared vocabulary, so a fact here and a column header in a table
 * cannot be restyled apart (FE-122). */
function Fact({
  label,
  value,
  children,
  wide = false,
}: {
  readonly label: string;
  readonly value?: string;
  readonly children?: React.ReactNode;
  /** Take the whole row rather than one column. A fact that lands alone on a
   * final row sits beside three empty cells, which reads as missing data
   * rather than as the end of the strip — measured in a browser on a run with
   * nine facts in a four-column grid. */
  readonly wide?: boolean;
}) {
  return (
    <div className={`${factCell}${wide ? " md:col-span-4" : ""}`} data-fact>
      <dt className={fieldLabel}>{label}</dt>
      <dd className={factValue}>{value === undefined ? children : value}</dd>
    </div>
  );
}
