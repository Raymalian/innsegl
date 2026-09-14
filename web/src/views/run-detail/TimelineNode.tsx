// SPDX-License-Identifier: Apache-2.0

/*
 * One event of the run's chain — doc 06 §3.3.
 *
 *   "Timeline: ordered event chain from the ledger — registered → tool-call
 *    events (count, expandable to digests) → commit intents → commits (SHA +
 *    Rekor entry) → retired/expired. Each timeline node shows its chain
 *    position; reconciler-sourced events are labelled `source: reconciler` so
 *    repaired history is visible as repaired, per P1."
 *
 * ── THE ORDINARY EVENT IS NOT A PANEL ──────────────────────────────────────
 *
 * It sits on the rail as plain content: a title, a time, a chain position, and
 * whatever members doc 02 §3 gives its type. No ground, no border, no card.
 *
 * That is doc 06 P3 followed through rather than a preference. "Design the
 * alarm first" has a consequence for everything that is not the alarm: a
 * timeline that draws every event as a panel has spent its entire visual
 * vocabulary on the ordinary case, and the amber band and the red fill then
 * land on a page where every row already has a border and the eye has nowhere
 * to go. The bands work because the rows around them are bare.
 *
 * Three things earn a box, and only three:
 *
 *   alert      doc 02 §3's two "Alert:" rows. Red, filled, with the words
 *              "Integrity alert" in visible text (doc 06 §5.3, §8's
 *              anti-pattern 2).
 *   degraded   an expired commit intent, and an expired run. Amber, and they
 *              carry DIFFERENT words: a promise nobody kept and an identity
 *              that ran out under an agent still working are two facts, and P2
 *              forbids collapsing them.
 *   a commit   neutral, outlined. Not emphasis — doc 06 §3.3 makes the
 *              three-check panel "the load-bearing component" and this node is
 *              where a reader reaches it, so the node is a document: repo,
 *              SHA, Rekor entry, and the control that runs the checks. §5.3 is
 *              explicit that a commit the ledger holds is not a verification,
 *              so the card stays neutral and the green stays behind the panel.
 *
 * ── AND ONE THING MOVED, WITHOUT ANYTHING BEING DROPPED ────────────────────
 *
 * `source: <value>` used to be on every row, with a sentence under it saying
 * who that writer is. doc 06 §3.3 asks for the label so that "repaired history
 * is visible as repaired" — and the same label on all 1220 rows of a real run
 * is what made the repaired one unreadable.
 *
 * So the label is rendered for every event, always, and `writerIsInformative`
 * decides where: on the rail when doc 02 §3 permits the type more than one
 * writer (`commit_recorded` alone — "source: reconciler when repaired"), or
 * when the writer is not one the type permits at all; otherwise inside the
 * evidence disclosure that already holds the event id and both chain hashes.
 * REPAIRED HISTORY IS UNAFFECTED: `commit_recorded` is exactly the two-writer
 * type, so a repair keeps its label, its badge, its amber ground and its
 * sentence on the rail where a reader cannot miss them.
 */

import type { ReactNode } from "react";

import { Icon } from "../../components/common/Icon";
import type { IconName } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import type { IdentifierKind } from "../../components/common/identifier";
import { CommitVerification } from "./CommitVerification";
import type { VerifyCommit } from "./CommitVerification";
import { Instant } from "./RelativeTime";
import { RailGutter } from "./Rail";
import { strings } from "./strings";
import {
  badgeBase,
  chainMarker,
  commitCard,
  degraded,
  disclosure,
  expiredOutline,
  factList,
  factRow,
  focusRing,
  hairline,
  identifierText,
  integrityAlert,
  link,
  mutedText,
  nodeBand,
  nodeBody,
  nodeHeadline,
  nodeTitle,
  railRow,
  secondaryText,
  srOnly,
} from "./styles";
import {
  canonicalOf,
  commitSHAOf,
  isRepairedHistory,
  memberString,
  nodeAnchorId,
  severityOf,
  writerIsExpected,
  writerIsInformative,
  type ChainLink,
} from "./events";
import {
  EVENT_TYPES,
  MEMBERS,
  eventTypeIdOf,
  sourceIdOf,
  type TimelineEvent,
} from "./types";

export interface TimelineNodeProps {
  readonly event: TimelineEvent;
  readonly link: ChainLink;
  readonly now: Date;
  /** Whether this is the last row of its rail. The connector is drawn by the
   * row ABOVE it, so a node cannot decide this for itself — see Timeline.tsx. */
  readonly last?: boolean;
  /** Absent when the deployment offers no proof endpoint; the node then says
   * nothing about verification rather than implying there is nothing to say. */
  readonly verifyCommit?: VerifyCommit;
  readonly freshnessMs?: number;
}

/** The members doc 02 §3 gives the eleven types, in the order a reader wants
 * them: what was done, then to what, then the external record of it. */
const MEMBER_VIEWS: readonly {
  readonly member: string;
  readonly label: string;
  readonly kind?: IdentifierKind;
}[] = [
  { member: MEMBERS.agentType, label: strings.detail.agentType },
  { member: MEMBERS.taskRef, label: strings.detail.taskRef },
  { member: MEMBERS.toolName, label: strings.detail.toolName },
  { member: MEMBERS.audience, label: strings.detail.audience },
  { member: MEMBERS.repo, label: strings.detail.repo },
  { member: MEMBERS.treeHash, label: strings.detail.treeHash, kind: "sha" },
  { member: MEMBERS.commitSHA, label: strings.detail.commitSha, kind: "sha" },
  { member: MEMBERS.rekorLogIndex, label: strings.detail.rekorLogIndex, kind: "rekor" },
  { member: MEMBERS.rekorEntryUUID, label: strings.detail.rekorEntryUuid, kind: "generic" },
  { member: MEMBERS.intentEventID, label: strings.detail.intentEventId, kind: "generic" },
  {
    member: MEMBERS.certificateIdentity,
    label: strings.detail.certificateIdentity,
    kind: "spiffe",
  },
  { member: MEMBERS.subjectEventID, label: strings.detail.subjectEventId, kind: "generic" },
  { member: MEMBERS.reason, label: strings.detail.reason },
  { member: MEMBERS.supersedes, label: strings.detail.supersedes, kind: "generic" },
];

/** The rail marker for an event. Neutral in every case — a node is a statement
 * that the ledger holds an event and not a verdict on it — but the SHAPE still
 * carries the exception, so the two alarms are findable by running an eye down
 * the gutter and survive greyscale (doc 06 §6.4). */
function markerFor(event: TimelineEvent): "node" | "status-expired" | "integrity-alert" {
  const severity = severityOf(event);
  if (severity === "alert") return "integrity-alert";
  if (severity === "degraded") return "status-expired";
  return "node";
}

export function TimelineNode({
  event,
  link: chainLink,
  now,
  last = false,
  verifyCommit,
  freshnessMs,
}: TimelineNodeProps) {
  const typeId = eventTypeIdOf(event.event_type);
  const severity = severityOf(event);
  const repaired = isRepairedHistory(event);
  const canonical = canonicalOf(event);
  const title = typeId === undefined ? event.event_type : strings.event[typeId];
  const commitSHA = commitSHAOf(event);
  const isCommit = event.event_type === EVENT_TYPES.commitRecorded;

  /* doc 06 §3.2 requires expired to be told from retired without a hue, and
   * StatusBadge carries that distinction as a dashed outline. The same fact on
   * the timeline gets the same cue rather than a second invented one. */
  const outline = typeId === "runExpired" ? ` ${expiredOutline}` : "";
  const treatment =
    severity === "alert"
      ? `${nodeBand} ${integrityAlert}${outline}`
      : severity === "degraded" || repaired
        ? `${nodeBand} ${degraded}${outline}`
        : isCommit
          ? commitCard
          : "";

  return (
    <li id={nodeAnchorId(event)} className={railRow}>
      <RailGutter icon={markerFor(event)} last={last} />
      <div
        data-event-type={event.event_type}
        data-source={event.source}
        data-chain-position={event.chain_position}
        data-node-body
        className={`${nodeBody}${treatment === "" ? "" : ` ${treatment}`}`}
      >
        <div className={nodeHeadline}>
          <span className={nodeTitle}>{title}</span>
          {typeId === undefined ? (
            <span className={secondaryText}>{strings.event.unrecognised}</span>
          ) : null}
          <Instant value={event.ts} now={now} label={title} />
          {/* doc 06 §3.3: each node shows its chain position. */}
          <span className={chainMarker}>
            {strings.timeline.chainPosition(event.chain_position)}
          </span>
        </div>

        {severity === "neutral" ? null : <SeverityMark event={event} />}

        {/* doc 06 §3.3's label, with the ledger's own enum value inside it —
          * on the rail only where it says something the event type does not
          * already say. See the file comment, and `writerIsInformative`. */}
        {writerIsInformative(event) ? <Writer event={event} /> : null}

        {repaired ? (
          <div className={factList}>
            <Mark
              icon="staleness"
              tone={degraded}
              label={strings.event.repaired}
              meaning={strings.event.repairedDetail}
            />
            <p>{strings.event.repairedDetail}</p>
          </div>
        ) : null}

        <ChainLinkLine link={chainLink} event={event} />

        <Members event={event} />

        {event.event_type === EVENT_TYPES.toolCall ? (
          <ToolCallDigests event={event} />
        ) : null}

        {isCommit ? (
          commitSHA === undefined ? (
            <p className={secondaryText}>{strings.verification.noCommit}</p>
          ) : verifyCommit === undefined ? null : (
            <CommitVerification
              commitSHA={commitSHA}
              verifyCommit={verifyCommit}
              {...(freshnessMs === undefined ? {} : { freshnessMs })}
            />
          )
        ) : null}

        <CanonicalMembers canonical={canonical} />
      </div>
    </li>
  );
}

/** What the severity of this event is, in words, with its own icon.
 *
 * The two degradations get different sentences. doc 06 §3.2's expired run —
 * "an agent died unretired" — is not the same fact as a commit intent that
 * never became a commit, and P2 forbids one set of words standing for both. */
function SeverityMark({ event }: { readonly event: TimelineEvent }) {
  const severity = severityOf(event);
  if (severity === "alert") {
    return (
      <Mark
        icon="integrity-alert"
        tone={integrityAlert}
        label={strings.severity.alert}
        meaning={strings.severity.alertMeaning}
      />
    );
  }
  const ranOut = eventTypeIdOf(event.event_type) === "runExpired";
  return (
    <Mark
      icon="status-expired"
      tone={degraded}
      label={ranOut ? strings.severity.expired : strings.severity.degraded}
      meaning={ranOut ? strings.severity.expiredMeaning : strings.severity.degradedMeaning}
    />
  );
}

/** `source: <value>`, and who that writer is. One component, used in two
 * places — on the rail where the writer is a fact, and inside the evidence
 * disclosure where it is a restatement of the event type. The markup is the
 * same in both, so moving it cannot change what it says. */
function Writer({ event }: { readonly event: TimelineEvent }) {
  const sourceId = sourceIdOf(event.source);
  return (
    <p className={factRow}>
      <span className={identifierText}>{strings.event.source(event.source)}</span>
      <span className={secondaryText}>
        {sourceId === undefined
          ? strings.event.writer.unrecognised
          : strings.event.writer[sourceId]}
      </span>
      {writerIsExpected(event) ? null : (
        <Mark
          icon="unknown"
          tone={degraded}
          label={strings.event.unexpectedWriter}
          meaning={strings.event.unexpectedWriter}
        />
      )}
    </p>
  );
}

/** A labelled badge with its own icon, and its meaning spoken. Colour is never
 * the only cue (doc 06 §6.4). */
function Mark({
  icon,
  tone,
  label,
  meaning,
}: {
  readonly icon: IconName;
  readonly tone: string;
  readonly label: string;
  readonly meaning: string;
}) {
  return (
    <span className={`${badgeBase} ${hairline} ${tone} self-start`} title={meaning}>
      <Icon name={icon} className="shrink-0" />
      <span>{label}</span>
      <span className={srOnly}>{meaning}</span>
    </span>
  );
}

/** What can be said about this event's link to the one above it, and — for the
 * eleven types with one legal writer — who wrote it. Four link states, because
 * three of them would mean asserting a chain nobody followed. */
function ChainLinkLine({
  link: chainLink,
  event,
}: {
  readonly link: ChainLink;
  readonly event: TimelineEvent;
}) {
  const presentation: Record<
    ChainLink,
    { icon: IconName; label: string; detail: string; tone: string | null }
  > = {
    first: {
      icon: "empty",
      label: strings.chain.first,
      detail: strings.chain.firstDetail,
      tone: null,
    },
    linked: {
      icon: "anchor-pulse",
      label: strings.chain.linked,
      detail: strings.chain.linkedDetail,
      tone: null,
    },
    unchecked: {
      icon: "unknown",
      label: strings.chain.unchecked,
      detail: strings.chain.uncheckedDetail,
      tone: null,
    },
    broken: {
      icon: "integrity-alert",
      label: strings.chain.broken,
      detail: strings.chain.brokenDetail,
      tone: integrityAlert,
    },
  };
  const { icon, label, detail, tone } = presentation[chainLink];

  return (
    <details className={factList}>
      <summary className={`${disclosure} ${focusRing} ${factRow}`}>
        {tone === null ? (
          <span className={`${factRow} ${mutedText}`}>
            <Icon name={icon} className="shrink-0" />
            <span>{label}</span>
          </span>
        ) : (
          <Mark icon={icon} tone={tone} label={label} meaning={detail} />
        )}
      </summary>
      <p className={secondaryText}>{detail}</p>
      {/* Moved here, not dropped: P1 puts the evidence next to the claim, and
        * this disclosure is the event's own evidence. The value is still the
        * ledger's own enum value, passed through untouched. */}
      {writerIsInformative(event) ? null : <Writer event={event} />}
      <dl className={factList}>
        <Fact label={strings.timeline.eventId} value={event.event_id} kind="generic" />
        <Fact label={strings.timeline.eventHash} value={event.event_hash} kind="generic" />
        <Fact
          label={strings.timeline.prevEventHash}
          value={event.prev_event_hash}
          kind="generic"
        />
      </dl>
    </details>
  );
}

/** doc 02 §3's type-specific members, as the ledger returned them. */
function Members({ event }: { readonly event: TimelineEvent }) {
  const canonical = canonicalOf(event);
  const shown = MEMBER_VIEWS.map((view) => ({
    ...view,
    value: memberString(canonical, view.member),
  })).filter((view) => view.value !== undefined);
  if (shown.length === 0) return null;

  return (
    <dl className={factList}>
      {shown.map((view) => (
        <Fact
          key={view.member}
          label={view.label}
          value={view.value as string}
          {...(view.kind === undefined ? {} : { kind: view.kind })}
        />
      ))}
    </dl>
  );
}

/**
 * doc 06 §3.3: tool-call events are "expandable to digests".
 *
 * The digest is genuinely all there is — doc 02 §3 says the body lives "only
 * as `payload_digest`", which is IP E4 made mechanical — so the panel says so.
 * A reader who expects a body and finds an empty panel concludes the dashboard
 * is withholding one.
 */
function ToolCallDigests({ event }: { readonly event: TimelineEvent }) {
  const canonical = canonicalOf(event);
  const digest = memberString(canonical, MEMBERS.payloadDigest);
  return (
    <details className={factList}>
      <summary className={`${disclosure} ${focusRing} ${link}`}>
        {strings.toolCall.expand}
      </summary>
      {digest === undefined ? (
        <p className={secondaryText}>{strings.toolCall.noDigest}</p>
      ) : (
        <dl className={factList}>
          <Fact label={strings.detail.payloadDigest} value={digest} kind="generic" />
        </dl>
      )}
      <p className={secondaryText}>{strings.toolCall.bodyNotStored}</p>
    </details>
  );
}

/**
 * The event's canonical members — doc 06 P1 and P5, with an honest bound on
 * what they are. `internal/api` writes the RFC 8785 bytes into the response
 * verbatim, but the client's own `JSON.parse` has already consumed them by the
 * time a component sees them, so this is the decoded members and not the byte
 * sequence doc 02 §4 hashes. Saying so is the difference between evidence and
 * something that looks like evidence.
 */
function CanonicalMembers({
  canonical,
}: {
  readonly canonical: ReturnType<typeof canonicalOf>;
}) {
  if (canonical.state === "undecodable") {
    return (
      <div className={factList}>
        <Mark
          icon="unknown"
          tone={degraded}
          label={strings.canonical.undecodable}
          meaning={strings.canonical.undecodableDetail}
        />
        <p>{strings.canonical.undecodableDetail}</p>
      </div>
    );
  }
  if (canonical.state === "absent") {
    return <p className={mutedText}>{strings.canonical.absent}</p>;
  }
  return (
    <details className={factList}>
      <summary className={`${disclosure} ${focusRing} ${link}`}>
        {strings.canonical.heading}
      </summary>
      <p className={secondaryText}>{strings.canonical.detail}</p>
      <pre className={`${identifierText} overflow-x-auto`}>
        {JSON.stringify(canonical.members, null, 2)}
      </pre>
    </details>
  );
}

/** A label and an identifier, the way doc 06 P4 wants every identifier. */
function Fact({
  label,
  value,
  kind,
}: {
  readonly label: string;
  readonly value: string;
  readonly kind?: IdentifierKind;
}): ReactNode {
  return (
    <div className={factRow}>
      <dt className={mutedText}>{label}</dt>
      <dd>
        {kind === undefined ? (
          <span>{value}</span>
        ) : (
          <IdentifierChip value={value} kind={kind} />
        )}
      </dd>
    </div>
  );
}
