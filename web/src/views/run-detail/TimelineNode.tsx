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
 * ── FOUR THINGS EVERY NODE SAYS, WHATEVER THE EVENT IS ─────────────────────
 *
 *   its chain position — doc 06 §3.3 in as many words;
 *   who wrote it       — `source: {value}`, plus a sentence saying what that
 *                        writer is, because "reaper" is not self-explanatory
 *                        to an auditor who has not read doc 02;
 *   what can be said about its link to the event above it — including, in the
 *                        common case, that nothing can be (see timeline.ts);
 *   its canonical members — doc 06 P1: the evidence sits next to the claim.
 *
 * ── AND TWO THINGS ONLY SOME NODES SAY ─────────────────────────────────────
 *
 * REPAIRED HISTORY. A `commit_recorded` the reconciler wrote is a fact the
 * agent never recorded and the ledger got back from Rekor afterwards. It
 * carries the label, a badge with its own icon, its own amber ground, and a
 * sentence saying what happened — four cues, of which three survive greyscale
 * and two survive a screen reader. doc 06 §3.3 asks for repaired history to be
 * "visible as repaired"; a label a reader has to already know how to read is
 * not visible in that sense.
 *
 * SEVERITY. doc 06 §8's anti-pattern 2 forbids a node whose event is a failure
 * rendering as merely informational. doc 02 §3's two "Alert:" rows are
 * integrity alerts and take red, filled, with the word "Integrity alert" in
 * visible text; `commit_intent_expired` takes amber and says what it means.
 * Neither is ever the calm neutral the rest of the timeline uses, and neither
 * is ever the other (P2).
 */

import type { ReactNode } from "react";

import { Icon } from "../../components/common/Icon";
import type { IconName } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import type { IdentifierKind } from "../../components/common/identifier";
import { CommitVerification } from "./CommitVerification";
import type { VerifyCommit } from "./CommitVerification";
import { Instant } from "./RelativeTime";
import { strings } from "./strings";
import {
  badgeBase,
  chainMarker,
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
  nodeHeadline,
  nodeNeutral,
  nodeOutline,
  nodeShell,
  nodeTitle,
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

export function TimelineNode({
  event,
  link: chainLink,
  now,
  verifyCommit,
  freshnessMs,
}: TimelineNodeProps) {
  const typeId = eventTypeIdOf(event.event_type);
  const sourceId = sourceIdOf(event.source);
  const severity = severityOf(event);
  const repaired = isRepairedHistory(event);
  const canonical = canonicalOf(event);
  const title = typeId === undefined ? event.event_type : strings.event[typeId];
  const commitSHA = commitSHAOf(event);

  const tone =
    severity === "alert"
      ? integrityAlert
      : severity === "degraded" || repaired
        ? degraded
        : nodeNeutral;
  /* doc 06 §3.2 requires expired to be told from retired without a hue, and
   * StatusBadge carries that distinction as a dashed outline. The same fact on
   * the timeline gets the same cue rather than a second invented one. */
  const outline = typeId === "runExpired" ? expiredOutline : nodeOutline;

  return (
    <li
      id={nodeAnchorId(event)}
      data-event-type={event.event_type}
      data-source={event.source}
      data-chain-position={event.chain_position}
      className={`${nodeShell} ${outline} ${tone}`}
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

      {severity === "neutral" ? null : (
        <Mark
          icon={severity === "alert" ? "integrity-alert" : "status-expired"}
          tone={severity === "alert" ? integrityAlert : degraded}
          label={severity === "alert" ? strings.severity.alert : strings.severity.degraded}
          meaning={
            severity === "alert"
              ? strings.severity.alertMeaning
              : strings.severity.degradedMeaning
          }
        />
      )}

      {/* doc 06 §3.3's label, with the ledger's own enum value inside it. */}
      <p className={factRow}>
        <span className={identifierText}>{strings.event.source(event.source)}</span>
        <span className={secondaryText}>
          {sourceId === undefined
            ? strings.event.writer.unrecognised
            : strings.event.writer[sourceId]}
        </span>
      </p>

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

      {event.event_type === EVENT_TYPES.commitRecorded ? (
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
    </li>
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

/** What can be said about this event's link to the one above it. Four states,
 * because three of them would mean asserting a chain nobody followed. */
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
