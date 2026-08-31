// SPDX-License-Identifier: Apache-2.0

/*
 * Everything the run-detail view decides, as functions over data.
 *
 * None of it renders, all of it is testable without a DOM, and the three
 * judgements that could quietly go wrong live here where a test can hold them
 * still:
 *
 *   1. WHAT COUNTS AS REPAIRED HISTORY. doc 06 §3.3 asks for reconciler-
 *      sourced events to be visible as repaired. But three of doc 02 §3's
 *      eleven types name the reconciler as their ONLY emitter —
 *      `commit_intent_expired`, `unattributed_signature_detected` and
 *      `ledger_drift_detected`. Those are the reconciler doing its job, not
 *      the ledger recovering from a loss, and marking them "repaired" would
 *      invent a loss that never happened. A repair is the reconciler writing
 *      an event the AGENT ordinarily writes, which by doc 02 §3's "Emitted by"
 *      column means `commit_recorded` — "source: reconciler when repaired".
 *
 *   2. WHAT CAN BE SAID ABOUT THE CHAIN. A run's events are not adjacent in
 *      the ledger: `timelineSQL` selects `WHERE run_id = $1`, so every other
 *      run's events sit between them and `prev_event_hash` usually names an
 *      event this response does not contain. A link can therefore only be
 *      checked when the two chain positions are consecutive. Reporting
 *      anything else as intact would be asserting a hash chain nobody
 *      followed; reporting it as broken would be a false alarm on the one
 *      component whose job is to be believed. So there are four states and the
 *      third one — "not checkable here" — is the honest majority case.
 *
 *   3. WHICH EVENTS ARE FAILURES. doc 06 §8's anti-pattern 2 forbids a node
 *      whose event is a failure rendering as merely informational. doc 02 §3
 *      labels two rows "Alert:", and those two are the integrity alerts doc 06
 *      §5.3 gives red to. `commit_intent_expired` is not an alert — nothing
 *      was violated, a promised commit simply never arrived — so it is amber:
 *      degraded, per §5.3, and never collapsed into either neighbour (P2).
 */

import {
  EMITTED_BY,
  EVENT_TYPES,
  MEMBERS,
  eventTypeIdOf,
  sourceIdOf,
  type EventTypeId,
  type TimelineEvent,
} from "./types";

/* ── time ──────────────────────────────────────────────────────────────── */

/**
 * An RFC 3339 instant, or null. Null rather than a thrown error or an epoch
 * fallback: doc 06 P2 forbids collapsing "we could not read this" into a
 * value, and 1970 rendered as a timestamp is a value.
 */
export function parseInstant(value: string | undefined): Date | null {
  if (value === undefined || value === "") return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at;
}

/* ── canonical members ─────────────────────────────────────────────────── */

export type Canonical =
  | { readonly state: "decoded"; readonly members: Readonly<Record<string, unknown>> }
  | { readonly state: "absent" }
  | { readonly state: "undecodable" };

/**
 * The event's canonical members.
 *
 * `internal/api` writes `json.RawMessage` into the response, so by the time a
 * component sees it the surrounding `JSON.parse` has already decoded it into
 * an object. A string is still accepted and parsed, because a transport that
 * double-encodes it is a plausible accident and dropping the members over it
 * would hide evidence. Anything else is reported as undecodable rather than
 * rendered as empty — an absence that looks like "nothing to see" is the
 * failure doc 06 P2 is about.
 */
export function canonicalOf(event: TimelineEvent): Canonical {
  const raw = event.canonical;
  if (raw === undefined || raw === null) return { state: "absent" };
  if (typeof raw === "string") {
    try {
      const parsed: unknown = JSON.parse(raw);
      return isPlainObject(parsed)
        ? { state: "decoded", members: parsed }
        : { state: "undecodable" };
    } catch {
      return { state: "undecodable" };
    }
  }
  return isPlainObject(raw) ? { state: "decoded", members: raw } : { state: "undecodable" };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One canonical member as a string, or undefined when it is absent. Numbers
 * are rendered exactly, never rounded — doc 06 §6.2, "counts are exact". */
export function memberString(
  canonical: Canonical,
  name: string,
): string | undefined {
  if (canonical.state !== "decoded") return undefined;
  const value = canonical.members[name];
  if (typeof value === "string") return value === "" ? undefined : value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return String(value);
  return undefined;
}

/* ── repaired history ──────────────────────────────────────────────────── */

/**
 * Whether this event is history the reconciler put back.
 *
 * True when the reconciler wrote an event type the AGENT ordinarily writes.
 * doc 02 §3 gives `commit_recorded` two emitters and says which one means
 * what: "mcp or reconciler | Phase C; `source: reconciler` when repaired".
 */
export function isRepairedHistory(event: TimelineEvent): boolean {
  if (sourceIdOf(event.source) !== "reconciler") return false;
  const id = eventTypeIdOf(event.event_type);
  if (id === undefined) return false;
  return EMITTED_BY[id].includes("mcp");
}

/* ── severity ──────────────────────────────────────────────────────────── */

/** doc 06 §5.3's three bands, as they apply to an event. Never four, and never
 * two: a failure and a degradation are different facts (P2). */
export type Severity = "alert" | "degraded" | "neutral";

const ALERT_TYPES: readonly EventTypeId[] = [
  "unattributedSignatureDetected",
  "ledgerDriftDetected",
];

export function severityOf(event: TimelineEvent): Severity {
  const id = eventTypeIdOf(event.event_type);
  if (id === undefined) return "neutral";
  if (ALERT_TYPES.includes(id)) return "alert";
  if (id === "commitIntentExpired") return "degraded";
  return "neutral";
}

/* ── the chain ─────────────────────────────────────────────────────────── */

export type ChainLink = "first" | "linked" | "broken" | "unchecked";

/**
 * What can be said about the link from `events[index]` to the event before it.
 *
 * Only consecutive chain positions can be checked at all; see the file
 * comment. The check itself is doc 02 §4's: an event names the hash of the
 * event immediately before it.
 */
export function chainLinkAt(
  events: readonly TimelineEvent[],
  index: number,
): ChainLink {
  if (index <= 0) return "first";
  const event = events[index];
  const previous = events[index - 1];
  if (event === undefined || previous === undefined) return "first";
  if (event.chain_position !== previous.chain_position + 1) return "unchecked";
  return event.prev_event_hash === previous.event_hash ? "linked" : "broken";
}

/* ── things the header and the banner need ─────────────────────────────── */

export interface CredentialIssue {
  readonly eventId: string;
  readonly chainPosition: number;
  readonly issuedAt: string;
  readonly expiry: string | undefined;
  readonly audience: string | undefined;
}

/** doc 06 §3.3's "credential expiry history", in the order the ledger holds
 * it. Every issue is listed, including ones long past: the history is the
 * point, and a view that showed only the newest would be answering a
 * different question. */
export function credentialHistory(
  events: readonly TimelineEvent[],
): readonly CredentialIssue[] {
  return events
    .filter((event) => event.event_type === EVENT_TYPES.credentialIssued)
    .map((event) => {
      const canonical = canonicalOf(event);
      return {
        eventId: event.event_id,
        chainPosition: event.chain_position,
        issuedAt: event.ts,
        expiry: memberString(canonical, MEMBERS.credentialExpiry),
        audience: memberString(canonical, MEMBERS.audience),
      };
    });
}

export interface RunEnd {
  readonly kind: "retired" | "expired";
  readonly at: string;
  readonly chainPosition: number;
}

/**
 * How this run ended, or null while it has not.
 *
 * Retired and expired are kept apart here for the same reason `StatusBadge`
 * keeps them apart: one run ended because something retired it, the other
 * because its credential ran out while nothing was watching (doc 06 §3.2).
 */
export function runEnd(events: readonly TimelineEvent[]): RunEnd | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event === undefined) continue;
    if (event.event_type === EVENT_TYPES.runRetired) {
      return { kind: "retired", at: event.ts, chainPosition: event.chain_position };
    }
    if (event.event_type === EVENT_TYPES.runExpired) {
      return { kind: "expired", at: event.ts, chainPosition: event.chain_position };
    }
  }
  return null;
}

/** How many tool calls this run made (doc 06 §3.3's "count"). */
export function toolCallCount(events: readonly TimelineEvent[]): number {
  return events.filter((event) => event.event_type === EVENT_TYPES.toolCall).length;
}

/** The commit SHA a `commit_recorded` event names, if it names one. */
export function commitSHAOf(event: TimelineEvent): string | undefined {
  if (event.event_type !== EVENT_TYPES.commitRecorded) return undefined;
  return memberString(canonicalOf(event), MEMBERS.commitSHA);
}

/** The anchor a page-level alert links to (doc 06 §4.5: "links directly to
 * the evidence"). Chain position rather than event id: it is unique within the
 * ledger and it is the number the node itself displays. */
export function nodeAnchorId(event: TimelineEvent): string {
  return `run-event-${event.chain_position}`;
}

/* ── the page-level conditions ─────────────────────────────────────────── */

export type ConditionKind = "drift" | "unattributed" | "chain-broken";

export interface Condition {
  readonly kind: ConditionKind;
  readonly anchorId: string;
}

/**
 * Every condition doc 06 §4.5 wants a page-level banner for that this response
 * can establish: "drift detection, chain-verification failure" — the third,
 * anchoring lag, belongs to the header heartbeat and not to a run.
 *
 * One banner per condition, not one per event: three drift events are one
 * drift, and three identical red banners is an alarm a reader learns to skim.
 * The banner links to the first event that established the condition.
 */
export function conditionsOf(events: readonly TimelineEvent[]): readonly Condition[] {
  const found: Condition[] = [];
  const add = (kind: ConditionKind, event: TimelineEvent) => {
    if (found.some((condition) => condition.kind === kind)) return;
    found.push({ kind, anchorId: nodeAnchorId(event) });
  };

  events.forEach((event, index) => {
    if (event.event_type === EVENT_TYPES.ledgerDriftDetected) add("drift", event);
    if (event.event_type === EVENT_TYPES.unattributedSignatureDetected) {
      add("unattributed", event);
    }
    if (chainLinkAt(events, index) === "broken") add("chain-broken", event);
  });

  return found;
}
