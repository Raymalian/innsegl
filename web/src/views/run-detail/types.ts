// SPDX-License-Identifier: Apache-2.0

/*
 * The run-detail response, as `internal/api` actually returns one.
 *
 * Every member below carries the JSON name the Go type carries — snake_case
 * and all — for the same reason `components/verification/types.ts` gives: a
 * second vocabulary is a second thing to keep in agreement by hand.
 * `internal/api/query.go`'s RunSummary, TimelineEvent and RunDetail are the
 * source.
 *
 * ── PROTECTED STRINGS ──────────────────────────────────────────────────────
 *
 * doc 02 §3: "Enum values, field names, and the trailer keys Agent-Identity /
 * Agent-Run / Agent-Task are protected strings." The `event_type` enum, the
 * `source` enum and the type-specific member names are restated here because
 * this file may depend on nothing, and they are restated EXACTLY — a spelling
 * invented here would be a spelling the ledger never writes, and the node
 * would silently render as an unrecognised event forever.
 *
 * They are used to RECOGNISE an event, never to render one: every word a
 * reader sees comes from strings.ts, so a translator can move it and these
 * cannot be moved.
 */

/** doc 02 §3's event types, in document order, with schema 3's run_adopted
 * (ADR-0051) beside the other lifecycle events. */
export const EVENT_TYPES = {
  runRegistered: "run_registered",
  credentialIssued: "credential_issued",
  toolCall: "tool_call",
  commitIntent: "commit_intent",
  commitRecorded: "commit_recorded",
  commitIntentExpired: "commit_intent_expired",
  runRetired: "run_retired",
  runExpired: "run_expired",
  runAdopted: "run_adopted",
  schemaMigrated: "schema_migrated",
  unattributedSignatureDetected: "unattributed_signature_detected",
  ledgerDriftDetected: "ledger_drift_detected",
  segmentSealed: "segment_sealed",
} as const;

export type EventTypeId = keyof typeof EVENT_TYPES;

export const EVENT_TYPE_IDS: readonly EventTypeId[] = [
  "runRegistered",
  "credentialIssued",
  "toolCall",
  "commitIntent",
  "commitRecorded",
  "commitIntentExpired",
  "runRetired",
  "runExpired",
  "runAdopted",
  "schemaMigrated",
  "unattributedSignatureDetected",
  "ledgerDriftDetected",
  "segmentSealed",
];

/** doc 02 §2's source enum: who appended the event. */
export const SOURCES = {
  mcp: "mcp",
  reconciler: "reconciler",
  reaper: "reaper",
  system: "system",
} as const;

export type SourceId = keyof typeof SOURCES;

export const SOURCE_IDS: readonly SourceId[] = ["mcp", "reconciler", "reaper", "system"];

/**
 * doc 02 §3's "Emitted by" column, which is what makes a repair recognisable.
 *
 * `commit_recorded` is the one row with two emitters — "mcp or reconciler ...
 * `source: reconciler` when repaired" — so the reconciler appearing on it
 * means the ledger lost a phase C and got it back from Rekor. The reconciler
 * appearing on `commit_intent_expired` or either alert means nothing of the
 * kind: those rows name the reconciler as their ONLY emitter, and calling
 * them repairs would be inventing a loss that never happened.
 */
export const EMITTED_BY: Record<EventTypeId, readonly SourceId[]> = {
  runRegistered: ["mcp"],
  credentialIssued: ["mcp"],
  toolCall: ["mcp"],
  commitIntent: ["mcp"],
  commitRecorded: ["mcp", "reconciler"],
  commitIntentExpired: ["reconciler"],
  runRetired: ["mcp"],
  runExpired: ["reaper"],
  runAdopted: ["mcp"],
  schemaMigrated: ["system"],
  unattributedSignatureDetected: ["reconciler"],
  ledgerDriftDetected: ["reconciler"],
  segmentSealed: ["system"],
};

/** doc 02 §3's type-specific member names. Protected. */
export const MEMBERS = {
  agentType: "agent_type",
  taskRef: "task_ref",
  audience: "audience",
  credentialExpiry: "credential_expiry",
  toolName: "tool_name",
  repo: "repo",
  treeHash: "tree_hash",
  commitSHA: "commit_sha",
  rekorLogIndex: "rekor_log_index",
  rekorEntryUUID: "rekor_entry_uuid",
  intentEventID: "intent_event_id",
  certificateIdentity: "certificate_identity",
  subjectEventID: "subject_event_id",
  reason: "reason",
  payloadDigest: "payload_digest",
  supersedes: "supersedes",
  // Schema 2 (ADR-0045, ADR-0047, doc 02 §7).
  branch: "branch",
  parentRunID: "parent_run_id",
  patchID: "patch_id",
  fromSchemaVersion: "from_schema_version",
  toSchemaVersion: "to_schema_version",
  cutoverPosition: "cutover_position",
  // Schema 3 (ADR-0051).
  adoptedRunID: "adopted_run_id",
  adoptedRunState: "adopted_run_state",
  adoptionEventID: "adoption_event_id",
} as const;

/** One ledger event, as `internal/api`'s TimelineEvent serialises.
 *
 * `canonical` is `json.RawMessage` on the Go side: the event's RFC 8785 bytes
 * written verbatim into the response. By the time it reaches a component it
 * has been through `JSON.parse` with the rest of the body, so what is here is
 * the decoded members and NOT the byte sequence doc 02 §4 hashes. That
 * distinction is stated to the reader rather than glossed — see strings.ts's
 * `canonical.detail`. */
export interface TimelineEvent {
  readonly chain_position: number;
  readonly event_id: string;
  readonly event_type: string;
  readonly source: string;
  readonly ts: string;
  readonly event_hash: string;
  readonly prev_event_hash: string;
  readonly canonical?: unknown;
}

/** `internal/api`'s RunSummary.
 *
 * The five optional members after `last_event_at` are the EVIDENCE for
 * `status` (#256). Every one of them is OPTIONAL in this type because every
 * one of them is `omitempty` on the wire: a run that was never withdrawn
 * carries no withdrawal instant, and `internal/api` omits the member rather
 * than sending Go's zero time, which would reach a reader as
 * "0001-01-01T00:00:00Z" — a timestamp they have every right to read as a
 * timestamp. Absent here means absent there, and the view says so in words
 * (doc 06 P2). */
export interface RunSummary {
  readonly run_id: string;
  readonly spiffe_id: string;
  readonly agent_type: string;
  readonly task_ref: string;
  readonly status: string;
  readonly repos?: readonly string[];
  readonly commits: number;
  readonly chain_position: number;
  readonly registered_at: string;
  readonly last_event_at: string;
  /** The newest event on this run the reaper did NOT write. */
  readonly last_activity_at?: string;
  /** The newest `run_expired`: when the reaper last withdrew the credential. */
  readonly withdrawn_at?: string;
  /** `withdrawn_at` plus the restore horizon. Absent when the run was never
   * withdrawn, or when the deployment set no horizon. */
  readonly restorable_until?: string;
  /** The run that started this one, as `run_registered` recorded it. Absent on
   * a root run and on every run written before schema 2. */
  readonly parent_run_id?: string;
}

/** `internal/api`'s RunDetail: the run and its ordered event chain. */
export interface RunDetail extends RunSummary {
  readonly timeline?: readonly TimelineEvent[];
  /** The horizon `status` was computed with, in seconds; 0 means the
   * deployment set none. ABSENT means the query API did not say, which is a
   * third thing and not a zero (P2). */
  readonly restore_horizon_seconds?: number;
  readonly data_as_of: string;
}

/** Which of the eleven this is, or undefined for one this build does not know.
 * An unrecognised event is rendered under the ledger's own spelling rather
 * than dropped: a timeline that silently omits an event is a timeline that
 * hides one. */
export function eventTypeIdOf(eventType: string): EventTypeId | undefined {
  return EVENT_TYPE_IDS.find((id) => EVENT_TYPES[id] === eventType);
}

/** Which source this is, or undefined for a value outside doc 02 §2's enum. */
export function sourceIdOf(source: string): SourceId | undefined {
  return SOURCE_IDS.find((id) => SOURCES[id] === source);
}
