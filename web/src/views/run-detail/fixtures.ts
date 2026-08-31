// SPDX-License-Identifier: Apache-2.0

/*
 * One run's ledger history, in the shape `internal/api` returns it.
 *
 * Hand-built from `internal/api/query.go`'s RunDetail and TimelineEvent,
 * member for member, and from doc 02 §3's table for what each event type
 * carries. Nothing here invents a field name the ledger does not write: a view
 * tested against an invented shape is a view nobody has tested.
 *
 * The builders vary one thing each, for the reason
 * `components/verification/fixtures.ts` gives — two renders that differ in
 * several ways at once prove nothing about the one difference under test.
 */

import { EVENT_TYPES, SOURCES } from "./types";
import type { RunDetail, TimelineEvent } from "./types";

export const SPIFFE_ID = "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c";
export const RUN_ID = "run-7f3a2c";
export const COMMIT_SHA = "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291";

const HASHES = [
  "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
  "sha256:2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1",
  "sha256:3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1b2",
  "sha256:4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3",
  "sha256:5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3d4",
  "sha256:6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3d4e5",
  "sha256:708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3d4e5f6",
];

export interface EventOverrides {
  readonly chain_position?: number;
  readonly source?: string;
  readonly ts?: string;
  readonly event_hash?: string;
  readonly prev_event_hash?: string;
  readonly canonical?: unknown;
}

/**
 * One event. Chain hashes default to a chain that links: event at position N
 * carries HASHES[N] and names HASHES[N-1], so a test that wants a broken link
 * breaks it on purpose rather than inheriting one.
 */
export function ledgerEvent(
  eventType: string,
  position: number,
  overrides: EventOverrides = {},
): TimelineEvent {
  const at = position - 1;
  return {
    chain_position: overrides.chain_position ?? position,
    event_id: `01HQ8Z3K7M4N5P6Q7R8S9T0V${String(position).padStart(2, "0")}`,
    event_type: eventType,
    source: overrides.source ?? SOURCES.mcp,
    ts: overrides.ts ?? `2026-08-31T11:${String(40 + position).padStart(2, "0")}:00.000Z`,
    event_hash: overrides.event_hash ?? (HASHES[at % HASHES.length] as string),
    prev_event_hash:
      overrides.prev_event_hash ?? (HASHES[(at + HASHES.length - 1) % HASHES.length] as string),
    ...(overrides.canonical === undefined ? {} : { canonical: overrides.canonical }),
  };
}

/** A run that registered, took a credential, called a tool, intended a commit
 * and recorded it, then retired. The calm case doc 06 P3 describes. */
export function healthyTimeline(): readonly TimelineEvent[] {
  return [
    ledgerEvent(EVENT_TYPES.runRegistered, 1, {
      canonical: { agent_type: "fix-ci", task_ref: "JIRA-118" },
    }),
    ledgerEvent(EVENT_TYPES.credentialIssued, 2, {
      canonical: {
        audience: "innsegl.dev",
        credential_expiry: "2026-08-31T12:42:00.000Z",
      },
    }),
    ledgerEvent(EVENT_TYPES.toolCall, 3, {
      canonical: {
        tool_name: "edit_file",
        payload_digest:
          "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      },
    }),
    ledgerEvent(EVENT_TYPES.commitIntent, 4, {
      canonical: { repo: "innsegl", tree_hash: "9a8b7c6d5e4f302918273645afbecd0192837465" },
    }),
    ledgerEvent(EVENT_TYPES.commitRecorded, 5, {
      canonical: {
        commit_sha: COMMIT_SHA,
        intent_event_id: "01HQ8Z3K7M4N5P6Q7R8S9T0V04",
        rekor_entry_uuid:
          "24296fb24b8ad77a1c9f6d3e5b4a2f1908e7d6c5b4a39281706f5e4d3c2b1a09",
        rekor_log_index: 82914,
        repo: "innsegl",
        tree_hash: "9a8b7c6d5e4f302918273645afbecd0192837465",
      },
    }),
    ledgerEvent(EVENT_TYPES.runRetired, 6),
  ];
}

/** The whole response, with the timeline the caller chooses. */
export function runDetail(
  timeline: readonly TimelineEvent[] = healthyTimeline(),
  status = "retired",
): RunDetail {
  return {
    run_id: RUN_ID,
    spiffe_id: SPIFFE_ID,
    agent_type: "fix-ci",
    task_ref: "JIRA-118",
    status,
    repos: ["innsegl"],
    commits: 1,
    chain_position: 46,
    registered_at: "2026-08-31T11:41:00.000Z",
    last_event_at: "2026-08-31T11:46:00.000Z",
    timeline,
    data_as_of: "2026-08-31T12:00:00.000Z",
  };
}

/** The instant every test renders against, so a relative time is a constant. */
export const NOW = new Date("2026-08-31T12:00:00.000Z");
