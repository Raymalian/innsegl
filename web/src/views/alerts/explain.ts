// SPDX-License-Identifier: Apache-2.0

/*
 * What raised an alert, and what that means — RM-330 (#506).
 *
 * The reconciler raises ledger drift with fixed reasons
 * (internal/reconciler/drift.go, witness.go, commitwatch.go) and the sealer
 * with one fixed shape (internal/segment AnchorAlert); an unattributed
 * signature is its own event type. Each is a cause this page can explain in
 * a paragraph and a next step. The five Rekor reasons are one cause here:
 * they differ in which field of the log entry disagrees, and what an operator
 * does about each is the same. Anything else is "other", explained as the
 * reconciler's own words, never guessed at.
 */

import type { AlertRecord } from "../overview/types";
import { strings } from "./strings";

export type AlertCause =
  | "noTelemetryWitness"
  | "commitNotSigned"
  | "rekorMismatch"
  | "unanchored"
  | "unattributed"
  | "other";

/** internal/reconciler's reasons, verbatim, to their cause. */
const CAUSE_OF_REASON: Readonly<Record<string, AlertCause>> = {
  "the harness's own OTLP telemetry recorded no tool_result for this tool call":
    "noTelemetryWitness",
  "a git commit was made with no signature recorded for it": "commitNotSigned",
  "commit_recorded claims a Rekor entry that the log does not contain": "rekorMismatch",
  "the rekor_entry_uuid this commit_recorded names cannot name any transparency log entry":
    "rekorMismatch",
  "the transparency log entry this commit_recorded names attests a different artifact from its commit_sha":
    "rekorMismatch",
  "the transparency log entry this commit_recorded names was accepted under a different certificate identity from its spiffe_id":
    "rekorMismatch",
  "the transparency log entry this commit_recorded names is at a different rekor_log_index":
    "rekorMismatch",
};

/** The sealer's anchoring failure, as internal/segment AnchorAlert words it. */
export const UNANCHORED =
  /^segment sha256:[0-9a-f]+ \(positions (\d+)\.\.(\d+)\) is sealed but has no transparency log entry/;

export function alertCause(alert: AlertRecord): AlertCause {
  if (alert.event_type === "unattributed_signature_detected") return "unattributed";
  const reason = (alert.reason ?? "").trim();
  if (UNANCHORED.test(reason)) return "unanchored";
  return CAUSE_OF_REASON[reason] ?? "other";
}

export interface Explanation {
  readonly title: string;
  readonly whatDetail: string;
  readonly todoDetail: string;
}

export function explain(cause: AlertCause): Explanation {
  return strings.explain[cause];
}
