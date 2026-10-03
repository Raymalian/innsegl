// SPDX-License-Identifier: Apache-2.0

/*
 * What an alert is called and how it is said in one line — ADR-0054.
 *
 * The list in the header shows a title, a one-line summary and a time, and no
 * raw hash or field name: those are the detail view's job, where each one
 * sits in an identifier chip that can be copied whole (doc 06 §4.3).
 *
 * The reconciler raises drift with one of seven fixed reasons
 * (internal/reconciler/drift.go, witness.go, commitwatch.go); those are matched exactly and said in plain
 * words. A segment read raises drift with the storage error as its reason,
 * which is free text, so anything unmatched is shown as itself with long hex
 * runs shortened and field-name underscores spaced out. Nothing is inferred
 * from it: a summary that guessed at a cause would be a claim nobody made.
 */

import type { AlertRecord } from "../overview/types";
import { UNANCHORED } from "./explain";
import { strings } from "./strings";

/** internal/reconciler/drift.go's reasons, verbatim, to their plain words. */
const KNOWN_REASONS: Readonly<Record<string, string>> = {
  "commit_recorded claims a Rekor entry that the log does not contain":
    strings.alert.reasons.noLogEntry,
  "the rekor_entry_uuid this commit_recorded names cannot name any transparency log entry":
    strings.alert.reasons.unusableUuid,
  "the transparency log entry this commit_recorded names attests a different artifact from its commit_sha":
    strings.alert.reasons.otherArtifact,
  "the transparency log entry this commit_recorded names was accepted under a different certificate identity from its spiffe_id":
    strings.alert.reasons.otherIdentity,
  "the transparency log entry this commit_recorded names is at a different rekor_log_index":
    strings.alert.reasons.otherLogIndex,
  "the harness's own OTLP telemetry recorded no tool_result for this tool call":
    strings.alert.reasons.noTelemetryWitness,
  "a git commit was made with no signature recorded for it":
    strings.alert.reasons.commitNotSigned,
};

/** How long a summary may run before it is cut at a word. */
const SUMMARY_MAX = 110;
const ELLIPSIS = "…";

/** Open alerts only, newest first by chain position — the ledger's order. */
export function openNewestFirst(alerts: readonly AlertRecord[]): readonly AlertRecord[] {
  return alerts
    .filter((a) => !a.resolved)
    .slice()
    .sort((a, b) => b.chain_position - a.chain_position);
}

export function alertTitle(alert: AlertRecord): string {
  return alert.event_type === "ledger_drift_detected"
    ? strings.alert.driftTitle
    : strings.alert.unattributedTitle;
}

export function alertSummary(alert: AlertRecord): string {
  if (alert.event_type === "unattributed_signature_detected") {
    return strings.alert.unattributedDetail(alert.rekor_log_index ?? 0);
  }
  const reason = (alert.reason ?? "").trim();
  if (reason === "") return strings.alert.reasons.unknownDetail;
  // The sealer's own reason (internal/segment AnchorAlert), which has a fixed
  // shape: said as the range it is about, never as the hash (RM-203, #326).
  const unanchored = UNANCHORED.exec(reason);
  if (unanchored?.[1] !== undefined && unanchored[2] !== undefined) {
    return strings.alert.reasons.unanchored(unanchored[1], unanchored[2]);
  }
  return KNOWN_REASONS[reason] ?? readable(reason);
}

/** A free-text reason as one readable line. */
export function readable(reason: string): string {
  const spaced = reason
    .replace(/\b([0-9a-f]{8})[0-9a-f]{8,}\b/gi, `$1${ELLIPSIS}`)
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const clipped = clip(spaced);
  const capital = clipped.charAt(0).toUpperCase() + clipped.slice(1);
  return /[.?…]$/.test(capital) ? capital : `${capital}.`;
}

function clip(text: string): string {
  if (text.length <= SUMMARY_MAX) return text;
  const cut = text.slice(0, SUMMARY_MAX);
  const space = cut.lastIndexOf(" ");
  return `${(space > 0 ? cut.slice(0, space) : cut).replace(/[\s,;:.]+$/, "")}${ELLIPSIS}`;
}
