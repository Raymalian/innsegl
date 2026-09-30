// SPDX-License-Identifier: Apache-2.0

/*
 * Pure functions over a RunRecord — nothing here touches the DOM or fetches
 * anything, so every one of them is exercised directly by RPG-010..014
 * without mounting a component. Kept separate from the components for the
 * same reason run-detail/events.ts is: a view this dense needs one place to
 * audit for "where does this sentence's number come from".
 */

import type {
  RecordFile,
  RecordStep,
  RecordTree,
  RecordWitness,
  RecordWitnesses,
  RunRecord,
} from "./types";

/** The repository's own name, stripped of a leading host segment, for the
 * fact card's "Repository · branch" — doc 06's mockup shows
 * "innsegl-test/gateway-livetest", not "github.com/innsegl-test/…"; the
 * breadcrumb keeps the full value, which is what §4.3's "link to their
 * canonical view" needs the host for. */
export function shortRepo(repo: string): string {
  const slash = repo.indexOf("/");
  if (slash === -1) return repo;
  const host = repo.slice(0, slash);
  return host.includes(".") ? repo.slice(slash + 1) : repo;
}

/** The last path segment of a repository, for the files-changed tree's own
 * folder row. */
export function repoFolderName(repo: string): string {
  const parts = repo.split("/").filter((p) => p !== "");
  return parts.length === 0 ? repo : (parts[parts.length - 1] as string);
}

/** How many of the three witnesses (gateway, snapshot, telemetry) agree that
 * a step happened as recorded. "Agree" reads "unchanged" as a legitimate
 * observation, same as "changed" — both are the snapshot witness having
 * something to say; "none" is the snapshot witness having nothing to say,
 * which does not agree any more than "missing" does. */
export function witnessAgreeCount(w: RecordWitnesses): number {
  let n = 0;
  if (w.gateway === "present") n++;
  if (w.snapshot === "changed" || w.snapshot === "unchanged") n++;
  if (w.telemetry === "matched") n++;
  return n;
}

export const WITNESS_TOTAL = 3;

export function stepWitnessesAgree(w: RecordWitnesses): boolean {
  return witnessAgreeCount(w) === WITNESS_TOTAL;
}

/** doc 06 §3.3's fact card, read off the run-level witness rollup rather than
 * recomputed from steps: `witness.agree`/`witness.disagree` are the ledger's
 * own count and doc 06 §6.2 asks for exact counts, not a client re-derivation
 * that could disagree with them. */
export function allWitnessesAgree(witness: RecordWitness): boolean {
  return witness.disagree === 0 && witness.unchecked === 0 && witness.steps > 0;
}

/** Whether every step's body is both stored and verified — the header's
 * "Every step has a stored body; digests verify" line, or its honest partial
 * form. */
export function everyBodyStoredAndVerified(witness: RecordWitness): boolean {
  return (
    witness.steps > 0 &&
    witness.bodies_stored === witness.steps &&
    witness.bodies_verified === witness.steps
  );
}

export interface ActivitySummary {
  readonly steps: number;
  readonly commits: number;
  readonly subagents: number;
  readonly files: number;
}

export function activitySummary(record: RunRecord): ActivitySummary {
  return {
    steps: record.steps.length,
    commits: record.commits.length,
    subagents: subagentCount(record.tree),
    files: record.files.length,
  };
}

/** Every tree node that is not the root is a spawned subagent. */
export function subagentCount(tree: RecordTree): number {
  return tree.nodes.filter((node) => node.run_id !== tree.root_run_id).length;
}

/** The first step whose witnesses disagree, or null when none do — doc 06's
 * States board: the page-level alert names this step, and the step's own
 * card renders the expanded witness grid only for this one. */
export function firstDisagreeingStep(record: RunRecord): RecordStep | undefined {
  return record.steps.find((step) => !stepWitnessesAgree(step.witnesses));
}

/** The sentence clause naming why a step's witnesses disagree — the
 * mockup's "the gateway relayed a tool call the harness's telemetry never
 * reported", generalised to the other shapes a disagreement can take. */
export function disagreementReason(w: RecordWitnesses): "telemetry-missing" | "gateway-missing" | "snapshot" | "generic" {
  if (w.gateway === "present" && w.telemetry !== "matched") return "telemetry-missing";
  if (w.gateway === "missing") return "gateway-missing";
  if (w.snapshot === "none") return "snapshot";
  return "generic";
}

/** A file the run touched and then reverted before it ever reached a commit:
 * States.dc.html's "R" row — written, then undone, never committed. */
export function isNeverCommitted(file: RecordFile): boolean {
  return file.status === "R" && !file.committed;
}

export function isBySubagent(file: RecordFile): boolean {
  return file.by_run_id !== "";
}

/** The step (if any) that wrote and later reverted a file — for "written in
 * step N, deleted in step M". `steps` on a RecordFile is every step that
 * touched it, in order; a reverted file's first and last are the two the
 * mockup names. */
export function writtenAndRevertedAt(file: RecordFile): { written: number; reverted: number } | undefined {
  if (file.steps.length < 2) return undefined;
  const written = file.steps[0] as number;
  const reverted = file.steps[file.steps.length - 1] as number;
  return { written, reverted };
}

/** A keyed digest for display — "hmac-sha256:gateway-v1:413c…0bec" (the
 * mockup's own form for the brief's and reply's captions). The algorithm and
 * key-version prefix is what a reader compares the SCHEME by; the hash
 * itself is what they would compare byte for byte against a re-derivation,
 * which nobody does by eye — so only the hash is middle-truncated, the
 * prefix survives whole, and the full value is still what
 * `IdentifierChip`-style components would copy if this page grows a copy
 * affordance for it later. Not `truncateIdentifier` itself: that function's
 * "segmented" path treats every `:`-delimited run as a droppable middle
 * segment, which would drop "gateway-v1" as readily as it drops the hash. */
export function truncateDigest(digest: string, keep = 4): string {
  const lastColon = digest.lastIndexOf(":");
  if (lastColon === -1) return digest;
  const prefix = digest.slice(0, lastColon + 1);
  const hash = digest.slice(lastColon + 1);
  if (hash.length <= keep * 2 + 1) return digest;
  return `${prefix}${hash.slice(0, keep)}…${hash.slice(hash.length - keep)}`;
}
