// SPDX-License-Identifier: Apache-2.0

/*
 * A runtime shape check for the run page's contract (types.ts).
 *
 * `types.ts` is the contract (#395-397) and is not this issue's to edit; this
 * file is the other half the task calls for — "a typed import or a runtime
 * shape check" that the provided fixtures satisfy it. A `JSON.parse()` result
 * is `any`, so assigning it to a `RunRecord`-typed constant would type-check
 * regardless of what the fixture actually contains; only a runtime walk of
 * the value proves the fixture matches the contract, which is what
 * `contract.test.ts` asks this module to do.
 */

import type {
  DiffFile,
  DiffHunk,
  DiffLine,
  RecordAgent,
  RecordAncestor,
  RecordChild,
  RecordCommit,
  RecordFile,
  RecordMessage,
  RecordRun,
  RecordStep,
  RecordText,
  RecordTree,
  RecordTreeNode,
  RecordWitness,
  RecordWitnesses,
  RecordWrite,
  RunRecord,
  StepDiff,
} from "./types";

function isString(v: unknown): v is string {
  return typeof v === "string";
}
function isNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}
function isBoolean(v: unknown): v is boolean {
  return typeof v === "boolean";
}
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isArray(v: unknown): v is unknown[] {
  return Array.isArray(v);
}

const RUN_STATUSES = ["active", "retired", "expired", "lapsed", "abandoned"];
const FILE_STATUSES = ["A", "M", "D", "R"];
const WRITE_STATUSES = ["A", "M", "W"];
const OUTCOME_KINDS = ["ok", "error", "refused", "unknown"];
const LANDED = ["landed", "not_landed", "rewritten", "unknown"];
const GATEWAY = ["present", "missing"];
// "inactive" belongs here same as it does on TELEMETRY (#438): a run
// recorded before the snapshot witness existed has nothing to say either,
// which is not the same fact as "none" (a snapshot witness that ran and saw
// nothing worth reporting).
const SNAPSHOT = ["changed", "unchanged", "none", "inactive"];
const TELEMETRY = ["matched", "missing", "pending", "inactive"];
const DIFF_LINE_KINDS = ["context", "add", "del"];
const AGENT_ROLES = ["session", "subagent"];
const LINKED_BY = ["", "agent_id", "brief"];
const STEP_KINDS = ["tool", "spawn", "report"];

function isRecordRun(v: unknown): v is RecordRun {
  if (!isObject(v)) return false;
  return (
    isString(v["run_id"]) &&
    isString(v["spiffe_id"]) &&
    isString(v["agent_type"]) &&
    isString(v["task_ref"]) &&
    isString(v["repo"]) &&
    isString(v["branch"]) &&
    isString(v["status"]) &&
    RUN_STATUSES.includes(v["status"] as string) &&
    (v["status_at"] === null || isString(v["status_at"])) &&
    isString(v["registered_at"]) &&
    isString(v["parent_run_id"]) &&
    isString(v["forked_from_run_id"])
  );
}

function isRecordTreeNode(v: unknown): v is RecordTreeNode {
  if (!isObject(v)) return false;
  return (
    isString(v["run_id"]) &&
    isString(v["agent_type"]) &&
    isString(v["parent_run_id"]) &&
    isString(v["status"]) &&
    RUN_STATUSES.includes(v["status"] as string) &&
    isNumber(v["spawned_by"])
  );
}

function isRecordTree(v: unknown): v is RecordTree {
  if (!isObject(v)) return false;
  return (
    isString(v["root_run_id"]) &&
    isArray(v["nodes"]) &&
    v["nodes"].every(isRecordTreeNode)
  );
}

function isRecordMessage(v: unknown): v is RecordMessage {
  if (!isObject(v)) return false;
  return (
    isString(v["text"]) &&
    isString(v["digest"]) &&
    isBoolean(v["available"]) &&
    isString(v["at"])
  );
}

function isRecordWitnesses(v: unknown): v is RecordWitnesses {
  if (!isObject(v)) return false;
  return (
    isString(v["gateway"]) &&
    GATEWAY.includes(v["gateway"] as string) &&
    isString(v["snapshot"]) &&
    SNAPSHOT.includes(v["snapshot"] as string) &&
    isString(v["telemetry"]) &&
    TELEMETRY.includes(v["telemetry"] as string)
  );
}

function isRecordFile(v: unknown): v is RecordFile {
  if (!isObject(v)) return false;
  return (
    isString(v["path"]) &&
    isString(v["status"]) &&
    FILE_STATUSES.includes(v["status"] as string) &&
    isNumber(v["additions"]) &&
    isNumber(v["deletions"]) &&
    isArray(v["steps"]) &&
    v["steps"].every(isNumber) &&
    isBoolean(v["committed"]) &&
    isString(v["by_run_id"])
  );
}

function isRecordStep(v: unknown): v is RecordStep {
  if (!isObject(v)) return false;
  const outcome = v["outcome"];
  const okOutcome =
    isObject(outcome) &&
    isString(outcome["kind"]) &&
    OUTCOME_KINDS.includes(outcome["kind"] as string) &&
    (outcome["exit_code"] === null || isNumber(outcome["exit_code"]));
  return (
    isNumber(v["n"]) &&
    isString(v["tool_use_id"]) &&
    isString(v["event_id"]) &&
    isNumber(v["chain_position"]) &&
    isString(v["at"]) &&
    isString(v["tool"]) &&
    isString(v["summary"]) &&
    isString(v["input"]) &&
    isString(v["output"]) &&
    isBoolean(v["truncated"]) &&
    isBoolean(v["clipped"]) &&
    okOutcome &&
    isString(v["tree_before"]) &&
    isString(v["tree_after"]) &&
    isArray(v["files"]) &&
    v["files"].every(isRecordFile) &&
    isString(v["spawned_run_id"]) &&
    isArray(v["spawned_commits"]) &&
    v["spawned_commits"].every(isString) &&
    isString(v["kind"]) &&
    STEP_KINDS.includes(v["kind"] as string) &&
    isString(v["commit_sha"]) &&
    isRecordWitnesses(v["witnesses"])
  );
}

function isRecordCommit(v: unknown): v is RecordCommit {
  if (!isObject(v)) return false;
  return (
    isString(v["sha"]) &&
    isString(v["subject"]) &&
    isNumber(v["step"]) &&
    isString(v["landed"]) &&
    LANDED.includes(v["landed"] as string) &&
    isNumber(v["rekor_log_index"]) &&
    isString(v["signed_by"])
  );
}

function isRecordAncestor(v: unknown): v is RecordAncestor {
  if (!isObject(v)) return false;
  return (
    isString(v["run_id"]) &&
    isString(v["title"]) &&
    isString(v["agent_type"]) &&
    isString(v["role"]) &&
    AGENT_ROLES.includes(v["role"] as string) &&
    isNumber(v["spawned_at_step"]) &&
    isNumber(v["agents"])
  );
}

function isRecordText(v: unknown): v is RecordText {
  if (!isObject(v)) return false;
  return isString(v["text"]) && isBoolean(v["available"]) && isNumber(v["step"]);
}

function isRecordAgent(v: unknown): v is RecordAgent {
  if (!isObject(v)) return false;
  return (
    isString(v["title"]) &&
    isString(v["role"]) &&
    AGENT_ROLES.includes(v["role"] as string) &&
    isString(v["model"]) &&
    isNumber(v["spawned_at_step"]) &&
    isString(v["linked_by"]) &&
    LINKED_BY.includes(v["linked_by"] as string) &&
    isArray(v["lineage"]) &&
    v["lineage"].every(isRecordAncestor) &&
    isRecordText(v["asked"]) &&
    isRecordText(v["reported"])
  );
}

function isRecordChild(v: unknown): v is RecordChild {
  if (!isObject(v)) return false;
  return (
    isString(v["run_id"]) &&
    isString(v["title"]) &&
    isString(v["agent_type"]) &&
    isString(v["model"]) &&
    isNumber(v["spawned_at_step"]) &&
    isNumber(v["steps"]) &&
    isNumber(v["commits"]) &&
    isString(v["status"]) &&
    (v["ended_at"] === null || isString(v["ended_at"]))
  );
}

function isRecordWrite(v: unknown): v is RecordWrite {
  if (!isObject(v)) return false;
  return (
    isString(v["path"]) &&
    isString(v["status"]) &&
    WRITE_STATUSES.includes(v["status"] as string) &&
    isNumber(v["step"])
  );
}

function isRecordWitness(v: unknown): v is RecordWitness {
  if (!isObject(v)) return false;
  return (
    isNumber(v["steps"]) &&
    isNumber(v["agree"]) &&
    isNumber(v["disagree"]) &&
    isNumber(v["unchecked"]) &&
    isNumber(v["bodies_stored"]) &&
    isNumber(v["bodies_verified"])
  );
}

/** Whether `v` satisfies `RunRecord` — every field, every nested shape. */
export function isRunRecord(v: unknown): v is RunRecord {
  if (!isObject(v)) return false;
  return (
    isRecordRun(v["run"]) &&
    isRecordAgent(v["agent"]) &&
    isArray(v["children"]) &&
    v["children"].every(isRecordChild) &&
    isArray(v["written"]) &&
    v["written"].every(isRecordWrite) &&
    isRecordTree(v["tree"]) &&
    isRecordMessage(v["brief"]) &&
    isArray(v["replies"]) &&
    v["replies"].every(isRecordMessage) &&
    isArray(v["steps"]) &&
    v["steps"].every(isRecordStep) &&
    isArray(v["files"]) &&
    v["files"].every(isRecordFile) &&
    isArray(v["commits"]) &&
    v["commits"].every(isRecordCommit) &&
    isRecordWitness(v["witness"]) &&
    isString(v["data_as_of"]) &&
    isNumber(v["chain_head"])
  );
}

function isDiffLine(v: unknown): v is DiffLine {
  if (!isObject(v)) return false;
  return (
    isString(v["kind"]) &&
    DIFF_LINE_KINDS.includes(v["kind"] as string) &&
    isNumber(v["old_no"]) &&
    isNumber(v["new_no"]) &&
    isString(v["text"])
  );
}

function isDiffHunk(v: unknown): v is DiffHunk {
  if (!isObject(v)) return false;
  return (
    isNumber(v["old_start"]) &&
    isNumber(v["old_lines"]) &&
    isNumber(v["new_start"]) &&
    isNumber(v["new_lines"]) &&
    isArray(v["lines"]) &&
    v["lines"].every(isDiffLine)
  );
}

function isDiffFile(v: unknown): v is DiffFile {
  if (!isObject(v)) return false;
  return (
    isString(v["path"]) &&
    isString(v["old_path"]) &&
    isString(v["status"]) &&
    FILE_STATUSES.includes(v["status"] as string) &&
    isBoolean(v["binary"]) &&
    isBoolean(v["truncated"]) &&
    isArray(v["hunks"]) &&
    v["hunks"].every(isDiffHunk)
  );
}

/** Whether `v` satisfies `StepDiff`. */
export function isStepDiff(v: unknown): v is StepDiff {
  if (!isObject(v)) return false;
  return isArray(v["files"]) && v["files"].every(isDiffFile);
}
