// SPDX-License-Identifier: Apache-2.0

/*
 * The run page's contract (E19, #395–#397): one agent's full record, as
 * `internal/api/record.go` returns it. Every member carries the Go type's
 * JSON name, snake_case and all. `fixtures/record.json` is read by both this
 * page and `internal/api`'s TestRunRecordFixtureMatchesTheContract, which
 * decodes it strictly, so the two sides cannot drift.
 */

export type RunStatus = "active" | "retired" | "expired" | "lapsed" | "abandoned";

export interface RecordRun {
  run_id: string;
  spiffe_id: string;
  agent_type: string;
  task_ref: string;
  repo: string;
  branch: string;
  status: RunStatus;
  status_at: string | null;
  registered_at: string;
  parent_run_id: string;
  forked_from_run_id: string;
}

export interface RecordTreeNode {
  run_id: string;
  agent_type: string;
  parent_run_id: string;
  status: RunStatus;
  /** The parent's step that spawned this agent; 0 for the root. */
  spawned_by: number;
}

export interface RecordTree {
  root_run_id: string;
  nodes: RecordTreeNode[];
}

export interface RecordMessage {
  text: string;
  digest: string;
  available: boolean;
  at: string;
}

export type OutcomeKind = "ok" | "error" | "refused" | "unknown";

export interface RecordOutcome {
  kind: OutcomeKind;
  exit_code: number | null;
}

export interface RecordWitnesses {
  gateway: "present" | "missing";
  snapshot: "changed" | "unchanged" | "none" | "inactive";
  telemetry: "matched" | "missing" | "pending" | "inactive";
}

/** A added, M modified, D deleted, R changed during the run and back. */
export type FileStatus = "A" | "M" | "D" | "R";

export interface RecordFile {
  path: string;
  status: FileStatus;
  additions: number;
  deletions: number;
  steps: number[];
  committed: boolean;
  /** The agent that changed it when that is not this run; "" for this run. */
  by_run_id: string;
}

export interface RecordStep {
  n: number;
  tool_use_id: string;
  event_id: string;
  chain_position: number;
  at: string;
  tool: string;
  summary: string;
  input: string;
  output: string;
  truncated: boolean;
  /** The record capped input or output; GET .../steps/{n} serves it in full (#440). */
  clipped: boolean;
  outcome: RecordOutcome;
  tree_before: string;
  tree_after: string;
  files: RecordFile[];
  spawned_run_id: string;
  spawned_commits: string[];
  /** "tool", "spawn" (started a subagent) or "report" (its final report) (#443). */
  kind: "tool" | "spawn" | "report";
  commit_sha: string;
  witnesses: RecordWitnesses;
}

export type Landed = "landed" | "not_landed" | "rewritten" | "unknown";

export interface RecordCommit {
  sha: string;
  subject: string;
  /** The step that made it; 0 when none can be named. */
  step: number;
  landed: Landed;
  /** Why a not_landed commit did not land, when the run's own result says:
   * "ref_lock" (git's ref lock went to a parallel commit), else "". */
  landed_reason: "" | "ref_lock";
  rekor_log_index: number;
  /** The run whose identity signed it: this run, or a one-commit signing identity it started (#443). */
  signed_by: string;
}

export interface RecordWitness {
  steps: number;
  agree: number;
  disagree: number;
  unchecked: number;
  bodies_stored: number;
  bodies_verified: number;
}

/** One ancestor of this agent, the session first (#443). */
export interface RecordAncestor {
  run_id: string;
  title: string;
  agent_type: string;
  role: "session" | "subagent";
  /** The step of this ancestor's own parent that started it; 0 for the session. */
  spawned_at_step: number;
}

/** Text the record holds, or not (#443). */
export interface RecordText {
  text: string;
  available: boolean;
  /** The step of this run it came from; 0 for the parent's spawn or none. */
  step: number;
}

/** This run seen as one agent (#443). */
export interface RecordAgent {
  /** The task its parent gave it when spawning it; "" when none is on record. */
  title: string;
  role: "session" | "subagent";
  model: string;
  /** The parent's step that started it; 0 when unknown or a session. */
  spawned_at_step: number;
  /** How that step was matched: the spawn's returned agent id, the exact prompt, or not at all. */
  linked_by: "" | "agent_id" | "brief";
  /** Every ancestor, the session first and the parent last. */
  lineage: RecordAncestor[];
  asked: RecordText;
  reported: RecordText;
}

/** One agent this run started (#443). */
export interface RecordChild {
  run_id: string;
  title: string;
  agent_type: string;
  model: string;
  spawned_at_step: number;
  steps: number;
  commits: number;
  status: string;
  ended_at: string | null;
}

/** A file a step of this run wrote: A created, M changed, W written without saying which (#443). */
export interface RecordWrite {
  path: string;
  status: "A" | "M" | "W";
  step: number;
}

export interface RunRecord {
  run: RecordRun;
  agent: RecordAgent;
  children: RecordChild[];
  written: RecordWrite[];
  tree: RecordTree;
  brief: RecordMessage;
  replies: RecordMessage[];
  steps: RecordStep[];
  files: RecordFile[];
  commits: RecordCommit[];
  witness: RecordWitness;
  data_as_of: string;
  chain_head: number;
}

export type DiffLineKind = "context" | "add" | "del";

export interface DiffLine {
  kind: DiffLineKind;
  old_no: number;
  new_no: number;
  text: string;
}

export interface DiffHunk {
  old_start: number;
  old_lines: number;
  new_start: number;
  new_lines: number;
  lines: DiffLine[];
}

export interface DiffFile {
  path: string;
  old_path: string;
  status: FileStatus;
  binary: boolean;
  truncated: boolean;
  hunks: DiffHunk[];
}

export interface StepDiff {
  files: DiffFile[];
}
