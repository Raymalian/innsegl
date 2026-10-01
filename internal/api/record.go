// SPDX-License-Identifier: Apache-2.0

package api

// The run page's contract (E19, #395–#397): one agent's full record, as the
// operator reads it — identity and place in the tree, the brief, every step
// with its input, output and outcome, what each step changed in the code,
// the commits linked to the steps that made them, and whether the three
// witnesses (the gateway, the workspace snapshots, the harness's telemetry)
// agree on each step.
//
// The web page's types (web/src/views/run-page/types.ts) mirror these
// member for member, and the one fixture both sides read
// (web/src/views/run-page/fixtures/record.json) is decoded strictly here
// (TestRunRecordFixtureMatchesTheContract), so neither side can add or
// rename a member the other does not know.

import "time"

// RunRecord answers GET /api/v1/runs/{run_id}/record.
type RunRecord struct {
	Run RecordRun `json:"run"`
	// Agent is this run as one agent: what it was for, where it came from,
	// what it was asked and what it reported (#443).
	Agent RecordAgent `json:"agent"`
	// Children are the agents this run started, direct children only and
	// never an identity that only signed a commit (#443).
	Children []RecordChild `json:"children"`
	// Written lists the files this run's own steps wrote, read from each
	// file-writing step's own input (#443).
	Written  []RecordWrite   `json:"written"`
	Tree     RecordTree      `json:"tree"`
	Brief    RecordMessage   `json:"brief"`
	Replies  []RecordMessage `json:"replies"`
	Steps    []RecordStep    `json:"steps"`
	Files    []RecordFile    `json:"files"`
	Commits  []RecordCommit  `json:"commits"`
	Witness  RecordWitness   `json:"witness"`
	DataAsOf time.Time       `json:"data_as_of"`
	// ChainHead is the chain position this record was read at.
	ChainHead int64 `json:"chain_head"`
}

// RecordRun is who the agent is and where it works.
type RecordRun struct {
	RunID     string `json:"run_id"`
	SPIFFEID  string `json:"spiffe_id"`
	AgentType string `json:"agent_type"`
	TaskRef   string `json:"task_ref"`
	Repo      string `json:"repo"`
	Branch    string `json:"branch"`
	// Status is the ledger's: active, retired, expired, lapsed or abandoned.
	Status       string     `json:"status"`
	StatusAt     *time.Time `json:"status_at"`
	RegisteredAt time.Time  `json:"registered_at"`
	ParentRunID  string     `json:"parent_run_id"`
	// ForkedFromRunID is set only on a fork (ADR-0058 decision 5).
	ForkedFromRunID string `json:"forked_from_run_id"`
}

// RecordAgent is a run seen as one agent (#443).
type RecordAgent struct {
	// Title is the task its parent gave it when spawning it (the spawn's
	// own description), "" when none is on record.
	Title string `json:"title"`
	// Role is "session" for a run nothing started, else "subagent".
	Role string `json:"role"`
	// Model is the model the spawn named, "" when it named none.
	Model string `json:"model"`
	// SpawnedAtStep is the parent's step that started it, 0 when unknown or
	// a session.
	SpawnedAtStep int `json:"spawned_at_step"`
	// LinkedBy says how the parent's step was matched: "agent_id" (the id
	// the spawn returned, carried by this run's own steps), "brief" (the
	// exact prompt), or "" (not matched).
	LinkedBy string `json:"linked_by"`
	// Lineage is every ancestor, the session first and the parent last.
	Lineage []RecordAncestor `json:"lineage"`
	// Asked is the instructions it was given: the spawn's prompt, or for a
	// session its first message.
	Asked RecordText `json:"asked"`
	// Reported is its final report to its parent, or a session's last reply.
	Reported RecordText `json:"reported"`
}

// RecordAncestor is one agent above this one.
type RecordAncestor struct {
	RunID     string `json:"run_id"`
	Title     string `json:"title"`
	AgentType string `json:"agent_type"`
	Role      string `json:"role"`
	// SpawnedAtStep is the step of THIS ancestor's own parent that started
	// it, 0 for the session.
	SpawnedAtStep int `json:"spawned_at_step"`
	// Agents is how many agents this ancestor started, signing identities
	// not counted.
	Agents int `json:"agents"`
}

// RecordText is a piece of text this run's record holds, or not.
type RecordText struct {
	Text      string `json:"text"`
	Available bool   `json:"available"`
	// Step is the step of this run it came from, 0 when it came from the
	// parent's spawn or no step.
	Step int `json:"step"`
}

// RecordChild is one agent this run started.
type RecordChild struct {
	RunID         string     `json:"run_id"`
	Title         string     `json:"title"`
	AgentType     string     `json:"agent_type"`
	Model         string     `json:"model"`
	SpawnedAtStep int        `json:"spawned_at_step"`
	Steps         int        `json:"steps"`
	Commits       int        `json:"commits"`
	Status        string     `json:"status"`
	EndedAt       *time.Time `json:"ended_at"`
}

// RecordWrite is one file a step of this run wrote. Status is A (the tool
// created it), M (it changed an existing file) or W (written, and the tool
// did not say which).
type RecordWrite struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Step   int    `json:"step"`
}

// RecordTree is the whole family this run belongs to, root first.
type RecordTree struct {
	RootRunID string           `json:"root_run_id"`
	Nodes     []RecordTreeNode `json:"nodes"`
}

// RecordTreeNode is one agent in the family.
type RecordTreeNode struct {
	RunID       string `json:"run_id"`
	AgentType   string `json:"agent_type"`
	ParentRunID string `json:"parent_run_id"`
	Status      string `json:"status"`
	// SpawnedBy is the parent's step that spawned this agent, 0 for the root.
	SpawnedBy int `json:"spawned_by"`
}

// RecordMessage is a brief or a reply. Text is empty when the body is not
// held (Available false); Digest is always the ledger's keyed digest.
type RecordMessage struct {
	Text      string    `json:"text"`
	Digest    string    `json:"digest"`
	Available bool      `json:"available"`
	At        time.Time `json:"at"`
}

// RecordStep is one tool call, numbered from 1 in the order the run made them.
type RecordStep struct {
	N             int       `json:"n"`
	ToolUseID     string    `json:"tool_use_id"`
	EventID       string    `json:"event_id"`
	ChainPosition int64     `json:"chain_position"`
	At            time.Time `json:"at"`
	Tool          string    `json:"tool"`
	// Summary is the one line the timeline shows: a command, a file path.
	Summary string `json:"summary"`
	// Input and Output are the stored body's own text, possibly truncated.
	Input     string `json:"input"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
	// Clipped is true when the record capped Input or Output to keep the
	// page light; GET .../steps/{n} serves the step in full (#440).
	Clipped bool          `json:"clipped"`
	Outcome RecordOutcome `json:"outcome"`
	// TreeBefore and TreeAfter are the workspace snapshots around the step;
	// empty when no snapshot was taken.
	TreeBefore string       `json:"tree_before"`
	TreeAfter  string       `json:"tree_after"`
	Files      []RecordFile `json:"files"`
	// SpawnedRunID is the agent this step started, when it started one, and
	// SpawnedCommits the commits that agent made on its own run.
	SpawnedRunID   string   `json:"spawned_run_id"`
	SpawnedCommits []string `json:"spawned_commits"`
	// Kind is "tool", "spawn" (it started a subagent) or "report" (its
	// final report to its parent) (#443).
	Kind string `json:"kind"`
	// CommitSHA is the commit this step made, when it made one.
	CommitSHA string          `json:"commit_sha"`
	Witnesses RecordWitnesses `json:"witnesses"`
}

// RecordOutcome is how the step ended.
type RecordOutcome struct {
	// Kind is ok, error, refused or unknown (no result was observed).
	Kind string `json:"kind"`
	// ExitCode is set when the tool reported one.
	ExitCode *int `json:"exit_code"`
}

// RecordWitnesses is each witness's view of one step.
type RecordWitnesses struct {
	// Gateway is present (the gateway relayed and stored it) or missing.
	Gateway string `json:"gateway"`
	// Snapshot is changed, unchanged, none (no snapshot around the step, in a
	// run that has them) or inactive (this run never had snapshots).
	Snapshot string `json:"snapshot"`
	// Telemetry is matched, missing, pending (inside the window) or
	// inactive (this run's harness was not yet, or never, exporting it).
	Telemetry string `json:"telemetry"`
}

// RecordFile is one file a step (or the whole run) changed. Status is A, M,
// D, or R (changed during the run and back to where it started).
type RecordFile struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	// Steps lists the steps that changed it (whole-run files only).
	Steps []int `json:"steps"`
	// Committed is whether a commit carries the change.
	Committed bool `json:"committed"`
	// ByRunID is the agent that changed it when that is not this run (a
	// subagent writing in the same working tree); empty for this run.
	ByRunID string `json:"by_run_id"`
}

// RecordCommit is a commit this run signed.
type RecordCommit struct {
	SHA     string `json:"sha"`
	Subject string `json:"subject"`
	// Step is the step that made it, 0 when none can be named.
	Step int `json:"step"`
	// Landed is landed, not_landed, rewritten or unknown (ADR-0059 §6:
	// derived, never recorded).
	Landed string `json:"landed"`
	// LandedReason says why a not_landed commit did not land when the run's
	// own git commit result shows it: "ref_lock" (git's ref lock went to a
	// parallel commit), else "".
	LandedReason  string `json:"landed_reason"`
	RekorLogIndex int64  `json:"rekor_log_index"`
	// SignedBy is the run whose identity signed it: this run, or a
	// one-commit signing identity this run started (#443).
	SignedBy string `json:"signed_by"`
}

// RecordWitness sums the per-step witness agreement.
type RecordWitness struct {
	Steps     int `json:"steps"`
	Agree     int `json:"agree"`
	Disagree  int `json:"disagree"`
	Unchecked int `json:"unchecked"`
	// BodiesStored and BodiesVerified count the steps whose body is held
	// and whose digest matches the ledger's.
	BodiesStored   int `json:"bodies_stored"`
	BodiesVerified int `json:"bodies_verified"`
}

// StepDiff answers GET /api/v1/runs/{run_id}/steps/{n}/diff: what the step
// changed, from TreeBefore to TreeAfter.
type StepDiff struct {
	Files []DiffFile `json:"files"`
}

// DiffFile is one file's hunks.
type DiffFile struct {
	Path      string     `json:"path"`
	OldPath   string     `json:"old_path"`
	Status    string     `json:"status"`
	Binary    bool       `json:"binary"`
	Truncated bool       `json:"truncated"`
	Hunks     []DiffHunk `json:"hunks"`
}

// DiffHunk is one @@ block.
type DiffHunk struct {
	OldStart int        `json:"old_start"`
	OldLines int        `json:"old_lines"`
	NewStart int        `json:"new_start"`
	NewLines int        `json:"new_lines"`
	Lines    []DiffLine `json:"lines"`
}

// DiffLine is one line: context, add or del, with its line numbers (0 where
// the side has none).
type DiffLine struct {
	Kind  string `json:"kind"`
	OldNo int    `json:"old_no"`
	NewNo int    `json:"new_no"`
	Text  string `json:"text"`
}
