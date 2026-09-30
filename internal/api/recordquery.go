// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// recordquery.go reads everything the run page's record (RunRecord, record.go)
// needs out of the ledger. It answers to two rules the rest of this package
// already holds: nothing here computes a verdict the database alone could not
// honestly give (IP §6.11, FD P2 — see query.go's own package comment), and
// the four lifecycle states are internal/ledger's rule, reused rather than
// rederived (see runFactsFromRows below).
//
// # One read per run, not one read per field
//
// A run's steps, its commits, its messages and the facts its status is
// derived from are all folded out of ONE ordered read of its own event
// chain (runTimeline) — the same "one walk, N readers" discipline
// internal/reconciler's own passes hold each other to (writes.go's package
// comment). Building a RunRecord costs a handful of additional queries (the
// family tree, the bodies on disk, the snapshot store), never a second walk
// of the same run's own events.

// recordEventRow is one event of a run's own chain, read once and folded by
// every reader that needs it (facts, steps, commits, messages).
type recordEventRow struct {
	ChainPosition int64
	EventID       string
	EventType     string
	Source        string
	TS            time.Time
	Body          map[string]any
}

const runTimelineSQL = `
SELECT chain_position, event_id, event_type, source, ts,
       convert_from(canonical, 'UTF8')::jsonb
  FROM innsegl.events
 WHERE run_id = $1
 ORDER BY chain_position`

// runTimeline reads every event of one run, in chain order. Unpaged, for
// runSQL's own reason (query.go): doc 05 §4 sizes a run at ~20 events, and a
// page of a run's own history could cut off the one event that says what
// happened to it.
func (s *Store) runTimeline(ctx context.Context, runID string) ([]recordEventRow, error) {
	rows, err := s.pool.Query(ctx, runTimelineSQL, runID)
	if err != nil {
		return nil, fmt.Errorf("api: reading the chain of %s: %w", runID, err)
	}
	defer rows.Close()

	var out []recordEventRow
	for rows.Next() {
		var r recordEventRow
		if err := rows.Scan(&r.ChainPosition, &r.EventID, &r.EventType, &r.Source, &r.TS, &r.Body); err != nil {
			return nil, fmt.Errorf("api: reading an event of %s: %w", runID, err)
		}
		r.TS = r.TS.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: reading the chain of %s: %w", runID, err)
	}
	return out, nil
}

// registeredFields is what a run_registered event carries that the rest of
// this file needs — doc 02 §3's run_registered members, read out of the
// canonical body rather than duplicated into a second table.
type registeredFields struct {
	SpiffeID        string
	AgentType       string
	TaskRef         string
	Repo            string
	Branch          string
	ParentRunID     string
	ForkedFromRunID string
	RegisteredAt    time.Time
}

// registeredFieldsOf finds the run_registered event among rows — the
// timeline of a single run, already scoped to it by runTimeline's own
// WHERE clause — or false when it holds none, a run id this ledger has
// never registered.
func registeredFieldsOf(rows []recordEventRow) (registeredFields, bool) {
	for _, r := range rows {
		if r.EventType != event.EventTypeRunRegistered {
			continue
		}
		return registeredFields{
			SpiffeID:        stringOf(r.Body[event.FieldSpiffeID]),
			AgentType:       stringOf(r.Body[event.FieldAgentType]),
			TaskRef:         stringOf(r.Body[event.FieldTaskRef]),
			Repo:            stringOf(r.Body[event.FieldRepo]),
			Branch:          stringOf(r.Body[event.FieldBranch]),
			ParentRunID:     stringOf(r.Body[event.FieldParentRunID]),
			ForkedFromRunID: stringOf(r.Body[event.FieldForkedFromRunID]),
			RegisteredAt:    r.TS,
		}, true
	}
	return registeredFields{}, false
}

// runFactsFromRows folds runFacts (internal/ledger.RunFacts) out of one run's
// own timeline — the SAME four facts runIndexCTE folds in SQL for the runs
// table, refolded here in Go because this handler already reads every event
// of the run for its steps and has no reason to ask Postgres the same
// question twice. RunStateOf (internal/ledger/runstate.go) is the one rule;
// this is the one place besides query.go that supplies its inputs.
func runFactsFromRows(rows []recordEventRow) ledger.RunFacts {
	var f ledger.RunFacts
	for _, r := range rows {
		switch r.EventType {
		case event.EventTypeRunRegistered:
			if f.RegisteredAt.IsZero() {
				f.RegisteredAt = r.TS
			}
		case event.EventTypeRunRetired:
			f.Retired = true
			if f.RetiredAt.IsZero() || r.TS.Before(f.RetiredAt) {
				f.RetiredAt = r.TS
			}
		case event.EventTypeRunExpired:
			if r.TS.After(f.WithdrawnAt) {
				f.WithdrawnAt = r.TS
			}
		}
		// r.Source is always readable here: it is scanned from the events
		// table's own required `source` column, never a value that failed to
		// parse out of a JSON body.
		if ledger.CountsAsActivity(r.Source, true) && r.TS.After(f.LastActivityAt) {
			f.LastActivityAt = r.TS
		}
	}
	return f
}

// retiredAtOf returns the earliest run_retired's own ts, and false when the
// run was never retired — record.go's RunRecord.StatusAt needs the INSTANT,
// not merely the bool runFactsFromRows already folds.
func retiredAtOf(rows []recordEventRow) (time.Time, bool) {
	var at time.Time
	found := false
	for _, r := range rows {
		if r.EventType != event.EventTypeRunRetired {
			continue
		}
		if !found || r.TS.Before(at) {
			at = r.TS
			found = true
		}
	}
	return at, found
}

// statusAndAt derives RunRecord.Status and RunRecord.StatusAt from facts: the
// ledger's own four-state rule (RunStateOf), plus the one instant that rule
// rests on — the retirement, or the standing withdrawal. An active run
// carries no particular instant of its own: it is not ended and it has not
// lapsed, so nothing here would be honest to point StatusAt at.
func statusAndAt(facts ledger.RunFacts, retiredAt time.Time, retired bool, now time.Time, horizon time.Duration) (status string, at *time.Time) {
	status = ledger.RunStateOf(facts, now, horizon)
	switch status {
	case ledger.RunRetired:
		if retired {
			t := retiredAt.UTC()
			return status, &t
		}
	case ledger.RunLapsed, ledger.RunAbandoned:
		if !facts.WithdrawnAt.IsZero() {
			t := facts.WithdrawnAt.UTC()
			return status, &t
		}
	}
	return status, nil
}

const parentSnapshotBeforeSQL = `
SELECT body->>'workspace_tree_hash'
  FROM (SELECT convert_from(canonical, 'UTF8')::jsonb AS body, chain_position
          FROM innsegl.events
         WHERE run_id = $1 AND event_type = 'tool_call' AND ts <= $2) t
 WHERE body->>'workspace_tree_hash' IS NOT NULL
 ORDER BY chain_position DESC
 LIMIT 1`

// parentSnapshotBefore answers the newest workspace_tree_hash parentRunID's
// own tool_call stream carries at or before `before` — record.go's rule for
// a subagent's own first snapshot: "the tree before is ... the parent
// session" when the subagent's own run has taken none of its own yet.
// Empty, not an error, when the parent took no snapshot before that
// instant at all.
func (s *Store) parentSnapshotBefore(ctx context.Context, parentRunID string, before time.Time) (string, error) {
	var tree *string
	err := s.pool.QueryRow(ctx, parentSnapshotBeforeSQL, parentRunID, before).Scan(&tree)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("api: reading %s's snapshot before %s: %w", parentRunID, before, err)
	}
	if tree == nil {
		return "", nil
	}
	return *tree, nil
}

// chainHead answers the chain position of the newest event this ledger
// holds, at the instant of this read — RunRecord.ChainHead's own evidence
// that the record was read against a stated point in the chain rather than
// an unstated one. Zero on a chain with no events at all.
func (s *Store) chainHead(ctx context.Context) (int64, error) {
	var head int64
	if err := s.pool.QueryRow(ctx,
		"SELECT coalesce(max(chain_position), 0) FROM innsegl.events").Scan(&head); err != nil {
		return 0, fmt.Errorf("api: reading the chain head: %w", err)
	}
	return head, nil
}

// ---------------------------------------------------------------------------
// The family tree: every run related to runID by parent_run_id, root first.
// ---------------------------------------------------------------------------

// familyNode is one run_registered in the family, as familySQL reads it.
type familyNode struct {
	RunID        string
	ParentRunID  string
	AgentType    string
	RegisteredAt time.Time
}

// maxFamilyDepth bounds both halves of familySQL's own recursion: the walk
// up to the root, and the walk down from it. A cycle in parent_run_id cannot
// exist in an honestly-written chain, but this query does not trust that —
// it stops rather than recursing forever against one that was tampered with
// or simply wrong.
const maxFamilyDepth = 128

const familySQL = `
WITH RECURSIVE reg AS (
    SELECT run_id, ts AS registered_at,
           convert_from(canonical, 'UTF8')::jsonb->>'agent_type'    AS agent_type,
           convert_from(canonical, 'UTF8')::jsonb->>'parent_run_id' AS parent_run_id
      FROM innsegl.events
     WHERE event_type = 'run_registered'
), up AS (
    SELECT run_id, parent_run_id, 0 AS depth FROM reg WHERE run_id = $1
    UNION ALL
    SELECT r.run_id, r.parent_run_id, u.depth + 1
      FROM reg r JOIN up u ON r.run_id = u.parent_run_id
     WHERE u.depth < $2
), root AS (
    SELECT run_id FROM up ORDER BY depth DESC LIMIT 1
), down AS (
    SELECT reg.run_id, reg.parent_run_id, reg.agent_type, reg.registered_at, 0 AS depth
      FROM reg, root WHERE reg.run_id = root.run_id
    UNION ALL
    SELECT r.run_id, r.parent_run_id, r.agent_type, r.registered_at, d.depth + 1
      FROM reg r JOIN down d ON r.parent_run_id = d.run_id
     WHERE d.depth < $2
)
SELECT run_id, coalesce(parent_run_id, ''), coalesce(agent_type, ''), registered_at
  FROM down`

// family reads the whole family runID belongs to: every run_registered
// reachable by following parent_run_id up to the root and back down to
// every descendant. A run with no run_registered at all (never registered,
// or a chain this deployment never held) answers a single-node family of
// runID alone — RunRecord.Tree still has to name SOMETHING, and inventing a
// parent for an unregistered run would be a guess record.go's own
// RecordRun.ParentRunID does not make either.
func (s *Store) family(ctx context.Context, runID string) ([]familyNode, error) {
	rows, err := s.pool.Query(ctx, familySQL, runID, maxFamilyDepth)
	if err != nil {
		return nil, fmt.Errorf("api: reading the family of %s: %w", runID, err)
	}
	defer rows.Close()

	var out []familyNode
	for rows.Next() {
		var n familyNode
		if err := rows.Scan(&n.RunID, &n.ParentRunID, &n.AgentType, &n.RegisteredAt); err != nil {
			return nil, fmt.Errorf("api: reading a family member of %s: %w", runID, err)
		}
		n.RegisteredAt = n.RegisteredAt.UTC()
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: reading the family of %s: %w", runID, err)
	}
	if len(out) == 0 {
		// No run_registered for runID at all: familySQL's `up` seed found
		// nothing, so `root` and `down` are both empty. Named explicitly
		// rather than left for a caller to puzzle out from a zero-length
		// slice with no run_id in it anywhere.
		out = append(out, familyNode{RunID: runID})
	}
	return out, nil
}

const familyFactsSQL = `
SELECT run_id,
       bool_or(event_type = 'run_retired') AS retired,
       min(ts) FILTER (WHERE event_type = 'run_retired') AS retired_at,
       max(ts) FILTER (WHERE event_type = 'run_expired') AS withdrawn_at,
       max(ts) FILTER (WHERE ` + ledger.ActivitySQL + `) AS last_activity_at,
       min(ts) FILTER (WHERE event_type = 'run_registered') AS registered_at
  FROM innsegl.events
 WHERE run_id = ANY($1)
 GROUP BY run_id`

// familyFacts reads runFacts for every run id in ids, in one query — the
// batched counterpart of runFactsFromRows for every OTHER member of a
// family, none of whose full timelines this handler otherwise reads.
func (s *Store) familyFacts(ctx context.Context, ids []string) (map[string]ledger.RunFacts, error) {
	out := make(map[string]ledger.RunFacts, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, familyFactsSQL, ids)
	if err != nil {
		return nil, fmt.Errorf("api: reading family status facts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var runID string
		var f ledger.RunFacts
		var retiredAt, withdrawnAt, lastActivityAt, registeredAt *time.Time
		if err := rows.Scan(&runID, &f.Retired, &retiredAt, &withdrawnAt, &lastActivityAt, &registeredAt); err != nil {
			return nil, fmt.Errorf("api: reading a family member's status facts: %w", err)
		}
		if retiredAt != nil {
			f.RetiredAt = retiredAt.UTC()
		}
		if withdrawnAt != nil {
			f.WithdrawnAt = withdrawnAt.UTC()
		}
		if lastActivityAt != nil {
			f.LastActivityAt = lastActivityAt.UTC()
		}
		if registeredAt != nil {
			f.RegisteredAt = registeredAt.UTC()
		}
		out[runID] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: reading family status facts: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Commits: commit_recorded, for one run or for a set (spawned_commits).
// ---------------------------------------------------------------------------

// commitRow is one commit_recorded, as this file reads it.
type commitRow struct {
	EventID       string
	RunID         string
	TS            time.Time
	CommitSHA     string
	TreeHash      string
	Subject       string
	RekorLogIndex int64
	Supersedes    string
	Repo          string
}

const commitsByRunSQL = `
SELECT event_id, run_id, ts, convert_from(canonical, 'UTF8')::jsonb
  FROM innsegl.events
 WHERE run_id = $1 AND event_type = 'commit_recorded'
 ORDER BY chain_position`

// commitsOf reads every commit_recorded this run itself signed, chain order.
// commit_recorded carries no subject (doc 02 §3): RecordCommit.Subject is
// read from the commit object itself (readCommitSubject), a separate git
// call this function does not make.
func (s *Store) commitsOf(ctx context.Context, runID string) ([]commitRow, error) {
	rows, err := s.pool.Query(ctx, commitsByRunSQL, runID)
	if err != nil {
		return nil, fmt.Errorf("api: reading commits of %s: %w", runID, err)
	}
	defer rows.Close()

	var out []commitRow
	for rows.Next() {
		var eventID, rowRunID string
		var ts time.Time
		var body map[string]any
		if err := rows.Scan(&eventID, &rowRunID, &ts, &body); err != nil {
			return nil, fmt.Errorf("api: reading a commit of %s: %w", runID, err)
		}
		out = append(out, commitRow{
			EventID:       eventID,
			RunID:         rowRunID,
			TS:            ts.UTC(),
			CommitSHA:     stringOf(body[event.FieldCommitSHA]),
			TreeHash:      stringOf(body[event.FieldTreeHash]),
			RekorLogIndex: int64Of(body[event.FieldRekorLogIndex]),
			Supersedes:    stringOf(body[event.FieldSupersedes]),
			Repo:          stringOf(body[event.FieldRepo]),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: reading commits of %s: %w", runID, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Spawn candidates: a parent's own Agent-tool tool_call steps, for matching
// a child run to the step that spawned it (recordspawn.go).
// ---------------------------------------------------------------------------

// agentStepRow is one Agent-tool tool_call of a (potential) parent run.
type agentStepRow struct {
	RunID         string
	EventID       string
	ChainPosition int64
	PayloadDigest string
}

const agentStepsSQL = `
SELECT run_id, event_id, chain_position, convert_from(canonical, 'UTF8')::jsonb
  FROM innsegl.events
 WHERE event_type = 'tool_call' AND run_id = ANY($1)
   AND convert_from(canonical, 'UTF8')::jsonb->>'tool_name' = 'Agent'
 ORDER BY run_id, chain_position`

const stepNumberingSQL = `
SELECT event_id
  FROM innsegl.events
 WHERE run_id = $1 AND event_type = 'tool_call'
 ORDER BY chain_position`

// stepNumbering answers, for one run, the 1-based step number
// (record.go's RecordStep.N) of every tool_call event_id it made, in chain
// order — the SAME numbering buildRunRecord gives the run whose full record
// is being built, computed here for a run this handler is not otherwise
// reading in full (recordspawn.go's own spawnedByForFamily, resolving
// RecordTreeNode.SpawnedBy for a family member that is not the one
// requested).
func (s *Store) stepNumbering(ctx context.Context, runID string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, stepNumberingSQL, runID)
	if err != nil {
		return nil, fmt.Errorf("api: numbering the steps of %s: %w", runID, err)
	}
	defer rows.Close()

	out := map[string]int{}
	n := 0
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, fmt.Errorf("api: numbering the steps of %s: %w", runID, err)
		}
		n++
		out[eventID] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: numbering the steps of %s: %w", runID, err)
	}
	return out, nil
}

// agentSteps reads every Agent-tool tool_call made by any run in parentIDs,
// in chain order within each run — the candidates recordspawn.go checks a
// child's own retained bodies against.
func (s *Store) agentSteps(ctx context.Context, parentIDs []string) ([]agentStepRow, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, agentStepsSQL, parentIDs)
	if err != nil {
		return nil, fmt.Errorf("api: reading Agent-tool steps: %w", err)
	}
	defer rows.Close()

	var out []agentStepRow
	for rows.Next() {
		var r agentStepRow
		var body map[string]any
		if err := rows.Scan(&r.RunID, &r.EventID, &r.ChainPosition, &body); err != nil {
			return nil, fmt.Errorf("api: reading an Agent-tool step: %w", err)
		}
		r.PayloadDigest = stringOf(body[event.FieldPayloadDigest])
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: reading Agent-tool steps: %w", err)
	}
	return out, nil
}
