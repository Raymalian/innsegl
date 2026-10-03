// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// What the ledger recorded for an organisation (RM-333, #511): read with the
// read-only credential, like every other ledger read. The organisation's
// machines are named by id (innsegl.gateway_run_mapping.client_id, which the
// gateway writes for a run it maps from an enrolled machine) and its
// repositories by name; which of them belong to the user is the accounts
// spine's answer, never this one's.

// MaxAccountRuns bounds the account page's recent agent runs.
const MaxAccountRuns = 20

// MachineLastRun answers, per machine id, when a run was last mapped to it.
// A machine with none is absent from the map.
func (s *Store) MachineLastRun(ctx context.Context, machineIDs []string) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT client_id, max(recorded_at) FROM innsegl.gateway_run_mapping
		 WHERE client_id = ANY($1) GROUP BY client_id`, nonNilIDs(machineIDs))
	if err != nil {
		return nil, fmt.Errorf("api: reading machine activity: %w", err)
	}
	out := map[string]time.Time{}
	var id string
	var at time.Time
	_, err = pgx.ForEachRow(rows, []any{&id, &at}, func() error {
		out[id] = at.UTC()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("api: reading machine activity: %w", err)
	}
	return out, nil
}

// repoActivitySQL is reposSQL narrowed to named repositories.
const repoActivitySQL = `
WITH scoped AS (
    SELECT run_id, ts, event_type,
           convert_from(canonical, 'UTF8')::jsonb->>'repo' AS repo
      FROM innsegl.events
     WHERE run_id IS NOT NULL
)
SELECT repo,
       count(DISTINCT run_id)::int,
       (count(*) FILTER (WHERE event_type = 'commit_recorded'))::int,
       max(ts)
  FROM scoped
 WHERE repo = ANY($1)
 GROUP BY repo`

// RepoActivity answers the ledger's runs, commits and last event for each
// named repository the ledger holds anything for.
func (s *Store) RepoActivity(ctx context.Context, repos []string) (map[string]RepoSummary, error) {
	rows, err := s.pool.Query(ctx, repoActivitySQL, nonNilIDs(repos))
	if err != nil {
		return nil, fmt.Errorf("api: reading repository activity: %w", err)
	}
	out := map[string]RepoSummary{}
	var r RepoSummary
	_, err = pgx.ForEachRow(rows, []any{&r.Repo, &r.Runs, &r.Commits, &r.LastEventAt}, func() error {
		r.LastEventAt = r.LastEventAt.UTC()
		out[r.Repo] = r
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("api: reading repository activity: %w", err)
	}
	return out, nil
}

// agentRunsCTE is the runs mapped to the named machines, each with the
// agent type and task its run_registered event recorded. A run mapped more
// than once (a resumed session) counts once, under the machine it was first
// mapped from.
const agentRunsCTE = `
WITH mapped AS (
    SELECT run_id, (array_agg(client_id ORDER BY recorded_at, id))[1] AS machine_id
      FROM innsegl.gateway_run_mapping
     WHERE client_id = ANY($1)
     GROUP BY run_id
), runs AS (
    SELECT e.run_id, e.ts, m.machine_id,
           coalesce(convert_from(e.canonical, 'UTF8')::jsonb->>'agent_type', '') AS agent_type,
           coalesce(convert_from(e.canonical, 'UTF8')::jsonb->>'task_ref', '') AS task_ref
      FROM innsegl.events e
      JOIN mapped m ON m.run_id = e.run_id
     WHERE e.event_type = 'run_registered'
)`

// AgentRuns answers the agent types that ran on the named machines, most
// runs first, and the most recent runs, newest first. MachineName is left
// for the caller, which knows the machines.
func (s *Store) AgentRuns(ctx context.Context, machineIDs []string, limit int) ([]AccountAgentType, []AccountAgentRun, error) {
	ids := nonNilIDs(machineIDs)
	rows, err := s.pool.Query(ctx, agentRunsCTE+`
		SELECT agent_type, count(*)::int, max(ts) FROM runs
		 GROUP BY agent_type ORDER BY count(*) DESC, agent_type`, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("api: reading agent types: %w", err)
	}
	types := []AccountAgentType{}
	var at AccountAgentType
	if _, err = pgx.ForEachRow(rows, []any{&at.AgentType, &at.Runs, &at.LastRegisteredAt}, func() error {
		at.LastRegisteredAt = at.LastRegisteredAt.UTC()
		types = append(types, at)
		return nil
	}); err != nil {
		return nil, nil, fmt.Errorf("api: reading agent types: %w", err)
	}

	rows, err = s.pool.Query(ctx, agentRunsCTE+`
		SELECT run_id, agent_type, task_ref, ts, machine_id FROM runs
		 ORDER BY ts DESC, run_id LIMIT $2`, ids, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("api: reading agent runs: %w", err)
	}
	runs := []AccountAgentRun{}
	var r AccountAgentRun
	if _, err = pgx.ForEachRow(rows, []any{&r.RunID, &r.AgentType, &r.TaskRef, &r.RegisteredAt, &r.MachineID}, func() error {
		r.RegisteredAt = r.RegisteredAt.UTC()
		runs = append(runs, r)
		return nil
	}); err != nil {
		return nil, nil, fmt.Errorf("api: reading agent runs: %w", err)
	}
	return types, runs, nil
}

// nonNilIDs keeps a nil list from reaching ANY($1) as NULL.
func nonNilIDs(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}
