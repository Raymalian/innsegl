// SPDX-License-Identifier: Apache-2.0

package gateway

// silentruns.go is #380's own enumeration for the silence backstop
// (lifecycle.go's Backstop, ADR-0058 decision 7c): "a ticker enumerating
// silent runs from the chain — you own that enumeration." Backstop.Sweep
// only ever judges the candidates it is handed; it holds no candidate list
// of its own (lifecycle.go's own doc comment on SilentRun), and this file is
// what produces one, read directly off innsegl.events -- the same four
// recorded facts internal/ledger/runstate.go's own rule reads, aggregated
// per run_id rather than fetched one run at a time (which is what
// internal/rundir.Directory does, and is the wrong shape for "every run
// that might be silent": it would mean already knowing which run ids to
// ask about).
//
// This is a READ ONLY query. It opens its own small pool on the same DSN
// the mapping store already uses (ADR-0060 decision 3: one database, no new
// store) rather than reaching into internal/ledger.Store, which exposes no
// pool of its own and no "every run" read -- EventsForRun (internal/rundir's
// own dependency) answers one run at a time, on purpose, and generalising it
// to every run would be a second, slower way to ask the identical question
// this file's own aggregate query answers in one round trip.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// silentRunCandidatesQuery aggregates innsegl.events per run_id into exactly
// the four facts ledger.RunFacts reads, for every run that is not already
// retired. Built from event.* and ledger.ActivitySQL rather than spelled as
// literal strings, so a rename of any of them fails this file to compile
// instead of silently drifting from doc 02's own vocabulary.
var silentRunCandidatesQuery = fmt.Sprintf(`
	SELECT run_id,
	       min(ts) FILTER (WHERE event_type = '%s') AS registered_at,
	       max(ts) FILTER (WHERE event_type = '%s') AS withdrawn_at,
	       max(ts) FILTER (WHERE %s) AS last_activity_at
	  FROM innsegl.events
	 WHERE run_id IS NOT NULL
	 GROUP BY run_id
	HAVING NOT bool_or(event_type = '%s')`,
	event.EventTypeRunRegistered, event.EventTypeRunExpired, ledger.ActivitySQL, event.EventTypeRunRetired)

// SilentRunCandidates implements the backstop's own candidate feed on a
// real chain: OpenSilentRunCandidates gives its own pool, Close releases it.
type SilentRunCandidates struct {
	pool *pgxpool.Pool
}

// OpenSilentRunCandidates connects to the ledger database. dsn is the same
// DSN internal/ledger.Open and OpenPostgresMappingStore take.
func OpenSilentRunCandidates(ctx context.Context, dsn string) (*SilentRunCandidates, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("gateway: open the silent-run enumeration: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("gateway: open the silent-run enumeration: %w", err)
	}
	return &SilentRunCandidates{pool: pool}, nil
}

// Close releases the pool. Safe on a nil or zero-valued value.
func (c *SilentRunCandidates) Close() {
	if c != nil && c.pool != nil {
		c.pool.Close()
	}
}

// Candidates answers every run that is not (yet) retired, as a Backstop
// sweep needs it: RunFacts.Retired is always false in what this method
// returns (the HAVING clause already excluded every retired run_id), and
// Backstop.Sweep's own "skip an already-retired candidate" check is
// defensive against a caller that built a SilentRun some other way, not a
// case this method itself ever produces.
func (c *SilentRunCandidates) Candidates(ctx context.Context) ([]SilentRun, error) {
	rows, err := c.pool.Query(ctx, silentRunCandidatesQuery)
	if err != nil {
		return nil, fmt.Errorf("gateway: enumerate silent-run candidates: %w", err)
	}
	defer rows.Close()

	var out []SilentRun
	for rows.Next() {
		var (
			runID                                   string
			registeredAt, withdrawnAt, lastActivity *time.Time
		)
		if err := rows.Scan(&runID, &registeredAt, &withdrawnAt, &lastActivity); err != nil {
			return nil, fmt.Errorf("gateway: enumerate silent-run candidates: %w", err)
		}
		facts := ledger.RunFacts{Retired: false}
		if registeredAt != nil {
			facts.RegisteredAt = *registeredAt
		}
		if withdrawnAt != nil {
			facts.WithdrawnAt = *withdrawnAt
		}
		if lastActivity != nil {
			facts.LastActivityAt = *lastActivity
		}
		out = append(out, SilentRun{RunID: runID, Facts: facts})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gateway: enumerate silent-run candidates: %w", err)
	}
	return out, nil
}
