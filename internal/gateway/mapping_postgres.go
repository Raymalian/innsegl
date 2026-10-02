// SPDX-License-Identifier: Apache-2.0

package gateway

// PostgresMappingStore implements MappingStore (lifecycle_contract.go) on the
// ledger database, migrations/0007_gateway_run_mapping.sql's
// innsegl.gateway_run_mapping (ADR-0060 decision 3): a table beside
// innsegl.events, written through the same writer role internal/ledger.Store
// already holds, not a second store and not a second package for the
// database half of it.
//
// This file opens no migration path of its own. migrations/0007 ships beside
// migrations/0001, and internal/ledger.Store.Migrate is the one place any
// migration in this project is applied; a second applier here would be a
// second place the schema could drift from.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresMappingStore is MappingStore on Postgres.
type PostgresMappingStore struct {
	pool *pgxpool.Pool
}

// The fake in lifecycle_fakes_test.go and this store answer the same
// contract; a drift in either fails to compile here.
var _ MappingStore = (*PostgresMappingStore)(nil)

// OpenPostgresMappingStore connects to the ledger database and checks that it
// answers. dsn is the same DSN internal/ledger.Open takes: one database, one
// chain (ADR-0005), and this table lives inside it.
func OpenPostgresMappingStore(ctx context.Context, dsn string) (*PostgresMappingStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("gateway: open the run mapping store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("gateway: open the run mapping store: %w", err)
	}
	return &PostgresMappingStore{pool: pool}, nil
}

// Close releases the pool. Safe on a nil or zero-valued store, so a failed
// Open path in a caller's cleanup does not panic.
func (s *PostgresMappingStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Insert appends one row. recorded_at is never sent, whatever m.RecordedAt
// holds: migrations/0007's DEFAULT clock_timestamp() assigns it, the same way
// innsegl.events.ts is always the server clock and never the caller's value
// (doc 02 §2). run_id, session_id and agent_id are required -- the table's
// own CHECK constraints would refuse an empty one, but a caller reads a
// clearer error from here first.
func (s *PostgresMappingStore) Insert(ctx context.Context, m RunMapping) error {
	if m.RunID == "" || m.SessionID == "" || m.AgentID == "" {
		return fmt.Errorf("gateway: insert a run mapping: run_id, session_id and agent_id are required, got %+v", m)
	}
	// client_id (GW-019, #460): the installation the client guard verified
	// for the request this row was inserted for, read from ctx; NULL in
	// single-host mode, where no installation exists. It sits outside the
	// event chain (ADR-0063 decision 7), so ownership is a read-time join.
	clientID, _ := InstallationFromContext(ctx)
	if clientID == "" {
		clientID = m.ClientID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO innsegl.gateway_run_mapping
			(run_id, session_id, agent_id, fingerprint,
			 parent_run_id, forked_from_run_id, adopted_from_run_id, client_id, agent_type_verbatim)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		m.RunID, m.SessionID, m.AgentID, string(m.Fingerprint),
		nullableText(m.ParentRunID), nullableText(m.ForkedFromRunID), nullableText(m.AdoptedFromRunID),
		nullableText(clientID), nullableText(m.AgentTypeVerbatim))
	if err != nil {
		return fmt.Errorf("gateway: insert a run mapping for session %s agent %s: %w", m.SessionID, m.AgentID, err)
	}
	return nil
}

// BySessionAgent answers the newest row for (sessionID, agentID): "Lookups
// answer the most recent row for their key; a later row ... supersedes an
// earlier one without changing it" (lifecycle_contract.go's MappingStore
// doc). Ordered by recorded_at and then by the surrogate id, so two rows
// written in the same clock tick still come back in the order they were
// written rather than in whatever order Postgres happens to return a tie.
func (s *PostgresMappingStore) BySessionAgent(ctx context.Context, sessionID, agentID string) (RunMapping, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT run_id, session_id, agent_id, fingerprint,
		       parent_run_id, forked_from_run_id, adopted_from_run_id, client_id, agent_type_verbatim, recorded_at
		  FROM innsegl.gateway_run_mapping
		 WHERE session_id = $1 AND agent_id = $2
		 ORDER BY recorded_at DESC, id DESC
		 LIMIT 1`, sessionID, agentID)

	m, err := scanMapping(row)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return RunMapping{}, false, nil
	case err != nil:
		return RunMapping{}, false, fmt.Errorf("gateway: look up session %s agent %s: %w", sessionID, agentID, err)
	}
	return m, true, nil
}

// ByFingerprint answers every row recorded for fp, oldest first -- the same
// order the fake in lifecycle_fakes_test.go answers in. An empty fp answers
// no rows without a query at all: lifecycle_contract.go's Fingerprint is
// "empty until the conversation has a first assistant turn", so a lookup for
// "no fingerprint yet" is not a question this store has a row for, and a
// fingerprint column of ” is never the value ADR-0058 decision 4's
// fingerprint means.
func (s *PostgresMappingStore) ByFingerprint(ctx context.Context, fp Fingerprint) ([]RunMapping, error) {
	if fp == "" {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT run_id, session_id, agent_id, fingerprint,
		       parent_run_id, forked_from_run_id, adopted_from_run_id, client_id, agent_type_verbatim, recorded_at
		  FROM innsegl.gateway_run_mapping
		 WHERE fingerprint = $1
		 ORDER BY id ASC`, string(fp))
	if err != nil {
		return nil, fmt.Errorf("gateway: look up fingerprint %s: %w", fp, err)
	}
	defer rows.Close()

	var out []RunMapping
	for rows.Next() {
		m, serr := scanMapping(rows)
		if serr != nil {
			return nil, fmt.Errorf("gateway: look up fingerprint %s: %w", fp, serr)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gateway: look up fingerprint %s: %w", fp, err)
	}
	return out, nil
}

// rowScanner is the common half of pgx.Row and pgx.Rows that scanMapping
// needs, so BySessionAgent's single row and ByFingerprint's several share one
// column-to-struct mapping.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanMapping reads one row of innsegl.gateway_run_mapping into a RunMapping.
func scanMapping(row rowScanner) (RunMapping, error) {
	var (
		m                                              RunMapping
		fingerprint                                    string
		parentRunID, forkedFromRunID, adoptedFromRunID *string
		clientID, agentTypeVerbatim                    *string
	)
	if err := row.Scan(
		&m.RunID, &m.SessionID, &m.AgentID, &fingerprint,
		&parentRunID, &forkedFromRunID, &adoptedFromRunID, &clientID, &agentTypeVerbatim, &m.RecordedAt,
	); err != nil {
		return RunMapping{}, err
	}
	m.Fingerprint = Fingerprint(fingerprint)
	m.ParentRunID = derefOrEmpty(parentRunID)
	m.ForkedFromRunID = derefOrEmpty(forkedFromRunID)
	m.AdoptedFromRunID = derefOrEmpty(adoptedFromRunID)
	m.ClientID = derefOrEmpty(clientID)
	m.AgentTypeVerbatim = derefOrEmpty(agentTypeVerbatim)
	return m, nil
}

// nullableText turns an absent (empty) optional link into SQL NULL, matching
// migrations/0007's NULL-means-none columns.
func nullableText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// derefOrEmpty is nullableText's inverse: a NULL optional link reads back as
// RunMapping's own zero value, "".
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
