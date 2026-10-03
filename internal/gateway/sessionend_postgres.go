// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresSessionEndStore is the SessionEndStore over
// innsegl.gateway_session_end (migration 0012), on the gateway's own pool.
type PostgresSessionEndStore struct {
	pool *pgxpool.Pool
}

var _ SessionEndStore = (*PostgresSessionEndStore)(nil)

// NewPostgresSessionEndStore uses pool; the caller owns and closes it.
func NewPostgresSessionEndStore(pool *pgxpool.Pool) *PostgresSessionEndStore {
	return &PostgresSessionEndStore{pool: pool}
}

// Record appends e.
func (s *PostgresSessionEndStore) Record(ctx context.Context, e SessionEndEvent) error {
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO innsegl.gateway_session_end (session_id, kind, at) VALUES ($1, $2, $3)`,
		e.SessionID, string(e.Kind), e.At); err != nil {
		return fmt.Errorf("gateway: keep the session-end %s for %s: %w", e.Kind, e.SessionID, err)
	}
	return nil
}

// Open answers each session whose latest event is a signal at or after since.
func (s *PostgresSessionEndStore) Open(ctx context.Context, since time.Time) ([]SessionEndEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT session_id, at FROM (
			SELECT DISTINCT ON (session_id) session_id, kind, at
			  FROM innsegl.gateway_session_end
			 WHERE at >= $1
			 ORDER BY session_id, at DESC, id DESC
		) latest
		WHERE kind = 'signalled'`, since)
	if err != nil {
		return nil, fmt.Errorf("gateway: read the open session-end marks: %w", err)
	}
	defer rows.Close()
	var out []SessionEndEvent
	for rows.Next() {
		e := SessionEndEvent{Kind: SessionEndSignalled}
		if err := rows.Scan(&e.SessionID, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
