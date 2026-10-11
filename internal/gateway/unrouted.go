// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresUnroutedStore keeps the sessions enrolled machines report as
// unrouted (RM-319; innsegl.unrouted_sessions, migration 0022): one row per
// machine and session, with the newest activity any report carried.
type PostgresUnroutedStore struct {
	pool *pgxpool.Pool
}

// NewPostgresUnroutedStore uses pool; the caller owns and closes it.
func NewPostgresUnroutedStore(pool *pgxpool.Pool) *PostgresUnroutedStore {
	return &PostgresUnroutedStore{pool: pool}
}

// Report keeps installation's report that session's model traffic, last at
// lastActivity, did not pass through innsegl. An older report never moves
// the activity back.
func (s *PostgresUnroutedStore) Report(ctx context.Context, installation, session string, lastActivity time.Time) error {
	if installation == "" || session == "" {
		return errors.New("gateway: an unrouted session needs a machine and a session")
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO innsegl.unrouted_sessions (installation_id, session_id, last_activity_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (installation_id, session_id) DO UPDATE
		   SET last_activity_at = GREATEST(innsegl.unrouted_sessions.last_activity_at, EXCLUDED.last_activity_at),
		       reported_at = clock_timestamp()`,
		installation, session, lastActivity); err != nil {
		return fmt.Errorf("gateway: keep the unrouted session %s of %s: %w", session, installation, err)
	}
	return nil
}
