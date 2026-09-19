// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
)

// conn is the read surface AssertReadOnly needs: a single connection or a
// pool, both of which pgx gives this shape.
type conn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store is the read-only query surface over the hot tier.
type Store struct {
	pool     *pgxpool.Pool
	readOnly ReadOnlyReport
	// restoreHorizon divides Lapsed from Abandoned (#256). It is read from the
	// deployment's own environment at Open, so this API and the MCP server that
	// actually refuses a restore are working from one number — see
	// EnvRestoreHorizon for why it arrives that way rather than as a field.
	restoreHorizon time.Duration
}

// Open connects and REFUSES any credential that can write.
//
// The assertion is not optional and there is no flag to skip it. A query API
// that would start on a writing credential is a query API whose read-only
// property is a claim about its source code rather than about its deployment
// (FD §7, P6).
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("api: parsing the query DSN: %w", err)
	}
	return OpenConfig(ctx, cfg)
}

// OpenConfig is Open with the pool configured by the caller, for a deployment
// that sizes its own pool and for a test that wants to watch the wire.
func OpenConfig(ctx context.Context, cfg *pgxpool.Config) (*Store, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("api: opening the query pool: %w", err)
	}
	report, err := AssertReadOnly(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	// And the other half of "this build can answer for this chain": a chain
	// migrated to a schema_version this binary predates is one whose later
	// events it cannot fully check, and a query API that started anyway would
	// serve verdicts it is in no position to give (#188, E9's exit criterion).
	// Refused at startup rather than per request, for AssertReadOnly's reason:
	// a property asserted once at boot is a property of the deployment, not a
	// claim about the source code.
	if serr := ledger.AssertReadableSchema(ctx, pool); serr != nil {
		pool.Close()
		return nil, serr
	}
	return &Store{
		pool:           pool,
		readOnly:       report,
		restoreHorizon: restoreHorizonFromEnv(),
	}, nil
}

// ReadOnly returns the evidence gathered when this store was opened.
func (s *Store) ReadOnly() ReadOnlyReport { return s.readOnly }

// RestoreHorizon is how long after a withdrawal a run may still be restored —
// the number every Lapsed/Abandoned answer this store gives was computed with.
// Zero means the deployment set none, and nothing is ever Abandoned.
//
// Exported because it is EVIDENCE, not configuration: every response carries it
// (RunPage.RestoreHorizonSeconds) so a reader can check the conclusion rather
// than take it.
func (s *Store) RestoreHorizon() time.Duration { return s.restoreHorizon }

// SetRestoreHorizon replaces the horizon this store answers with.
//
// It exists so a test can hold the horizon still — the difference between
// Lapsed and Abandoned is one comparison against a clock, and a test that had
// to wait thirty days to see the second one would not be a test. A deployment
// sets EnvRestoreHorizon instead; nothing in the serving path calls this.
func (s *Store) SetRestoreHorizon(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.restoreHorizon = d
}

// Close releases the pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}
