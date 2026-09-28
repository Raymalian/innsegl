// SPDX-License-Identifier: Apache-2.0

package gateway

// gwpgharness_test.go — RM-231 (#376): a real, throwaway Postgres for
// registrar_test.go. MCPRegistrar.Register and Restore call straight into
// internal/mcp.RegisterRunForGateway, which runs register_agent's own mint
// path — and that path's idempotency claim (ADR-0017) is a real
// *mcp.IdempotencyStore backed by a real pgxpool.Pool, a concrete type this
// package cannot fake. internal/mcp's own test suite
// (idempotency_pgharness_test.go) faces the identical requirement and
// solves it the identical way: one throwaway container, standed up once for
// the package's test binary, never the running deployment's own
// innsegl-postgres (doc 05's; touching it would not be a throwaway
// database). #101, from that file, is the reason this is a FAILURE and not
// a SKIP when Docker is present and the container still does not start —
// only an absent Docker daemon is honestly a skip.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
)

// The registrar's Postgres helpers, over the package's one shared test
// Postgres (pgharness_test.go). Two harnesses in one package meant two
// TestMain functions; #376 and #378 each built one in parallel, and the
// merge keeps #378's (it carries the skip-versus-failure check, #101) with
// these names kept as thin adapters so registrar_test.go reads unchanged.

// requireGWPG hands the test the shared Postgres, skipping or failing
// exactly as requirePG does.
func requireGWPG(t *testing.T) *pgContainer {
	t.Helper()
	return requirePG(t)
}

// gwFreshDSN creates an empty database of the test's own and returns its DSN.
func gwFreshDSN(t *testing.T, c *pgContainer) string {
	t.Helper()
	return freshDatabase(t, c)
}

// gwMigrate applies the shipped migrations through the ledger's own runner --
// the idempotency table ships in migration 0002, so a database that has run
// this has the idempotency store's schema too.
func gwMigrate(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
}

// gwPool opens a pgx pool the caller owns, exactly as an MCP replica would.
func gwPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
