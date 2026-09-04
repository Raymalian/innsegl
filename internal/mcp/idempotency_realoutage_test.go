// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/ledger"
)

// MCP-021 (RM-067, #87): the disagreement RM-028 (#36) found is only
// findable against a REAL Postgres. A stub returning an error picks its own
// SQLSTATE and proves nothing about what a stale pooled connection actually
// receives when the postmaster is genuinely killed. This file drives a
// dedicated, disposable Postgres container to a real SIGKILL and asks BOTH
// classifiers — internal/ledger.classify, through a *ledger.Store, and this
// package's classifyStorage, through an *IdempotencyStore — about the same
// outage, over the same database, on the first call each pool makes
// afterwards.
//
// Before RM-067's fix this test failed exactly as measured (captured live: of
// four runs against the pre-fix code, one reproduced the disagreement itself
// and the other three could not even reach the premise — the race this file's
// retry loop below exists for): internal/ledger reported LEDGER_UNAVAILABLE
// retryable=TRUE for SQLSTATE 57P01 ("terminating connection due to
// unexpected postmaster exit"), and this package's classifyStorage reported
// the same class retryable=FALSE for the identical SQLSTATE — one outage, two
// answers, and which one a caller got depended on connection-pool state
// (ADR-0016 §2, §5).
//
// # Why this retries the whole container, and why that is honest
//
// Whether a backend gets to send its own SQLSTATE before the OS tears the
// connection down is a real race against exactly how fast this process issues
// its next query after the SIGKILL — the same raciness test/contract's
// settleOutage documents living with. Retrying with a FRESH container (never
// the same one — a backend that has already noticed the postmaster is gone
// will never again produce a graceful SQLSTATE) is not softening the
// assertion: it is giving the real race enough tries to land the shape this
// issue is about, then judging the two layers strictly on that shape. If it
// never lands, the test says so and fails — it does not fall back to a milder
// claim.
//
// This container is always its own, never the package-wide sharedPG: killing
// the shared container would break every other test in this package.
func TestMCP021TheSamePostgresOutageClassifiesTheSameOnBothLayers(t *testing.T) {
	requirePG(t) // honest skip/failure split (#101) before anything is started

	// A generous bound: each round is cheap when it succeeds (typically 1-4
	// rounds in practice), and the graceful-shutdown window this test is
	// racing for narrows further under heavy concurrent Docker load — a
	// second agent's containers, or the rest of this package's own real-
	// Postgres tests running alongside this one. More rounds buys back the
	// margin load costs, without slowing a quiet machine's runs at all.
	const maxRounds = 24
	var lastLedgerSeen, lastMCPSeen bool
	for round := 1; round <= maxRounds; round++ {
		result := runOutageProbeRound(t, round)
		lastLedgerSeen, lastMCPSeen = result.ledgerSeen, result.mcpSeen
		if !result.ledgerSeen || !result.mcpSeen {
			t.Logf("round %d/%d: the graceful-shutdown window closed before one or both layers "+
				"reused their stale connection (ledger saw a SQLSTATE: %v, mcp idempotency store "+
				"saw one: %v); retrying with a fresh container", round, maxRounds,
				result.ledgerSeen, result.mcpSeen)
			continue
		}

		t.Logf("round %d/%d: internal/ledger:          SQLSTATE %s -> %s retryable=%v",
			round, maxRounds, result.ledgerCode, result.ledgerClass, result.ledgerRetryable)
		t.Logf("round %d/%d: internal/mcp idempotency: SQLSTATE %s -> %s retryable=%v",
			round, maxRounds, result.mcpCode, result.mcpClass, result.mcpRetryable)

		if result.ledgerClass != string(result.mcpClass) || result.ledgerRetryable != result.mcpRetryable {
			t.Fatalf("RM-067 (#87): one real Postgres outage, two verdicts — internal/ledger says "+
				"%s retryable=%v (SQLSTATE %s), internal/mcp's idempotency store says %s "+
				"retryable=%v (SQLSTATE %s). The advice a caller gets must not depend on which "+
				"layer's connection pool happened to answer first.",
				result.ledgerClass, result.ledgerRetryable, result.ledgerCode,
				result.mcpClass, result.mcpRetryable, result.mcpCode)
		}
		return // both observed, and they agree: RM-067 holds for this SQLSTATE.
	}
	t.Fatalf("MCP-021: in %d rounds, never observed a *pgconn.PgError from a freshly killed "+
		"Postgres on both layers in the same round (last round: ledger saw one: %v, mcp "+
		"idempotency store saw one: %v) — this run measured nothing about RM-067 and must be "+
		"re-run, not trusted as a pass", maxRounds, lastLedgerSeen, lastMCPSeen)
}

// outageProbeResult is one round's answer from each layer.
type outageProbeResult struct {
	ledgerClass     string
	ledgerRetryable bool
	ledgerCode      string
	ledgerSeen      bool

	mcpClass     Class
	mcpRetryable bool
	mcpCode      string
	mcpSeen      bool
}

// runOutageProbeRound starts a dedicated Postgres, proves it works, warms one
// connection into internal/ledger's pool and one into the idempotency store's
// pool, kills the container, and reports what the first *pgconn.PgError-
// carrying answer from each pool was — or that none arrived before the
// probing budget ran out.
func runOutageProbeRound(t *testing.T, round int) outageProbeResult {
	t.Helper()

	startCtx := testCtx(t, 3*time.Minute)
	victim, err := startPG(startCtx)
	if err != nil {
		t.Fatalf("round %d: starting a dedicated Postgres to kill: %v", round, err)
	}
	t.Cleanup(func() {
		if rerr := victim.remove(); rerr != nil {
			t.Logf("round %d: warning: removing the killed container %s: %v", round, victim.id, rerr)
		}
	})

	dsn := victim.dsn(postgresDB)
	migrate(t, dsn)

	ledgerStore, err := ledger.Open(testCtx(t, 30*time.Second), dsn)
	if err != nil {
		t.Fatalf("round %d: ledger.Open: %v", round, err)
	}
	t.Cleanup(ledgerStore.Close)
	idem := NewIdempotencyStore(newPool(t, dsn))

	// Warm each pool with one successful call, so each holds an established,
	// idle connection at the moment of the kill — the "stale pooled
	// connection" RM-028 measured, not a fresh dial against an already-dead
	// port (which the plain not-a-*pgconn.PgError branch already agreed on,
	// even before this fix).
	warmCtx := testCtx(t, 30*time.Second)
	if _, herr := ledgerStore.Head(warmCtx); herr != nil {
		t.Fatalf("round %d: warm-up Head: %v", round, herr)
	}
	if _, _, lerr := idem.Lookup(warmCtx, "mcp021-warm-up"); lerr != nil {
		t.Fatalf("round %d: warm-up Lookup: %v", round, lerr)
	}

	if kerr := victim.kill(context.Background()); kerr != nil {
		t.Fatalf("round %d: kill postgres: %v", round, kerr)
	}

	probeCtx := testCtx(t, 15*time.Second)
	// Bounded, not timed: a pool surfaces each connection it was holding
	// exactly once (as test/contract's settleOutage documents), and only the
	// FIRST PgError-carrying answer is the "stale pooled connection" case this
	// issue is about.
	const attempts = 64

	var result outageProbeResult
	result.ledgerClass, result.ledgerRetryable, result.ledgerCode, result.ledgerSeen =
		firstPgErrorFromLedger(probeCtx, t, ledgerStore, attempts)
	result.mcpClass, result.mcpRetryable, result.mcpCode, result.mcpSeen =
		firstPgErrorFromIdempotencyStore(probeCtx, t, idem, attempts)
	return result
}

// firstPgErrorFromLedger calls Head repeatedly and returns the class,
// retryable flag and SQLSTATE of the first answer that carries a
// *pgconn.PgError. Head can never succeed once the container is truly dead,
// so a nil error is itself a failure of the premise, not a pass.
func firstPgErrorFromLedger(ctx context.Context, t *testing.T, s *ledger.Store, attempts int) (
	class string, retryable bool, code string, seen bool,
) {
	t.Helper()
	for i := 0; i < attempts; i++ {
		_, err := s.Head(ctx)
		if err == nil {
			t.Fatalf("internal/ledger.Store.Head still answers after the container was killed (attempt %d)", i+1)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			continue
		}
		var se *ledger.StoreError
		if !errors.As(err, &se) {
			t.Fatalf("internal/ledger returned an error carrying SQLSTATE %s that is not a "+
				"*ledger.StoreError: %v (%T)", pgErr.Code, err, err)
		}
		return se.Class, se.Retryable, pgErr.Code, true
	}
	return "", false, "", false
}

// firstPgErrorFromIdempotencyStore is firstPgErrorFromLedger's twin for the
// MCP idempotency store: it calls Lookup with a fresh key each attempt (the
// key space does not matter — an absent key and an unreachable database both
// answer through the same error path here) until it sees a *pgconn.PgError.
func firstPgErrorFromIdempotencyStore(ctx context.Context, t *testing.T, s *IdempotencyStore, attempts int) (
	class Class, retryable bool, code string, seen bool,
) {
	t.Helper()
	for i := 0; i < attempts; i++ {
		_, _, err := s.Lookup(ctx, fmt.Sprintf("mcp021-probe-%d", i))
		if err == nil {
			t.Fatalf("IdempotencyStore.Lookup still answers after the container was killed (attempt %d)", i+1)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			continue
		}
		ie := mcpError(t, err)
		return ie.Class, ie.Retryable, pgErr.Code, true
	}
	return "", false, "", false
}
