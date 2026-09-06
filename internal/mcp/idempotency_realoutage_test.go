// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/ledger"
)

// MCP-021 (RM-067, #87): the disagreement RM-028 (#36) found is only
// findable against a REAL Postgres. A stub returning an error picks its own
// SQLSTATE and proves nothing about what a stale pooled connection actually
// receives when a real backend genuinely goes away. This file drives a
// dedicated, disposable Postgres container to a real, targeted backend death
// and asks BOTH classifiers — internal/ledger.classify, through a
// *ledger.Store, and this package's classifyStorage, through an
// *IdempotencyStore — about the same outage, over the same database, on the
// first call each pool makes afterwards.
//
// Before RM-067's fix this test failed exactly as measured (captured live: of
// four runs against the pre-fix code, one reproduced the disagreement itself
// and the other three could not even reach the premise): internal/ledger
// reported LEDGER_UNAVAILABLE retryable=TRUE for SQLSTATE 57P01, and this
// package's classifyStorage reported the same class retryable=FALSE for the
// identical SQLSTATE — one outage, two answers, and which one a caller got
// depended on connection-pool state (ADR-0016 §2, §5).
//
// # pg_terminate_backend, not docker kill — and why that is still a real outage
//
// This test used to induce the outage with `docker kill --signal SIGKILL` on
// the whole container. That is real Postgres dying, but it races the OS
// tearing the container's networking down against a backend getting a word
// out on its socket: on Docker Desktop the teardown is slow enough that a
// backend often wins that race, and on a Linux CI runner it routinely does
// not, so the SAME premise (both layers see a *pgconn.PgError in the SAME
// round) went unmeasured for all 24 rounds — reproducibly, not occasionally —
// on Linux while passing on macOS. Raising the round count does not fix a
// race that is lost almost every time on one platform; it only hides how
// often it is lost.
//
// This version drives the outage a different way: it warms each pool's one
// idle pooled connection exactly as before, finds the two backend PIDs
// serving those specific connections in pg_stat_activity (tagged unambiguously
// by a unique application_name each pool's DSN carries), and calls
// `SELECT pg_terminate_backend(pid)` — Postgres's own, deliberate way of
// ending one session — over a third, administrative connection. That is
// driving the condition instead of racing it: pg_terminate_backend sends
// SIGTERM to a specific backend, which Postgres's signal handler (die())
// catches, reports as SQLSTATE 57P01 ("terminating connection due to
// administrator command") to that backend's own client, and only then exits —
// unlike SIGKILL, which cannot be caught and so can end the process mid-write
// with nothing sent at all. This test additionally blocks until
// pg_stat_activity confirms the targeted backend is actually gone before it
// ever calls Head/Lookup again, so the FATAL message Postgres wrote is
// already sitting in that connection's kernel socket buffer by the time this
// test reads it — no further race to win.
//
// Is this still the SAME outage the file's name promises? It is still a real
// outage: a genuine Postgres backend process, signaled for real, sending a
// genuine FATAL down a genuinely pooled, previously-idle connection — not a
// stub choosing its own SQLSTATE. What changed is the trigger, not the
// symptom: SIGKILL of the whole container produces SQLSTATE 57P01 because a
// surviving backend notices the postmaster is gone; pg_terminate_backend
// produces the SAME SQLSTATE, 57P01, because Postgres was told to end that
// one session. Both are "operator intervention" class 57, both are the exact
// code #87's disagreement was about, and classifyStorage's and
// ledger.classify's rules key off the SQLSTATE class, not off which command
// produced it (errors.go's isConnectionLifecycleSQLState, postgres.go's
// classify). A different cause, the identical class of answer from a real
// server — which is exactly what this test needs to still be honest about
// what it measures.
//
// This container is always its own, never the package-wide sharedPG: the
// backends this test terminates are its own DSNs' connections, uniquely
// tagged, so nothing here could ever reach another test's connection even on
// sharedPG — but keeping a dedicated, disposable container means this test's
// churn (and the round-retry below, kept as a defensive margin rather than
// the mechanism) can never affect any other test in this package regardless.
func TestMCP021TheSamePostgresOutageClassifiesTheSameOnBothLayers(t *testing.T) {
	requirePG(t) // honest skip/failure split (#101) before anything is started

	// The mechanism above is deterministic — round 1 is expected to land it —
	// so this is a small defensive margin against something outside the
	// mechanism's control (e.g. this process itself being descheduled between
	// finding the backend PIDs and terminating them), never a substitute for
	// determinism. Do not raise this to paper over a failure: a failure here
	// means the mechanism itself regressed, and the fix is to find out why,
	// not to try more times.
	const maxRounds = 5
	var lastLedgerSeen, lastMCPSeen bool
	for round := 1; round <= maxRounds; round++ {
		result := runOutageProbeRound(t, round)
		lastLedgerSeen, lastMCPSeen = result.ledgerSeen, result.mcpSeen
		if !result.ledgerSeen || !result.mcpSeen {
			t.Logf("round %d/%d: one or both layers did not observe a *pgconn.PgError from "+
				"its terminated backend (ledger saw a SQLSTATE: %v, mcp idempotency store saw "+
				"one: %v); retrying with a fresh container", round, maxRounds,
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

		// The two layers agreeing with each other is not enough on its own —
		// they could agree on the wrong answer. IP §4 / ADR-0016's table below
		// is hand-written from the spec, never derived from classify or
		// classifyStorage, so this checks both layers against the actual rule
		// rather than merely against one another.
		want, ok := wantOutageClassification[result.ledgerCode]
		if !ok {
			t.Fatalf("MCP-021: observed SQLSTATE %s is not in this test's hand-written "+
				"IP §4/ADR-0016 table; add it there before trusting this result", result.ledgerCode)
		}
		if result.ledgerClass != want.class || result.ledgerRetryable != want.retryable {
			t.Fatalf("MCP-021: both layers agree with each other on SQLSTATE %s (%s "+
				"retryable=%v), but ADR-0016's table says %s retryable=%v — they agree on the "+
				"wrong answer", result.ledgerCode, result.ledgerClass, result.ledgerRetryable,
				want.class, want.retryable)
		}
		return // both observed, they agree, and the agreed answer is the right one.
	}
	t.Fatalf("MCP-021: in %d rounds, never observed a *pgconn.PgError from a terminated "+
		"backend on both layers in the same round (last round: ledger saw one: %v, mcp "+
		"idempotency store saw one: %v) — this run measured nothing about RM-067 and must be "+
		"re-run, not trusted as a pass", maxRounds, lastLedgerSeen, lastMCPSeen)
}

// wantOutageClassification is IP §4 / ADR-0016's answer for the connection-
// lifecycle SQLSTATEs a killed backend can raise, copied from the same table
// internal/ledger/postgres_schema_test.go asserts against — never computed by
// calling ledger.classify or classifyStorage, which are the functions under
// test here.
var wantOutageClassification = map[string]struct {
	class     string
	retryable bool
}{
	"57P01": {ledger.ClassLedgerUnavailable, true}, // admin shutdown (pg_terminate_backend)
	"57P02": {ledger.ClassLedgerUnavailable, true}, // crash shutdown
	"57P03": {ledger.ClassLedgerUnavailable, true}, // cannot connect now
	"08006": {ledger.ClassLedgerUnavailable, true}, // connection failure
	"08003": {ledger.ClassLedgerUnavailable, true}, // connection does not exist
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

// mcp021LedgerApp and mcp021IdemApp tag each pool's DSN so this test can find
// the exact backend PID serving each one in pg_stat_activity. Fixed names are
// safe: each round gets a brand-new, disposable container, so there is never
// a second connection anywhere to confuse them with.
const (
	mcp021LedgerApp = "mcp021-ledger"
	mcp021IdemApp   = "mcp021-idem"
)

// withApplicationName tags dsn with name so pg_stat_activity can identify the
// exact backend serving a connection opened with it, rather than this test
// guessing at one.
func withApplicationName(dsn, name string) string {
	return dsn + "&application_name=" + name
}

// runOutageProbeRound starts a dedicated Postgres, proves it works, warms one
// connection into internal/ledger's pool and one into the idempotency store's
// pool, terminates the two backends serving them, and reports what the first
// answer from each pool was afterwards — or that none arrived.
func runOutageProbeRound(t *testing.T, round int) outageProbeResult {
	t.Helper()

	startCtx := testCtx(t, 3*time.Minute)
	victim, err := startPG(startCtx)
	if err != nil {
		t.Fatalf("round %d: starting a dedicated Postgres: %v", round, err)
	}
	t.Cleanup(func() {
		if rerr := victim.remove(); rerr != nil {
			t.Logf("round %d: warning: removing the container %s: %v", round, victim.id, rerr)
		}
	})

	dsn := victim.dsn(postgresDB)
	migrate(t, dsn)

	ledgerStore, err := ledger.Open(testCtx(t, 30*time.Second), withApplicationName(dsn, mcp021LedgerApp))
	if err != nil {
		t.Fatalf("round %d: ledger.Open: %v", round, err)
	}
	t.Cleanup(ledgerStore.Close)
	idem := NewIdempotencyStore(newPool(t, withApplicationName(dsn, mcp021IdemApp)))

	// Warm each pool with one successful call, so each holds an established,
	// idle connection at the moment of termination — the "stale pooled
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

	admin := rawConn(t, dsn)
	adminCtx := testCtx(t, 30*time.Second)

	ledgerPID := findIdleBackendPID(adminCtx, t, admin, mcp021LedgerApp, round)
	idemPID := findIdleBackendPID(adminCtx, t, admin, mcp021IdemApp, round)

	killBackendAndAwaitGone(adminCtx, t, admin, ledgerPID, "internal/ledger", round)
	killBackendAndAwaitGone(adminCtx, t, admin, idemPID, "internal/mcp idempotency store", round)

	probeCtx := testCtx(t, 15*time.Second)
	var result outageProbeResult
	result.ledgerClass, result.ledgerRetryable, result.ledgerCode, result.ledgerSeen =
		probeLedgerOnce(probeCtx, t, ledgerStore, round)
	result.mcpClass, result.mcpRetryable, result.mcpCode, result.mcpSeen =
		probeIdempotencyStoreOnce(probeCtx, t, idem, round)
	return result
}

// findIdleBackendPID polls pg_stat_activity for the single idle backend
// serving applicationName, and fails loudly if it cannot find exactly one
// within the deadline. This is how this test knows precisely which backend to
// terminate, rather than aiming at the whole container and hoping.
func findIdleBackendPID(ctx context.Context, t *testing.T, admin *pgx.Conn, applicationName string, round int) int32 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var count int
		var pid int32
		err := admin.QueryRow(ctx, `
			SELECT count(*), coalesce(max(pid), 0) FROM pg_stat_activity
			 WHERE application_name = $1 AND state = 'idle'`, applicationName).Scan(&count, &pid)
		if err != nil {
			t.Fatalf("round %d: query pg_stat_activity for %s: %v", round, applicationName, err)
		}
		switch count {
		case 1:
			return pid
		case 0:
			if time.Now().After(deadline) {
				t.Fatalf("round %d: no idle backend ever reported application_name=%s; this "+
					"test's own warm-up connection was never visible in pg_stat_activity",
					round, applicationName)
			}
			time.Sleep(5 * time.Millisecond)
		default:
			t.Fatalf("round %d: %d idle backends report application_name=%s, want exactly 1: "+
				"the pool opened more than the one connection this test's warm-up call assumed",
				round, count, applicationName)
		}
	}
}

// killBackendAndAwaitGone sends pg_terminate_backend to pid — Postgres's own
// deliberate way of ending one session, over a live administrative
// connection, rather than hoping a dying whole container gets a SQLSTATE out
// before the OS finishes tearing it down — and then blocks until
// pg_stat_activity confirms the backend is actually gone. By the time this
// returns, the FATAL Postgres sent that connection's client is already
// sitting in the socket's kernel buffer: the backend flushes it before it
// exits (die()'s ereport happens before proc_exit), unlike SIGKILL, which can
// end the process mid-write with nothing sent. The very next read on that
// connection needs no further luck.
func killBackendAndAwaitGone(ctx context.Context, t *testing.T, admin *pgx.Conn, pid int32, label string, round int) {
	t.Helper()
	var terminated bool
	if err := admin.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&terminated); err != nil {
		t.Fatalf("round %d: pg_terminate_backend(%d) for %s: %v", round, pid, label, err)
	}
	if !terminated {
		t.Fatalf("round %d: pg_terminate_backend(%d) for %s reported false; the backend this "+
			"test just found in pg_stat_activity was already gone", round, pid, label)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var stillThere bool
		err := admin.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)`, pid).Scan(&stillThere)
		if err != nil {
			t.Fatalf("round %d: poll pg_stat_activity for pid %d (%s): %v", round, pid, label, err)
		}
		if !stillThere {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("round %d: backend %d (%s) never left pg_stat_activity after "+
				"pg_terminate_backend", round, pid, label)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// probeLedgerOnce issues exactly one call on ledgerStore's now-terminated
// connection. Unlike the whole-container kill this replaces, Postgres itself
// is still up, so a nil error here is a real (if unlucky) outcome — it would
// mean the pool already swapped this test's targeted connection for a fresh,
// live one before this call reached it — not a violated premise to fail the
// whole test on; the caller retries with a fresh round instead.
func probeLedgerOnce(ctx context.Context, t *testing.T, s *ledger.Store, round int) (
	class string, retryable bool, code string, seen bool,
) {
	t.Helper()
	_, err := s.Head(ctx)
	if err == nil {
		t.Logf("round %d: internal/ledger.Store.Head answered successfully; the terminated "+
			"connection was already replaced before this call reached it", round)
		return "", false, "", false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Logf("round %d: internal/ledger.Store.Head failed without a SQLSTATE: %v (%T)", round, err, err)
		return "", false, "", false
	}
	var se *ledger.StoreError
	if !errors.As(err, &se) {
		t.Fatalf("internal/ledger returned an error carrying SQLSTATE %s that is not a "+
			"*ledger.StoreError: %v (%T)", pgErr.Code, err, err)
	}
	return se.Class, se.Retryable, pgErr.Code, true
}

// probeIdempotencyStoreOnce is probeLedgerOnce's twin for the MCP idempotency
// store, over its now-terminated connection.
func probeIdempotencyStoreOnce(ctx context.Context, t *testing.T, s *IdempotencyStore, round int) (
	class Class, retryable bool, code string, seen bool,
) {
	t.Helper()
	_, _, err := s.Lookup(ctx, fmt.Sprintf("mcp021-probe-%d", round))
	if err == nil {
		t.Logf("round %d: IdempotencyStore.Lookup answered successfully; the terminated "+
			"connection was already replaced before this call reached it", round)
		return "", false, "", false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Logf("round %d: IdempotencyStore.Lookup failed without a SQLSTATE: %v (%T)", round, err, err)
		return "", false, "", false
	}
	ie := mcpError(t, err)
	return ie.Class, ie.Retryable, pgErr.Code, true
}
