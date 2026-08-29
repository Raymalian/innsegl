// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/migrations"
)

// What this file proves, and what it deliberately does not.
//
// LED-008 (RM-009, merged) is the LEDGER's idempotency: one `idempotency_key`
// names at most one row in innsegl.events, so a replayed APPEND returns the
// original event and writes nothing. It dedupes a record.
//
// This file is the layer above: the MCP TOOL CALL. A tool call is not an
// append. register-shaped tools create a SPIRE entry and mint an identity
// before any event exists, and their result carries values no event holds
// (an expiry, for instance). So a crash between the effect and the append, or
// after the append and before the reply reached the agent, leaves the ledger
// unable to answer "what did that call return?" — which is exactly what IP
// §6.6 requires a replay to answer: "replaying any request after a crash
// returns the original result, never a second identity, second event, or
// second commit."
//
// The two layers must agree and must not duplicate each other:
//   * the ledger's UNIQUE idempotency_key is the permanent guarantee that one
//     key names one event (I3, I4);
//   * this store is the record of what the CALL returned, so the reply is the
//     first one and not a second computation.
// TestTheStoreAndTheLedgerAgreeOnOneKey composes them and holds both.
//
// Every storage test below runs against a real containerised Postgres. Doc 05
// §2: "MCP replicas are stateless (idempotency store lives in Postgres)". An
// in-memory store would pass a single-process test and silently break the
// property the moment a second replica existed, so the tests use two store
// instances on two pools wherever the claim is about replicas.

const (
	probeTool  = "probe_tool"
	otherTool  = "other_probe_tool"
	probeRunID = "run-42"
)

// randomToken returns a value that cannot be recomputed.
//
// This is the anti-vacuity device for the whole file. "The replay returned the
// original" passes trivially if both calls simply recompute the same
// deterministic value, so every tool body below mints a fresh random token and
// every replay assertion is an assertion about a value the replay could not
// have produced. Where the replay must not run the tool at all, the tool body
// is mustNotRun.
func randomToken(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func probeCall(key string) Call {
	return Call{Tool: probeTool, Key: key, Params: map[string]any{"run_id": probeRunID, "n": 1}}
}

// mustNotRun is a tool body that fails the test if it is ever called. A replay
// that recomputes rather than reads has run it.
func mustNotRun(t *testing.T) func(context.Context) (any, error) {
	t.Helper()
	return func(context.Context) (any, error) {
		t.Error("the tool ran again on a replay: the response was recomputed, not read from the store (IP §6.6)")
		return map[string]any{"token": "recomputed"}, nil
	}
}

// mintToken is a tool body returning a fresh unrecomputable response.
func mintToken(t *testing.T, ran *atomic.Int64, hold <-chan struct{}) func(context.Context) (any, error) {
	t.Helper()
	return func(context.Context) (any, error) {
		if ran != nil {
			ran.Add(1)
		}
		if hold != nil {
			<-hold
		}
		return map[string]any{"token": randomToken(t), "tool": probeTool}, nil
	}
}

// ---------------------------------------------------------------------------
// The core property (IP §6.6): a replay returns the ORIGINAL result.
// ---------------------------------------------------------------------------

func TestReplayReturnsTheStoredResponseAndNotARecomputedOne(t *testing.T) {
	t.Parallel()
	store, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-replay")
	var ran atomic.Int64

	first, err := store.Do(ctx, call, mintToken(t, &ran, nil))
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first.Replayed {
		t.Fatal("the first call reported itself as a replay")
	}
	if len(first.Response) == 0 {
		t.Fatal("the first call recorded no response")
	}

	// A second replica: a different store on a different pool, against the same
	// database. Doc 05 §2 — this is the property that makes the replicas
	// stateless, and a single-instance test would not see it fail.
	replica := NewIdempotencyStore(newPool(t, dsn))

	second, err := replica.Do(ctx, call, mustNotRun(t))
	if err != nil {
		t.Fatalf("replay on a second replica: %v", err)
	}
	if !second.Replayed {
		t.Fatal("the replay did not report itself as one")
	}
	if !bytes.Equal(first.Response, second.Response) {
		t.Fatalf("the replay returned %q, the original was %q", second.Response, first.Response)
	}
	if n := ran.Load(); n != 1 {
		t.Fatalf("the tool ran %d times for one idempotency_key, want exactly 1 (IP §6.6)", n)
	}

	rec, found, err := replica.Lookup(ctx, call.Key)
	if err != nil || !found {
		t.Fatalf("Lookup(%q) = found %v, err %v", call.Key, found, err)
	}
	if rec.Status != statusCompleted {
		t.Fatalf("status is %q, want %q", rec.Status, statusCompleted)
	}
	if rec.Claims != 1 {
		t.Fatalf("claim_count is %d, want 1: the replay claimed the key a second time", rec.Claims)
	}
	if !bytes.Equal(rec.Response, first.Response) {
		t.Fatalf("the stored response %q is not the one returned %q", rec.Response, first.Response)
	}
	if rec.CompletedAt.IsZero() {
		t.Fatal("a completed record carries no completed_at")
	}
	if rec.Tool != probeTool || rec.RequestDigest == "" {
		t.Fatalf("record does not name its call: %+v", rec)
	}
}

// A recorded response survives the database being killed, because it is in the
// database and nowhere else (IP §6.6: "no in-memory-only state that matters").
func TestARecordedResponseSurvivesAPostgresSIGKILL(t *testing.T) {
	t.Parallel()
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s); crash survival cannot be proved without one", dockerSkip)
	}
	ctx := testCtx(t, 6*time.Minute)

	// A container of its own: this test kills the server.
	pg, err := startPG(ctx)
	if err != nil {
		t.Fatalf("start a dedicated postgres: %v", err)
	}
	t.Cleanup(func() {
		if rerr := pg.remove(); rerr != nil {
			t.Logf("warning: removing container: %v", rerr)
		}
	})
	dsn := pg.dsn(postgresDB)
	migrate(t, dsn)

	call := probeCall("idem-crash")
	var ran atomic.Int64

	first, err := NewIdempotencyStore(newPool(t, dsn)).Do(ctx, call, mintToken(t, &ran, nil))
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// SIGKILL, not a shutdown: the restart runs WAL crash recovery.
	if kerr := pg.kill(ctx); kerr != nil {
		t.Fatalf("kill postgres: %v", kerr)
	}
	if rerr := pg.restart(ctx); rerr != nil {
		t.Fatalf("restart postgres: %v", rerr)
	}

	// A new process's worth of state: new pool, new store, nothing carried
	// over in memory.
	revived := NewIdempotencyStore(newPool(t, dsn))
	second, err := revived.Do(ctx, call, mustNotRun(t))
	if err != nil {
		t.Fatalf("replay after the crash: %v", err)
	}
	if !second.Replayed || !bytes.Equal(first.Response, second.Response) {
		t.Fatalf("after the crash the replay returned %q (replayed=%v), the original was %q",
			second.Response, second.Replayed, first.Response)
	}
	if n := ran.Load(); n != 1 {
		t.Fatalf("the tool ran %d times across the crash, want exactly 1", n)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: one effect, whatever the caller count.
// ---------------------------------------------------------------------------

func TestConcurrentReplaysOfOneKeyProduceExactlyOneEffect(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrate(t, dsn)
	ctx := testCtx(t, 3*time.Minute)

	const (
		replicas         = 4
		callersPerReplic = 4
	)
	call := probeCall("idem-concurrent")

	var (
		ran       atomic.Int64
		responses = make([][]byte, replicas*callersPerReplic)
		replayed  = make([]bool, replicas*callersPerReplic)
		errs      = make([]error, replicas*callersPerReplic)
		start     = make(chan struct{})
		wg        sync.WaitGroup
	)

	for r := range replicas {
		// One store per replica, each on its own pool: sixteen callers spread
		// over four "MCP replicas", which is the shape doc 05 §2 describes.
		store := NewIdempotencyStore(newPool(t, dsn))
		for i := range callersPerReplic {
			slot := r*callersPerReplic + i
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				out, err := store.Do(ctx, call, func(context.Context) (any, error) {
					ran.Add(1)
					// Long enough that the other fifteen callers are certainly
					// looking at an in-flight claim rather than a completed one.
					time.Sleep(150 * time.Millisecond)
					return map[string]any{"token": randomToken(t), "tool": probeTool}, nil
				})
				responses[slot], replayed[slot], errs[slot] = out.Response, out.Replayed, err
			}()
		}
	}
	close(start)
	wg.Wait()

	if n := ran.Load(); n != 1 {
		t.Fatalf("the tool ran %d times for one idempotency_key under %d concurrent callers, want exactly 1 (IP §6.6)",
			n, replicas*callersPerReplic)
	}
	firsts := 0
	for i := range responses {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if !bytes.Equal(responses[i], responses[0]) {
			t.Fatalf("caller %d returned %q, caller 0 returned %q: the callers disagree about what the call returned",
				i, responses[i], responses[0])
		}
		if !replayed[i] {
			firsts++
		}
	}
	if firsts != 1 {
		t.Fatalf("%d callers reported themselves the first, want exactly 1", firsts)
	}

	rec, found, err := NewIdempotencyStore(newPool(t, dsn)).Lookup(ctx, call.Key)
	if err != nil || !found {
		t.Fatalf("Lookup = found %v, err %v", found, err)
	}
	if rec.Claims != 1 {
		t.Fatalf("claim_count is %d after %d concurrent callers, want 1: a second caller claimed a live lease",
			rec.Claims, replicas*callersPerReplic)
	}
}

// ---------------------------------------------------------------------------
// A key reused for a DIFFERENT request is an error, never a wrong answer.
//
// RM-009 chose DUPLICATE_REQUEST for the same situation one layer down, with
// the same reasoning: doc 02 §2 gives the key one job, dedupe, and returning
// the earlier result would answer a question the caller did not ask.
// ---------------------------------------------------------------------------

func TestAKeyReusedForADifferentRequestIsRefused(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-reuse")
	first, err := store.Do(ctx, call, mintToken(t, nil, nil))
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	different := []struct {
		name string
		call Call
	}{
		{"different params", Call{Tool: probeTool, Key: call.Key, Params: map[string]any{"run_id": probeRunID, "n": 2}}},
		{"different tool", Call{Tool: otherTool, Key: call.Key, Params: call.Params}},
		{"no params at all", Call{Tool: probeTool, Key: call.Key}},
	}
	for _, d := range different {
		t.Run(d.name, func(t *testing.T) {
			derr := runDo(ctx, store, d.call, mustNotRun(t))
			if derr == nil {
				t.Fatal("a reused key was accepted for a different request")
			}
			ie := mcpError(t, derr)
			if ie.Class != ClassDuplicateRequest {
				t.Fatalf("error_class is %s, want %s", ie.Class, ClassDuplicateRequest)
			}
			if ie.Retryable {
				t.Fatal("key reuse is reported retryable; retrying it produces the same refusal forever")
			}
			if !errors.Is(derr, ErrKeyNamesADifferentRequest) {
				t.Fatalf("error %v does not wrap ErrKeyNamesADifferentRequest", derr)
			}
		})
	}

	// The refusals changed nothing.
	replay, err := store.Do(ctx, call, mustNotRun(t))
	if err != nil {
		t.Fatalf("replay of the original after the refusals: %v", err)
	}
	if !bytes.Equal(replay.Response, first.Response) {
		t.Fatalf("the refusals disturbed the record: %q, want %q", replay.Response, first.Response)
	}
}

// ---------------------------------------------------------------------------
// A replay that arrives while the original is still running.
// ---------------------------------------------------------------------------

func TestACallStillInFlightIsWaitedForAndNeverRunAgain(t *testing.T) {
	t.Parallel()
	store, dsn := newStore(t)
	ctx := testCtx(t, 3*time.Minute)

	call := probeCall("idem-inflight")
	hold := make(chan struct{})
	done := make(chan Outcome, 1)
	var ran atomic.Int64

	go func() {
		out, err := store.Do(ctx, call, mintToken(t, &ran, hold))
		if err != nil {
			t.Errorf("in-flight call: %v", err)
		}
		done <- out
	}()
	waitForStatus(ctx, t, store, call.Key, statusInProgress)

	// A caller whose own context ends while it waits. It is told the original
	// is still running, in a class that says a retry can help — never that the
	// call was a duplicate to be abandoned, which would strand a reply that
	// does exist.
	t.Run("a caller that gives up is told the reply is still coming", func(t *testing.T) {
		impatient, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		replica := NewIdempotencyStore(newPool(t, dsn))

		_, err := replica.Do(impatient, call, mustNotRun(t))
		if err == nil {
			t.Fatal("a second call ran the tool while the first was still in flight")
		}
		e := mcpError(t, err)
		if e.Class != ClassLedgerUnavailable {
			t.Fatalf("error_class is %s, want %s", e.Class, ClassLedgerUnavailable)
		}
		if !e.Retryable {
			t.Fatal("a caller that stopped waiting is told not to retry; the recorded reply would then never be collected")
		}
		if !errors.Is(err, ErrCallInFlight) {
			t.Fatalf("error %v does not wrap ErrCallInFlight", err)
		}
	})

	// The same report when it is the store, not the clock, that ends the wait.
	t.Run("a waiter that loses the database is told the same thing", func(t *testing.T) {
		pool := newPool(t, dsn)
		replica := NewIdempotencyStore(pool)
		failed := make(chan error, 1)
		go func() {
			_, err := replica.Do(ctx, call, mustNotRun(t))
			failed <- err
		}()
		// Long enough that the caller is inside the wait rather than inside
		// its first claim, so what fails is a claim made while waiting.
		time.Sleep(200 * time.Millisecond)
		pool.Close()

		err := <-failed
		if err == nil {
			t.Fatal("a waiter whose pool was closed reported success")
		}
		e := mcpError(t, err)
		if e.Class != ClassLedgerUnavailable || !e.Retryable {
			t.Fatalf("class %s retryable %v, want %s retryable", e.Class, e.Retryable, ClassLedgerUnavailable)
		}
		if !errors.Is(err, ErrCallInFlight) {
			t.Fatalf("error %v does not name the call it was waiting for", err)
		}
	})

	// A caller that does wait gets the original reply, and the tool is not run
	// a second time.
	patient := make(chan Outcome, 1)
	replica := NewIdempotencyStore(newPool(t, dsn))
	go func() {
		out, err := replica.Do(ctx, call, mustNotRun(t))
		if err != nil {
			t.Errorf("patient replay: %v", err)
		}
		patient <- out
	}()
	// Let the patient caller reach the wait before the original finishes, so
	// it is the wait path and not a plain completed read that is exercised.
	time.Sleep(150 * time.Millisecond)
	close(hold)

	first := <-done
	waited := <-patient
	if !waited.Replayed || !bytes.Equal(waited.Response, first.Response) {
		t.Fatalf("the patient caller got %q (replayed=%v), the original was %q",
			waited.Response, waited.Replayed, first.Response)
	}
	if n := ran.Load(); n != 1 {
		t.Fatalf("the tool ran %d times, want 1", n)
	}
}

// A claim that commits WHILE another caller's claim statement is running is
// invisible to that statement: its INSERT blocks on the uncommitted row and
// then declines, and its SELECT arm reads a snapshot taken before the commit.
// The concurrency test above hits this perhaps two runs in three; this one
// makes it happen every time, by holding the conflicting INSERT open in a
// transaction of its own and committing it once the store is demonstrably
// blocked on it.
func TestAClaimThatCommitsDuringAnotherCallersStatementIsWaitedForNotLost(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrate(t, dsn)
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-invisible-claim")
	digest, err := call.fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	// A claim held open, uncommitted, with a lease that will not expire.
	conn := rawConn(t, dsn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() {
		if rerr := tx.Rollback(ctx); rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			t.Logf("rolling back the seeded claim: %v", rerr)
		}
	}()
	if _, ierr := tx.Exec(ctx, `
		INSERT INTO innsegl.idempotency
		       (idempotency_key, tool, request_digest, status, lease_expires_at)
		VALUES ($1, $2, $3, 'in_progress', clock_timestamp() + interval '1 hour')`,
		call.Key, call.Tool, digest); ierr != nil {
		t.Fatalf("seed an uncommitted claim: %v", ierr)
	}

	// This caller blocks inside its INSERT until the transaction above
	// commits, and then finds neither arm of its statement returned a row.
	brief, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	store := NewIdempotencyStore(newPool(t, dsn))
	failed := make(chan error, 1)
	go func() {
		_, derr := store.Do(brief, call, mustNotRun(t))
		failed <- derr
	}()

	time.Sleep(300 * time.Millisecond)
	if cerr := tx.Commit(ctx); cerr != nil {
		t.Fatalf("commit the seeded claim: %v", cerr)
	}

	derr := <-failed
	if derr == nil {
		t.Fatal("the caller ran the tool under a key another claim already held")
	}
	if !errors.Is(derr, ErrCallInFlight) {
		t.Fatalf("a claim that committed mid-statement was reported as %v, "+
			"want the in-flight report: the row exists and the caller must wait for it", derr)
	}
	e := mcpError(t, derr)
	if e.Class != ClassLedgerUnavailable || !e.Retryable {
		t.Fatalf("class %s retryable %v, want %s retryable", e.Class, e.Retryable, ClassLedgerUnavailable)
	}

	rec, found, err := store.Lookup(ctx, call.Key)
	if err != nil || !found {
		t.Fatalf("Lookup = found %v, err %v", found, err)
	}
	if rec.Claims != 1 {
		t.Fatalf("claim_count is %d, want 1: the blocked caller took a claim it should not have", rec.Claims)
	}
}

// ---------------------------------------------------------------------------
// Failure and takeover.
// ---------------------------------------------------------------------------

func TestAFailedCallReleasesTheKeyForARetry(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-failed")
	boom := errors.New("the tool failed")

	if _, err := store.Do(ctx, call, func(context.Context) (any, error) {
		return nil, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("Do returned %v, want the tool's own error", err)
	}

	rec, found, err := store.Lookup(ctx, call.Key)
	if err != nil || !found {
		t.Fatalf("Lookup = found %v, err %v", found, err)
	}
	if rec.Status != statusInProgress {
		t.Fatalf("a failed call left status %q; nothing completed, so nothing may be replayed", rec.Status)
	}
	if rec.Response != nil {
		t.Fatalf("a failed call recorded a response: %q", rec.Response)
	}

	// The key is available again, and the retry runs the tool.
	var ran atomic.Int64
	out, err := store.Do(ctx, call, mintToken(t, &ran, nil))
	if err != nil {
		t.Fatalf("retry after a failed call: %v", err)
	}
	if out.Replayed || ran.Load() != 1 {
		t.Fatalf("the retry did not run the tool: replayed=%v ran=%d", out.Replayed, ran.Load())
	}

	rec, _, err = store.Lookup(ctx, call.Key)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rec.Claims != 2 {
		t.Fatalf("claim_count is %d after a failure and a retry, want 2", rec.Claims)
	}
}

// An expired lease is taken over, because a crash between the claim and the
// response would otherwise wedge the key forever — and IP §6.6 requires the
// replay to RETURN something. The takeover runs the tool a second time; that
// second effect is what the inner idempotency (LED-008 for events, the SPIRE
// entry for identities) exists to absorb. What must never happen is two
// answers: every caller converges on the response that was recorded first.
func TestAnExpiredLeaseIsTakenOverAndEveryCallerGetsTheSameResponse(t *testing.T) {
	t.Parallel()
	// Lease zero: every claim is immediately expired, which is the state a
	// SIGKILLed replica leaves behind, without the wait.
	store, dsn := newStore(t, WithIdempotencyLease(0))
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-takeover")
	hold := make(chan struct{})
	done := make(chan Outcome, 1)
	var ran atomic.Int64

	go func() {
		out, err := store.Do(ctx, call, mintToken(t, &ran, hold))
		if err != nil {
			t.Errorf("the slow call: %v", err)
		}
		done <- out
	}()
	waitForStatus(ctx, t, store, call.Key, statusInProgress)

	taker := NewIdempotencyStore(newPool(t, dsn), WithIdempotencyLease(0))
	takeover, err := taker.Do(ctx, call, mintToken(t, &ran, nil))
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if takeover.Replayed {
		t.Fatal("the takeover reported itself a replay; it ran the tool")
	}

	close(hold)
	slow := <-done

	if !bytes.Equal(slow.Response, takeover.Response) {
		t.Fatalf("the two callers disagree: %q and %q. Exactly one response is the answer",
			slow.Response, takeover.Response)
	}
	if !slow.Replayed {
		t.Fatal("the overtaken caller returned its own response rather than the recorded one")
	}
	if n := ran.Load(); n != 2 {
		t.Fatalf("the tool ran %d times, want 2: the takeover is a second execution by construction", n)
	}
	rec, _, err := store.Lookup(ctx, call.Key)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rec.Claims != 2 {
		t.Fatalf("claim_count is %d, want 2", rec.Claims)
	}
}

// ---------------------------------------------------------------------------
// The store and the ledger: two layers, one key, no contradiction.
// ---------------------------------------------------------------------------

func TestTheStoreAndTheLedgerAgreeOnOneKey(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrate(t, dsn)
	ctx := testCtx(t, 2*time.Minute)

	led, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(led.Close)

	store := NewIdempotencyStore(newPool(t, dsn))
	key := "idem-ledger"
	call := Call{Tool: probeTool, Key: key, Params: map[string]any{"run_id": probeRunID}}

	var appends atomic.Int64
	first, err := store.Do(ctx, call, func(ctx context.Context) (any, error) {
		appends.Add(1)
		return led.Append(ctx, ledgerBody(key))
	})
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	second, err := store.Do(ctx, call, mustNotRun(t))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Replayed || !bytes.Equal(first.Response, second.Response) {
		t.Fatalf("replay returned %q, the original was %q", second.Response, first.Response)
	}
	if n := appends.Load(); n != 1 {
		t.Fatalf("the ledger was appended to %d times, want 1 (I3: one action, one record)", n)
	}

	count, err := led.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Fatalf("the chain holds %d events after one call and one replay, want 1", count)
	}

	// LED-008 is the layer below and is a different guarantee: appending the
	// SAME event under the same key returns the original event and writes
	// nothing. It cannot answer "what did the tool call return?", which is why
	// the store above it exists — and the two must not contradict.
	again, err := led.Append(ctx, ledgerBody(key))
	if err != nil {
		t.Fatalf("LED-008 replay at the ledger layer: %v", err)
	}
	stored, found, err := led.EventByIdempotencyKey(ctx, key)
	if err != nil || !found {
		t.Fatalf("EventByIdempotencyKey = found %v, err %v", found, err)
	}
	if again[event.FieldEventID] != stored[event.FieldEventID] {
		t.Fatalf("the ledger minted a second event for one key: %v and %v",
			again[event.FieldEventID], stored[event.FieldEventID])
	}
	count, err = led.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Fatalf("the chain holds %d events, want 1", count)
	}
}

func ledgerBody(key string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldRunID:          probeRunID,
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: key,
		event.FieldToolName:       probeTool,
	}
}

// ---------------------------------------------------------------------------
// Calls the store refuses before it touches the database. No Postgres needed:
// nothing has happened yet, and the pool is deliberately nil so that a
// regression which reaches it panics rather than passing.
// ---------------------------------------------------------------------------

func TestACallTheLedgerCouldNotStoreIsRefusedBeforeAnythingHappens(t *testing.T) {
	t.Parallel()
	store := NewIdempotencyStore(nil)
	ctx := testCtx(t, time.Minute)

	cases := []struct {
		name string
		call Call
	}{
		{"no tool", Call{Key: "k", Params: map[string]any{}}},
		{"no key", Call{Tool: probeTool, Params: map[string]any{}}},
		{"key over doc 02 §2's 128 bytes", Call{Tool: probeTool, Key: strings.Repeat("k", event.MaxIdempotencyKeyBytes+1)}},
		{"key that is not UTF-8", Call{Tool: probeTool, Key: "\xff\xfe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := store.Do(ctx, tc.call, mustNotRun(t))
			if err == nil {
				t.Fatal("the call was accepted")
			}
			ie := mcpError(t, err)
			if ie.Class != ClassInvariantViolation {
				t.Fatalf("error_class is %s, want %s", ie.Class, ClassInvariantViolation)
			}
			if ie.Retryable {
				t.Fatal("a malformed call is reported retryable")
			}
			if !errors.Is(err, ErrInvalidCall) {
				t.Fatalf("error %v does not wrap ErrInvalidCall", err)
			}
		})
	}

	// A key of exactly the limit is accepted by the fingerprint and fails
	// later, at the database, rather than here.
	if _, err := (&Call{Tool: probeTool, Key: strings.Repeat("k", event.MaxIdempotencyKeyBytes)}).fingerprint(); err != nil {
		t.Fatalf("a key of exactly %d bytes was refused: %v", event.MaxIdempotencyKeyBytes, err)
	}
}

func TestACallThatCannotBeFingerprintedIsRefused(t *testing.T) {
	t.Parallel()
	store := NewIdempotencyStore(nil)
	ctx := testCtx(t, time.Minute)

	bad := Call{Tool: probeTool, Key: "idem-unfingerprintable", Params: map[string]any{"ch": make(chan int)}}
	_, err := store.Do(ctx, bad, mustNotRun(t))
	if err == nil {
		t.Fatal("a call whose parameters cannot be canonicalized was accepted")
	}
	ie := mcpError(t, err)
	if ie.Class != ClassInvariantViolation {
		t.Fatalf("error_class is %s, want %s", ie.Class, ClassInvariantViolation)
	}
	if !errors.Is(err, ErrInvalidCall) {
		t.Fatalf("error %v does not wrap ErrInvalidCall", err)
	}
}

// A tool whose result cannot be canonicalized has already had its effect, so
// the key stays claimed: the lease, not an immediate release, paces the retry.
func TestAResponseThatCannotBeCanonicalizedIsAnInvariantViolation(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	call := probeCall("idem-unserializable")
	_, err := store.Do(ctx, call, func(context.Context) (any, error) {
		return map[string]any{"ch": make(chan int)}, nil
	})
	if err == nil {
		t.Fatal("a response that cannot be canonicalized was recorded")
	}
	ie := mcpError(t, err)
	if ie.Class != ClassInvariantViolation {
		t.Fatalf("error_class is %s, want %s", ie.Class, ClassInvariantViolation)
	}

	rec, found, err := store.Lookup(ctx, call.Key)
	if err != nil || !found {
		t.Fatalf("Lookup = found %v, err %v", found, err)
	}
	if rec.Status != statusInProgress || rec.Response != nil {
		t.Fatalf("the record is %+v; nothing completed, so nothing may be replayed", rec)
	}
}

// ---------------------------------------------------------------------------
// Error classes. The vocabulary is IP §4's and is a protected surface; this
// store reports the same three classes internal/ledger does, spelled once,
// there.
// ---------------------------------------------------------------------------

func TestClassifyMapsDatabaseFailuresOntoTheLedgersVocabulary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		err       error
		class     Class
		retryable bool
	}{
		{
			"not a database answer at all",
			errors.New("closed pool"),
			ClassLedgerUnavailable, true,
		},
		{
			"the schema's own state-machine guard",
			&pgconn.PgError{Code: IdempotencyStateSQLState, Message: "refused"},
			ClassInvariantViolation, false,
		},
		{
			"an integrity constraint",
			&pgconn.PgError{Code: "23514", Message: "check violation"},
			ClassInvariantViolation, false,
		},
		{
			"a database that answered, but not usefully",
			&pgconn.PgError{Code: "42P01", Message: "relation does not exist"},
			ClassLedgerUnavailable, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := classifyStorage("probe", tc.err)
			ie := mcpError(t, err)
			if ie.Class != tc.class {
				t.Fatalf("error_class is %s, want %s", ie.Class, tc.class)
			}
			if ie.Retryable != tc.retryable {
				t.Fatalf("retryable is %v, want %v", ie.Retryable, tc.retryable)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("%v does not wrap the cause", err)
			}
			if !strings.Contains(ie.Error(), string(tc.class)) {
				t.Fatalf("the rendered error %q does not name its class", ie.Error())
			}
		})
	}
}

func TestAnUnreachableLedgerIsReportedAsSuch(t *testing.T) {
	t.Parallel()
	ctx := testCtx(t, 2*time.Minute)

	t.Run("pool closed before the claim", func(t *testing.T) {
		t.Parallel()
		c := requirePG(t)
		dsn := freshDSN(t, c)
		migrate(t, dsn)
		pool := newPool(t, dsn)
		pool.Close()

		_, err := NewIdempotencyStore(pool).Do(ctx, probeCall("idem-closed"), mustNotRun(t))
		ie := mcpError(t, err)
		if ie.Class != ClassLedgerUnavailable || !ie.Retryable {
			t.Fatalf("class %s retryable %v, want %s retryable", ie.Class, ie.Retryable, ClassLedgerUnavailable)
		}
		if _, _, lerr := NewIdempotencyStore(pool).Lookup(ctx, "idem-closed"); lerr == nil {
			t.Fatal("Lookup against a closed pool succeeded")
		}
	})

	t.Run("database never migrated", func(t *testing.T) {
		t.Parallel()
		c := requirePG(t)
		dsn := freshDSN(t, c) // deliberately not migrated
		store := NewIdempotencyStore(newPool(t, dsn))

		_, err := store.Do(ctx, probeCall("idem-unmigrated"), mustNotRun(t))
		ie := mcpError(t, err)
		if ie.Class != ClassLedgerUnavailable {
			t.Fatalf("error_class is %s, want %s", ie.Class, ClassLedgerUnavailable)
		}
		if ie.Retryable {
			t.Fatal("a missing table is reported retryable; no amount of retrying creates it")
		}
	})

	t.Run("the ledger goes away while the tool runs", func(t *testing.T) {
		t.Parallel()
		c := requirePG(t)
		dsn := freshDSN(t, c)
		migrate(t, dsn)
		pool := newPool(t, dsn)
		store := NewIdempotencyStore(pool)

		_, err := store.Do(ctx, probeCall("idem-lost-after"), func(context.Context) (any, error) {
			pool.Close()
			return map[string]any{"token": "recorded nowhere"}, nil
		})
		ie := mcpError(t, err)
		if ie.Class != ClassLedgerUnavailable {
			t.Fatalf("error_class is %s, want %s", ie.Class, ClassLedgerUnavailable)
		}
	})

	t.Run("the ledger goes away and the tool fails too", func(t *testing.T) {
		t.Parallel()
		c := requirePG(t)
		dsn := freshDSN(t, c)
		migrate(t, dsn)
		pool := newPool(t, dsn)
		store := NewIdempotencyStore(pool)
		boom := errors.New("the tool failed")

		_, err := store.Do(ctx, probeCall("idem-lost-release"), func(context.Context) (any, error) {
			pool.Close()
			return nil, boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("Do returned %v, want the tool's own error", err)
		}
		ie := mcpError(t, err)
		if ie.Class != ClassLedgerUnavailable {
			t.Fatalf("the release failure is reported as %s, want %s", ie.Class, ClassLedgerUnavailable)
		}
	})

	t.Run("a response larger than the column allows", func(t *testing.T) {
		t.Parallel()
		store, _ := newStore(t)
		_, err := store.Do(ctx, probeCall("idem-oversize"), func(context.Context) (any, error) {
			return map[string]any{"blob": strings.Repeat("x", MaxIdempotencyResponseBytes+1)}, nil
		})
		ie := mcpError(t, err)
		if ie.Class != ClassInvariantViolation {
			t.Fatalf("error_class is %s, want %s", ie.Class, ClassInvariantViolation)
		}
	})
}

func TestLookupReportsAnAbsentKeyWithoutInventingOne(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	rec, found, err := store.Lookup(ctx, "never-used")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Fatalf("Lookup invented a record: %+v", rec)
	}
}

// ---------------------------------------------------------------------------
// The schema's own guards, exercised through raw SQL. The Go layer never
// attempts any of these; the point is that the database refuses them anyway,
// which is the only version of the claim that survives a psql prompt.
// ---------------------------------------------------------------------------

func TestTheSchemaRefusesToRewriteOrDiscardAClaim(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrate(t, dsn)
	ctx := testCtx(t, 2*time.Minute)

	store := NewIdempotencyStore(newPool(t, dsn))
	completed := probeCall("idem-sql-completed")
	if _, err := store.Do(ctx, completed, mintToken(t, nil, nil)); err != nil {
		t.Fatalf("seed a completed record: %v", err)
	}

	inflight := probeCall("idem-sql-inflight")
	hold := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := store.Do(ctx, inflight, mintToken(t, nil, hold)); err != nil {
			t.Errorf("seed an in-flight record: %v", err)
		}
	}()
	waitForStatus(ctx, t, store, inflight.Key, statusInProgress)

	conn := rawConn(t, dsn)
	refused := []struct {
		name string
		sql  string
		args []any
	}{
		{"rewrite a recorded response",
			`UPDATE innsegl.idempotency SET response = $2 WHERE idempotency_key = $1`,
			[]any{completed.Key, []byte("a different answer")}},
		{"reopen a completed call",
			`UPDATE innsegl.idempotency SET status = 'in_progress', response = NULL, completed_at = NULL WHERE idempotency_key = $1`,
			[]any{completed.Key}},
		{"repoint a claim at another request",
			`UPDATE innsegl.idempotency SET request_digest = $2 WHERE idempotency_key = $1`,
			[]any{inflight.Key, "sha256:" + strings.Repeat("ab", 32)}},
		{"rename the tool a claim belongs to",
			`UPDATE innsegl.idempotency SET tool = $2 WHERE idempotency_key = $1`,
			[]any{inflight.Key, otherTool}},
		{"delete a claim that is still in flight",
			`DELETE FROM innsegl.idempotency WHERE idempotency_key = $1`,
			[]any{inflight.Key}},
		{"truncate the store",
			`TRUNCATE innsegl.idempotency`, nil},
	}
	for _, r := range refused {
		t.Run(r.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, r.sql, r.args...)
			if err == nil {
				t.Fatalf("the database accepted: %s", r.sql)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("error %v is not a PgError", err)
			}
			if pgErr.Code != IdempotencyStateSQLState {
				t.Fatalf("SQLSTATE is %s, want %s: a caller cannot recognise the refusal without matching message text",
					pgErr.Code, IdempotencyStateSQLState)
			}
		})
	}

	// Pruning a completed record IS allowed: this table is a bounded record of
	// recent calls, not the ledger. The ledger's own UNIQUE idempotency_key is
	// the permanent guarantee (I4), and it is untouched by this.
	if _, err := conn.Exec(ctx,
		`DELETE FROM innsegl.idempotency WHERE idempotency_key = $1`, completed.Key); err != nil {
		t.Fatalf("pruning a completed record was refused: %v", err)
	}

	close(hold)
	<-done
}

// The Go constant and the column's CHECK are two spellings of one limit.
func TestTheResponseLimitIsSpelledTheSameInGoAndInSQL(t *testing.T) {
	t.Parallel()

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	want := fmt.Sprintf("octet_length(response) <= %d", MaxIdempotencyResponseBytes)
	for _, m := range all {
		if strings.Contains(m.SQL, want) {
			return
		}
	}
	t.Fatalf("no migration carries %q; the Go cap and the column CHECK can drift apart", want)
}

// ---------------------------------------------------------------------------

// runDo calls Do and keeps only the error, so a subtest can name its own
// variable without shadowing the enclosing one.
func runDo(ctx context.Context, s *IdempotencyStore, call Call, fn func(context.Context) (any, error)) error {
	_, err := s.Do(ctx, call, fn)
	return err
}

// waitForStatus blocks until key reaches status, so a test never races the
// goroutine it just started.
func waitForStatus(ctx context.Context, t *testing.T, s *IdempotencyStore, key, status string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		rec, found, err := s.Lookup(ctx, key)
		if err != nil {
			t.Fatalf("Lookup while waiting for %q: %v", status, err)
		}
		if found && rec.Status == status {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%q never reached status %q", key, status)
}
