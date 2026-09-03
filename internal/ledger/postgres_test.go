// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
)

// storeBody is an event body as a caller supplies it: no chain_position, no
// prev_event_hash, no event_hash, no event_id and no ts. Those five are the
// ledger's to assign (doc 02 §2).
func storeBody(n int) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldRunID:          "run-42",
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("idem-%05d", n),
		event.FieldToolName:       fmt.Sprintf("tool-%d", n),
	}
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// storeError extracts the *StoreError an operation must have returned.
func storeError(t *testing.T, err error) *StoreError {
	t.Helper()
	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("error %v (%T) is not a *StoreError; the MCP layer has no error_class to report (IP §5)", err, err)
	}
	return se
}

// ---------------------------------------------------------------------------
// LED-003 — attempt DELETE/UPDATE via any API surface.
//
// Two halves, and both are required. The Go half proves the repository type
// offers no mutating call at all: absence at compile time, not a guard at run
// time. The SQL half proves the database refuses the same operations even when
// the Go layer is bypassed entirely — which is the only version of the claim
// that survives an operator with a psql prompt.
// ---------------------------------------------------------------------------

// mutatingMethodPrefixes is the vocabulary a delete-or-update surface would be
// spelled with. It is deliberately wider than the one in surface_test.go.
var mutatingMethodPrefixes = []string{
	"Delete", "Remove", "Drop", "Truncate", "Purge", "Erase", "Expunge",
	"Update", "Set", "Replace", "Rewrite", "Mutate", "Overwrite", "Patch",
	"Prune", "Clear", "Reset", "Revoke", "Amend", "Edit",
}

func TestLED003StoreExposesNoMutatingMethod(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(&Store{})
	var names []string
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}

	// Guards against a vacuous pass: an empty or stubbed method set trivially
	// contains no mutating name and proves nothing.
	if len(names) == 0 {
		t.Fatal("*Store exports no method at all; the scan proves nothing")
	}
	for _, want := range []string{"Append", "Head", "Events", "Count"} {
		if !slices.Contains(names, want) {
			t.Fatalf("*Store has no %s method; this is not the repository LED-003 is about (have %v)",
				want, names)
		}
	}

	for _, name := range names {
		for _, verb := range mutatingMethodPrefixes {
			if strings.HasPrefix(name, verb) {
				t.Errorf("*Store.%s reads as a mutating call; no record is ever deleted or mutated (I4)",
					name)
			}
		}
	}
	t.Logf("*Store exports %d methods, none mutating: %v", len(names), names)
}

func TestLED003DirectSQLMutationIsRefused(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	for n := range 3 {
		if _, err := s.Append(ctx, storeBody(n)); err != nil {
			t.Fatalf("append %d: %v", n, err)
		}
	}

	conn := rawConn(t, dsn)

	// The precondition. Without it every statement below "fails" for the
	// uninteresting reason that there is no table and no row, and the test
	// passes while proving nothing.
	var before int64
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM innsegl.events`).Scan(&before); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if before != 3 {
		t.Fatalf("expected 3 events in innsegl.events before the mutation attempts, got %d", before)
	}
	var original []byte
	if err := conn.QueryRow(ctx,
		`SELECT canonical FROM innsegl.events WHERE chain_position = 2`).Scan(&original); err != nil {
		t.Fatalf("read canonical bytes at position 2: %v", err)
	}
	if len(original) == 0 {
		t.Fatal("position 2 carries no canonical bytes; nothing to protect")
	}

	attempts := []struct {
		name string
		sql  string
	}{
		{"UPDATE one row", `UPDATE innsegl.events SET run_id = 'tampered' WHERE chain_position = 2`},
		{"UPDATE the hash", `UPDATE innsegl.events SET event_hash = 'sha256:` + strings.Repeat("0", 64) + `' WHERE chain_position = 2`},
		{"UPDATE the canonical bytes", `UPDATE innsegl.events SET canonical = '{}'::bytea WHERE chain_position = 2`},
		{"UPDATE matching no row", `UPDATE innsegl.events SET run_id = run_id WHERE false`},
		{"DELETE one row", `DELETE FROM innsegl.events WHERE chain_position = 2`},
		{"DELETE everything", `DELETE FROM innsegl.events`},
		{"DELETE matching no row", `DELETE FROM innsegl.events WHERE false`},
		{"TRUNCATE", `TRUNCATE innsegl.events`},
	}

	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, a.sql)
			if err == nil {
				t.Fatalf("%s succeeded; the ledger is append-only (I4)", a.sql)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("%s failed with %v, which is not a Postgres error; "+
					"the refusal must come from the database, not from the driver", a.sql, err)
			}
			if pgErr.Code != AppendOnlySQLState {
				t.Fatalf("%s failed with SQLSTATE %s (%s); want %s from the append-only guard",
					a.sql, pgErr.Code, pgErr.Message, AppendOnlySQLState)
			}
			t.Logf("refused: SQLSTATE %s: %s", pgErr.Code, pgErr.Message)
		})
	}

	var after int64
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM innsegl.events`).Scan(&after); err != nil {
		t.Fatalf("count events after: %v", err)
	}
	if after != before {
		t.Fatalf("event count moved from %d to %d across the refused mutations", before, after)
	}
	var current []byte
	if err := conn.QueryRow(ctx,
		`SELECT canonical FROM innsegl.events WHERE chain_position = 2`).Scan(&current); err != nil {
		t.Fatalf("re-read canonical bytes at position 2: %v", err)
	}
	if string(current) != string(original) {
		t.Fatalf("the canonical bytes at position 2 changed:\n before %q\n after  %q", original, current)
	}

	records, err := s.Events(ctx, 1, 3)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if _, err := Verify(records); err != nil {
		t.Fatalf("chain no longer verifies after the refused mutations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LED-007 — N parallel writers (N >= 50) append concurrently.
// Exactly N events, no gaps, no duplicate positions.
// ---------------------------------------------------------------------------

func TestLED007ParallelWritersAppendWithoutGapsOrDuplicates(t *testing.T) {
	t.Parallel()
	const writers = 64 // the catalog's floor is 50

	s, _ := newStore(t)
	ctx := testCtx(t, 3*time.Minute)

	type outcome struct {
		record event.Fields
		err    error
	}
	results := make([]outcome, writers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, so they contend
			rec, err := s.Append(ctx, storeBody(i))
			results[i] = outcome{record: rec, err: err}
		}()
	}
	close(start)
	wg.Wait()

	positions := make(map[int64]int, writers)
	eventIDs := make(map[string]int, writers)
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("writer %d: %v", i, r.err)
		}
		head, err := RecordHead(r.record)
		if err != nil {
			t.Fatalf("writer %d returned a record that is not a chain link: %v", i, err)
		}
		if prev, dup := positions[head.Position]; dup {
			t.Fatalf("writers %d and %d were both assigned chain_position %d",
				prev, i, head.Position)
		}
		positions[head.Position] = i

		id, ok := r.record[event.FieldEventID].(string)
		if !ok {
			t.Fatalf("writer %d: event_id is %T, want string", i, r.record[event.FieldEventID])
		}
		if prev, dup := eventIDs[id]; dup {
			t.Fatalf("writers %d and %d were both assigned event_id %s", prev, i, id)
		}
		eventIDs[id] = i
	}

	for p := int64(1); p <= writers; p++ {
		if _, ok := positions[p]; !ok {
			t.Fatalf("no writer was assigned chain_position %d; the chain has a gap", p)
		}
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != writers {
		t.Fatalf("stored %d events, %d writers each appended exactly one", count, writers)
	}

	records, err := s.Events(ctx, 1, writers)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(records) != writers {
		t.Fatalf("read back %d events, want %d", len(records), writers)
	}
	head, err := Verify(records)
	if err != nil {
		t.Fatalf("the chain %d concurrent writers produced does not verify: %v", writers, err)
	}
	if head.Position != writers {
		t.Fatalf("chain head is at %d, want %d", head.Position, writers)
	}

	// What each writer was handed must be what the ledger kept.
	for i, r := range results {
		pos, herr := RecordHead(r.record)
		if herr != nil {
			t.Fatalf("writer %d: %v", i, herr)
		}
		stored := records[pos.Position-1]
		if !reflect.DeepEqual(r.record, stored) {
			t.Fatalf("writer %d was returned a record that differs from the stored one at position %d:\n returned %v\n stored   %v",
				i, pos.Position, r.record, stored)
		}
	}
}

// ---------------------------------------------------------------------------
// LED-008 — the same idempotency_key appended twice returns the original
// event. Identical result; not an error surface.
// ---------------------------------------------------------------------------

func TestLED008SameIdempotencyKeyReturnsTheOriginalEvent(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	body := storeBody(1)
	first, err := s.Append(ctx, body.Clone())
	if err != nil {
		t.Fatalf("first append: %v", err)
	}

	// A replay arrives later, so a store that re-stamped ts or re-assigned
	// event_id would be caught by the comparison below rather than by luck.
	time.Sleep(5 * time.Millisecond)

	second, err := s.Append(ctx, body.Clone())
	if err != nil {
		t.Fatalf("replay of the same idempotency_key returned an error: %v; "+
			"LED-008 says the second call returns the original event, identically", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replay returned a different event:\n first  %v\n second %v", first, second)
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("a replayed append produced %d events; one action, one record (I3)", count)
	}
}

func TestLED008ConcurrentReplaysCollapseToOneEvent(t *testing.T) {
	t.Parallel()
	const replays = 16

	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	body := storeBody(7)
	records := make([]event.Fields, replays)
	errs := make([]error, replays)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range replays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			records[i], errs[i] = s.Append(ctx, body.Clone())
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		if !reflect.DeepEqual(records[0], records[i]) {
			t.Fatalf("replay %d returned a different event:\n 0 %v\n %d %v",
				i, records[0], i, records[i])
		}
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("%d concurrent replays of one key produced %d events, want 1", replays, count)
	}
}

// TestLED008KeyReuseForADifferentEventIsRefused guards the edge doc 02 §2 does
// not spell out: a dedupe key that has already named a different action.
// Returning the first event would answer a question the caller did not ask.
func TestLED008KeyReuseForADifferentEventIsRefused(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	body := storeBody(1)
	if _, err := s.Append(ctx, body.Clone()); err != nil {
		t.Fatalf("first append: %v", err)
	}

	other := body.Clone()
	other[event.FieldToolName] = "a-different-tool"
	_, err := s.Append(ctx, other)
	if err == nil {
		t.Fatal("reusing an idempotency_key for a different event returned the earlier event; " +
			"that is a silently wrong answer, not a replay")
	}
	se := storeError(t, err)
	if se.Class != ClassDuplicateRequest {
		t.Fatalf("error_class is %s, want %s", se.Class, ClassDuplicateRequest)
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("the refused append left %d events, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// LED-009 — Postgres down during append.
// LEDGER_UNAVAILABLE returned; no partial write on recovery.
//
// The failure is injected for real: the container is SIGKILLed, so the restart
// runs WAL crash recovery rather than replaying a clean shutdown. A stub that
// returned an error on demand would prove nothing about what is on disk
// afterwards, which is the half of LED-009 that matters.
// ---------------------------------------------------------------------------

func TestLED009PostgresDownDuringAppend(t *testing.T) {
	t.Parallel()
	// requirePG, not a bare nil check: a Postgres that failed to start on a
	// machine that has Docker is a failure, and LED-009 is exactly the case
	// that must not silently not run (#101).
	requirePG(t)

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

	// Enough connections that every in-flight append reaches the append lock
	// rather than queueing for a connection; the kill must land on backends
	// inside a transaction.
	dsn := pg.dsn(postgresDB) + "&pool_max_conns=60"
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)
	if merr := s.Migrate(ctx); merr != nil {
		t.Fatalf("migrate: %v", merr)
	}

	// Acknowledged before the crash. These must all be there afterwards.
	const committed = 5
	acknowledged := make([]event.Fields, committed)
	for i := range committed {
		rec, aerr := s.Append(ctx, storeBody(i))
		if aerr != nil {
			t.Fatalf("pre-crash append %d: %v", i, aerr)
		}
		acknowledged[i] = rec
	}

	// Park every in-flight append on the append lock, so the kill lands while
	// they are inside their transaction rather than whenever the scheduler
	// happens to get there. Deterministic, and it is the same lock the store
	// itself takes.
	blocker, err := pgx.Connect(ctx, pg.dsn(postgresDB))
	if err != nil {
		t.Fatalf("connect the blocker: %v", err)
	}
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, appendLockKey); err != nil {
		t.Fatalf("take the append lock: %v", err)
	}

	const inflight = 50
	type outcome struct {
		record event.Fields
		err    error
	}
	results := make([]outcome, inflight)
	var wg sync.WaitGroup
	for i := range inflight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, aerr := s.Append(ctx, storeBody(committed+i))
			results[i] = outcome{record: rec, err: aerr}
		}()
	}

	// Give them time to reach the lock, then pull the server out from under
	// them. Waiting on pg_locks would be tighter, but the server is about to
	// be killed either way: what matters is that they are inside Append.
	if err := waitForLockWaiters(ctx, pg.dsn(postgresDB), inflight); err != nil {
		t.Logf("note: %v (killing anyway)", err)
	}
	if err := pg.kill(ctx); err != nil {
		t.Fatalf("kill postgres: %v", err)
	}
	wg.Wait()
	if cerr := blocker.Close(context.Background()); cerr != nil {
		t.Logf("closing the blocker after the kill: %v", cerr)
	}

	t.Run("every in-flight append reports LEDGER_UNAVAILABLE", func(t *testing.T) {
		for i, r := range results {
			if r.err == nil {
				t.Fatalf("in-flight append %d succeeded after the server was killed", i)
			}
			se := storeError(t, r.err)
			if se.Class != ClassLedgerUnavailable {
				t.Fatalf("in-flight append %d reported %s (%v), want %s",
					i, se.Class, r.err, ClassLedgerUnavailable)
			}
			if !se.Retryable {
				t.Fatalf("in-flight append %d reported %s as not retryable; "+
					"a dead ledger is the retryable case (IP §6.4)", i, se.Class)
			}
		}
	})

	t.Run("an append against a dead server reports LEDGER_UNAVAILABLE", func(t *testing.T) {
		down, derr := context.WithTimeout(ctx, 30*time.Second)
		defer derr()
		_, aerr := s.Append(down, storeBody(9000))
		if aerr == nil {
			t.Fatal("append succeeded against a stopped Postgres")
		}
		se := storeError(t, aerr)
		if se.Class != ClassLedgerUnavailable {
			t.Fatalf("error_class is %s (%v), want %s", se.Class, aerr, ClassLedgerUnavailable)
		}
	})

	t.Run("every reader reports LEDGER_UNAVAILABLE while the server is down", func(t *testing.T) {
		down, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		reads := map[string]func() error{
			"head":  func() error { _, err := s.Head(down); return err },
			"count": func() error { _, err := s.Count(down); return err },
			"events": func() error {
				_, err := s.Events(down, 1, 5)
				return err
			},
			"event at": func() error { _, err := s.EventAt(down, 1); return err },
			"event by idempotency_key": func() error {
				_, _, err := s.EventByIdempotencyKey(down, "idem-00000")
				return err
			},
			"chain identity": func() error { _, err := s.Chain(down); return err },
			"migrate":        func() error { return s.Migrate(down) },
		}
		for name, read := range reads {
			err := read()
			if err == nil {
				t.Fatalf("%s answered from a stopped Postgres", name)
			}
			se := storeError(t, err)
			if se.Class != ClassLedgerUnavailable {
				t.Fatalf("%s reported %s (%v), want %s", name, se.Class, err, ClassLedgerUnavailable)
			}
		}
	})

	if err := pg.restart(ctx); err != nil {
		t.Fatalf("restart postgres: %v", err)
	}

	t.Run("no partial write survives recovery", func(t *testing.T) {
		count, cerr := s.Count(ctx)
		if cerr != nil {
			t.Fatalf("count after recovery: %v", cerr)
		}
		if count != committed {
			t.Fatalf("after crash recovery the ledger holds %d events; "+
				"%d were acknowledged and %d were in flight and refused",
				count, committed, inflight)
		}

		records, rerr := s.Events(ctx, 1, committed)
		if rerr != nil {
			t.Fatalf("read back after recovery: %v", rerr)
		}
		head, verr := Verify(records)
		if verr != nil {
			t.Fatalf("the chain does not verify after crash recovery: %v", verr)
		}
		if head.Position != committed {
			t.Fatalf("chain head is at %d after recovery, want %d", head.Position, committed)
		}
		for i, want := range acknowledged {
			if !reflect.DeepEqual(want, records[i]) {
				t.Fatalf("acknowledged event at position %d did not survive the crash intact:\n want %v\n got  %v",
					i+1, want, records[i])
			}
		}
	})

	t.Run("replay after recovery is absorbed by idempotency", func(t *testing.T) {
		for i := range inflight {
			if _, aerr := s.Append(ctx, storeBody(committed+i)); aerr != nil {
				t.Fatalf("replay %d after recovery: %v", i, aerr)
			}
		}
		// Once more, to prove the replay itself is idempotent.
		for i := range inflight {
			if _, aerr := s.Append(ctx, storeBody(committed+i)); aerr != nil {
				t.Fatalf("second replay %d: %v", i, aerr)
			}
		}
		want := int64(committed + inflight)
		count, cerr := s.Count(ctx)
		if cerr != nil {
			t.Fatalf("count: %v", cerr)
		}
		if count != want {
			t.Fatalf("after replay the ledger holds %d events, want %d", count, want)
		}
		records, rerr := s.Events(ctx, 1, want)
		if rerr != nil {
			t.Fatalf("read back: %v", rerr)
		}
		if _, verr := Verify(records); verr != nil {
			t.Fatalf("the chain does not verify after replay: %v", verr)
		}
	})
}

// waitForLockWaiters blocks until at least n backends are waiting on the
// append lock.
func waitForLockWaiters(ctx context.Context, dsn string, n int) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect the lock observer: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	deadline := time.Now().Add(30 * time.Second)
	var waiting int
	for time.Now().Before(deadline) {
		if err := conn.QueryRow(ctx,
			`SELECT count(*) FROM pg_locks
			  WHERE locktype = 'advisory' AND NOT granted AND objid = $1::bigint & x'FFFFFFFF'::bigint`,
			appendLockKey).Scan(&waiting); err != nil {
			return fmt.Errorf("read pg_locks: %w", err)
		}
		if waiting >= n {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("only %d backend(s) reached the append lock, wanted %d", waiting, n)
}

// ---------------------------------------------------------------------------
// LED-010 — a client-supplied timestamp is ignored.
// ---------------------------------------------------------------------------

func TestLED010ClientSuppliedTimestampIsIgnored(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	skews := []struct {
		name string
		ts   string
	}{
		{"far in the past", "1999-12-31T23:59:59.999Z"},
		{"far in the future", "2099-01-01T00:00:00.000Z"},
		{"a second off", event.NewTimestamp(time.Now().Add(-time.Second)).String()},
	}

	for i, skew := range skews {
		t.Run(skew.name, func(t *testing.T) {
			body := storeBody(i)
			body[event.FieldTS] = skew.ts

			before := event.NewTimestamp(time.Now().Add(-2 * time.Second))
			rec, err := s.Append(ctx, body)
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			after := event.NewTimestamp(time.Now().Add(2 * time.Second))

			got, ok := rec[event.FieldTS].(string)
			if !ok {
				t.Fatalf("ts is %T, want string", rec[event.FieldTS])
			}
			if got == skew.ts {
				t.Fatalf("the stored ts is the client's %q; ts is the server clock at append (doc 02 §2, IP §6.8)",
					skew.ts)
			}
			parsed, err := event.ParseTimestamp(got)
			if err != nil {
				t.Fatalf("stored ts %q: %v", got, err)
			}
			if parsed.Time().Before(before.Time()) || parsed.Time().After(after.Time()) {
				t.Fatalf("stored ts %q is not the server clock at append (between %s and %s)",
					got, before, after)
			}
		})
	}

	// The skewed value must not survive anywhere in the record either.
	conn := rawConn(t, dsn)
	for _, skew := range skews {
		var found int64
		if err := conn.QueryRow(ctx,
			`SELECT count(*) FROM innsegl.events WHERE position($1 in encode(canonical, 'escape')) > 0`,
			skew.ts).Scan(&found); err != nil {
			t.Fatalf("scan canonical bytes: %v", err)
		}
		if found != 0 {
			t.Fatalf("the client timestamp %q appears in %d stored event(s)", skew.ts, found)
		}
	}
}

// ---------------------------------------------------------------------------
// Supporting behaviour the five IDs above rest on.
// ---------------------------------------------------------------------------

func TestAppendRefusesLedgerAssignedMembers(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	assigned := map[string]any{
		event.FieldChainPosition: int64(1),
		event.FieldPrevEventHash: event.GenesisPrevEventHash(),
		event.EventHashField:     event.GenesisPrevEventHash(),
		event.FieldEventID:       "01a047a5-cc41-7c45-86fd-000000000001",
	}
	for name, value := range assigned {
		t.Run(name, func(t *testing.T) {
			body := storeBody(0)
			body[name] = value
			if _, err := s.Append(ctx, body); err == nil {
				t.Fatalf("append accepted a caller-supplied %s; it is assigned by the ledger (doc 02 §2)",
					name)
			}
		})
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("the refused appends left %d events behind", count)
	}
}

func TestAppendStampsGenesisAndChains(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	first, err := s.Append(ctx, storeBody(0))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if got := first[event.FieldChainPosition]; got != int64(1) {
		t.Fatalf("first event is at chain_position %v, want 1", got)
	}
	if got := first[event.FieldPrevEventHash]; got != event.GenesisPrevEventHash() {
		t.Fatalf("first event carries prev_event_hash %v, want the genesis constant %s (doc 02 §4.4)",
			got, event.GenesisPrevEventHash())
	}
	if verr := event.ValidateEvent(first); verr != nil {
		t.Fatalf("the appended event does not satisfy the closed schema: %v", verr)
	}

	second, err := s.Append(ctx, storeBody(1))
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if second[event.FieldPrevEventHash] != first[event.EventHashField] {
		t.Fatalf("second event's prev_event_hash %v is not the first's event_hash %v",
			second[event.FieldPrevEventHash], first[event.EventHashField])
	}

	head, err := s.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	want, err := RecordHead(second)
	if err != nil {
		t.Fatalf("record head: %v", err)
	}
	if head != want {
		t.Fatalf("stored head is %+v, want %+v", head, want)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t) // newStore already migrated once
	ctx := testCtx(t, 2*time.Minute)

	if _, err := s.Append(ctx, storeBody(0)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("re-running the migration left %d events, want 1", count)
	}
}
