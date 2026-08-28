// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/migrations"
)

// ---------------------------------------------------------------------------
// The schema's own guards, exercised through raw SQL rather than through the
// store. Anything the Go layer is the only thing enforcing is enforced only
// until someone writes a second writer.
// ---------------------------------------------------------------------------

// TestChainLinkTriggerRefusesGapsAndForks writes directly to the table, which
// is what a second writer, a repair script or an operator would do.
func TestChainLinkTriggerRefusesGapsAndForks(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	for n := range 2 {
		if _, err := s.Append(ctx, storeBody(n)); err != nil {
			t.Fatalf("append %d: %v", n, err)
		}
	}
	tip := mustEventHash(ctx, t, s, 2)

	conn := rawConn(t, dsn)
	insert := `INSERT INTO innsegl.events
		 (chain_position, event_id, event_hash, prev_event_hash, event_type,
		  source, run_id, idempotency_key, ts, canonical)
		 VALUES ($1, $2, $3, $4, 'tool_call', 'mcp', 'run-42', $5, now(), $6)`

	fakeHash := func(seed string) string {
		sum := sha256.Sum256([]byte(seed))
		return event.HashPrefix + hex.EncodeToString(sum[:])
	}

	cases := []struct {
		name     string
		position int64
		prev     string
		wantCode string
	}{
		{"a gap", 4, tip, ChainLinkSQLState},
		{"the wrong predecessor", 3, fakeHash("not the tip"), ChainLinkSQLState},
		{"a fork off position 1", 3, mustEventHash(ctx, t, s, 1), ChainLinkSQLState},
		{"a rewritten genesis", 1, fakeHash("a different genesis"), ChainLinkSQLState},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, insert,
				c.position,
				"01a047a5-cc41-7c45-86fd-00000000000"+string(rune('0'+i)),
				fakeHash("event "+c.name),
				c.prev,
				"raw-"+c.name,
				[]byte(`{"raw":"bytes"}`))
			if err == nil {
				t.Fatalf("a direct INSERT of %s was accepted; the chain rule is not enforced by the database", c.name)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("insert failed with %v, not a Postgres error", err)
			}
			if pgErr.Code != c.wantCode {
				t.Fatalf("insert of %s failed with SQLSTATE %s (%s), want %s",
					c.name, pgErr.Code, pgErr.Message, c.wantCode)
			}
			t.Logf("refused: SQLSTATE %s: %s", pgErr.Code, pgErr.Message)
		})
	}

	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("the refused inserts left %d events, want 2", count)
	}
}

func mustEventHash(ctx context.Context, t *testing.T, s *Store, position int64) string {
	t.Helper()
	rec, err := s.EventAt(ctx, position)
	if err != nil {
		t.Fatalf("read position %d: %v", position, err)
	}
	h, ok := rec[event.EventHashField].(string)
	if !ok {
		t.Fatalf("position %d has no event_hash", position)
	}
	return h
}

// TestStoredColumnsAgreeWithTheCanonicalBytes holds the denormalised columns to
// the bytes they are derived from. They exist to be indexed; the moment one
// disagrees with the canonical record it is a second, unhashed answer to a
// question the ledger already answers.
func TestStoredColumnsAgreeWithTheCanonicalBytes(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	for n := range 4 {
		if _, err := s.Append(ctx, storeBody(n)); err != nil {
			t.Fatalf("append %d: %v", n, err)
		}
	}

	conn := rawConn(t, dsn)
	rows, err := conn.Query(ctx,
		`SELECT chain_position, event_id, event_hash, prev_event_hash, event_type,
		        source, run_id, idempotency_key, ts, canonical
		   FROM innsegl.events ORDER BY chain_position`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var (
			position                      int64
			id, hash, prev, etype, source string
			runID, key                    *string
			ts                            time.Time
			canonical                     []byte
		)
		if err := rows.Scan(&position, &id, &hash, &prev, &etype, &source,
			&runID, &key, &ts, &canonical); err != nil {
			t.Fatalf("scan: %v", err)
		}
		record, err := event.ParseFields(canonical)
		if err != nil {
			t.Fatalf("position %d: canonical bytes do not parse: %v", position, err)
		}
		if err := record.Verify(); err != nil {
			t.Fatalf("position %d: %v", position, err)
		}
		want := map[string]any{
			event.FieldChainPosition: position,
			event.FieldEventID:       id,
			event.EventHashField:     hash,
			event.FieldPrevEventHash: prev,
			event.FieldEventType:     etype,
			event.FieldSource:        source,
			event.FieldTS:            event.NewTimestamp(ts).String(),
		}
		if runID != nil {
			want[event.FieldRunID] = *runID
		}
		if key != nil {
			want[event.FieldIdempotencyKey] = *key
		}
		for name, v := range want {
			if record[name] != v {
				t.Fatalf("position %d: column %s is %v, the canonical bytes say %v",
					position, name, v, record[name])
			}
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if seen != 4 {
		t.Fatalf("checked %d rows, want 4", seen)
	}
}

// TestMigrationGenesisConstantIsDerived holds the literal in the schema to
// doc 02 §4.4: "Compute it; do not hardcode without a test deriving it."
func TestMigrationGenesisConstantIsDerived(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte(event.GenesisSeed))
	derived := event.HashPrefix + hex.EncodeToString(sum[:])
	if derived != event.GenesisPrevEventHash() {
		t.Fatalf("the package computes %s, deriving it here gives %s",
			event.GenesisPrevEventHash(), derived)
	}

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	found := false
	for _, m := range all {
		if strings.Contains(m.SQL, derived) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no migration carries the derived genesis constant %s; "+
			"the schema and the code would disagree about where a chain starts", derived)
	}
}

func TestMigrateRefusesADatabaseRootedAtADifferentGenesis(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	ctx := testCtx(t, 2*time.Minute)

	// A database that claims migration 0001 already ran, and whose chain was
	// rooted somewhere else entirely.
	conn := rawConn(t, dsn)
	if _, err := conn.Exec(ctx, `
		CREATE SCHEMA innsegl;
		CREATE TABLE innsegl.chain (
			singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
			chain_id uuid NOT NULL DEFAULT gen_random_uuid(),
			genesis_prev_event_hash text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO innsegl.chain (singleton, genesis_prev_event_hash)
			VALUES (true, 'sha256:`+strings.Repeat("ab", 32)+`');
		CREATE TABLE innsegl.schema_migrations (
			version text PRIMARY KEY, name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO innsegl.schema_migrations (version, name)
			VALUES ('0001', '0001_ledger.sql');`); err != nil {
		t.Fatalf("seed a foreign database: %v", err)
	}

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)

	err = s.Migrate(ctx)
	if err == nil {
		t.Fatal("migrate accepted a database rooted at a different genesis constant")
	}
	se := storeError(t, err)
	if se.Class != ClassInvariantViolation {
		t.Fatalf("error_class is %s, want %s", se.Class, ClassInvariantViolation)
	}
}

// ---------------------------------------------------------------------------
// Reads, and the failures they can report.
// ---------------------------------------------------------------------------

func TestReadersOnAnEmptyChain(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	head, err := s.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if !head.IsEmpty() {
		t.Fatalf("head of an empty chain is %+v, want the empty head", head)
	}
	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("count is %d on an empty chain", count)
	}
	records, err := s.Events(ctx, 1, 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("read %d events from an empty chain", len(records))
	}
	if _, err := s.EventAt(ctx, 1); err == nil {
		t.Fatal("EventAt returned an event from an empty chain")
	}
	if _, found, err := s.EventByIdempotencyKey(ctx, "never-used"); err != nil || found {
		t.Fatalf("EventByIdempotencyKey(unused) = found %v, err %v", found, err)
	}
}

func TestEventsRejectsANonAscendingRange(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	for _, r := range [][2]int64{{0, 5}, {5, 4}, {-1, -1}} {
		if _, err := s.Events(ctx, r[0], r[1]); err == nil {
			t.Fatalf("Events(%d, %d) was accepted", r[0], r[1])
		}
	}
}

func TestEventAtAndEventByIdempotencyKeyReturnTheStoredEvent(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	written, err := s.Append(ctx, storeBody(3))
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	at, err := s.EventAt(ctx, 1)
	if err != nil {
		t.Fatalf("EventAt: %v", err)
	}
	if !reflect.DeepEqual(written, at) {
		t.Fatalf("EventAt returned\n %v\nwant\n %v", at, written)
	}

	key, ok := written[event.FieldIdempotencyKey].(string)
	if !ok {
		t.Fatalf("the written event carries no idempotency_key")
	}
	byKey, found, err := s.EventByIdempotencyKey(ctx, key)
	if err != nil || !found {
		t.Fatalf("EventByIdempotencyKey(%q) = found %v, err %v", key, found, err)
	}
	if !reflect.DeepEqual(written, byKey) {
		t.Fatalf("EventByIdempotencyKey returned\n %v\nwant\n %v", byKey, written)
	}
}

// TestEventsRefusesUnreadableStoredBytes covers the one case a reader cannot
// repair: bytes in the table that are not an event. INSERT is the only write
// the schema allows, so this is exactly the shape a bad second writer leaves.
func TestEventsRefusesUnreadableStoredBytes(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	conn := rawConn(t, dsn)
	if _, err := conn.Exec(ctx,
		`INSERT INTO innsegl.events
		   (chain_position, event_id, event_hash, prev_event_hash, event_type,
		    source, run_id, idempotency_key, ts, canonical)
		 VALUES (1, '01a047a5-cc41-7c45-86fd-00000000000f', $1, $2,
		         'tool_call', 'mcp', NULL, NULL, now(), $3)`,
		event.HashPrefix+strings.Repeat("0", 64),
		event.GenesisPrevEventHash(),
		[]byte(`{not json`)); err != nil {
		t.Fatalf("seed an unreadable row: %v", err)
	}

	_, err := s.Events(ctx, 1, 1)
	if err == nil {
		t.Fatal("Events returned an event for bytes that are not an event")
	}
	se := storeError(t, err)
	if se.Class != ClassInvariantViolation {
		t.Fatalf("error_class is %s, want %s", se.Class, ClassInvariantViolation)
	}
	if _, _, err := s.EventByIdempotencyKey(ctx, "unused"); err != nil {
		t.Fatalf("EventByIdempotencyKey on an unrelated key: %v", err)
	}
}

// TestAppendWithoutARunOrAKey covers the events doc 02 §2 lets omit run_id,
// spiffe_id and idempotency_key: a NULL column rather than an empty string.
func TestAppendWithoutARunOrAKey(t *testing.T) {
	t.Parallel()
	s, dsn := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	sealed := event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventType:         event.EventTypeSegmentSealed,
		event.FieldSource:            event.SourceSystem,
		event.FieldSegmentID:         "seg-000001",
		event.FieldSegmentMerkleRoot: event.HashPrefix + strings.Repeat("a", 64),
		event.FieldFirstPosition:     int64(1),
		event.FieldLastPosition:      int64(1),
	}
	record, err := s.Append(ctx, sealed)
	if err != nil {
		t.Fatalf("append segment_sealed: %v", err)
	}
	for _, absent := range []string{event.FieldRunID, event.FieldSpiffeID, event.FieldIdempotencyKey} {
		if _, present := record[absent]; present {
			t.Fatalf("%s is present on a segment_sealed event", absent)
		}
	}

	conn := rawConn(t, dsn)
	var nulls int
	if qerr := conn.QueryRow(ctx,
		`SELECT count(*) FROM innsegl.events
		  WHERE run_id IS NULL AND idempotency_key IS NULL`).Scan(&nulls); qerr != nil {
		t.Fatalf("count nulls: %v", qerr)
	}
	if nulls != 1 {
		t.Fatalf("%d rows carry NULL run_id and idempotency_key, want 1; "+
			"an absent member is NULL, never the empty string (doc 02 §1)", nulls)
	}

	// Two keyless events in a row: NULLs are distinct in a UNIQUE index, so
	// the dedupe constraint does not collapse them.
	if _, aerr := s.Append(ctx, sealed); aerr != nil {
		t.Fatalf("second keyless append: %v", aerr)
	}
	count, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("two keyless appends produced %d events, want 2", count)
	}
}

func TestChainIdentityIsStorageLevelOnly(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	id, err := s.Chain(ctx)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if id.ChainID == "" {
		t.Fatal("the database names no chain")
	}
	if id.Genesis != event.GenesisPrevEventHash() {
		t.Fatalf("chain genesis is %s, want %s", id.Genesis, event.GenesisPrevEventHash())
	}

	record, err := s.Append(ctx, storeBody(0))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	// ADR-0005: the chain's identity is storage metadata and never enters an
	// event. doc 02 §2 is a protected surface with no chain_id member, and an
	// event carrying one would be a different schema version.
	for name, value := range record {
		if s, ok := value.(string); ok && s == id.ChainID {
			t.Fatalf("member %q carries the storage-level chain_id; "+
				"doc 02 §2 has no chain_id member and §2 is protected", name)
		}
	}
	if _, present := record["chain_id"]; present {
		t.Fatal("the appended event carries a chain_id member")
	}
}

// ---------------------------------------------------------------------------
// Unit tests: no database needed, and none of them prove anything about one.
// ---------------------------------------------------------------------------

func TestMonotonicTimestampNeverGoesBackwards(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 28, 9, 14, 3, 201_000_000, time.UTC)
	previous := event.NewTimestamp(base)

	cases := []struct {
		name  string
		clock time.Time
		want  event.Timestamp
	}{
		{"an empty chain takes the clock", base, event.NewTimestamp(base)},
		{"the clock has advanced", base.Add(time.Second), event.NewTimestamp(base.Add(time.Second))},
		{"the clock is unchanged", base, previous},
		{"the clock stepped backwards", base.Add(-time.Hour), previous},
		{"sub-millisecond precision is truncated", base.Add(1_500_000), event.NewTimestamp(base.Add(time.Millisecond))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := previous
			if c.name == "an empty chain takes the clock" {
				prev = event.Timestamp{}
			}
			got := monotonicTS(c.clock, prev)
			if got.String() != c.want.String() {
				t.Fatalf("monotonicTS(%s, %s) = %s, want %s",
					c.clock.Format(time.RFC3339Nano), prev, got, c.want)
			}
			if !prev.IsZero() && got.Time().Before(prev.Time()) {
				t.Fatalf("ts %s is before the previous event's %s (IP §6.8)", got, prev)
			}
		})
	}
}

func TestPrepareRefusesWhatTheCallerMayNotSupply(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body event.Fields
	}{
		{"no members at all", event.Fields{}},
		{"nil body", nil},
		{"a non-string idempotency_key", event.Fields{
			event.FieldEventType:      event.EventTypeToolCall,
			event.FieldIdempotencyKey: int64(7),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := prepare(c.body)
			if err == nil {
				t.Fatalf("prepare accepted %s", c.name)
			}
			se := storeError(t, err)
			if se.Class != ClassInvariantViolation {
				t.Fatalf("error_class is %s, want %s", se.Class, ClassInvariantViolation)
			}
		})
	}
}

func TestPrepareDropsTheClientTimestampAndStampsTheSchemaVersion(t *testing.T) {
	t.Parallel()

	body := storeBody(0)
	body[event.FieldTS] = "1999-12-31T23:59:59.999Z"
	delete(body, event.FieldSchemaVersion)

	p, err := prepare(body)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, present := p.body[event.FieldTS]; present {
		t.Fatal("the client's ts survived prepare")
	}
	if p.body[event.FieldSchemaVersion] != event.SchemaVersion {
		t.Fatalf("schema_version is %v, want %q", p.body[event.FieldSchemaVersion], event.SchemaVersion)
	}
	if p.idempotencyKey != body[event.FieldIdempotencyKey] {
		t.Fatalf("prepare read the idempotency_key as %q", p.idempotencyKey)
	}
	if p.eventType != event.EventTypeToolCall || p.source != event.SourceMCP || p.runID != "run-42" {
		t.Fatalf("prepare read the indexed members as %+v", p)
	}
	// The caller's map is never touched.
	if body[event.FieldTS] != "1999-12-31T23:59:59.999Z" {
		t.Fatal("prepare modified the caller's body")
	}
}

func TestClassifyMapsDatabaseFailuresOntoErrorClasses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		err           error
		wantClass     string
		wantRetryable bool
	}{
		{"append-only refusal", &pgconn.PgError{Code: AppendOnlySQLState}, ClassInvariantViolation, false},
		{"chain link refusal", &pgconn.PgError{Code: ChainLinkSQLState}, ClassInvariantViolation, false},
		{"unique violation", &pgconn.PgError{Code: "23505"}, ClassInvariantViolation, false},
		{"data exception", &pgconn.PgError{Code: "22001"}, ClassInvariantViolation, false},
		{"undefined table", &pgconn.PgError{Code: "42P01"}, ClassInvariantViolation, false},
		{"serialization failure", &pgconn.PgError{Code: "40001"}, ClassLedgerUnavailable, true},
		{"too many connections", &pgconn.PgError{Code: "53300"}, ClassLedgerUnavailable, true},
		{"admin shutdown", &pgconn.PgError{Code: "57P01"}, ClassLedgerUnavailable, true},
		{"system error", &pgconn.PgError{Code: "58030"}, ClassLedgerUnavailable, true},
		{"connection exception", &pgconn.PgError{Code: "08006"}, ClassLedgerUnavailable, true},
		{"read-only transaction", &pgconn.PgError{Code: "25006"}, ClassLedgerUnavailable, false},
		{"a bare transport error", errors.New("unexpected EOF"), ClassLedgerUnavailable, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := classify("append", c.err)
			se := storeError(t, err)
			if se.Class != c.wantClass || se.Retryable != c.wantRetryable {
				t.Fatalf("classify(%v) = %s retryable=%v, want %s retryable=%v",
					c.err, se.Class, se.Retryable, c.wantClass, c.wantRetryable)
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("the cause was lost: %v", err)
			}
			if !strings.Contains(err.Error(), c.wantClass) {
				t.Fatalf("Error() is %q and does not name the class", err.Error())
			}
		})
	}

	if classify("append", nil) != nil {
		t.Fatal("classify(nil) invented an error")
	}
	already := &StoreError{Class: ClassDuplicateRequest, Op: "append", Err: ErrIdempotencyKeyConflict}
	if got := classify("append", already); !errors.Is(got, already) {
		t.Fatalf("classify re-wrapped a classified error: %v", got)
	}
}

// retryableTestError stands in for the pgconn errors that report whether the
// statement reached the server. pgconn's own types keep that flag unexported,
// and the question here is what safeToRetry does with the answer.
type retryableTestError struct{ safe bool }

func (e retryableTestError) Error() string     { return "test transport failure" }
func (e retryableTestError) SafeToRetry() bool { return e.safe }

func TestSafeToRetryOnlyWhenNothingWasSent(t *testing.T) {
	t.Parallel()

	live := context.Background()
	if safeToRetry(live, errors.New("some failure")) {
		t.Fatal("an unclassified failure was reported as safe to retry")
	}
	if safeToRetry(live, retryableTestError{safe: false}) {
		t.Fatal("a statement that may have reached the server was reported as safe to retry; " +
			"replaying one is how a ledger acquires a duplicate record")
	}
	if !safeToRetry(live, retryableTestError{safe: true}) {
		t.Fatal("a statement that never reached the server is safe to retry")
	}

	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if safeToRetry(dead, retryableTestError{safe: true}) {
		t.Fatal("a retry was allowed on a cancelled context")
	}
}

func TestOpenReportsABadDSNAndAnUnreachableServer(t *testing.T) {
	t.Parallel()
	ctx := testCtx(t, 30*time.Second)

	_, err := Open(ctx, "://not a dsn")
	if err == nil {
		t.Fatal("Open accepted a malformed DSN")
	}
	if se := storeError(t, err); se.Class != ClassInvariantViolation {
		t.Fatalf("error_class for a malformed DSN is %s, want %s", se.Class, ClassInvariantViolation)
	}

	// Port 1 on the loopback: nothing listens, and nothing will.
	_, err = Open(ctx, "postgres://innsegl:innsegl@127.0.0.1:1/innsegl?sslmode=disable&connect_timeout=2")
	if err == nil {
		t.Fatal("Open succeeded against a port nothing listens on")
	}
	if se := storeError(t, err); se.Class != ClassLedgerUnavailable {
		t.Fatalf("error_class for an unreachable server is %s, want %s",
			se.Class, ClassLedgerUnavailable)
	}
}

func TestCloseIsSafeOnAZeroStore(t *testing.T) {
	t.Parallel()
	var s *Store
	s.Close()
	(&Store{}).Close()
}
