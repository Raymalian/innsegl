// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/migrations"
)

// Store is the ledger's hot tier: a Postgres-backed, append-only event log
// (RM-009, doc 05).
//
// # There is no mutating call, at either layer
//
// The type below offers Append and a set of readers, and nothing else. There
// is no Delete, no Update, no Set — not as a method that returns "forbidden",
// but as a method that does not exist, because a guard that can return 403 can
// also return 200 after a bad refactor (LED-003, I4).
//
// Absence in Go would still leave the table open to any client with the
// password, so the schema carries the same rule: a statement-level trigger
// raises on UPDATE, DELETE and TRUNCATE, and INSERT is checked against the
// chain rule. See migrations/0001_ledger.sql, including its honest note about
// what a superuser can still do.
//
// # What a chain is, here
//
// One chain per database (ADR-0005). doc 02 §2 says chain_position is
// "strictly consecutive per chain" and gives the envelope no chain_id member;
// §2 is a protected surface, so the scope had to come from storage rather than
// from the event. It comes from the database: everything in innsegl.events is
// one chain, chain_position is its primary key, and a second chain is a second
// database.
//
// # Serialized append
//
// Position assignment runs under pg_advisory_xact_lock, so appends to one
// chain are strictly single-writer while readers are untouched. The head is
// read from committed rows inside that lock, never from cached state, so a
// rolled-back append leaves no gap and no reserved position (LED-007).
type Store struct {
	pool *pgxpool.Pool
}

// Error classes, from IP §5's vocabulary. The string values are a protected
// surface: an MCP tool reports one of these verbatim, and a client switches on
// it.
const (
	// ClassLedgerUnavailable is returned when the ledger cannot be reached or
	// cannot answer. Identity-issuing and signing fail closed on it (IP §6.4).
	ClassLedgerUnavailable = "LEDGER_UNAVAILABLE"
	// ClassInvariantViolation is returned when an append would break something
	// that must hold — the closed schema, the chain rule, a uniqueness rule.
	ClassInvariantViolation = "INVARIANT_VIOLATION"
	// ClassDuplicateRequest is returned when an idempotency_key has already
	// named a *different* action. A replay of the same action is not an error
	// at all; it returns the original event (LED-008).
	ClassDuplicateRequest = "DUPLICATE_REQUEST"
)

// SQLSTATEs raised by the schema's own guards. IN is a user-defined class:
// Postgres reserves classes beginning with 0-4 and A-H.
const (
	// AppendOnlySQLState is raised by the trigger that refuses UPDATE, DELETE
	// and TRUNCATE on a written event (I4).
	AppendOnlySQLState = "IN001"
	// ChainLinkSQLState is raised when an INSERT would leave a gap or a fork
	// (doc 02 §4.5).
	ChainLinkSQLState = "IN002"
)

// appendLockKey is the pg_advisory_xact_lock key that serializes position
// assignment. Derived from a fixed string rather than written as a magic
// number, so the value is reproducible from the name and cannot be confused
// with another subsystem's lock. Advisory locks are database-scoped, which is
// the same scope as a chain (ADR-0005).
var appendLockKey = int64(binary.BigEndian.Uint64(
	func() []byte { sum := sha256.Sum256([]byte("innsegl-ledger-append-v1")); return sum[:8] }()))

// maxAttempts bounds how often an operation is retried after a failure that
// pgx reports as safe to retry — that is, one where the query was never sent.
// Nothing else is ever retried: replaying a statement that may have committed
// is how a ledger acquires a duplicate record.
const maxAttempts = 3

// StoreError is a ledger failure with the error class an MCP tool reports
// (IP §5). Retryable answers the caller's only real question: try again, or
// fail the operation.
type StoreError struct {
	Class     string
	Op        string
	Retryable bool
	Err       error
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("%s: %s: %v", e.Op, e.Class, e.Err)
}

func (e *StoreError) Unwrap() error { return e.Err }

// ErrIdempotencyKeyConflict reports a dedupe key already used for a different
// event. doc 02 §2 gives the key one job — dedupe — and says nothing about
// reuse; returning the earlier event would answer a question the caller did
// not ask, so the reuse is refused instead.
var ErrIdempotencyKeyConflict = errors.New("idempotency_key already names a different event")

// ledgerAssignedByStore are the members the store assigns on top of the three
// chain.Append assigns. doc 02 §2 calls event_id "assigned by the ledger", so
// a caller supplying one is refused rather than overwritten.
var ledgerAssignedByStore = []string{event.FieldEventID}

// Open connects to the ledger database and checks that it answers.
//
// The DSN may carry pgx pool settings (pool_max_conns and friends). Nothing
// here writes: Migrate does that, separately, so that a read-only consumer can
// open a store without holding DDL rights.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "open", Retryable: false,
			Err: fmt.Errorf("parse dsn: %w", err),
		}
	}
	// Statements are sent as extended-protocol queries with parameters and are
	// never assembled from strings, so the cache is a straight win and the
	// only string interpolation in this package is the migration SQL itself.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, classify("open", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, classify("open", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool. Safe on a nil-pooled store so a failed Open path in
// a caller's cleanup does not panic.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Migrate applies every embedded migration that has not run, in version order,
// each in its own transaction, and records it.
//
// Applying a migration twice is not an error; applying half of one is
// impossible, because the file and the row that records it commit together.
func (s *Store) Migrate(ctx context.Context) error {
	all, err := migrations.All()
	if err != nil {
		return &StoreError{
			Class: ClassInvariantViolation, Op: "migrate", Retryable: false, Err: err,
		}
	}

	const bootstrap = `
		CREATE SCHEMA IF NOT EXISTS innsegl;
		CREATE TABLE IF NOT EXISTS innsegl.schema_migrations (
			version    text PRIMARY KEY,
			name       text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		);`
	if _, err := s.pool.Exec(ctx, bootstrap); err != nil {
		return classify("migrate", err)
	}

	for _, m := range all {
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return s.checkGenesisConstant(ctx)
}

// applyMigration runs one migration if it has not run, inside one transaction.
func (s *Store) applyMigration(ctx context.Context, m migrations.Migration) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return classify("migrate", err)
	}
	defer func() {
		rerr := tx.Rollback(ctx)
		if err == nil && rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			err = classify("migrate", rerr)
		}
	}()

	// The insert is the lock: a concurrent migrator blocks here and then finds
	// zero rows affected, rather than both running the same DDL.
	tag, err := tx.Exec(ctx,
		`INSERT INTO innsegl.schema_migrations (version, name) VALUES ($1, $2)
		 ON CONFLICT (version) DO NOTHING`, m.Version, m.Name)
	if err != nil {
		return classify("migrate", err)
	}
	if tag.RowsAffected() == 0 {
		return nil // already applied
	}
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return classify("migrate "+m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return classify("migrate "+m.Name, err)
	}
	return nil
}

// checkGenesisConstant refuses a database whose recorded genesis differs from
// the running code's. The two disagreeing means the chain in this database was
// rooted by a different schema version, and appending to it would produce a
// chain no single verifier can walk (doc 02 §4.4, §7).
func (s *Store) checkGenesisConstant(ctx context.Context) error {
	var stored string
	err := s.pool.QueryRow(ctx, `SELECT genesis_prev_event_hash FROM innsegl.chain`).Scan(&stored)
	if err != nil {
		return classify("migrate", err)
	}
	if stored != event.GenesisPrevEventHash() {
		return &StoreError{
			Class: ClassInvariantViolation, Op: "migrate", Retryable: false,
			Err: fmt.Errorf("this database was rooted at genesis %s, this build computes %s (doc 02 §4.4)",
				stored, event.GenesisPrevEventHash()),
		}
	}
	return nil
}

// ChainIdentity names the chain a database holds. It is storage-level
// metadata: no part of it enters an event or its preimage (ADR-0005).
type ChainIdentity struct {
	ChainID   string
	Genesis   string
	CreatedAt time.Time
}

// Chain returns this database's chain identity.
func (s *Store) Chain(ctx context.Context) (ChainIdentity, error) {
	var id ChainIdentity
	err := s.pool.QueryRow(ctx,
		`SELECT chain_id::text, genesis_prev_event_hash, created_at FROM innsegl.chain`).
		Scan(&id.ChainID, &id.Genesis, &id.CreatedAt)
	if err != nil {
		return ChainIdentity{}, classify("chain", err)
	}
	return id, nil
}

// Append appends one event and returns the record as it was written.
//
// body carries everything the caller supplies. The ledger assigns event_id,
// chain_position, prev_event_hash, event_hash and ts; supplying one of the
// first four is an error, because a silently ignored chain_position is a
// caller that believes it chose one. ts is the exception doc 02 §2 states
// outright — "Client-supplied values are ignored" — so a ts in body is dropped
// rather than refused (LED-010).
//
// When body carries an idempotency_key that has already been appended, the
// original event is returned unchanged and nothing is written: a replay is a
// success, not an error (LED-008, IP §6.6).
func (s *Store) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	p, err := prepare(body)
	if err != nil {
		return nil, err
	}

	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		record, err := s.appendOnce(ctx, p)
		if err == nil {
			return record, nil
		}
		last = err
		if !safeToRetry(ctx, err) {
			return nil, err
		}
	}
	return nil, last
}

// pending is one append after the caller's half has been checked: the body the
// ledger will hash, and the four string members the table indexes. Reading
// them once, here, is what keeps the insert free of type assertions whose
// failure would have nowhere sensible to go.
//
// An empty string means the member is absent, and only members doc 02 §2
// allows to be absent are held that way — a present-but-empty value is
// rejected by event.Fields.Validate long before this.
type pending struct {
	body           event.Fields
	eventType      string
	source         string
	runID          string
	idempotencyKey string
}

// prepare validates what the caller supplied and returns the body the ledger
// will hash.
func prepare(body event.Fields) (pending, error) {
	reject := func(format string, args ...any) (pending, error) {
		return pending{}, &StoreError{
			Class: ClassInvariantViolation, Op: "append", Retryable: false,
			Err: fmt.Errorf(format, args...),
		}
	}
	if len(body) == 0 {
		return reject("an event body with no members carries no action to record (I3)")
	}
	for _, name := range slicesConcat(ledgerAssignedMembers, ledgerAssignedByStore) {
		if _, present := body[name]; present {
			return reject("%w: %s is assigned by the ledger (doc 02 §2)",
				ErrLedgerAssignedMember, name)
		}
	}

	staged := body.Clone()
	// doc 02 §2: ts is the server clock at append and a client value is
	// ignored. Dropped here so it cannot reach the preimage by any route.
	delete(staged, event.FieldTS)
	if _, present := staged[event.FieldSchemaVersion]; !present {
		staged[event.FieldSchemaVersion] = event.SchemaVersion
	}

	p := pending{body: staged}
	for _, m := range []struct {
		name string
		into *string
	}{
		{event.FieldEventType, &p.eventType},
		{event.FieldSource, &p.source},
		{event.FieldRunID, &p.runID},
		{event.FieldIdempotencyKey, &p.idempotencyKey},
	} {
		v, err := stringMember(staged, m.name)
		if err != nil {
			return reject("%s", err)
		}
		*m.into = v
	}
	return p, nil
}

// stringMember reads a member that must be a string if it is there at all.
// Absence is "", which is a value the schema does not otherwise admit.
func stringMember(f event.Fields, name string) (string, error) {
	raw, present := f[name]
	if !present {
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s is %T, want string", name, raw)
	}
	return v, nil
}

// slicesConcat joins two name lists. Written out rather than pulled in so the
// two protected member lists stay visibly separate at their definitions.
func slicesConcat(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// appendOnce is one attempt: one transaction, one advisory lock, one insert.
func (s *Store) appendOnce(ctx context.Context, p pending) (record event.Fields, err error) {
	// READ COMMITTED on purpose. The advisory lock makes the append
	// single-writer, and READ COMMITTED takes a fresh snapshot per statement,
	// so the head read after the lock sees every committed append. Under
	// REPEATABLE READ the snapshot would predate the lock and the head could
	// be stale — the one isolation level that would be worse than the default.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, classify("append", err)
	}
	defer func() {
		rerr := tx.Rollback(ctx)
		if err == nil && rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			record, err = nil, classify("append", rerr)
		}
	}()

	if _, lerr := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockKey); lerr != nil {
		return nil, classify("append", lerr)
	}

	if p.idempotencyKey != "" {
		existing, found, lerr := readByKey(ctx, tx, p.idempotencyKey)
		if lerr != nil {
			return nil, lerr
		}
		if found {
			if cerr := sameRequest(existing, p.body); cerr != nil {
				return nil, &StoreError{
					Class: ClassDuplicateRequest, Op: "append", Retryable: false, Err: cerr,
				}
			}
			return existing, nil
		}
	}

	head, headTS, err := readHead(ctx, tx)
	if err != nil {
		return nil, err
	}

	var clock time.Time
	if cerr := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&clock); cerr != nil {
		return nil, classify("append", cerr)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "append", Retryable: false,
			Err: fmt.Errorf("assign event_id: %w", err),
		}
	}

	stamped := p.body.Clone()
	stamped[event.FieldEventID] = id.String()
	ts := monotonicTS(clock, headTS)
	stamped[event.FieldTS] = ts.String()

	position, prev := head.Next()
	record, newHead, aerr := Append(head, stamped)
	if aerr == nil {
		// doc 02 §1: the schema is closed and unknown members are rejected at
		// append. Checked after the chain members are stamped, because the
		// record that must satisfy the schema is the one that gets stored.
		aerr = event.ValidateEvent(record)
	}
	var canonical []byte
	if aerr == nil {
		canonical, aerr = event.Canonicalize(record)
	}
	if aerr != nil {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "append", Retryable: false, Err: aerr,
		}
	}

	if ierr := insertEvent(ctx, tx, eventRow{
		position:       position,
		eventID:        id.String(),
		eventHash:      newHead.EventHash,
		prevEventHash:  prev,
		eventType:      p.eventType,
		source:         p.source,
		runID:          p.runID,
		idempotencyKey: p.idempotencyKey,
		ts:             ts.Time(),
		canonical:      canonical,
	}); ierr != nil {
		return nil, ierr
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return nil, classify("append", cerr)
	}
	return record, nil
}

// monotonicTS is the ts an append carries: the server clock, never earlier
// than the event before it.
//
// IP §6.8 requires ledger timestamps to be monotonic per chain. Appends are
// serialized, so the clock only regresses when the machine's does — an NTP
// step. Clamping keeps the ledger writable through one, and the regression
// stays visible as a run of identical timestamps rather than being hidden by a
// fabricated increment. Truncation to the millisecond is doc 02 §1's
// precision, and truncating rather than rounding means ts never names an
// instant that had not happened yet.
func monotonicTS(clock time.Time, previous event.Timestamp) event.Timestamp {
	ts := event.NewTimestamp(clock)
	if !previous.IsZero() && ts.Time().Before(previous.Time()) {
		return previous
	}
	return ts
}

// readHead returns the chain tip and the tip's timestamp, inside the caller's
// transaction and therefore under the append lock.
func readHead(ctx context.Context, tx pgx.Tx) (Head, event.Timestamp, error) {
	var (
		position int64
		hash     string
		ts       time.Time
	)
	err := tx.QueryRow(ctx,
		`SELECT chain_position, event_hash, ts FROM innsegl.events
		  ORDER BY chain_position DESC LIMIT 1`).Scan(&position, &hash, &ts)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Head{}, event.Timestamp{}, nil
	case err != nil:
		return Head{}, event.Timestamp{}, classify("head", err)
	}
	return Head{Position: position, EventHash: hash}, event.NewTimestamp(ts), nil
}

// eventRow is one row of innsegl.events. canonical is the event; every other
// column is a key or an index over those same bytes, carried here as typed
// values rather than dug back out of the record, so the insert cannot disagree
// with what was hashed.
type eventRow struct {
	position       int64
	eventID        string
	eventHash      string
	prevEventHash  string
	eventType      string
	source         string
	runID          string
	idempotencyKey string
	ts             time.Time
	canonical      []byte
}

// insertEvent writes the row.
func insertEvent(ctx context.Context, tx pgx.Tx, row eventRow) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO innsegl.events
		   (chain_position, event_id, event_hash, prev_event_hash,
		    event_type, source, run_id, idempotency_key, ts, canonical)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		row.position, row.eventID, row.eventHash, row.prevEventHash,
		row.eventType, row.source,
		nullable(row.runID), nullable(row.idempotencyKey),
		row.ts, row.canonical)
	if err != nil {
		return classify("append", err)
	}
	return nil
}

// nullable turns an absent member into SQL NULL, so that absent and empty stay
// distinct in the table as they are in the schema (doc 02 §1).
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// readByKey returns the event an idempotency_key already produced.
func readByKey(ctx context.Context, tx pgx.Tx, key string) (event.Fields, bool, error) {
	var canonical []byte
	err := tx.QueryRow(ctx,
		`SELECT canonical FROM innsegl.events WHERE idempotency_key = $1`, key).Scan(&canonical)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, classify("append", err)
	}
	record, err := decode(canonical)
	if err != nil {
		return nil, false, err
	}
	return record, true, nil
}

// sameRequest reports whether a stored event is the one this append is a
// replay of: identical on every member the caller supplies.
//
// The comparison is over canonical bytes rather than the maps, so that a
// caller passing int and a stored int64 are the same request — the canonical
// form is the definition of sameness everywhere else in this system, and a
// second definition here is a second thing to disagree with it.
func sameRequest(stored, staged event.Fields) error {
	subset := stored.Clone()
	for _, name := range slicesConcat(ledgerAssignedMembers, ledgerAssignedByStore) {
		delete(subset, name)
	}
	delete(subset, event.FieldTS)

	have, err := event.Canonicalize(subset)
	if err != nil {
		return fmt.Errorf("canonicalize the stored event: %w", err)
	}
	want, err := event.Canonicalize(staged)
	if err != nil {
		return fmt.Errorf("canonicalize the replayed event: %w", err)
	}
	if string(have) != string(want) {
		return fmt.Errorf("%w: stored %s, replayed %s", ErrIdempotencyKeyConflict, have, want)
	}
	return nil
}

// decode turns stored canonical bytes back into an event.
func decode(canonical []byte) (event.Fields, error) {
	record, err := event.ParseFields(canonical)
	if err != nil {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "read", Retryable: false,
			Err: fmt.Errorf("stored event is not readable: %w", err),
		}
	}
	return record, nil
}

// Head returns the tip of the chain. The zero Head means an empty chain, whose
// next event is position 1 carrying the genesis constant.
func (s *Store) Head(ctx context.Context) (Head, error) {
	var (
		position int64
		hash     string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT chain_position, event_hash FROM innsegl.events
		  ORDER BY chain_position DESC LIMIT 1`).Scan(&position, &hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Head{}, nil
	case err != nil:
		return Head{}, classify("head", err)
	}
	return Head{Position: position, EventHash: hash}, nil
}

// Count returns how many events the chain holds.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM innsegl.events`).Scan(&n); err != nil {
		return 0, classify("count", err)
	}
	return n, nil
}

// Events returns the events at positions from..to inclusive, in position
// order, exactly as they were written.
func (s *Store) Events(ctx context.Context, from, to int64) ([]event.Fields, error) {
	if from < 1 || to < from {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "events", Retryable: false,
			Err: fmt.Errorf("range %d..%d is not a 1-based ascending range", from, to),
		}
	}

	rows, err := s.pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE chain_position BETWEEN $1 AND $2
		  ORDER BY chain_position`, from, to)
	if err != nil {
		return nil, classify("events", err)
	}
	defer rows.Close()

	out := make([]event.Fields, 0, min(to-from+1, 1024))
	for rows.Next() {
		var canonical []byte
		if err := rows.Scan(&canonical); err != nil {
			return nil, classify("events", err)
		}
		record, err := decode(canonical)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("events", err)
	}
	return out, nil
}

// EventAt returns the event at one chain position.
func (s *Store) EventAt(ctx context.Context, position int64) (event.Fields, error) {
	records, err := s.Events(ctx, position, position)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "event", Retryable: false,
			Err: fmt.Errorf("no event at chain_position %d", position),
		}
	}
	return records[0], nil
}

// EventByIdempotencyKey returns the event a key produced, if any. It is the
// read half of LED-008: a caller that wants to know whether its request was
// already recorded asks, rather than appending to find out.
func (s *Store) EventByIdempotencyKey(ctx context.Context, key string) (event.Fields, bool, error) {
	var canonical []byte
	err := s.pool.QueryRow(ctx,
		`SELECT canonical FROM innsegl.events WHERE idempotency_key = $1`, key).Scan(&canonical)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, classify("event", err)
	}
	record, err := decode(canonical)
	if err != nil {
		return nil, false, err
	}
	return record, true, nil
}

// safeToRetry reports whether an operation may be attempted again. It is true
// only when pgx says the statement never reached the server: a statement that
// may have committed is never replayed, whatever it returned.
func safeToRetry(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	return pgconn.SafeToRetry(err)
}

// classify maps a driver or database error onto IP §5's error classes.
//
// The default is LEDGER_UNAVAILABLE and retryable: an unrecognised failure
// talking to the ledger is a ledger the caller could not reach, and I3 wants
// the operation to fail closed rather than proceed unrecorded.
func classify(op string, err error) error {
	if err == nil {
		return nil
	}
	var already *StoreError
	if errors.As(err, &already) {
		return err
	}

	unavailable := func(retryable bool) error {
		return &StoreError{Class: ClassLedgerUnavailable, Op: op, Retryable: retryable, Err: err}
	}
	invariant := func() error {
		return &StoreError{Class: ClassInvariantViolation, Op: op, Retryable: false, Err: err}
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == AppendOnlySQLState, pgErr.Code == ChainLinkSQLState:
			// The database refused to break the ledger. That is never a
			// transport problem and never worth retrying.
			return invariant()
		case strings.HasPrefix(pgErr.Code, "23"), // integrity constraint violation
			strings.HasPrefix(pgErr.Code, "22"), // data exception
			strings.HasPrefix(pgErr.Code, "42"): // syntax error or access rule violation
			return invariant()
		case strings.HasPrefix(pgErr.Code, "40"), // transaction rollback, serialization failure
			strings.HasPrefix(pgErr.Code, "53"), // insufficient resources
			strings.HasPrefix(pgErr.Code, "57"), // operator intervention, shutdown
			strings.HasPrefix(pgErr.Code, "58"), // system error
			strings.HasPrefix(pgErr.Code, "08"): // connection exception
			return unavailable(true)
		default:
			return unavailable(false)
		}
	}
	return unavailable(true)
}
