// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
)

// The query surface, and why every clause of it is in SQL.
//
// FD §7: "server-side pagination, filtering, and search only — never
// ship-the-table-to-the-client", and FD §3.2 wants the runs table responsive
// "at millions of rows". A handler that SELECTs and filters in Go satisfies
// every test written against a fixture of twenty rows and none of the ones
// that matter. So the filters, the search, the ordering, the page bound and
// the total are all expressions in the statements below, and API-003 measures
// the row count the SERVER returned rather than the row count the handler
// passed on.
//
// # The run index is derived, not stored
//
// A run's agent type, task and repositories live inside the canonical bytes of
// its events and nowhere else: innsegl.events indexes chain_position, event_id,
// the two hashes, event_type, source, run_id, idempotency_key and ts, and
// everything the runs table shows is read out of `canonical` with
// convert_from(...)::jsonb.
//
// That is correct and it is not fast. A filter on agent_type is a sequential
// scan with a JSON parse per row, and no expression index exists for it.
// MEASURED, NOT ASSUMED: the fixtures here are two dozen runs, so nothing in
// this package demonstrates the scale posture FD §3.2 asks for. Closing that
// gap needs either expression indexes or a materialised run index, and both
// are migrations — `migrations/` is not this issue's to change, so the need is
// reported rather than half-met.
//
// # No verdict is ever read out of this database
//
// Nothing here returns a verification result. IP §6.11 and FD P2 forbid a
// database-only answer, and the surest way not to give one is to have no code
// that could. Verification lives in proof.go, it runs live against Fulcio and
// Rekor through internal/verify, and it never consults these tables.

// Run status, as FD §4.2 spells it. Expired is styled distinctly from retired
// because it means an agent died unretired, which is a different fact.
const (
	StatusActive  = "active"
	StatusRetired = "retired"
	StatusExpired = "expired"
)

// MaxPageSize is the largest page the server will serve, whatever is asked
// for. FD §7's "never ship the table" is a bound the server keeps, not a
// request the client is trusted to make politely.
const MaxPageSize = 200

// DefaultPageSize is the page a request that names none gets.
const DefaultPageSize = 50

// Errors a caller can act on.
var (
	// ErrBadRequest is a query this API cannot make sense of.
	ErrBadRequest = errors.New("api: malformed query")
	// ErrNotFound is a run, commit or repository this ledger does not hold.
	ErrNotFound = errors.New("api: not found")
)

// RunFilter is the runs table's query. Every field is applied in SQL.
type RunFilter struct {
	Repo      string
	AgentType string
	Status    string
	Search    string
	From, To  time.Time
	Cursor    string
	Limit     int
}

// RunSummary is one row of the runs table.
type RunSummary struct {
	RunID         string    `json:"run_id"`
	SPIFFEID      string    `json:"spiffe_id"`
	AgentType     string    `json:"agent_type"`
	TaskRef       string    `json:"task_ref"`
	Status        string    `json:"status"`
	Repos         []string  `json:"repos"`
	Commits       int       `json:"commits"`
	ChainPosition int64     `json:"chain_position"`
	RegisteredAt  time.Time `json:"registered_at"`
	LastEventAt   time.Time `json:"last_event_at"`
}

// RunPage is one page of the runs table.
type RunPage struct {
	Runs  []RunSummary `json:"runs"`
	Total int          `json:"total"`
	Limit int          `json:"limit"`
	// NextCursor is empty at the end of the set. It is the chain position of
	// the last row served: a keyset cursor rather than an offset, so a page
	// stays correct while events are appended underneath it.
	NextCursor string `json:"next_cursor,omitempty"`
	// DataAsOf is FD §4.4's marker. Every response carries one so a view can
	// render "data as of" without a second round trip.
	DataAsOf time.Time `json:"data_as_of"`
}

// TimelineEvent is one ledger event as FD §3.3's run detail shows it.
type TimelineEvent struct {
	ChainPosition int64     `json:"chain_position"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	Source        string    `json:"source"`
	TS            time.Time `json:"ts"`
	EventHash     string    `json:"event_hash"`
	PrevEventHash string    `json:"prev_event_hash"`
	// Canonical is the event's RFC 8785 bytes exactly as they are stored. It
	// is here for FD P1: a reader who removes the `event_hash` member and
	// re-canonicalizes what is left reproduces `event_hash` (doc 02 §4.1-4.3),
	// so the timeline carries its own evidence rather than a rendering of it.
	Canonical json.RawMessage `json:"canonical"`
}

// RunDetail is one run and its ordered event chain.
type RunDetail struct {
	RunSummary
	Timeline []TimelineEvent `json:"timeline"`
	DataAsOf time.Time       `json:"data_as_of"`
}

// AnchorHeartbeat is FD §3.1's tamper-evidence pulse: the newest sealed
// segment and whether Rekor has it yet.
type AnchorHeartbeat struct {
	Present       bool      `json:"present"`
	SegmentID     string    `json:"segment_id,omitempty"`
	FirstPosition int64     `json:"first_position,omitempty"`
	LastPosition  int64     `json:"last_position,omitempty"`
	SealedAt      time.Time `json:"sealed_at,omitempty"`
	Anchored      bool      `json:"anchored"`
	RekorLogIndex int64     `json:"rekor_log_index,omitempty"`
}

// Overview is FD §3.1's landing view.
//
// There is deliberately NO verification pass rate here. FD §3.1 asks for one;
// a rate computed from these tables would be a database-only verdict, which IP
// §6.11 and FD P2 forbid in terms, and FD anti-pattern 10 warns about metrics
// chosen because they are easy. A live pass rate has to come from running the
// three checks, which is proof.go's job and costs a Fulcio and a Rekor round
// trip per commit. The tension is reported to the humans rather than resolved
// by inventing a number here.
type Overview struct {
	ActiveRuns      int             `json:"active_runs"`
	RetiredRuns     int             `json:"retired_runs"`
	ExpiredRuns     int             `json:"expired_runs"`
	CommitsRecorded int             `json:"commits_recorded"`
	OpenAlerts      int             `json:"open_alerts"`
	Anchor          AnchorHeartbeat `json:"anchor"`
	DataAsOf        time.Time       `json:"data_as_of"`
}

// runIndexCTE derives the runs table from the event chain. It is shared by
// ListRuns and Run so that a run reads the same either way — a detail view
// that disagreed with the row that linked to it would be a bug nobody sees.
const runIndexCTE = `
WITH scoped AS (
    SELECT chain_position, run_id, ts, event_type,
           convert_from(canonical, 'UTF8')::jsonb AS body
      FROM innsegl.events
     WHERE run_id IS NOT NULL
), registered AS (
    SELECT run_id, chain_position, ts AS registered_at,
           body->>'spiffe_id'  AS spiffe_id,
           body->>'agent_type' AS agent_type,
           body->>'task_ref'   AS task_ref
      FROM scoped
     WHERE event_type = 'run_registered'
), rollup AS (
    SELECT run_id,
           max(ts) AS last_event_at,
           count(*) FILTER (WHERE event_type = 'commit_recorded')::int AS commits,
           bool_or(event_type = 'run_retired') AS retired,
           bool_or(event_type = 'run_expired') AS expired,
           coalesce(array_agg(DISTINCT body->>'repo')
                    FILTER (WHERE body->>'repo' IS NOT NULL), '{}'::text[]) AS repos
      FROM scoped
     GROUP BY run_id
), runs AS (
    SELECT r.run_id, r.chain_position, r.registered_at, r.spiffe_id,
           r.agent_type, r.task_ref,
           g.last_event_at, g.commits, g.repos,
           CASE WHEN g.retired THEN 'retired'
                WHEN g.expired THEN 'expired'
                ELSE 'active' END AS status
      FROM registered r JOIN rollup g USING (run_id)
)`

const listRunsSQL = runIndexCTE + `, filtered AS (
    SELECT runs.*, count(*) OVER ()::int AS total
      FROM runs
     WHERE ($1::text IS NULL OR agent_type = $1)
       AND ($2::text IS NULL OR $2 = ANY(repos))
       AND ($3::text IS NULL OR status = $3)
       AND ($4::timestamptz IS NULL OR registered_at >= $4)
       AND ($5::timestamptz IS NULL OR registered_at <= $5)
       AND ($6::text IS NULL
            OR run_id    ILIKE $6 ESCAPE '\'
            OR spiffe_id ILIKE $6 ESCAPE '\'
            OR task_ref  ILIKE $6 ESCAPE '\')
)
SELECT run_id, spiffe_id, agent_type, task_ref, status, repos, commits,
       chain_position, registered_at, last_event_at, total
  FROM filtered
 WHERE ($7::bigint IS NULL OR chain_position < $7)
 ORDER BY chain_position DESC
 LIMIT $8`

// ListRuns serves one page of FD §3.2's runs table.
func (s *Store) ListRuns(ctx context.Context, f RunFilter) (RunPage, error) {
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}
	if f.Status != "" && f.Status != StatusActive &&
		f.Status != StatusRetired && f.Status != StatusExpired {
		return RunPage{}, fmt.Errorf("%w: status %q is not one of %s, %s, %s",
			ErrBadRequest, f.Status, StatusActive, StatusRetired, StatusExpired)
	}
	var cursor *int64
	if f.Cursor != "" {
		n, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil || n < 0 {
			return RunPage{}, fmt.Errorf("%w: %q is not a cursor this API issued", ErrBadRequest, f.Cursor)
		}
		cursor = &n
	}

	rows, err := s.pool.Query(ctx, listRunsSQL,
		nullable(f.AgentType), nullable(f.Repo), nullable(f.Status),
		nullableTime(f.From), nullableTime(f.To), likePattern(f.Search),
		cursor, limit)
	if err != nil {
		return RunPage{}, fmt.Errorf("api: listing runs: %w", err)
	}
	defer rows.Close()

	page := RunPage{Limit: limit, DataAsOf: time.Now().UTC(), Runs: []RunSummary{}}
	for rows.Next() {
		var r RunSummary
		if err := rows.Scan(&r.RunID, &r.SPIFFEID, &r.AgentType, &r.TaskRef,
			&r.Status, &r.Repos, &r.Commits, &r.ChainPosition,
			&r.RegisteredAt, &r.LastEventAt, &page.Total); err != nil {
			return RunPage{}, fmt.Errorf("api: reading a run: %w", err)
		}
		r.RegisteredAt = r.RegisteredAt.UTC()
		r.LastEventAt = r.LastEventAt.UTC()
		page.Runs = append(page.Runs, r)
	}
	if err := rows.Err(); err != nil {
		return RunPage{}, fmt.Errorf("api: listing runs: %w", err)
	}
	if len(page.Runs) == limit && len(page.Runs) > 0 {
		page.NextCursor = strconv.FormatInt(page.Runs[len(page.Runs)-1].ChainPosition, 10)
	}
	return page, nil
}

const runSQL = runIndexCTE + `
SELECT run_id, spiffe_id, agent_type, task_ref, status, repos, commits,
       chain_position, registered_at, last_event_at
  FROM runs WHERE run_id = $1`

const timelineSQL = `
SELECT chain_position, event_id, event_type, source, ts,
       event_hash, prev_event_hash, convert_from(canonical, 'UTF8')
  FROM innsegl.events
 WHERE run_id = $1
 ORDER BY chain_position`

// Run serves FD §3.3's run detail: the run, and its ordered event chain.
//
// The timeline is unpaged, deliberately. Doc 05 §4 sizes a run at ~20 events
// and LED-011 bounds each at 1 KB, and a page of a run's own history could cut
// off the `run_retired` that says what the run's status is.
func (s *Store) Run(ctx context.Context, runID string) (RunDetail, error) {
	if runID == "" {
		return RunDetail{}, fmt.Errorf("%w: an empty run id names no run", ErrBadRequest)
	}
	var d RunDetail
	err := s.pool.QueryRow(ctx, runSQL, runID).Scan(&d.RunID, &d.SPIFFEID,
		&d.AgentType, &d.TaskRef, &d.Status, &d.Repos, &d.Commits,
		&d.ChainPosition, &d.RegisteredAt, &d.LastEventAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunDetail{}, fmt.Errorf("%w: no run %q in this ledger", ErrNotFound, runID)
	}
	if err != nil {
		return RunDetail{}, fmt.Errorf("api: reading run %s: %w", runID, err)
	}
	d.RegisteredAt = d.RegisteredAt.UTC()
	d.LastEventAt = d.LastEventAt.UTC()
	d.DataAsOf = time.Now().UTC()

	rows, err := s.pool.Query(ctx, timelineSQL, runID)
	if err != nil {
		return RunDetail{}, fmt.Errorf("api: reading the timeline of %s: %w", runID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var e TimelineEvent
		var canonical string
		if err := rows.Scan(&e.ChainPosition, &e.EventID, &e.EventType, &e.Source,
			&e.TS, &e.EventHash, &e.PrevEventHash, &canonical); err != nil {
			return RunDetail{}, fmt.Errorf("api: reading a timeline event: %w", err)
		}
		e.TS = e.TS.UTC()
		e.Canonical = json.RawMessage(canonical)
		d.Timeline = append(d.Timeline, e)
	}
	if err := rows.Err(); err != nil {
		return RunDetail{}, fmt.Errorf("api: reading the timeline of %s: %w", runID, err)
	}
	return d, nil
}

const overviewSQL = `
WITH scoped AS (
    SELECT run_id, event_type FROM innsegl.events WHERE run_id IS NOT NULL
), rollup AS (
    SELECT run_id,
           bool_or(event_type = 'run_registered') AS registered,
           bool_or(event_type = 'run_retired')    AS retired,
           bool_or(event_type = 'run_expired')    AS expired
      FROM scoped GROUP BY run_id
)
SELECT
    count(*) FILTER (WHERE registered AND NOT retired AND NOT expired)::int,
    count(*) FILTER (WHERE retired)::int,
    count(*) FILTER (WHERE expired AND NOT retired)::int,
    (SELECT count(*) FROM innsegl.events
      WHERE event_type = 'commit_recorded')::int,
    (SELECT count(*) FROM innsegl.events
      WHERE event_type IN ('unattributed_signature_detected', 'ledger_drift_detected'))::int
  FROM rollup`

const anchorSQL = `
SELECT ts, convert_from(canonical, 'UTF8')::jsonb
  FROM innsegl.events
 WHERE event_type = 'segment_sealed'
 ORDER BY chain_position DESC
 LIMIT 1`

// Overview serves FD §3.1's landing view.
func (s *Store) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	if err := s.pool.QueryRow(ctx, overviewSQL).Scan(&o.ActiveRuns, &o.RetiredRuns,
		&o.ExpiredRuns, &o.CommitsRecorded, &o.OpenAlerts); err != nil {
		return Overview{}, fmt.Errorf("api: reading the overview: %w", err)
	}
	o.DataAsOf = time.Now().UTC()

	var sealedAt time.Time
	var body map[string]any
	err := s.pool.QueryRow(ctx, anchorSQL).Scan(&sealedAt, &body)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No segment has been sealed yet. Absent is not "anchored 0 minutes
		// ago": FD §3.1 makes the heartbeat the system's public pulse, and a
		// zero rendered as a time would be the quietest possible lie.
		return o, nil
	case err != nil:
		return Overview{}, fmt.Errorf("api: reading the anchoring heartbeat: %w", err)
	}
	o.Anchor = AnchorHeartbeat{
		Present:       true,
		SealedAt:      sealedAt.UTC(),
		SegmentID:     stringOf(body[event.FieldSegmentID]),
		FirstPosition: int64Of(body[event.FieldFirstPosition]),
		LastPosition:  int64Of(body[event.FieldLastPosition]),
		RekorLogIndex: int64Of(body[event.FieldAnchorRekorLogIndex]),
	}
	_, o.Anchor.Anchored = body[event.FieldAnchorRekorEntryUUID]
	return o, nil
}

// nullable turns an empty filter value into an SQL NULL, which every predicate
// above reads as "not filtered".
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// likePattern wraps a search term for ILIKE, escaping the two wildcards so a
// user searching for "run_1" does not match "run-1". The escape character is a
// backslash, named by the ESCAPE clause in the statement.
func likePattern(search string) *string {
	if search == "" {
		return nil
	}
	escaped := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(search)
	pattern := "%" + escaped + "%"
	return &pattern
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// int64Of reads a JSON number out of a decoded event body. Postgres hands
// jsonb integers back through encoding/json, so they arrive as float64; the
// values here are chain positions and log indices, well inside float64's exact
// integer range.
func int64Of(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	default:
		return 0
	}
}
