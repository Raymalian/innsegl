// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
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

// The four lifecycle states (#256), and the one place they are decided (#258).
//
// "Active / retired / expired" cannot express the difference between a run
// that is QUIET and a run that is OVER. Nothing in this system can observe an
// agent ending: one waiting on a provider usage limit, running a long build,
// or on a sleeping machine is silent and alive, and the reaper withdrawing a
// credential is the system acting on silence, not the agent stopping. Three
// words forced those two into one, and the one they landed in read as death.
//
// The rule that derives the four is NOT WRITTEN HERE. It is internal/ledger's
// RunStateOf / RunStateSQL, and it is written there because this package was
// not the only component deciding: the SPIRE reconciler decided too, on its
// own terms, and reported a run this API showed as active as an entry that
// should have been deleted (RM-155, #258). What this file keeps is the
// spelling the wire uses; what it consumes is the rule.
//
// Each of the four is DERIVED FROM RECORDED FACTS AND THEIR ORDER. None is
// stored: there is no state column and no state table, and there must not be
// one — a stored state is a fact nobody appended (doc 08, IP §6.1).
//
// `expired` is gone from this vocabulary and stays gone. It survives as the
// name of the `run_expired` EVENT, which is a protected string (doc 02 §3) and
// is untouched — the event is what these states are derived from.
const (
	StatusActive    = ledger.RunActive
	StatusLapsed    = ledger.RunLapsed
	StatusAbandoned = ledger.RunAbandoned
	StatusRetired   = ledger.RunRetired
)

// RunStatuses is the closed set, in lifecycle order. The value reaches SQL, so
// it is checked against this at the edge rather than carried as a string.
var RunStatuses = ledger.RunStates

// DefaultRestoreHorizon is how long after a withdrawal a run may still be
// restored when the deployment names no other bound.
//
// The number reaches the answer as evidence — see RunPage.RestoreHorizonSeconds
// — so a reader can check the Lapsed/Abandoned claim rather than take it. It is
// internal/ledger's constant, not a second copy of it: the horizon this API
// divides Lapsed from Abandoned with is the horizon get_credential actually
// refuses a restore at, and two numbers that were meant to be one is a
// dashboard that says "restorable" about a run the MCP will turn away.
const DefaultRestoreHorizon = ledger.DefaultRestoreHorizon

// EnvRestoreHorizon is the environment variable the horizon is read from, and
// it is `innsegl serve`'s own — the same process configures both halves, so
// reading the same variable is what keeps them one number rather than two.
// Since #258 the SPIRE reconciler reads it as well, from the same function.
//
// READ RATHER THAN PASSED IN, and that is a gap stated rather than hidden:
// `cmd/innsegl` parses this variable into a flag and hands it to
// register_agent, and the query API's wiring has no field to carry it. Giving
// ServerConfig one is the right shape and belongs to whoever owns that wiring;
// until then a deployment that sets the variable gets one horizon everywhere,
// and a deployment that sets neither gets the same default everywhere.
const EnvRestoreHorizon = ledger.EnvRestoreHorizon

// restoreHorizonFromEnv reads EnvRestoreHorizon, falling back to the default.
func restoreHorizonFromEnv() time.Duration { return ledger.RestoreHorizonFromEnv() }

// abandonedBefore is the instant a withdrawal has to predate for its run to be
// past the horizon, or nil when the deployment set no horizon.
//
// Computed once per request and passed into SQL rather than expressed there as
// `now() - interval`, so every row of one answer is judged against ONE instant.
// A page whose first row was measured against a different "now" than its last
// is a page that can show the same run twice in two states.
func abandonedBefore(horizon time.Duration, now time.Time) *time.Time {
	return ledger.AbandonedBefore(horizon, now)
}

// restorableUntil is when a withdrawn run stops being restorable, or nil when
// it was never withdrawn or the deployment set no horizon.
func restorableUntil(withdrawn *time.Time, horizon time.Duration) *time.Time {
	if withdrawn == nil || horizon <= 0 {
		return nil
	}
	until := withdrawn.Add(horizon).UTC()
	return &until
}

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
	// Order is "asc" or "desc"; empty means newest-first.
	Order    string
	Search   string
	From, To time.Time
	Cursor   string
	Limit    int
}

// RunSummary is one row of the runs table.
//
// The five members after LastEventAt are the EVIDENCE for Status (#256). A
// page that states a conclusion must be able to state what it concluded from,
// and every one of these is a recorded instant or a recorded id — nothing here
// is an inference about an agent.
//
// They are pointers, not zero values, because an absent fact must be ABSENT.
// Go's `omitempty` does not omit a struct, so a `time.Time` field would
// marshal as "0001-01-01T00:00:00Z" on a run that was never withdrawn — a
// timestamp a reader has every right to read as a timestamp. The same trap is
// documented on AnchorHeartbeat.SealedAt and Alert.ResolvedAt; this is the
// third place it would have been sprung.
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

	// LastActivityAt is the newest event on this run that the reaper did NOT
	// write. It is the instant "nothing heard since" names, and it is the only
	// thing this system knows about whether a run is still working: an event
	// the agent's own tooling appended. Absent for a run whose entire record
	// is the reaper's.
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"`
	// WithdrawnAt is the newest `run_expired` — the instant the reaper last
	// withdrew this run's standing authorisation. Absent when it never did.
	//
	// NEWEST, not earliest. A run can lapse, be restored, work, and lapse
	// again, and the horizon is measured from the withdrawal that stands.
	WithdrawnAt *time.Time `json:"withdrawn_at,omitempty"`
	// RestorableUntil is WithdrawnAt plus the horizon: the instant after which
	// this run's identity can no longer be restored by resuming it. Absent
	// when the run was never withdrawn, or when the deployment set no horizon
	// — in which case a withdrawn run stays restorable until it is retired.
	RestorableUntil *time.Time `json:"restorable_until,omitempty"`
	// ParentRunID is the run that started this one, as `run_registered`
	// recorded it (doc 02 §5, ADR-0045). Absent on a root run, and absent on
	// every run that predates schema 2 — nothing here infers one.
	ParentRunID string `json:"parent_run_id,omitempty"`
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
	// RestoreHorizonSeconds is the horizon every Status on this page was
	// computed with, in seconds; 0 means the deployment set none.
	//
	// It is on the PAGE rather than on the row because it is one number for
	// the whole answer, and it is here at all because Lapsed and Abandoned
	// differ by nothing else. A reader told "abandoned" and not told the
	// horizon has been handed a verdict; told both, they can check it.
	RestoreHorizonSeconds int64 `json:"restore_horizon_seconds"`
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
	// RestoreHorizonSeconds is RunPage.RestoreHorizonSeconds, on the one run:
	// the horizon this run's Status was computed with. The run page states a
	// conclusion in a word, so it carries the number behind it.
	RestoreHorizonSeconds int64     `json:"restore_horizon_seconds"`
	DataAsOf              time.Time `json:"data_as_of"`
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
	ActiveRuns int `json:"active_runs"`
	// LapsedRuns and AbandonedRuns are #256's two new counts, and NEITHER is
	// counted in ActiveRuns. `expired_runs` is gone with the word: it named
	// one bucket for two states that mean different things to an operator —
	// one is waiting to be resumed, the other cannot be.
	LapsedRuns      int             `json:"lapsed_runs"`
	AbandonedRuns   int             `json:"abandoned_runs"`
	RetiredRuns     int             `json:"retired_runs"`
	CommitsRecorded int             `json:"commits_recorded"`
	OpenAlerts      int             `json:"open_alerts"`
	Anchor          AnchorHeartbeat `json:"anchor"`
	// RestoreHorizonSeconds is the horizon the two counts above were split
	// with; 0 means the deployment set none, and nothing is ever abandoned.
	RestoreHorizonSeconds int64     `json:"restore_horizon_seconds"`
	DataAsOf              time.Time `json:"data_as_of"`
}

// runIndexCTE derives the runs table from the event chain. It is shared by
// ListRuns and Run so that a run reads the same either way — a detail view
// that disagreed with the row that linked to it would be a bug nobody sees.
//
// # $1 is the abandonment cutoff, and it is a parameter for a reason
//
// Every statement built on this CTE takes the cutoff as its FIRST parameter:
// the instant a withdrawal must predate for its run to have passed the restore
// horizon, or NULL when the deployment set none. It is computed once in Go
// (abandonedBefore) rather than written here as `now() - interval` so that
// every row of one answer is judged against one instant — and so that the
// horizon is a value a test can hold still instead of a clock it must race.
const runIndexCTE = `
WITH scoped AS (
    SELECT chain_position, run_id, ts, event_type, source,
           convert_from(canonical, 'UTF8')::jsonb AS body
      FROM innsegl.events
     WHERE run_id IS NOT NULL
), registered AS (
    SELECT run_id, chain_position, ts AS registered_at,
           body->>'spiffe_id'     AS spiffe_id,
           body->>'agent_type'    AS agent_type,
           body->>'task_ref'      AS task_ref,
           -- doc 02 §5's optional member (ADR-0045). NULL on a root run and on
           -- every run written before schema 2; nothing here invents one.
           body->>'parent_run_id' AS parent_run_id
      FROM scoped
     WHERE event_type = 'run_registered'
), rollup AS (
    SELECT run_id,
           max(ts) AS last_event_at,
           count(*) FILTER (WHERE event_type = 'commit_recorded')::int AS commits,
           bool_or(event_type = 'run_retired') AS retired,
           -- WITHDRAWAL IS NOT AN ENDING, because a quiet run is not an ended
           -- one. The reaper withdraws a credential from a run that went quiet;
           -- a run that speaks again has answered the only question the reaper
           -- was asking, and get_credential restores its entry. Reading
           -- withdrawal as terminal made the dashboard call a working agent
           -- dead: measured 2026-09-18, two runs withdrawn on 2026-09-16
           -- carried 656 and 876 tool calls afterwards, the newest landing in
           -- the same minute the operator was told nothing was active.
           --
           -- This infers nothing about liveness (E7). It is two recorded facts
           -- and their order: a withdrawal at one timestamp, an event the reaper
           -- did not write at a later one. The run_expired event stays in the
           -- timeline either way; what changes is whether the newest fact or the
           -- oldest names the state.
           --
           -- NEWEST withdrawal, not earliest: a run can lapse, be restored,
           -- work, and lapse again, and the horizon is measured from the
           -- withdrawal that stands.
           max(ts) FILTER (WHERE event_type = 'run_expired') AS withdrawn_at,
           max(ts) FILTER (WHERE source IS DISTINCT FROM 'reaper') AS last_activity_at,
           coalesce(array_agg(DISTINCT body->>'repo')
                    FILTER (WHERE body->>'repo' IS NOT NULL), '{}'::text[]) AS repos
      FROM scoped
     GROUP BY run_id
), cutoff AS (
    -- $1, named. internal/ledger's RunStateSQL reads four columns by name and
    -- pastes no table aliases, so the abandonment cutoff arrives as a one-row
    -- CTE cross-joined in rather than as a parameter written into the rule.
    SELECT $1::timestamptz AS abandoned_before
), runs AS (
    SELECT r.run_id, r.chain_position, r.registered_at, r.spiffe_id,
           r.agent_type, r.task_ref, r.parent_run_id,
           g.last_event_at, g.commits, g.repos,
           g.withdrawn_at, g.last_activity_at,
           -- THE RULE, from the one place it is written: internal/ledger's
           -- RunStateSQL, which is internal/ledger's RunStateOf as a SQL
           -- expression. It is here rather than inline because the SPIRE
           -- reconciler decides the same question in Go, and the two used to
           -- disagree — a run this query showed as active was reported there as
           -- an entry that should have been deleted (RM-155, #258).
           --
           -- It is an expression rather than a value computed in Go per row
           -- because FD §7 requires the filter, the count and the page bound to
           -- be the SERVER's: a status the handler computes cannot be a WHERE
           -- clause.
           ` + ledger.RunStateSQL + ` AS status
      FROM registered r JOIN rollup g USING (run_id) CROSS JOIN cutoff
)`

const listRunsSQL = runIndexCTE + `, filtered AS (
    SELECT runs.*, count(*) OVER ()::int AS total
      FROM runs
     WHERE ($2::text IS NULL OR agent_type = $2)
       AND ($3::text IS NULL OR $3 = ANY(repos))
       AND ($4::text IS NULL OR status = $4)
       AND ($5::timestamptz IS NULL OR registered_at >= $5)
       AND ($6::timestamptz IS NULL OR registered_at <= $6)
       AND ($7::text IS NULL
            OR run_id    ILIKE $7 ESCAPE '\'
            OR spiffe_id ILIKE $7 ESCAPE '\'
            OR task_ref  ILIKE $7 ESCAPE '\')
)
SELECT run_id, spiffe_id, agent_type, task_ref, status, repos, commits,
       chain_position, registered_at, last_event_at,
       last_activity_at, withdrawn_at, parent_run_id, total
  FROM filtered
 WHERE ($8::bigint IS NULL OR chain_position < $8)
 ORDER BY chain_position DESC
 LIMIT $9`

// listRunsSQLAsc is listRunsSQL's ascending twin.
//
// TWO COMPLETE STATEMENTS RATHER THAN ONE WITH THE DIRECTION PASTED IN, and
// the reason is the cursor rather than injection. Paging here is keyset:
// `chain_position < $8` is correct for DESC and WRONG for ASC. Interpolating
// only the ORDER BY would leave the comparison behind, and the failure is
// silent -- page one is right, page two is empty or repeats, and nothing
// raises an error. Keeping both statements whole means the two halves cannot
// drift apart, and API-021 reads them to check.
var listRunsSQLAsc = strings.Replace(
	strings.Replace(listRunsSQL, "chain_position < $8", "chain_position > $8", 1),
	"ORDER BY chain_position DESC", "ORDER BY chain_position ASC", 1)

// The two directions the runs table sorts in. A closed set: the value reaches
// SQL, so it is checked at the edge rather than carried as a string.
const (
	OrderDesc = "desc"
	OrderAsc  = "asc"
)

// runsOrder resolves the requested direction. Empty means newest-first, which
// is what the table did before this existed and what an unset parameter must
// keep doing.
func runsOrder(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", OrderDesc:
		return OrderDesc, nil
	case OrderAsc:
		return OrderAsc, nil
	default:
		return "", fmt.Errorf("order %q is neither %q nor %q", s, OrderAsc, OrderDesc)
	}
}

// runsQuery returns the statement for one direction.
func runsQuery(order string) string {
	if order == OrderAsc {
		return listRunsSQLAsc
	}
	return listRunsSQL
}

// ListRuns serves one page of FD §3.2's runs table.
func (s *Store) ListRuns(ctx context.Context, f RunFilter) (RunPage, error) {
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}
	if f.Status != "" && !slices.Contains(RunStatuses, f.Status) {
		return RunPage{}, fmt.Errorf("%w: status %q is not one of %s",
			ErrBadRequest, f.Status, strings.Join(RunStatuses, ", "))
	}
	var cursor *int64
	if f.Cursor != "" {
		n, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil || n < 0 {
			return RunPage{}, fmt.Errorf("%w: %q is not a cursor this API issued", ErrBadRequest, f.Cursor)
		}
		cursor = &n
	}

	order, err := runsOrder(f.Order)
	if err != nil {
		return RunPage{}, fmt.Errorf("%w: %w", ErrBadRequest, err)
	}

	// One clock for the whole answer. See abandonedBefore.
	now := time.Now().UTC()
	horizon := s.RestoreHorizon()

	rows, err := s.pool.Query(ctx, runsQuery(order),
		abandonedBefore(horizon, now),
		nullable(f.AgentType), nullable(f.Repo), nullable(f.Status),
		nullableTime(f.From), nullableTime(f.To), likePattern(f.Search),
		cursor, limit)
	if err != nil {
		return RunPage{}, fmt.Errorf("api: listing runs: %w", err)
	}
	defer rows.Close()

	page := RunPage{
		Limit:                 limit,
		RestoreHorizonSeconds: int64(horizon.Seconds()),
		DataAsOf:              now,
		Runs:                  []RunSummary{},
	}
	for rows.Next() {
		var r RunSummary
		var parent *string
		if err := rows.Scan(&r.RunID, &r.SPIFFEID, &r.AgentType, &r.TaskRef,
			&r.Status, &r.Repos, &r.Commits, &r.ChainPosition,
			&r.RegisteredAt, &r.LastEventAt,
			&r.LastActivityAt, &r.WithdrawnAt, &parent, &page.Total); err != nil {
			return RunPage{}, fmt.Errorf("api: reading a run: %w", err)
		}
		r.RegisteredAt = r.RegisteredAt.UTC()
		r.LastEventAt = r.LastEventAt.UTC()
		normaliseRunEvidence(&r, parent, horizon)
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
       chain_position, registered_at, last_event_at,
       last_activity_at, withdrawn_at, parent_run_id
  FROM runs WHERE run_id = $2`

// normaliseRunEvidence puts the scanned evidence into UTC and derives the one
// member that is arithmetic rather than a recorded fact.
//
// RestorableUntil is DERIVED HERE and not selected: it is WithdrawnAt plus the
// horizon, and the horizon is a property of this process rather than of the
// chain. Computing it in Go keeps the SQL saying only what the ledger recorded.
func normaliseRunEvidence(r *RunSummary, parent *string, horizon time.Duration) {
	if r.LastActivityAt != nil {
		at := r.LastActivityAt.UTC()
		r.LastActivityAt = &at
	}
	if r.WithdrawnAt != nil {
		at := r.WithdrawnAt.UTC()
		r.WithdrawnAt = &at
	}
	r.RestorableUntil = restorableUntil(r.WithdrawnAt, horizon)
	if parent != nil {
		r.ParentRunID = *parent
	}
}

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
	now := time.Now().UTC()
	horizon := s.RestoreHorizon()

	var d RunDetail
	var parent *string
	err := s.pool.QueryRow(ctx, runSQL, abandonedBefore(horizon, now), runID).Scan(
		&d.RunID, &d.SPIFFEID, &d.AgentType, &d.TaskRef, &d.Status, &d.Repos,
		&d.Commits, &d.ChainPosition, &d.RegisteredAt, &d.LastEventAt,
		&d.LastActivityAt, &d.WithdrawnAt, &parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunDetail{}, fmt.Errorf("%w: no run %q in this ledger", ErrNotFound, runID)
	}
	if err != nil {
		return RunDetail{}, fmt.Errorf("api: reading run %s: %w", runID, err)
	}
	d.RegisteredAt = d.RegisteredAt.UTC()
	d.LastEventAt = d.LastEventAt.UTC()
	normaliseRunEvidence(&d.RunSummary, parent, horizon)
	d.RestoreHorizonSeconds = int64(horizon.Seconds())
	d.DataAsOf = now

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
    SELECT run_id, event_type, ts, source FROM innsegl.events WHERE run_id IS NOT NULL
), rollup AS (
    SELECT run_id,
           bool_or(event_type = 'run_registered') AS registered,
           bool_or(event_type = 'run_retired')    AS retired,
           max(ts) FILTER (WHERE event_type = 'run_expired') AS withdrawn_at,
           max(ts) FILTER (WHERE source IS DISTINCT FROM 'reaper') AS last_activity_at
      FROM scoped GROUP BY run_id
), cutoff AS (
    SELECT $1::timestamptz AS abandoned_before
), state AS (
    -- THE SAME RULE, LITERALLY THE SAME STRING, as runIndexCTE uses: the
    -- overview saying "0 active" over a table listing active runs was one of
    -- the ways three copies of this rule made themselves felt. There is one
    -- copy now and it is internal/ledger's.
    SELECT registered, ` + ledger.RunStateSQL + ` AS status
      FROM rollup CROSS JOIN cutoff
)
SELECT
    count(*) FILTER (WHERE registered AND status = '` + ledger.RunActive + `')::int,
    count(*) FILTER (WHERE status = '` + ledger.RunLapsed + `')::int,
    count(*) FILTER (WHERE status = '` + ledger.RunAbandoned + `')::int,
    count(*) FILTER (WHERE status = '` + ledger.RunRetired + `')::int,
    (SELECT count(*) FROM innsegl.events
      WHERE event_type = 'commit_recorded')::int,
    -- #167: "open" is derived, not stored — an alert event with no row in
    -- innsegl.alert_resolutions. The alert events themselves are untouched by
    -- this: a resolved alert stays in innsegl.events forever, it just stops
    -- being counted here.
    (SELECT count(*) FROM innsegl.events e
      WHERE e.event_type IN ('unattributed_signature_detected', 'ledger_drift_detected')
        AND NOT EXISTS (
            SELECT 1 FROM innsegl.alert_resolutions r WHERE r.event_id = e.event_id
        ))::int
  FROM state`

const anchorSQL = `
SELECT ts, convert_from(canonical, 'UTF8')::jsonb
  FROM innsegl.events
 WHERE event_type = 'segment_sealed'
 ORDER BY chain_position DESC
 LIMIT 1`

// Overview serves FD §3.1's landing view.
func (s *Store) Overview(ctx context.Context) (Overview, error) {
	now := time.Now().UTC()
	horizon := s.RestoreHorizon()

	var o Overview
	if err := s.pool.QueryRow(ctx, overviewSQL, abandonedBefore(horizon, now)).Scan(
		&o.ActiveRuns, &o.LapsedRuns, &o.AbandonedRuns, &o.RetiredRuns,
		&o.CommitsRecorded, &o.OpenAlerts); err != nil {
		return Overview{}, fmt.Errorf("api: reading the overview: %w", err)
	}
	o.RestoreHorizonSeconds = int64(horizon.Seconds())
	o.DataAsOf = now

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

// The alerts feed (RM-102, #167).
//
// `unattributed_signature_detected` and `ledger_drift_detected` are the two
// event types doc 02 §3 marks "Alert:". Before this, the only thing the query
// API said about them was OpenAlerts above — a count with no endpoint that
// lists the events behind it. #167: "reading them currently requires database
// access... An operator who must reach for psql to learn why their deployment
// is showing red has the posture backwards."
//
// Like the runs table, every identifying field is read out of `canonical`
// (convert_from(...)::jsonb) rather than duplicated into new storage — this
// package's own rule, stated once above the run index. `resolved` and its
// three fields are the one exception: they come from
// innsegl.alert_resolutions (migration 0003), a table #167's decision put
// outside innsegl.events on purpose. See ADR-0044.

// AlertFilter is the alerts feed's query. EventType is one of the two alert
// event_type values, or empty for both.
type AlertFilter struct {
	EventType string
	Cursor    string
	Limit     int
}

// Alert is one alert event, joined against its resolution if it has one.
//
// The type-specific fields are #167's own list: SubjectEventID, RunID and
// Reason for a ledger_drift_detected; CertificateIdentity, RekorEntryUUID and
// RekorLogIndex for an unattributed_signature_detected. Exactly one triple is
// populated per row — never both, never neither — because EventType is one of
// the two and nothing here guesses.
type Alert struct {
	ChainPosition int64     `json:"chain_position"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	TS            time.Time `json:"ts"`
	// RunID is doc 02 §2's envelope member, present on a drift alert whose
	// subject is a run's own record and absent on a system-scope alert — an
	// unattributed_signature_detected always omits it (doc 02 §3).
	RunID string `json:"run_id,omitempty"`

	// ledger_drift_detected only.
	SubjectEventID string `json:"subject_event_id,omitempty"`
	Reason         string `json:"reason,omitempty"`

	// unattributed_signature_detected only.
	CertificateIdentity string `json:"certificate_identity,omitempty"`
	RekorEntryUUID      string `json:"rekor_entry_uuid,omitempty"`
	RekorLogIndex       int64  `json:"rekor_log_index,omitempty"`

	// Resolved and the three fields below come from
	// innsegl.alert_resolutions, never from innsegl.events. Resolved is false
	// and the rest are zero when no resolution row exists — which, per #167,
	// is what "open" means. Resolved is the field to branch on: like
	// AnchorHeartbeat.SealedAt, Go's `omitempty` does not omit a struct, so an
	// unresolved alert's ResolvedAt still marshals as "0001-01-01T00:00:00Z"
	// rather than being absent.
	Resolved       bool      `json:"resolved"`
	ResolvedBy     string    `json:"resolved_by,omitempty"`
	ResolvedAt     time.Time `json:"resolved_at,omitempty"`
	ResolvedReason string    `json:"resolved_reason,omitempty"`
}

// AlertPage is one page of the alerts feed.
type AlertPage struct {
	Alerts []Alert `json:"alerts"`
	Total  int     `json:"total"`
	Limit  int     `json:"limit"`
	// NextCursor is empty at the end of the set, matching RunPage's keyset
	// cursor: the chain position of the last row served.
	NextCursor string    `json:"next_cursor,omitempty"`
	DataAsOf   time.Time `json:"data_as_of"`
}

const listAlertsSQL = `
WITH alerts AS (
    SELECT chain_position, event_id, event_type, run_id, ts,
           convert_from(canonical, 'UTF8')::jsonb AS body
      FROM innsegl.events
     WHERE event_type IN ('unattributed_signature_detected', 'ledger_drift_detected')
), filtered AS (
    SELECT alerts.*, count(*) OVER ()::int AS total
      FROM alerts
     WHERE ($1::text IS NULL OR event_type = $1)
)
SELECT f.chain_position, f.event_id, f.event_type, f.run_id, f.ts, f.body, f.total,
       r.resolved_by, r.resolved_at, r.reason
  FROM filtered f
  LEFT JOIN innsegl.alert_resolutions r ON r.event_id = f.event_id
 WHERE ($2::bigint IS NULL OR f.chain_position < $2)
 ORDER BY f.chain_position DESC
 LIMIT $3`

// ListAlerts serves one page of the alerts feed, newest first.
func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) (AlertPage, error) {
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}
	if f.EventType != "" &&
		f.EventType != event.EventTypeUnattributedSignatureDetected &&
		f.EventType != event.EventTypeLedgerDriftDetected {
		return AlertPage{}, fmt.Errorf("%w: event_type %q is not one of %s, %s",
			ErrBadRequest, f.EventType,
			event.EventTypeUnattributedSignatureDetected, event.EventTypeLedgerDriftDetected)
	}
	var cursor *int64
	if f.Cursor != "" {
		n, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil || n < 0 {
			return AlertPage{}, fmt.Errorf("%w: %q is not a cursor this API issued", ErrBadRequest, f.Cursor)
		}
		cursor = &n
	}

	rows, err := s.pool.Query(ctx, listAlertsSQL, nullable(f.EventType), cursor, limit)
	if err != nil {
		return AlertPage{}, fmt.Errorf("api: listing alerts: %w", err)
	}
	defer rows.Close()

	page := AlertPage{Limit: limit, DataAsOf: time.Now().UTC(), Alerts: []Alert{}}
	for rows.Next() {
		var a Alert
		var runID, resolvedBy, resolvedReason *string
		var resolvedAt *time.Time
		var body map[string]any
		if err := rows.Scan(&a.ChainPosition, &a.EventID, &a.EventType, &runID, &a.TS,
			&body, &page.Total, &resolvedBy, &resolvedAt, &resolvedReason); err != nil {
			return AlertPage{}, fmt.Errorf("api: reading an alert: %w", err)
		}
		a.TS = a.TS.UTC()
		if runID != nil {
			a.RunID = *runID
		}
		switch a.EventType {
		case event.EventTypeLedgerDriftDetected:
			a.SubjectEventID = stringOf(body[event.FieldSubjectEventID])
			a.Reason = stringOf(body[event.FieldReason])
		case event.EventTypeUnattributedSignatureDetected:
			a.CertificateIdentity = stringOf(body[event.FieldCertificateIdentity])
			a.RekorEntryUUID = stringOf(body[event.FieldRekorEntryUUID])
			a.RekorLogIndex = int64Of(body[event.FieldRekorLogIndex])
		}
		if resolvedBy != nil {
			a.Resolved = true
			a.ResolvedBy = *resolvedBy
			if resolvedAt != nil {
				a.ResolvedAt = resolvedAt.UTC()
			}
			if resolvedReason != nil {
				a.ResolvedReason = *resolvedReason
			}
		}
		page.Alerts = append(page.Alerts, a)
	}
	if err := rows.Err(); err != nil {
		return AlertPage{}, fmt.Errorf("api: listing alerts: %w", err)
	}
	if len(page.Alerts) == limit && len(page.Alerts) > 0 {
		page.NextCursor = strconv.FormatInt(page.Alerts[len(page.Alerts)-1].ChainPosition, 10)
	}
	return page, nil
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
