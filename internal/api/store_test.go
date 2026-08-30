// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// TC-API — the query surface.
//
// FD §7: "server-side pagination, filtering, and search only — never
// ship-the-table-to-the-client". That is not a style note. The runs table has
// to stay responsive at millions of rows (FD §3.2), and a handler that reads
// the table and slices it in Go is one that stops working at a size nobody
// tests at.
//
// So these cases measure the ROW COUNT THE DATABASE RETURNED, not just the row
// count the handler passed on. A pgx query tracer records what came back over
// the wire; if the narrowing ever moves out of SQL, the numbers diverge and
// API-003 fails.

// rowCounter is a pgx tracer that records the rows each query returned.
type rowCounter struct {
	mu      sync.Mutex
	queries []string
	rows    []int64
}

func (c *rowCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = append(c.queries, data.SQL)
	return ctx
}

func (c *rowCounter) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, data.CommandTag.RowsAffected())
}

// maxRows is the largest number of rows any single query returned.
func (c *rowCounter) maxRows() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out int64
	for _, n := range c.rows {
		if n > out {
			out = n
		}
	}
	return out
}

// queryCount is how many queries the tracer saw. A row-count assertion over
// zero observed queries would pass vacuously.
func (c *rowCounter) queryCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.rows)
}

func (c *rowCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries, c.rows = nil, nil
}

// seededRun describes one run the fixture writes into the ledger.
type seededRun struct {
	runID     string
	agentType string
	taskRef   string
	repo      string
	status    string
	commits   int
}

// seed writes runs into the ledger with the OWNER credential and returns them
// newest-first, which is the order the runs table shows.
func seed(t *testing.T, owner *ledger.Store, n int) []seededRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	agentTypes := []string{"fix-ci", "release-bot", "doc-writer"}
	repos := []string{"github.com/innsegl/one", "github.com/innsegl/two"}
	statuses := []string{StatusActive, StatusRetired, StatusExpired}

	out := make([]seededRun, 0, n)
	for i := range n {
		r := seededRun{
			runID:     fmt.Sprintf("run-%03d", i),
			agentType: agentTypes[i%len(agentTypes)],
			taskRef:   fmt.Sprintf("JIRA-%d", 100+i),
			repo:      repos[i%len(repos)],
			status:    statuses[i%len(statuses)],
			commits:   i % 3,
		}
		spiffe := "spiffe://innsegl.dev/agent/" + r.agentType + "/" +
			strings.ToLower(r.taskRef) + "/" + r.runID

		base := func(eventType string) event.Fields {
			return event.Fields{
				event.FieldEventType: eventType,
				event.FieldRunID:     r.runID,
				event.FieldSpiffeID:  spiffe,
				event.FieldSource:    event.SourceMCP,
			}
		}
		reg := base(event.EventTypeRunRegistered)
		reg[event.FieldAgentType] = r.agentType
		reg[event.FieldTaskRef] = r.taskRef
		reg[event.FieldIdempotencyKey] = r.runID + "-register"
		appendOrFail(ctx, t, owner, reg)

		for c := range r.commits {
			intent := base(event.EventTypeCommitIntent)
			intent[event.FieldRepo] = r.repo
			intent[event.FieldTreeHash] = strings.Repeat("a", 40)
			intent[event.FieldIdempotencyKey] = fmt.Sprintf("%s-intent-%d", r.runID, c)
			rec := appendOrFail(ctx, t, owner, intent)

			done := base(event.EventTypeCommitRecorded)
			done[event.FieldRepo] = r.repo
			done[event.FieldTreeHash] = strings.Repeat("a", 40)
			done[event.FieldCommitSHA] = fmt.Sprintf("%040d", i*10+c)
			done[event.FieldIntentEventID] = rec[event.FieldEventID]
			done[event.FieldRekorEntryUUID] = strings.Repeat("b", 64)
			done[event.FieldRekorLogIndex] = int64(i*10 + c)
			done[event.FieldIdempotencyKey] = fmt.Sprintf("%s-recorded-%d", r.runID, c)
			appendOrFail(ctx, t, owner, done)
		}

		switch r.status {
		case StatusRetired:
			appendOrFail(ctx, t, owner, base(event.EventTypeRunRetired))
		case StatusExpired:
			expired := base(event.EventTypeRunExpired)
			expired[event.FieldSource] = event.SourceReaper
			appendOrFail(ctx, t, owner, expired)
		}
		out = append(out, r)
	}
	slices.Reverse(out)
	return out
}

func appendOrFail(ctx context.Context, t *testing.T, s *ledger.Store, body event.Fields) event.Fields {
	t.Helper()
	rec, err := s.Append(ctx, body)
	if err != nil {
		t.Fatalf("append %v: %v", body[event.FieldEventType], err)
	}
	return rec
}

// readStore opens the read-only store with a row counter attached.
func readStore(t *testing.T, readerDSN string) (*Store, *rowCounter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(readerDSN)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	counter := &rowCounter{}
	cfg.ConnConfig.Tracer = counter

	s, err := OpenConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("OpenConfig: %v", err)
	}
	t.Cleanup(s.Close)
	counter.reset()
	return s, counter
}

// API-003 — pagination, filtering and search happen in the database.
func TestAPI003PaginationFilteringAndSearchHappenServerSide(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	const runs = 24
	seeded := seed(t, owner, runs)
	s, counter := readStore(t, readerDSN)
	ctx := t.Context()

	t.Run("a cursor walk visits every run exactly once", func(t *testing.T) {
		counter.reset()
		const page = 7
		seen := map[string]int{}
		var order []int64
		cursor := ""
		for pages := 0; ; pages++ {
			if pages > runs {
				t.Fatalf("the cursor walk did not terminate after %d pages", pages)
			}
			p, err := s.ListRuns(ctx, RunFilter{Limit: page, Cursor: cursor})
			if err != nil {
				t.Fatalf("ListRuns: %v", err)
			}
			if len(p.Runs) > page {
				t.Fatalf("a page of limit %d returned %d runs", page, len(p.Runs))
			}
			if p.Total != runs {
				t.Errorf("page reports Total=%d, %d runs were seeded", p.Total, runs)
			}
			for _, r := range p.Runs {
				seen[r.RunID]++
				order = append(order, r.ChainPosition)
			}
			if p.NextCursor == "" {
				break
			}
			cursor = p.NextCursor
		}
		if len(seen) != runs {
			t.Errorf("the walk saw %d distinct runs, %d were seeded", len(seen), runs)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("%s appeared %d times in the walk", id, n)
			}
		}
		if !slices.IsSortedFunc(order, func(a, b int64) int { return int(b - a) }) {
			t.Errorf("the walk is not in a stable descending order: %v", order)
		}
		if counter.queryCount() == 0 {
			t.Fatal("the tracer observed no queries, so the row-count assertion " +
				"below would pass without measuring anything")
		}
		// The measurement that matters: no single query ever returned more
		// rows than one page. A handler that read the table and sliced it in
		// Go would show `runs` here.
		if got := counter.maxRows(); got > page {
			t.Errorf("a query returned %d rows for a page of %d: the narrowing is "+
				"not in SQL, and FD §7 forbids shipping the table to the client", got, page)
		}
	})

	t.Run("the page size is capped", func(t *testing.T) {
		p, err := s.ListRuns(ctx, RunFilter{Limit: 100000})
		if err != nil {
			t.Fatalf("ListRuns: %v", err)
		}
		if p.Limit != MaxPageSize {
			t.Errorf("a request for 100000 rows produced Limit=%d, want the cap %d",
				p.Limit, MaxPageSize)
		}
	})

	t.Run("filters and search run in the database", func(t *testing.T) {
		want := func(keep func(seededRun) bool) []string {
			var out []string
			for _, r := range seeded {
				if keep(r) {
					out = append(out, r.runID)
				}
			}
			return out
		}
		for _, tc := range []struct {
			name   string
			filter RunFilter
			keep   func(seededRun) bool
		}{
			{"agent type", RunFilter{AgentType: "release-bot"},
				func(r seededRun) bool { return r.agentType == "release-bot" }},
			{"repo", RunFilter{Repo: "github.com/innsegl/two"},
				func(r seededRun) bool { return r.repo == "github.com/innsegl/two" && r.commits > 0 }},
			{"status", RunFilter{Status: StatusExpired},
				func(r seededRun) bool { return r.status == StatusExpired }},
			{"free text over the task", RunFilter{Search: "JIRA-11"},
				func(r seededRun) bool { return strings.Contains(r.taskRef, "JIRA-11") }},
			{"free text over the run id", RunFilter{Search: "run-01"},
				func(r seededRun) bool { return strings.Contains(r.runID, "run-01") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				counter.reset()
				tc.filter.Limit = MaxPageSize
				p, err := s.ListRuns(ctx, tc.filter)
				if err != nil {
					t.Fatalf("ListRuns: %v", err)
				}
				var got []string
				for _, r := range p.Runs {
					got = append(got, r.RunID)
				}
				expect := want(tc.keep)
				if len(expect) == 0 {
					t.Fatalf("the fixture produced no rows for %s; the case would pass vacuously", tc.name)
				}
				if !slices.Equal(got, expect) {
					t.Errorf("filter %+v returned %v, want %v", tc.filter, got, expect)
				}
				if counter.queryCount() == 0 {
					t.Fatal("the tracer observed no queries for this filter")
				}
				if int64(len(expect)) < int64(runs) && counter.maxRows() > int64(len(expect)) {
					t.Errorf("a query returned %d rows for a filter matching %d: the "+
						"filter is not being applied in SQL", counter.maxRows(), len(expect))
				}
			})
		}
	})

	t.Run("the run detail carries the timeline with its sources", func(t *testing.T) {
		var expired string
		for _, r := range seeded {
			if r.status == StatusExpired {
				expired = r.runID
				break
			}
		}
		d, err := s.Run(ctx, expired)
		if err != nil {
			t.Fatalf("Run(%s): %v", expired, err)
		}
		if d.Status != StatusExpired {
			t.Errorf("run %s reads as %s, the fixture expired it", expired, d.Status)
		}
		if len(d.Timeline) == 0 {
			t.Fatal("the run detail carries no timeline; FD §3.3 makes it the view")
		}
		var sawReaper bool
		last := int64(-1)
		for _, e := range d.Timeline {
			if e.ChainPosition <= last {
				t.Errorf("the timeline is not in chain order: %d after %d", e.ChainPosition, last)
			}
			last = e.ChainPosition
			if e.Source == event.SourceReaper {
				sawReaper = true
			}
			if e.EventHash == "" || e.PrevEventHash == "" {
				t.Errorf("timeline event at %d carries no chain link; FD P1 wants the "+
					"evidence next to the claim", e.ChainPosition)
			}
		}
		if !sawReaper {
			t.Error("the timeline hides the source of a reaper-written event; FD §3.3 " +
				"requires repaired history to be visible as repaired")
		}
	})

	t.Run("an unknown run is not found rather than empty", func(t *testing.T) {
		if _, err := s.Run(ctx, "run-does-not-exist"); err == nil {
			t.Fatal("Run returned no error for a run that does not exist")
		}
	})
}

// The overview is counts and the anchoring heartbeat, and deliberately no
// verification pass rate: a pass rate read out of the database would be a
// database-only verdict, which IP §6.11 forbids in terms.
func TestTheOverviewCountsWithoutInventingAVerdict(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	seeded := seed(t, owner, 6)
	s, _ := readStore(t, readerDSN)

	o, err := s.Overview(t.Context())
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	var active, commits int
	for _, r := range seeded {
		if r.status == StatusActive {
			active++
		}
		commits += r.commits
	}
	if o.ActiveRuns != active {
		t.Errorf("ActiveRuns = %d, the fixture left %d unretired and unexpired",
			o.ActiveRuns, active)
	}
	if o.CommitsRecorded != commits {
		t.Errorf("CommitsRecorded = %d, the fixture recorded %d", o.CommitsRecorded, commits)
	}
	if o.DataAsOf.IsZero() {
		t.Error("the overview carries no data-as-of timestamp; FD §4.4 requires one " +
			"on every view that can be serving degraded data")
	}
}
