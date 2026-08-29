// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"innsegl.dev/innsegl/internal/event"
)

// The reaper's decisions, without SPIRE and without a ledger.
//
// SPI-003 is the case that matters and it runs against the real stack. These
// cases exist for the parts of the decision a single integration run cannot
// reach: the entries the reaper must refuse to judge, and the ledger failures
// that must stop it deleting. Each one is a branch that ends in "do not delete
// this identity", and an untaken branch there is an identity deleted on no
// evidence.

func TestEntryDeadlineUsesTheEntrysOwnTTL(t *testing.T) {
	created := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		cand  Candidate
		grace time.Duration
		want  time.Time
		ok    bool
	}{
		{
			name: "created_at plus TTL",
			cand: Candidate{Entry: Entry{TTL: 5 * time.Minute}, CreatedAt: created},
			want: created.Add(5 * time.Minute),
			ok:   true,
		},
		{
			name:  "grace is added to the TTL",
			cand:  Candidate{Entry: Entry{TTL: 5 * time.Minute}, CreatedAt: created},
			grace: 30 * time.Minute,
			want:  created.Add(35 * time.Minute),
			ok:    true,
		},
		{
			// SPIRE's own statement about when the entry ends wins: holding an
			// identity past the point its issuer says it ended is not something
			// a computed deadline gets to override.
			name:  "SPIRE's own entry expiry wins",
			cand:  Candidate{Entry: Entry{TTL: 5 * time.Minute}, CreatedAt: created, ExpiresAt: expires},
			grace: time.Minute,
			want:  expires.Add(time.Minute),
			ok:    true,
		},
		{
			name: "an entry with neither timestamp has no deadline",
			cand: Candidate{Entry: Entry{TTL: 5 * time.Minute}},
			ok:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := entryDeadline(tc.cand, tc.grace)
			if ok != tc.ok {
				t.Fatalf("entryDeadline ok = %v, want %v", ok, tc.ok)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("entryDeadline = %s, want %s", got, tc.want)
			}
			if !ok && !got.IsZero() {
				t.Errorf("entryDeadline returned %s with ok=false", got)
			}
		})
	}
}

func TestParseRunIdentityRefusesAnythingThatIsNotARun(t *testing.T) {
	good := "spiffe://innsegl.dev/agent/demo/rm-017/run-1"
	run, err := parseRunIdentity(good, "innsegl.dev")
	if err != nil {
		t.Fatalf("parseRunIdentity(%q): %v", good, err)
	}
	if run != (RunRef{AgentType: "demo", TaskID: "rm-017", RunID: "run-1"}) {
		t.Errorf("parseRunIdentity(%q) = %+v", good, run)
	}
	// The round trip is the real assertion: what the reaper parses out must
	// rebuild the identity it parsed, or it is expiring the wrong run.
	back, err := run.SPIFFEID("innsegl.dev")
	if err != nil || back != good {
		t.Errorf("round trip = %q (%v), want %q", back, err, good)
	}

	for _, bad := range []string{
		"spiffe://innsegl.dev/spire/agent/x509pop/abc",
		"spiffe://innsegl.dev/innsegl/mcp",
		"spiffe://innsegl.dev/agent/demo/rm-017",
		"spiffe://innsegl.dev/agent/demo/rm-017/run-1/extra",
		"spiffe://innsegl.dev/agent/DEMO/rm-017/run-1",
		"https://innsegl.dev/agent/demo/rm-017/run-1",
		"",
	} {
		if _, err := parseRunIdentity(bad, "innsegl.dev"); err == nil {
			t.Errorf("parseRunIdentity(%q) succeeded; it is not a run identity", bad)
		}
	}

	// A well-formed run identity from somebody else's trust domain is not
	// this deployment's to expire.
	other := "spiffe://example.org/agent/demo/rm-017/run-1"
	if _, err := parseRunIdentity(other, "innsegl.dev"); err == nil {
		t.Errorf("parseRunIdentity(%q) accepted a foreign trust domain", other)
	}
}

func TestNewReaperRefusesAConfigurationThatCouldDeleteBlindly(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ReaperConfig
		want string
	}{
		{name: "no client", cfg: ReaperConfig{Ledger: &fakeSink{}}, want: "no SPIRE client"},
		{name: "no ledger", cfg: ReaperConfig{Client: &Client{}}, want: "no ledger"},
		{
			name: "negative grace",
			cfg:  ReaperConfig{Client: &Client{}, Ledger: &fakeSink{}, Grace: -time.Second},
			want: "negative",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewReaper(tc.cfg)
			if err == nil {
				t.Fatalf("NewReaper(%+v) succeeded", tc.cfg)
			}
			if r != nil {
				t.Error("NewReaper returned a reaper alongside an error")
			}
			if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
				t.Errorf("class = %q (ok=%v), want %s", class, ok, ClassInvariantViolation)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	r, err := NewReaper(ReaperConfig{Client: &Client{}, Ledger: &fakeSink{}})
	if err != nil {
		t.Fatalf("NewReaper with a zero grace: %v", err)
	}
	// Zero means zero. DefaultReapGrace belongs to the operator surface, not
	// to a silent fallback here.
	if r.Grace() != 0 {
		t.Errorf("Grace() = %s, want 0: a zero grace must not be reinterpreted", r.Grace())
	}
}

func TestClassifyLeavesAloneWhatItCannotJudge(t *testing.T) {
	c := &Client{trustDomain: "innsegl.dev"}
	r, err := NewReaper(ReaperConfig{Client: c, Ledger: &fakeSink{}})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	t.Run("entries outside the agent subtree are not the reaper's", func(t *testing.T) {
		for _, id := range []string{
			"spiffe://innsegl.dev/spire/agent/x509pop/deadbeef",
			"spiffe://innsegl.dev/innsegl/mcp",
			"spiffe://example.org/agent/demo/rm-017/run-1",
		} {
			_, skipped, ours := r.classify(wireEntry(id, 60, time.Now().Add(-time.Hour)))
			if ours {
				t.Errorf("classify(%q) claimed the entry; it is outside %s's agent subtree",
					id, c.trustDomain)
			}
			if skipped != nil {
				t.Errorf("classify(%q) reported a skip for an entry that is not ours", id)
			}
		}
	})

	// Everything below IS in the subtree, so the reaper owns it — and refuses
	// to delete it anyway, because it has no basis to call it orphaned.
	for _, tc := range []struct {
		name   string
		entry  *types.Entry
		reason string
	}{
		{
			name:   "a SPIFFE ID that is not a run identity",
			entry:  wireEntry("spiffe://innsegl.dev/agent/demo", 60, time.Now().Add(-time.Hour)),
			reason: "not a run identity",
		},
		{
			name:   "no TTL of its own",
			entry:  wireEntry("spiffe://innsegl.dev/agent/demo/rm-017/run-1", 0, time.Now().Add(-time.Hour)),
			reason: "no TTL of its own",
		},
		{
			name:   "no creation time and no expiry",
			entry:  wireEntry("spiffe://innsegl.dev/agent/demo/rm-017/run-1", 60, time.Time{}),
			reason: "neither a creation time nor an expiry",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cand, skipped, ours := r.classify(tc.entry)
			if !ours {
				t.Fatal("classify disowned an entry inside the agent subtree")
			}
			if skipped == nil {
				t.Fatalf("classify judged it reapable: %+v", cand)
			}
			if !strings.Contains(skipped.Reason, tc.reason) {
				t.Errorf("skip reason %q does not mention %q", skipped.Reason, tc.reason)
			}
		})
	}

	t.Run("an ordinary run entry is a candidate", func(t *testing.T) {
		created := time.Now().Add(-time.Hour).Truncate(time.Second)
		cand, skipped, ours := r.classify(
			wireEntry("spiffe://innsegl.dev/agent/demo/rm-017/run-1", 300, created))
		if !ours || skipped != nil {
			t.Fatalf("classify skipped an ordinary run entry: ours=%v skipped=%+v", ours, skipped)
		}
		if cand.Run.RunID != "run-1" {
			t.Errorf("run id = %q, want run-1", cand.Run.RunID)
		}
		if !cand.CreatedAt.Equal(created.UTC()) {
			t.Errorf("created at = %s, want %s", cand.CreatedAt, created.UTC())
		}
		if want := created.UTC().Add(5 * time.Minute); !cand.Deadline.Equal(want) {
			t.Errorf("deadline = %s, want %s", cand.Deadline, want)
		}
	})
}

// TestRecordIsIdempotentAndRefusesAForeignKey covers the ledger half of reap
// without a database. The delete half needs SPIRE and belongs to SPI-003.
func TestRecordIsIdempotentAndRefusesAForeignKey(t *testing.T) {
	cand := Candidate{
		Entry: Entry{ID: "entry-1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-1", TTL: time.Minute},
		Run:   RunRef{AgentType: "demo", TaskID: "rm-017", RunID: "run-1"},
	}
	key := ExpiryKey(cand.Run.RunID)
	if !strings.HasSuffix(key, cand.Run.RunID) {
		t.Fatalf("ExpiryKey(%q) = %q, want it to end in the run id", cand.Run.RunID, key)
	}

	t.Run("the first pass appends", func(t *testing.T) {
		sink := &fakeSink{}
		r := &Reaper{ledger: sink}

		id, appended, err := r.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if !appended {
			t.Error("the first pass reported nothing appended")
		}
		if id == "" {
			t.Error("record returned no event id")
		}
		if len(sink.appended) != 1 {
			t.Fatalf("sink holds %d events, want 1", len(sink.appended))
		}
		body := sink.appended[0]
		// Protected spellings, checked as literals.
		if body[event.FieldEventType] != "run_expired" {
			t.Errorf("event_type = %v, want run_expired", body[event.FieldEventType])
		}
		if body[event.FieldSource] != "reaper" {
			t.Errorf("source = %v, want reaper", body[event.FieldSource])
		}
		if body[event.FieldIdempotencyKey] != key {
			t.Errorf("idempotency_key = %v, want %q", body[event.FieldIdempotencyKey], key)
		}
		if body[event.FieldSpiffeID] != cand.Entry.SPIFFEID {
			t.Errorf("spiffe_id = %v, want the id SPIRE held: %q",
				body[event.FieldSpiffeID], cand.Entry.SPIFFEID)
		}
		// The ledger assigns these; supplying any of them is refused at append.
		for _, name := range []string{
			event.FieldEventID, event.FieldTS, event.FieldChainPosition,
			event.FieldPrevEventHash, event.EventHashField,
		} {
			if _, present := body[name]; present {
				t.Errorf("the reaper supplied %s, which is the ledger's to assign", name)
			}
		}

		// The second pass over the same run finds the record and appends
		// nothing, whether or not SPIRE still lists the entry.
		id2, appended2, err := r.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("second record: %v", err)
		}
		if appended2 {
			t.Error("the second pass appended a second run_expired")
		}
		if id2 != id {
			t.Errorf("second pass reported event %q, first reported %q", id2, id)
		}
		if len(sink.appended) != 1 {
			t.Errorf("sink holds %d events after two passes, want 1", len(sink.appended))
		}
	})

	t.Run("a key held by something else is an alert, not a deletion", func(t *testing.T) {
		// The idempotency namespace is shared with the MCP's caller-supplied
		// keys (IP §4). If the reaper's key is occupied by an event that is not
		// this run's expiry, the reaper must not treat it as one — the entry
		// stays and a human looks.
		sink := &fakeSink{stored: map[string]event.Fields{
			key: {
				event.FieldEventType: event.EventTypeToolCall,
				event.FieldRunID:     "run-1",
				event.FieldEventID:   "01a04a16-db86-7f2e-9bb5-23822b92285a",
			},
		}}
		r := &Reaper{ledger: sink}

		_, appended, err := r.record(context.Background(), cand)
		if err == nil {
			t.Fatal("record accepted a foreign event under the reaper's key")
		}
		if appended {
			t.Error("record reported an append alongside the error")
		}
		if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
			t.Errorf("class = %q (ok=%v), want %s", class, ok, ClassInvariantViolation)
		}
		if len(sink.appended) != 0 {
			t.Error("record appended anyway")
		}
	})

	t.Run("an expiry recorded against a different run is refused too", func(t *testing.T) {
		sink := &fakeSink{stored: map[string]event.Fields{
			key: {
				event.FieldEventType: event.EventTypeRunExpired,
				event.FieldRunID:     "run-2",
				event.FieldEventID:   "01a04a16-db86-7f2e-9bb5-23822b92285a",
			},
		}}
		r := &Reaper{ledger: sink}
		if _, _, err := r.record(context.Background(), cand); err == nil {
			t.Fatal("record accepted an expiry belonging to another run")
		}
	})

	t.Run("a stored expiry with no event id is refused", func(t *testing.T) {
		sink := &fakeSink{stored: map[string]event.Fields{
			key: {
				event.FieldEventType: event.EventTypeRunExpired,
				event.FieldRunID:     "run-1",
			},
		}}
		r := &Reaper{ledger: sink}
		if _, _, err := r.record(context.Background(), cand); err == nil {
			t.Fatal("record accepted a stored expiry carrying no event_id")
		}
	})

	t.Run("a ledger that cannot be read stops the reap", func(t *testing.T) {
		sink := &fakeSink{lookupErr: errors.New("connection refused")}
		r := &Reaper{ledger: sink}

		_, _, err := r.record(context.Background(), cand)
		if err == nil {
			t.Fatal("record proceeded with an unreadable ledger")
		}
		if !IsRetryable(err) {
			t.Error("an unreachable ledger must be retryable; the orphan is still there")
		}
		if len(sink.appended) != 0 {
			t.Error("record appended despite failing to read")
		}
	})

	t.Run("a ledger that cannot be appended to stops the reap", func(t *testing.T) {
		sink := &fakeSink{appendErr: errors.New("disk full")}
		r := &Reaper{ledger: sink}

		_, appended, err := r.record(context.Background(), cand)
		if err == nil {
			t.Fatal("record reported success after the append failed")
		}
		if appended {
			t.Error("record claimed to have appended")
		}
	})

	t.Run("an append lost to a concurrent reaper resolves to its event", func(t *testing.T) {
		// Two reapers, no leader election. The second one's read misses, its
		// append is refused by the key, and it must resolve to the first one's
		// event rather than failing or writing a duplicate.
		sink := &fakeSink{
			appendErr: errors.New("idempotency key conflict"),
			onAppend: func(s *fakeSink) {
				s.stored = map[string]event.Fields{key: {
					event.FieldEventType: event.EventTypeRunExpired,
					event.FieldRunID:     "run-1",
					event.FieldEventID:   "01a04a16-db86-7f2e-9bb5-23822b92285a",
				}}
			},
		}
		r := &Reaper{ledger: sink}

		id, appended, err := r.record(context.Background(), cand)
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if appended {
			t.Error("record claimed the append it lost")
		}
		if id != "01a04a16-db86-7f2e-9bb5-23822b92285a" {
			t.Errorf("event id = %q, want the winner's", id)
		}
	})

	t.Run("a stored record with no event id is not silently accepted", func(t *testing.T) {
		sink := &fakeSink{appendResult: event.Fields{event.FieldEventType: event.EventTypeRunExpired}}
		r := &Reaper{ledger: sink}
		if _, _, err := r.record(context.Background(), cand); err == nil {
			t.Fatal("record accepted a stored event with no event_id")
		}
	})
}

func TestSweepReportRendersAndFindsNothingWhenEmpty(t *testing.T) {
	var nilReport *SweepReport
	if nilReport.OK() {
		t.Error("a nil report is not OK")
	}
	if _, ok := nilReport.FindExpired("run-1"); ok {
		t.Error("a nil report found an expiry")
	}
	if _, ok := nilReport.FindLive("run-1"); ok {
		t.Error("a nil report found a live run")
	}
	if s := nilReport.String(); !strings.Contains(s, "no report") {
		t.Errorf("nil report String() = %q", s)
	}

	empty := &SweepReport{StartedAt: time.Unix(0, 0).UTC()}
	if !empty.OK() {
		t.Error("a sweep that found no orphans is a healthy sweep, not a failure")
	}
	if _, ok := empty.FindExpired("run-1"); ok {
		t.Error("an empty report found an expiry")
	}
	if _, ok := empty.FindLive("run-1"); ok {
		t.Error("an empty report found a live run")
	}
	if s := empty.String(); !strings.Contains(s, "0 entries") {
		t.Errorf("empty report String() = %q, want it to say the subtree was empty", s)
	}

	full := &SweepReport{
		StartedAt: time.Unix(0, 0).UTC(),
		Examined:  1,
		Live: []Candidate{{
			Entry: Entry{ID: "e2", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-2"},
			Run:   RunRef{RunID: "run-2"},
		}},
		Expired: []Expiry{{
			Candidate: Candidate{
				Entry: Entry{ID: "e1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-1"},
				Run:   RunRef{RunID: "run-1"},
			},
			Recorded: true, Deleted: true,
		}},
		Skipped:  []Skipped{{EntryID: "e3", Reason: "unreadable"}},
		Failures: []Failure{{EntryID: "e4", Err: errors.New("boom")}},
	}
	if full.OK() {
		t.Error("a report with a failure is not OK")
	}
	if _, ok := full.FindExpired("run-1"); !ok {
		t.Error("FindExpired missed the expiry it holds")
	}
	if _, ok := full.FindLive("run-2"); !ok {
		t.Error("FindLive missed the live run it holds")
	}
	// "1 entry", not "1 entries": the report is read by a human.
	for _, want := range []string{"1 entry", "expired", "live", "skipped", "FAILED", "boom"} {
		if !strings.Contains(full.String(), want) {
			t.Errorf("report does not mention %q:\n%s", want, full.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Fakes.
// ---------------------------------------------------------------------------

// wireEntry builds a registration entry the way SPIRE hands one over, so that
// classify can be walked over entries a real server would be unlikely to
// produce on demand — an entry with no creation time, or with a SPIFFE ID that
// is not a run identity. It fabricates SPIRE's wire message, never SPIRE's
// answer to a question: every case that depends on what SPIRE actually does is
// in SPI-003, against the real server.
func wireEntry(spiffeID string, ttlSeconds int32, createdAt time.Time) *types.Entry {
	id, err := splitID(spiffeID)
	if err != nil {
		panic(err)
	}
	e := &types.Entry{
		Id:          "entry-for-" + spiffeID,
		SpiffeId:    id,
		X509SvidTtl: ttlSeconds,
	}
	if !createdAt.IsZero() {
		e.CreatedAt = createdAt.Unix()
	}
	return e
}

// fakeSink is a ledger that does nothing but answer, so the reaper's ledger
// branches can be walked without a Postgres. SPI-003 uses the real store.
type fakeSink struct {
	stored       map[string]event.Fields
	appended     []event.Fields
	lookupErr    error
	appendErr    error
	appendResult event.Fields
	onAppend     func(*fakeSink)
	seq          int
}

func (f *fakeSink) EventByIdempotencyKey(_ context.Context, key string) (event.Fields, bool, error) {
	if f.lookupErr != nil {
		return nil, false, f.lookupErr
	}
	rec, ok := f.stored[key]
	return rec, ok, nil
}

func (f *fakeSink) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	if f.onAppend != nil {
		f.onAppend(f)
	}
	if f.appendErr != nil {
		return nil, f.appendErr
	}
	f.appended = append(f.appended, body)
	if f.appendResult != nil {
		return f.appendResult, nil
	}
	f.seq++
	rec := body.Clone()
	rec[event.FieldEventID] = "01a04a16-db86-7f2e-9bb5-2382" + pad(f.seq)
	if key, ok := body[event.FieldIdempotencyKey].(string); ok {
		if f.stored == nil {
			f.stored = map[string]event.Fields{}
		}
		f.stored[key] = rec
	}
	return rec, nil
}

func pad(n int) string {
	s := "00000000"
	d := ""
	for n > 0 {
		d = string(rune('0'+n%10)) + d
		n /= 10
	}
	if d == "" {
		d = "0"
	}
	return s[:8-len(d)] + d
}

// TestSweepReportIsOrderedDeterministically pins the claim sortReport's comment
// makes: two sweeps over the same state print the same thing. SPIRE promises no
// order on ListEntries, so without this an operator diffing two reports would
// see phantom changes.
func TestSweepReportIsOrderedDeterministically(t *testing.T) {
	expiry := func(spiffeID string) Expiry {
		return Expiry{Candidate: Candidate{Entry: Entry{ID: "id-" + spiffeID, SPIFFEID: spiffeID}}}
	}
	live := func(spiffeID string) Candidate {
		return Candidate{Entry: Entry{ID: "id-" + spiffeID, SPIFFEID: spiffeID}}
	}
	report := &SweepReport{
		Expired:  []Expiry{expiry("spiffe://innsegl.dev/agent/demo/t/c"), expiry("spiffe://innsegl.dev/agent/demo/t/a"), expiry("spiffe://innsegl.dev/agent/demo/t/b")},
		Live:     []Candidate{live("spiffe://innsegl.dev/agent/demo/t/z"), live("spiffe://innsegl.dev/agent/demo/t/x"), live("spiffe://innsegl.dev/agent/demo/t/y")},
		Skipped:  []Skipped{{EntryID: "e3"}, {EntryID: "e1"}, {EntryID: "e2"}},
		Failures: []Failure{{EntryID: "f3"}, {EntryID: "f1"}, {EntryID: "f2"}},
	}

	sortReport(report)

	for i, want := range []string{"a", "b", "c"} {
		if got := report.Expired[i].Entry.SPIFFEID; !strings.HasSuffix(got, "/"+want) {
			t.Errorf("expired[%d] = %q, want it to end in /%s", i, got, want)
		}
	}
	for i, want := range []string{"x", "y", "z"} {
		if got := report.Live[i].Entry.SPIFFEID; !strings.HasSuffix(got, "/"+want) {
			t.Errorf("live[%d] = %q, want it to end in /%s", i, got, want)
		}
	}
	for i, want := range []string{"e1", "e2", "e3"} {
		if report.Skipped[i].EntryID != want {
			t.Errorf("skipped[%d] = %q, want %q", i, report.Skipped[i].EntryID, want)
		}
	}
	for i, want := range []string{"f1", "f2", "f3"} {
		if report.Failures[i].EntryID != want {
			t.Errorf("failures[%d] = %q, want %q", i, report.Failures[i].EntryID, want)
		}
	}
}
