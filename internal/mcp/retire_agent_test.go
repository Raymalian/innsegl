// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-025 (#33) — retire_agent(run_id) -> {retired_at}.
//
// Doc 07 puts MCP-005 and MCP-009 at layer C — contract — and IP §2 admits
// mocks there. What these cases are about is the tool's decision procedure and
// the ORDER it writes two systems in, which a double can drive exhaustively
// and a container cannot.
//
// Two things about the doubles below are load-bearing rather than convenient,
// because MCP-005 and MCP-009 are both easy to pass vacuously.
//
//  1. retireLedger is a REAL hash chain. It stamps event_id and ts, then calls
//     the shipped ledger.Append and event.ValidateEvent, so an event this tool
//     appends has to satisfy doc 02 §2-§3 to be accepted at all — including
//     ADR-0004's rule that `run_retired` carries NO idempotency_key, which is
//     enforced by the validator rather than by an assertion that could be
//     forgotten. Its ts advances by one millisecond on every append, so two
//     retirements of one run could never stamp one instant by accident: "the
//     second call returned the same timestamp" is only true here if there was
//     no second append.
//
//  2. retireRuns — the run directory both this tool and get_credential resolve
//     a run_id against — reads RetiredAt OUT OF THAT LEDGER, as the earliest
//     `run_retired` for the run. That is where retirement is durably recorded
//     (I4: the SPIRE entry is deleted, the record never is), so the reply's
//     "original timestamp" is the ledger's or it is nothing.

const (
	retireTrustDomain = "innsegl.dev"
	retireAgentType   = "demo"
	retireTaskID      = "rm-025"
)

func retireSPIFFEID(runID string) string {
	return "spiffe://" + retireTrustDomain + "/agent/" + retireAgentType + "/" + retireTaskID + "/" + runID
}

func retireRunRef(runID string) CredentialRun {
	return CredentialRun{
		RunID:     runID,
		AgentType: retireAgentType,
		TaskID:    retireTaskID,
		SPIFFEID:  retireSPIFFEID(runID),
	}
}

// ---------------------------------------------------------------------------
// The ledger: an in-memory chain built with the shipped chain primitives.
// ---------------------------------------------------------------------------

type retireLedger struct {
	mu      sync.Mutex
	head    ledger.Head
	stored  []event.Fields
	err     error
	next    int64
	base    time.Time
	noTS    bool
	badTS   string
	appends int
}

func newRetireLedger() *retireLedger {
	return &retireLedger{base: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
}

// Append stamps what the store stamps and then runs the shipped chain append
// and the shipped schema validator over the result.
func (l *retireLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appends++
	if l.err != nil {
		return nil, l.err
	}
	l.next++
	staged := body.Clone()
	staged[event.FieldEventID] = fmt.Sprintf("0192f0a0-0000-7000-8000-%012d", l.next)
	// noTS and badTS fabricate two defects the real store cannot produce, so
	// that the tool's refusal to answer with an instant it cannot read is
	// exercised rather than assumed. Otherwise: one millisecond apart and
	// strictly increasing, so a second append can never be mistaken for the
	// first.
	broken := l.noTS || l.badTS != ""
	switch {
	case l.noTS:
		// ts absent entirely.
	case l.badTS != "":
		staged[event.FieldTS] = l.badTS
	default:
		staged[event.FieldTS] = event.NewTimestamp(l.base.Add(time.Duration(l.next) * time.Millisecond)).String()
	}
	record, head, err := ledger.Append(l.head, staged)
	if err != nil {
		return nil, &ledger.StoreError{Class: ledger.ClassInvariantViolation, Op: "append", Err: err}
	}
	// Everything else is validated exactly as the store validates it — which
	// is what holds an appended event to doc 02 §2-§3, ADR-0004's forbidden
	// idempotency_key included.
	if !broken {
		if verr := event.ValidateEvent(record); verr != nil {
			return nil, &ledger.StoreError{Class: ledger.ClassInvariantViolation, Op: "append", Err: verr}
		}
	}
	l.head = head
	l.stored = append(l.stored, record)
	return record, nil
}

func (l *retireLedger) all() []event.Fields {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]event.Fields, len(l.stored))
	copy(out, l.stored)
	return out
}

// of returns every event of one type for one run, in chain order.
func (l *retireLedger) of(eventType, runID string) []event.Fields {
	var out []event.Fields
	for _, rec := range l.all() {
		if rec[event.FieldEventType] == eventType && rec[event.FieldRunID] == runID {
			out = append(out, rec)
		}
	}
	return out
}

// retiredAt is the instant of the EARLIEST run_retired for the run, zero when
// the run has not been retired. Earliest and not latest: it is the original
// retirement IP §4 requires every later call to be answered with.
func (l *retireLedger) retiredAt(runID string) time.Time {
	var earliest time.Time
	for _, rec := range l.of(event.EventTypeRunRetired, runID) {
		raw, ok := rec[event.FieldTS].(string)
		if !ok {
			continue
		}
		ts, err := event.ParseTimestamp(raw)
		if err != nil {
			continue
		}
		if earliest.IsZero() || ts.Time().Before(earliest) {
			earliest = ts.Time()
		}
	}
	return earliest
}

// stampBadTS makes the next append carry no ts, or an unreadable one.
func (l *retireLedger) stampBadTS(absent bool, bad string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.noTS, l.badTS = absent, bad
}

func (l *retireLedger) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

func (l *retireLedger) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appends
}

// ---------------------------------------------------------------------------
// The run directory, backed by that ledger.
// ---------------------------------------------------------------------------

type retireRuns struct {
	mu       sync.Mutex
	runs     map[string]CredentialRun
	override map[string]CredentialRun
	source   *retireLedger
	err      error
	calls    int

	// rendezvous, when armed, holds every one of the next rendezvousN calls to
	// CredentialRun until ALL of them have performed their own read of the
	// chain — so two (or more) concurrent callers can be PROVEN to have each
	// independently decided "not retired" before any of them is allowed to
	// proceed to record() and append. Without this, two goroutines racing
	// gate 2 might just as easily serialize by luck, and a test built on that
	// luck would be exactly the kind of vacuous timing-dependent case RM-082
	// (#120) warns about. See armRendezvous.
	rendezvous  *sync.WaitGroup
	rendezvousN int

	// atCall overrides exactly one call to CredentialRun, numbered from 1. It
	// exists to drive retire()'s post-append re-query (earliestRetiredAt) into
	// its own defensive error paths — a directory disagreeing with itself
	// immediately after this tool's own append is not a scenario the shipped
	// rundir.Directory produces (it reads the same chain this tool just wrote
	// to), but retire()'s refusal to trust it anyway is exactly what IP §2's
	// 100%-branch floor on "every error-return path of every MCP tool" holds
	// open. See answerAtCall.
	atCall map[int]retireRunsAnswer
}

// retireRunsAnswer is one forced answer for one call number.
type retireRunsAnswer struct {
	run CredentialRun
	ok  bool
	err error
}

func newRetireRuns(source *retireLedger, runs ...CredentialRun) *retireRuns {
	d := &retireRuns{
		runs:     make(map[string]CredentialRun, len(runs)),
		override: map[string]CredentialRun{},
		source:   source,
	}
	for _, r := range runs {
		d.runs[r.RunID] = r
	}
	return d
}

func (d *retireRuns) CredentialRun(_ context.Context, runID string) (CredentialRun, bool, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	if forced, has := d.atCall[call]; has {
		delete(d.atCall, call)
		d.mu.Unlock()
		return forced.run, forced.ok, forced.err
	}
	if d.err != nil {
		err := d.err
		d.mu.Unlock()
		return CredentialRun{}, false, err
	}
	var (
		r  CredentialRun
		ok bool
	)
	if or, has := d.override[runID]; has {
		r, ok = or, true
	} else {
		r, ok = d.runs[runID]
	}
	if ok {
		// Read from the chain, never from a field this test set.
		r.RetiredAt = d.source.retiredAt(runID)
	}
	// The rendezvous is joined and the lock released BEFORE returning, so a
	// second concurrent call to this same method — which also needs d.mu —
	// can make its own progress while this one waits. Holding the lock across
	// the wait would deadlock the second caller against the first.
	var wait *sync.WaitGroup
	if d.rendezvous != nil && d.rendezvousN > 0 {
		wait = d.rendezvous
		d.rendezvousN--
		if d.rendezvousN == 0 {
			d.rendezvous = nil
		}
	}
	d.mu.Unlock()
	if wait != nil {
		wait.Done()
		wait.Wait()
	}
	if !ok {
		return CredentialRun{}, false, nil
	}
	return r, true, nil
}

// armRendezvous holds the next n calls to CredentialRun at a barrier: each one
// completes its own read, then blocks until all n have done the same, and only
// then do any of them return. It is how a test forces ADR-0020 §5's window —
// two genuinely concurrent FIRST retirements — deterministically, instead of
// hoping two goroutines interleave the right way.
func (d *retireRuns) armRendezvous(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	wg := &sync.WaitGroup{}
	wg.Add(n)
	d.rendezvous, d.rendezvousN = wg, n
}

// answerAtCall forces call number `call` (1-indexed, across every run_id) to
// answer exactly (run, ok, err) instead of consulting the chain. It is a
// one-shot: the entry is consumed the first time that call number is reached.
func (d *retireRuns) answerAtCall(call int, run CredentialRun, ok bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.atCall == nil {
		d.atCall = map[int]retireRunsAnswer{}
	}
	d.atCall[call] = retireRunsAnswer{run: run, ok: ok, err: err}
}

func (d *retireRuns) answerWith(runID string, r CredentialRun) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.override[runID] = r
}

func (d *retireRuns) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

func (d *retireRuns) lookups() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// ---------------------------------------------------------------------------
// SPIRE: the entry this tool deletes, and the entry get_credential checks.
// ---------------------------------------------------------------------------

type retireEntries struct {
	mu      sync.Mutex
	held    map[string]string
	deletes []spire.RunRef
	checks  []spire.RunRef
	err     error
}

func newRetireEntries(runIDs ...string) *retireEntries {
	e := &retireEntries{held: map[string]string{}}
	for _, id := range runIDs {
		e.held[id] = "entry-" + id
	}
	return e
}

func (e *retireEntries) RetireRun(_ context.Context, run spire.RunRef) (spire.Retirement, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deletes = append(e.deletes, run)
	if e.err != nil {
		return spire.Retirement{}, e.err
	}
	id, held := e.held[run.RunID]
	if !held {
		// IP §4: retiring a run SPIRE holds no entry for is a success with
		// nothing deleted.
		return spire.Retirement{}, nil
	}
	delete(e.held, run.RunID)
	return spire.Retirement{EntryID: id, Deleted: true}, nil
}

// RequireActiveRun is get_credential's fourth gate. Sharing one double between
// the two tools is what makes MCP-009 an interaction and not two monologues.
func (e *retireEntries) RequireActiveRun(_ context.Context, run spire.RunRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checks = append(e.checks, run)
	if _, held := e.held[run.RunID]; !held {
		return &spire.Error{
			Class: spire.ClassRunNotFound, Op: "require_active_run", RunID: run.RunID,
			Message: "SPIRE holds no registration entry",
		}
	}
	return nil
}

func (e *retireEntries) holds(runID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, held := e.held[runID]
	return held
}

func (e *retireEntries) deleted() []spire.RunRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]spire.RunRef, len(e.deletes))
	copy(out, e.deletes)
	return out
}

func (e *retireEntries) fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.err = err
}

func (e *retireEntries) recover() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.err = nil
}

// retireMinter is get_credential's minter, present only so that the control
// half of MCP-009 — a credential the run CAN get while it is live — is real.
type retireMinter struct {
	mu  sync.Mutex
	n   int
	now func() time.Time
}

func (m *retireMinter) MintJWTSVID(_ context.Context, spiffeID, audience string) (MintedCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return MintedCredential{
		Token:     fmt.Sprintf("jwt-svid-%d", m.n),
		SPIFFEID:  spiffeID,
		Audience:  audience,
		ExpiresAt: m.now().Add(5 * time.Minute),
	}, nil
}

func (m *retireMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

// ---------------------------------------------------------------------------
// Fixture: the tool bound through the real registration seam, served over the
// real HTTP transport, driven by a real MCP client.
// ---------------------------------------------------------------------------

type retireFixture struct {
	session *sdk.ClientSession
	runs    *retireRuns
	entries *retireEntries
	ledger  *retireLedger
	minter  *retireMinter
	clock   time.Time
}

func withRetireConfig(t *testing.T, cfg RetireAgentConfig) {
	t.Helper()
	restore, err := ConfigureRetireAgent(cfg)
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restore)
}

// serveRetire binds retire_agent — and optionally get_credential — through
// RegisterTool/Bind, the seam New uses in production.
func serveRetire(t *testing.T, alsoCredential bool) *sdk.ClientSession {
	t.Helper()
	withEmptyToolRegistry(t)
	RegisterTool(ToolRetireAgent, bindRetireAgent)
	if alsoCredential {
		RegisterTool(ToolGetCredential, bindGetCredential)
	}
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

func newRetireFixture(t *testing.T, runs ...CredentialRun) *retireFixture {
	t.Helper()
	return buildRetireFixture(t, false, runs...)
}

// newRetireAndCredentialFixture serves both tools over one directory, one
// ledger and one set of SPIRE entries.
func newRetireAndCredentialFixture(t *testing.T, runs ...CredentialRun) *retireFixture {
	t.Helper()
	return buildRetireFixture(t, true, runs...)
}

func buildRetireFixture(t *testing.T, alsoCredential bool, runs ...CredentialRun) *retireFixture {
	t.Helper()
	held := make([]string, 0, len(runs))
	for _, r := range runs {
		held = append(held, r.RunID)
	}
	f := &retireFixture{
		ledger:  newRetireLedger(),
		entries: newRetireEntries(held...),
		clock:   time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
	}
	f.runs = newRetireRuns(f.ledger, runs...)
	f.minter = &retireMinter{now: func() time.Time { return f.clock }}

	withRetireConfig(t, RetireAgentConfig{
		Runs:    f.runs,
		Entries: f.entries,
		Ledger:  f.ledger,
	})
	if alsoCredential {
		withCredentialConfig(t, CredentialConfig{
			Runs:    f.runs,
			Entries: f.entries,
			Minter:  f.minter,
			Ledger:  f.ledger,
			Now:     func() time.Time { return f.clock },
		})
	}
	f.session = serveRetire(t, alsoCredential)
	return f
}

type retireReply struct {
	isError bool
	wire    map[string]any
}

func (f *retireFixture) call(t *testing.T, runID string) retireReply {
	t.Helper()
	res, err := f.session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolRetireAgent),
		Arguments: map[string]any{"run_id": runID},
	})
	if err != nil {
		t.Fatalf("tools/call retire_agent(%q): %v", runID, err)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want a JSON object: %+v", res.StructuredContent, res.Content)
	}
	return retireReply{isError: res.IsError, wire: wire}
}

// mustRetire requires success and returns the reply object.
func (f *retireFixture) mustRetire(t *testing.T, runID string) map[string]any {
	t.Helper()
	r := f.call(t, runID)
	if r.isError {
		t.Fatalf("retire_agent(%q) failed: %v", runID, r.wire)
	}
	return r.wire
}

// mustRefuse requires the named class and the retryable flag ADR-0016 fixes
// for it.
func (f *retireFixture) mustRefuse(t *testing.T, runID string, class Class) map[string]any {
	t.Helper()
	r := f.call(t, runID)
	if !r.isError {
		t.Fatalf("retire_agent(%q) succeeded; want %s", runID, class)
	}
	if got := r.wire["error_class"]; got != string(class) {
		t.Fatalf("retire_agent(%q): error_class = %v, want %s (message %v)",
			runID, got, class, r.wire["message"])
	}
	if got, want := r.wire["retryable"], class.Retryable(); got != want {
		t.Errorf("retryable = %v, want %v for %s (ADR-0016)", got, want, class)
	}
	return r.wire
}

// getCredential calls the OTHER tool, over the same session and the same
// directory.
func (f *retireFixture) getCredential(t *testing.T, runID string) retireReply {
	t.Helper()
	res, err := f.session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolGetCredential),
		Arguments: map[string]any{"run_id": runID, "audience": AudienceSigstore},
	})
	if err != nil {
		t.Fatalf("tools/call get_credential(%q): %v", runID, err)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want a JSON object: %+v", res.StructuredContent, res.Content)
	}
	return retireReply{isError: res.IsError, wire: wire}
}

// retiredAtOf reads the reply's retired_at, and refuses an empty or unreadable
// one. Every assertion about "the same timestamp" goes through here, so a pair
// of zero values can never satisfy one.
func retiredAtOf(t *testing.T, reply map[string]any, what string) string {
	t.Helper()
	raw, ok := reply["retired_at"].(string)
	if !ok {
		t.Fatalf("%s: retired_at = %#v, want a string", what, reply["retired_at"])
	}
	if raw == "" {
		t.Fatalf("%s: retired_at is empty; IP §4 requires the instant the run was retired", what)
	}
	if _, err := event.ParseTimestamp(raw); err != nil {
		t.Fatalf("%s: retired_at %q is not a doc 02 §1 timestamp: %v", what, raw, err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// MCP-005 — schema conformance, and the idempotency IP §4 states in the same
// sentence as the signature.
// ---------------------------------------------------------------------------

// TestMCP005RetireAgentSchemaConformance is doc 07 MCP-001..005 for this tool:
// "valid input → documented result shape | Exact schema match | IP §4".
//
// IP §4: retire_agent(run_id) → {retired_at}. One parameter and one result
// member — and, ADR-0004, no idempotency_key on either side, because a run
// retires once and its run_id is the only key that could ever name that.
func TestMCP005RetireAgentSchemaConformance(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))

	tools, err := f.session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var advertised *sdk.Tool
	for _, tool := range tools.Tools {
		if tool.Name == string(ToolRetireAgent) {
			advertised = tool
		}
	}
	if advertised == nil {
		t.Fatalf("tools/list does not advertise retire_agent: %+v", tools.Tools)
	}

	in := retireSchemaMembers(t, advertised.InputSchema)
	if want := []string{"run_id"}; !equalStrings(in, want) {
		t.Errorf("input schema members = %v, IP §4 says retire_agent(run_id) = %v", in, want)
	}
	out := retireSchemaMembers(t, advertised.OutputSchema)
	if want := []string{"retired_at"}; !equalStrings(out, want) {
		t.Errorf("result schema members = %v, IP §4 says {retired_at} = %v", out, want)
	}

	reply := f.mustRetire(t, "run-a")
	members := make([]string, 0, len(reply))
	for k := range reply {
		members = append(members, k)
	}
	if want := []string{"retired_at"}; !equalStrings(sortedStrings(members), want) {
		t.Errorf("result members = %v, IP §4 says %v", sortedStrings(members), want)
	}
	retiredAt := retiredAtOf(t, reply, "retire_agent(run-a)")

	// One retirement, one run_retired event (doc 02 §3, I3).
	recs := f.ledger.of(event.EventTypeRunRetired, "run-a")
	if len(recs) != 1 {
		t.Fatalf("appended %d run_retired events for one retirement, want 1: %+v", len(recs), recs)
	}
	rec := recs[0]
	for _, c := range []struct{ name, want string }{
		{event.FieldEventType, event.EventTypeRunRetired},
		{event.FieldRunID, "run-a"},
		{event.FieldSpiffeID, retireSPIFFEID("run-a")},
		{event.FieldSource, event.SourceMCP},
		{event.FieldSchemaVersion, event.SchemaVersion},
	} {
		if got := rec[c.name]; got != c.want {
			t.Errorf("run_retired[%s] = %#v, want %q", c.name, got, c.want)
		}
	}
	// The reply names the instant the ledger recorded, not a second reading of
	// a clock. Two records of one retirement cannot disagree.
	if got := rec[event.FieldTS]; got != retiredAt {
		t.Errorf("retired_at = %q, run_retired.ts = %#v; the reply must be the ledger's own instant",
			retiredAt, got)
	}
	// ADR-0004: forbidden on run_retired, whatever the source.
	if _, present := rec[event.FieldIdempotencyKey]; present {
		t.Errorf("run_retired carries an idempotency_key; ADR-0004 forbids it")
	}
	// E4/doc 02 §3: run_retired has no type-specific members at all.
	if _, present := rec[event.FieldPayloadDigest]; present {
		t.Errorf("run_retired carries a payload_digest; doc 02 §3 gives it none")
	}
	// The identity is gone; the record of it is not (I4).
	if f.entries.holds("run-a") {
		t.Errorf("the SPIRE entry survived retirement")
	}
}

func retireSchemaMembers(t *testing.T, schema any) []string {
	t.Helper()
	if schema == nil {
		t.Fatalf("tool advertises no schema")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var decoded struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode schema %s: %v", raw, err)
	}
	names := make([]string, 0, len(decoded.Properties))
	for k := range decoded.Properties {
		names = append(names, k)
	}
	return sortedStrings(names)
}

// TestMCP005RetireAgentIsIdempotentWithTheOriginalTimestamp. IP §4:
// "Idempotent: retiring a retired run returns success with the original
// timestamp."
//
// The reading that matters is ORIGINAL. A fresh timestamp on the second call
// would be a second answer to one question, and the ledger — which is the only
// durable record of when the retirement happened (I4) — would disagree with
// the reply the caller was given.
//
// This case is written so that it cannot pass vacuously. The first retirement
// is proved to have HAPPENED (a run_retired in the chain, an entry deleted)
// before the second is asked for; the timestamp is required to be non-empty
// and to parse; it is required to equal the ledger's own ts; and the fixture's
// ledger stamps a distinct instant on every append, which the probe at the end
// measures — so "the same timestamp twice" is unreachable if a second event
// was written.
func TestMCP005RetireAgentIsIdempotentWithTheOriginalTimestamp(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))

	if !f.entries.holds("run-a") {
		t.Fatalf("the fixture starts with no SPIRE entry; there would be nothing to retire")
	}

	first := f.mustRetire(t, "run-a")
	original := retiredAtOf(t, first, "first retire_agent(run-a)")

	// The first retirement really happened, in both systems.
	recs := f.ledger.of(event.EventTypeRunRetired, "run-a")
	if len(recs) != 1 {
		t.Fatalf("first call appended %d run_retired events, want 1: %+v", len(recs), recs)
	}
	if got := recs[0][event.FieldTS]; got != original {
		t.Fatalf("retired_at = %q but the ledger recorded ts = %#v", original, got)
	}
	if f.entries.holds("run-a") {
		t.Fatalf("first call left the SPIRE entry in place; nothing was retired")
	}
	if got := len(f.entries.deleted()); got != 1 {
		t.Fatalf("first call issued %d deletions, want 1", got)
	}

	second := f.mustRetire(t, "run-a")
	repeat := retiredAtOf(t, second, "second retire_agent(run-a)")

	if repeat != original {
		t.Errorf("second retire_agent(run-a) returned %q, want the original %q (IP §4)", repeat, original)
	}
	if got := f.ledger.of(event.EventTypeRunRetired, "run-a"); len(got) != 1 {
		t.Errorf("a second retirement appended a second run_retired: %d total", len(got))
	}
	// I4 again, from the other side: the chain still walks.
	if _, err := ledger.Verify(f.ledger.all()); err != nil {
		t.Errorf("the chain no longer verifies after two retirements: %v", err)
	}

	// The probe is what makes the assertion above bite: this ledger stamps a
	// different instant on every append, so two equal timestamps can only mean
	// one append.
	probe, err := f.ledger.Append(t.Context(), event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     event.EventTypeRunExpired,
		event.FieldSource:        event.SourceReaper,
		event.FieldRunID:         "run-a",
		event.FieldSpiffeID:      retireSPIFFEID("run-a"),
	})
	if err != nil {
		t.Fatalf("probe append: %v", err)
	}
	if got := probe[event.FieldTS]; got == original {
		t.Errorf("the fixture's clock does not advance between appends (%v); "+
			"the equality above would have proved nothing", got)
	}
}

// TestRetireAgentTakesNoIdempotencyKey. ADR-0004: retire_agent's idempotency
// is intrinsic to run_id — "a run retires once. A separate key would invent a
// way for two retirements of one run to disagree" — so the tool accepts none
// and the event carries none.
//
// The tool's input schema is closed, so a key cannot be smuggled into the call
// even by a caller that supplies one: it is refused at the protocol boundary,
// before any dependency is touched.
func TestRetireAgentTakesNoIdempotencyKey(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))

	res, err := f.session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolRetireAgent),
		Arguments: map[string]any{"run_id": "run-a", "idempotency_key": "ret-1"},
	})
	if err != nil {
		t.Fatalf("tools/call retire_agent: %v", err)
	}
	if !res.IsError {
		t.Fatalf("retire_agent accepted an idempotency_key; IP §4 gives it none")
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "idempotency_key") {
		t.Errorf("retire_agent refused for some reason other than the key: %q", text)
	}
	if got := f.ledger.calls(); got != 0 {
		t.Errorf("the refused call still reached the ledger (%d appends)", got)
	}
	if got := len(f.entries.deleted()); got != 0 {
		t.Errorf("the refused call still reached SPIRE (%d deletions)", got)
	}

	// And the retirement it does record carries no key either — enforced by
	// the validator in the double, and asserted here so the reason is legible.
	f.mustRetire(t, "run-a")
	for _, rec := range f.ledger.all() {
		if _, present := rec[event.FieldIdempotencyKey]; present {
			t.Errorf("%v carries an idempotency_key; ADR-0004 forbids it on run_retired",
				rec[event.FieldEventType])
		}
	}
}

// ---------------------------------------------------------------------------
// MCP-009 — any tool against a retired run.
// ---------------------------------------------------------------------------

// TestMCP009AnyToolAgainstARetiredRunIsRefused. Doc 07 MCP-009: "Any tool
// against retired run → RUN_ALREADY_RETIRED (retire itself: idempotent success
// with original timestamp)."
//
// This is an interaction, not an assumption: get_credential is the shipped
// tool, bound on the same server, resolving run_id against the same directory,
// and this test drives it before and after a real retirement.
//
// Three things make the refusal non-vacuous. A control call SUCCEEDS before
// retirement, so the run is known, live and credentialable and the later
// refusal cannot be a misconfigured fixture. The class is required to be
// RUN_ALREADY_RETIRED exactly — RUN_NOT_FOUND is what a merely-deleted SPIRE
// entry produces (spire.Client.RequireActiveRun), so the distinction is the
// whole content of the case: the refusal has to come from the LEDGER's record
// of the retirement. And the refusal's message must name the instant this
// retirement returned.
//
// IP §6.2 requires retirement to be effective immediately with no
// cached-credential grace path through the MCP. RM-014 measured SPIRE's own
// convergence at 3-7 seconds; there is no sleep anywhere below, because a test
// that waited would be measuring SPIRE instead of the MCP.
func TestMCP009AnyToolAgainstARetiredRunIsRefused(t *testing.T) {
	f := newRetireAndCredentialFixture(t, retireRunRef("run-a"))

	// Control: while the run is live, the other tool works.
	live := f.getCredential(t, "run-a")
	if live.isError {
		t.Fatalf("get_credential failed for a live run: %v", live.wire)
	}
	if got := f.minter.count(); got != 1 {
		t.Fatalf("the control call minted %d credentials, want 1", got)
	}

	retiredAt := retiredAtOf(t, f.mustRetire(t, "run-a"), "retire_agent(run-a)")

	started := time.Now()
	refused := f.getCredential(t, "run-a")
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("the refusal took %s; retirement must not wait for SPIRE to converge (IP §6.2)", elapsed)
	}
	if !refused.isError {
		t.Fatalf("get_credential succeeded for a retired run: %v", refused.wire)
	}
	if got := refused.wire["error_class"]; got != string(ClassRunAlreadyRetired) {
		t.Fatalf("error_class = %v, want %s (message %v)",
			got, ClassRunAlreadyRetired, refused.wire["message"])
	}
	if got := refused.wire["retryable"]; got != false {
		t.Errorf("retryable = %v, want false: I4 forbids un-retiring (ADR-0016)", got)
	}
	if got := refused.wire["run_id"]; got != "run-a" {
		t.Errorf("run_id = %v, want run-a", got)
	}
	// The refusal is caused by THIS retirement, not by some other state.
	msg, ok := refused.wire["message"].(string)
	if !ok {
		t.Fatalf("message = %#v, want a string", refused.wire["message"])
	}
	if !strings.Contains(msg, retiredAt) {
		t.Errorf("message %q does not name the instant retire_agent returned (%s)", msg, retiredAt)
	}
	if got := f.minter.count(); got != 1 {
		t.Errorf("a retired run minted another credential (%d)", got)
	}
	if got := len(f.ledger.of(event.EventTypeCredentialIssued, "run-a")); got != 1 {
		t.Errorf("a retired run appended a second credential_issued: %d total", got)
	}

	// "retire itself: idempotent success with original timestamp."
	again := retiredAtOf(t, f.mustRetire(t, "run-a"), "second retire_agent(run-a)")
	if again != retiredAt {
		t.Errorf("second retire_agent returned %q, want the original %q", again, retiredAt)
	}
	if got := len(f.ledger.of(event.EventTypeRunRetired, "run-a")); got != 1 {
		t.Errorf("the second retirement appended a second run_retired: %d total", got)
	}
}

// ---------------------------------------------------------------------------
// I4 — retirement deletes the identity and never the record.
// ---------------------------------------------------------------------------

// TestRetireAgentNeverDeletesLedgerContent. I4: "No record is ever deleted or
// mutated... Retirement deletes the SPIRE entry, never ledger content."
//
// RM-015's SPI-004 asserts this at the client layer. This is the same claim at
// the tool layer: the run's history is compared byte for byte across the
// retirement, and the chain is re-walked afterwards.
func TestRetireAgentNeverDeletesLedgerContent(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))

	seed := []event.Fields{
		{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeRunRegistered,
			event.FieldSource:         event.SourceMCP,
			event.FieldRunID:          "run-a",
			event.FieldSpiffeID:       retireSPIFFEID("run-a"),
			event.FieldIdempotencyKey: "reg-run-a",
			event.FieldAgentType:      retireAgentType,
			event.FieldTaskRef:        "RM-025",
		},
		{
			event.FieldSchemaVersion:    event.SchemaVersion,
			event.FieldEventType:        event.EventTypeCredentialIssued,
			event.FieldSource:           event.SourceMCP,
			event.FieldRunID:            "run-a",
			event.FieldSpiffeID:         retireSPIFFEID("run-a"),
			event.FieldAudience:         AudienceSigstore,
			event.FieldCredentialExpiry: event.NewTimestamp(f.clock.Add(5 * time.Minute)).String(),
		},
	}
	for _, body := range seed {
		if _, err := f.ledger.Append(t.Context(), body); err != nil {
			t.Fatalf("seeding the chain: %v", err)
		}
	}
	before := retireCanonicalBytes(t, f.ledger.all())

	f.mustRetire(t, "run-a")

	after := retireCanonicalBytes(t, f.ledger.all())
	if len(after) != len(before)+1 {
		t.Fatalf("the chain went from %d events to %d; retirement appends one and removes none",
			len(before), len(after))
	}
	for i, want := range before {
		if after[i] != want {
			t.Errorf("event %d changed across retirement:\n before %s\n  after %s", i+1, want, after[i])
		}
	}
	if _, err := ledger.Verify(f.ledger.all()); err != nil {
		t.Errorf("the chain does not verify after retirement: %v", err)
	}
	// Still readable, and still about this run.
	if got := len(f.ledger.of(event.EventTypeRunRegistered, "run-a")); got != 1 {
		t.Errorf("the run's run_registered is no longer readable after retirement (%d found)", got)
	}
	if got := len(f.ledger.of(event.EventTypeCredentialIssued, "run-a")); got != 1 {
		t.Errorf("the run's credential_issued is no longer readable after retirement (%d found)", got)
	}
}

func retireCanonicalBytes(t *testing.T, records []event.Fields) []string {
	t.Helper()
	out := make([]string, 0, len(records))
	for _, rec := range records {
		b, err := event.Canonicalize(rec)
		if err != nil {
			t.Fatalf("canonicalize %v: %v", rec, err)
		}
		out = append(out, string(b))
	}
	return out
}

// ---------------------------------------------------------------------------
// ADR-0020 §5 — two genuinely concurrent FIRST retirements of one run.
//
// The decision: "Two genuinely concurrent FIRST retirements of one run can
// therefore both find no record and both append, leaving two `run_retired`
// events in the chain. ... both callers are told the same instant, because
// the directory answers with the earliest." RM-095 (#150) is that the second
// half was never implemented: retire() answered a winning first-time caller
// with its OWN append's ts, never re-querying the directory for the earliest.
//
// New test ID, not in doc 07 (which is not edited by this issue's scope):
// MCP-019 (C) two concurrent first retirements of one run report the same,
// earliest instant.
// ---------------------------------------------------------------------------

// TestMCP019ConcurrentFirstRetirementsReportTheEarliestInstant drives the
// window rather than assuming it. armRendezvous holds two goroutines calling
// retire_agent for the SAME run at a barrier inside the run directory's
// CredentialRun, so BOTH have read "not retired" before EITHER is free to
// proceed to record() and append — the exact race ADR-0020 §5 accepts,
// forced instead of hoped for.
//
// The mechanism is checked before the consequence is: if the rendezvous
// failed to force a genuine double append, the chain would hold one
// run_retired event and the comparison below would prove nothing. Two
// investigations on this same campaign (RM-069, and #145's first answer)
// concluded from a confident reading of the code that the harness was at
// fault, and fault injection reversed both — so this case refuses to trust
// its own barrier without checking what it left on the chain.
func TestMCP019ConcurrentFirstRetirementsReportTheEarliestInstant(t *testing.T) {
	chain := newRetireLedger()
	runs := newRetireRuns(chain, retireRunRef("run-a"))
	entries := newRetireEntries("run-a")
	svc := &retireService{runs: runs, entries: entries, ledger: chain}
	runs.armRendezvous(2)

	type outcome struct {
		out retireAgentOut
		err error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			out, err := svc.retire(context.Background(), retireAgentIn{RunID: "run-a"})
			results <- outcome{out, err}
		}()
	}
	first := <-results
	second := <-results
	if first.err != nil {
		t.Fatalf("first concurrent retire_agent(run-a) failed: %v", first.err)
	}
	if second.err != nil {
		t.Fatalf("second concurrent retire_agent(run-a) failed: %v", second.err)
	}

	// The mechanism, confirmed rather than assumed: the rendezvous forced
	// both callers to observe "not retired" before either appended, so the
	// chain must hold two run_retired events for the one run.
	recorded := chain.of(event.EventTypeRunRetired, "run-a")
	if len(recorded) != 2 {
		t.Fatalf("the rendezvous did not force two genuinely concurrent first retirements of "+
			"run-a: %d run_retired events on the chain, want 2 — ADR-0020 §5's window was not "+
			"actually driven, and nothing below this line would be evidence of anything", len(recorded))
	}

	earliest := event.NewTimestamp(chain.retiredAt("run-a")).String()

	// ADR-0020 §5: "both callers are told the same instant, because the
	// directory answers with the earliest."
	if first.out.RetiredAt != second.out.RetiredAt {
		t.Errorf("two concurrent first retirements of run-a reported different instants: "+
			"%q and %q. ADR-0020 §5: both callers must be told the same, earliest instant.",
			first.out.RetiredAt, second.out.RetiredAt)
	}
	for i, got := range []string{first.out.RetiredAt, second.out.RetiredAt} {
		if got != earliest {
			t.Errorf("concurrent caller %d reported retired_at %q; the earliest run_retired on "+
				"the chain is %q (ADR-0020 §5)", i+1, got, earliest)
		}
	}
}

// TestMCP019SecondRetirementAfterAConcurrentPairStillReadsTheEarliest.
// ADR-0020 §5's reconciliation has to survive past the two racing callers
// too: doc 07 MCP-009 promises "idempotent success with original timestamp"
// to every LATER caller, and "original" is ambiguous on its own when two
// `run_retired` events exist. It means the earliest, same as the two racing
// callers were told.
func TestMCP019SecondRetirementAfterAConcurrentPairStillReadsTheEarliest(t *testing.T) {
	chain := newRetireLedger()
	runs := newRetireRuns(chain, retireRunRef("run-a"))
	entries := newRetireEntries("run-a")
	svc := &retireService{runs: runs, entries: entries, ledger: chain}
	runs.armRendezvous(2)

	results := make(chan retireAgentOut, 2)
	for range 2 {
		go func() {
			out, err := svc.retire(context.Background(), retireAgentIn{RunID: "run-a"})
			if err != nil {
				t.Errorf("concurrent retire_agent(run-a): %v", err)
			}
			results <- out
		}()
	}
	<-results
	<-results

	if n := len(chain.of(event.EventTypeRunRetired, "run-a")); n != 2 {
		t.Fatalf("the rendezvous did not force two run_retired events: got %d, want 2", n)
	}
	earliest := event.NewTimestamp(chain.retiredAt("run-a")).String()

	later, err := svc.retire(context.Background(), retireAgentIn{RunID: "run-a"})
	if err != nil {
		t.Fatalf("the later, uncontested retire_agent(run-a) failed: %v", err)
	}
	if later.RetiredAt != earliest {
		t.Errorf("a later retire_agent(run-a) returned %q, want the earliest of the two "+
			"concurrent appends, %q (ADR-0020 §5)", later.RetiredAt, earliest)
	}
	if n := len(chain.of(event.EventTypeRunRetired, "run-a")); n != 2 {
		t.Errorf("the later call appended a third run_retired event: %d total, want 2", n)
	}
}

// TestRetireAgentRefusesWhenTheEarliestReQueryFails. earliestRetiredAt's own
// three refusals: doc 02 §5's directory read can fail, can forget a run whose
// retirement this very call just appended, or can answer as though that
// append never happened. None of these three is a scenario the shipped
// rundir.Directory produces on its own — it reads the same chain this tool
// just wrote to — but IP §2's 100%-branch floor asks for every error-return
// path of every MCP tool, this one included, and answerAtCall is what makes
// each one reachable without inventing a second implementation of the
// directory to get there.
func TestRetireAgentRefusesWhenTheEarliestReQueryFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force func(runs *retireRuns)
		class Class
	}{
		{
			name: "the re-query itself fails",
			force: func(runs *retireRuns) {
				runs.answerAtCall(2, CredentialRun{}, false, &ledger.StoreError{
					Class: ledger.ClassLedgerUnavailable, Op: "read", Retryable: true,
					Err: fmt.Errorf("connection refused"),
				})
			},
			class: ClassLedgerUnavailable,
		},
		{
			name: "the re-query no longer finds the run",
			force: func(runs *retireRuns) {
				runs.answerAtCall(2, CredentialRun{}, false, nil)
			},
			class: ClassInvariantViolation,
		},
		{
			name: "the re-query reports the run not retired",
			force: func(runs *retireRuns) {
				runs.answerAtCall(2, CredentialRun{RunID: "run-a", SPIFFEID: retireSPIFFEID("run-a")}, true, nil)
			},
			class: ClassInvariantViolation,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := newRetireLedger()
			runs := newRetireRuns(chain, retireRunRef("run-a"))
			entries := newRetireEntries("run-a")
			svc := &retireService{runs: runs, entries: entries, ledger: chain}
			tc.force(runs)

			_, err := svc.retire(context.Background(), retireAgentIn{RunID: "run-a"})
			if err == nil {
				t.Fatalf("retire_agent(run-a) succeeded; the forced re-query answer should have "+
					"refused it with %s", tc.class)
			}
			if got := Classify(err).Class; got != tc.class {
				t.Errorf("class = %s, want %s (error: %v)", got, tc.class, err)
			}
			// The append this call made before the re-query is I4: it stands
			// regardless of what the re-query itself does afterward.
			if n := len(chain.of(event.EventTypeRunRetired, "run-a")); n != 1 {
				t.Errorf("the call's own run_retired should still stand: %d events, want 1", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Ordering: the ledger is written before the identity changes state.
// ---------------------------------------------------------------------------

// TestRetireAgentRecordsBeforeItDeletes. ADR-0018 states the rule for both
// directions: "the ledger may describe an identity that does not exist; SPIRE
// must never hold an identity the ledger does not describe." RM-017's reaper
// records run_expired before deleting for the same reason.
//
// With SPIRE refusing, the retirement is recorded and the call fails
// retryably. The window that leaves is a run the ledger describes as retired
// whose entry still exists — and that window cannot let anything happen,
// because every MCP path reads the ledger first (MCP-009 above). The retry
// converges: it deletes the entry and answers with the ORIGINAL instant.
func TestRetireAgentRecordsBeforeItDeletes(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))
	f.entries.fail(&spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "retire_agent",
		Message: "connection refused", Retryable: true,
	})

	f.mustRefuse(t, "run-a", ClassIdentityUnavailable)

	recs := f.ledger.of(event.EventTypeRunRetired, "run-a")
	if len(recs) != 1 {
		t.Fatalf("SPIRE refused and %d run_retired events were appended, want 1: the record "+
			"is written first so it can never fall behind SPIRE (ADR-0018)", len(recs))
	}
	if !f.entries.holds("run-a") {
		t.Fatalf("the entry was deleted by a call that reported failure")
	}
	original, ok := recs[0][event.FieldTS].(string)
	if !ok || original == "" {
		t.Fatalf("the recorded retirement has no readable ts: %#v", recs[0][event.FieldTS])
	}

	f.entries.recover()
	retry := retiredAtOf(t, f.mustRetire(t, "run-a"), "the retry")
	if retry != original {
		t.Errorf("the retry returned %q, want the originally recorded %q", retry, original)
	}
	if got := len(f.ledger.of(event.EventTypeRunRetired, "run-a")); got != 1 {
		t.Errorf("the retry appended a second run_retired: %d total", got)
	}
	if f.entries.holds("run-a") {
		t.Errorf("the retry did not delete the entry")
	}
}

// TestRetireAgentFailsClosedWhenTheLedgerIsDown. I3 and IP §6.4: no action
// without a record, so a retirement that cannot be recorded does not happen.
// The entry survives, and SPIRE is never even asked.
func TestRetireAgentFailsClosedWhenTheLedgerIsDown(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))
	f.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})

	f.mustRefuse(t, "run-a", ClassLedgerUnavailable)

	if got := f.entries.deleted(); len(got) != 0 {
		t.Errorf("SPIRE was asked to delete %d entries with the ledger down: %+v", len(got), got)
	}
	if !f.entries.holds("run-a") {
		t.Errorf("the entry was deleted without a record of the retirement (I3)")
	}
}

// TestRetireAgentReportsAnUnclassifiedLedgerFailure. IP §4's vocabulary is
// closed; a failure the ledger did not classify is a defect, which is
// alert-level and not retryable (ADR-0016).
func TestRetireAgentReportsAnUnclassifiedLedgerFailure(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))
	f.ledger.fail(fmt.Errorf("something the ledger did not name"))

	f.mustRefuse(t, "run-a", ClassInvariantViolation)
	if !f.entries.holds("run-a") {
		t.Errorf("the entry was deleted after an unclassified ledger failure")
	}
}

// ---------------------------------------------------------------------------
// The run has to exist, and the directory has to answer about it.
// ---------------------------------------------------------------------------

// TestRetireAgentRefusesAnUnknownRun. Doc 07 MCP-010: RUN_NOT_FOUND.
func TestRetireAgentRefusesAnUnknownRun(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))

	f.mustRefuse(t, "run-zz", ClassRunNotFound)
	if got := f.ledger.calls(); got != 0 {
		t.Errorf("appended for an unknown run (%d ledger calls)", got)
	}
	if got := len(f.entries.deleted()); got != 0 {
		t.Errorf("asked SPIRE to delete %d entries for an unknown run", got)
	}
}

// TestRetireAgentRefusesARunIDThatNamesNoRun. A run_id that cannot be one
// names no run, and is refused before any dependency is consulted.
func TestRetireAgentRefusesARunIDThatNamesNoRun(t *testing.T) {
	f := newRetireFixture(t, retireRunRef("run-a"))
	for _, bad := range []string{"", "Run-A", "run a", "-run", strings.Repeat("r", 64), "../run-a"} {
		t.Run(fmt.Sprintf("run_id=%q", bad), func(t *testing.T) {
			f.mustRefuse(t, bad, ClassRunNotFound)
		})
	}
	if got := f.runs.lookups(); got != 0 {
		t.Errorf("the run directory was consulted %d times for a malformed run id", got)
	}
	if got := f.ledger.calls(); got != 0 {
		t.Errorf("the ledger was written %d times for a malformed run id", got)
	}
}

// TestRetireAgentReportsADirectoryFailureAsTheLedgerFailureItIs. The directory
// reads the chain, so its outage is the ledger's outage and carries the
// ledger's class (ADR-0016: narrowed, never widened).
func TestRetireAgentReportsADirectoryFailureAsTheLedgerFailureItIs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		class Class
	}{
		{"a classified outage", &ledger.StoreError{
			Class: ledger.ClassLedgerUnavailable, Op: "read", Retryable: true,
			Err: fmt.Errorf("connection refused"),
		}, ClassLedgerUnavailable},
		{"an unclassified failure", fmt.Errorf("the directory broke"), ClassInvariantViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRetireFixture(t, retireRunRef("run-a"))
			f.runs.fail(tc.err)

			f.mustRefuse(t, "run-a", tc.class)
			if got := len(f.entries.deleted()); got != 0 {
				t.Errorf("SPIRE was asked to delete an entry after a directory failure")
			}
		})
	}
}

// TestRetireAgentRefusesADirectoryThatAnswersForTheWrongRun. The directory's
// answer is checked and not trusted: the same refusal get_credential makes
// before it asks SPIRE to mint, made here before it asks SPIRE to delete. A
// directory that named another run's identity would otherwise be a way to
// delete an entry that is not this run's.
func TestRetireAgentRefusesADirectoryThatAnswersForTheWrongRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  CredentialRun
	}{
		{"a different run id", CredentialRun{
			RunID: "run-b", AgentType: retireAgentType, TaskID: retireTaskID,
			SPIFFEID: retireSPIFFEID("run-b"),
		}},
		{"an identity that is not a run identity", CredentialRun{
			RunID: "run-a", AgentType: retireAgentType, TaskID: retireTaskID,
			SPIFFEID: "spiffe://" + retireTrustDomain + "/workload/run-a",
		}},
		{"an identity naming another run", CredentialRun{
			RunID: "run-a", AgentType: retireAgentType, TaskID: retireTaskID,
			SPIFFEID: retireSPIFFEID("run-b"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRetireFixture(t, retireRunRef("run-a"))
			f.runs.answerWith("run-a", tc.run)

			f.mustRefuse(t, "run-a", ClassInvariantViolation)
			if got := f.ledger.calls(); got != 0 {
				t.Errorf("appended %d events on the strength of an answer about another run", got)
			}
			if got := len(f.entries.deleted()); got != 0 {
				t.Errorf("asked SPIRE to delete %d entries on that answer", got)
			}
		})
	}
}

// TestRetireAgentRefusesARetirementTheLedgerDidNotTimestamp. The reply's whole
// content is the instant the run was retired; a record without one cannot be
// answered with, and an empty retired_at must never reach a caller — that is
// the shape a vacuous idempotency assertion takes, and the tool refuses it.
func TestRetireAgentRefusesARetirementTheLedgerDidNotTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name   string
		absent bool
		bad    string
	}{
		{"no ts at all", true, ""},
		{"a ts that is not an instant", false, "yesterday"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRetireFixture(t, retireRunRef("run-a"))
			f.ledger.stampBadTS(tc.absent, tc.bad)

			f.mustRefuse(t, "run-a", ClassInvariantViolation)
			if got := len(f.entries.deleted()); got != 0 {
				t.Errorf("deleted the entry on a record it could not read")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

// TestRetireAgentIsNotServedUntilItIsConfigured. An advertised tool with no
// dependencies behind it is a defect in the wiring, and IP §4 has no "internal
// error" class (ADR-0016).
func TestRetireAgentIsNotServedUntilItIsConfigured(t *testing.T) {
	retireMu.Lock()
	saved := retireActive
	retireActive = nil
	retireMu.Unlock()
	t.Cleanup(func() {
		retireMu.Lock()
		retireActive = saved
		retireMu.Unlock()
	})

	f := &retireFixture{session: serveRetire(t, false)}
	f.mustRefuse(t, "run-a", ClassInvariantViolation)
}

// TestConfigureRetireAgentRefusesAnIncompleteConfiguration. Each dependency is
// load-bearing: without the ledger the retirement is unrecordable (I3),
// without SPIRE the entry outlives the run (IP §1), and without the directory
// there is nothing that knows what a run_id names.
func TestConfigureRetireAgentRefusesAnIncompleteConfiguration(t *testing.T) {
	full := RetireAgentConfig{
		Runs:    newRetireRuns(newRetireLedger()),
		Entries: newRetireEntries(),
		Ledger:  newRetireLedger(),
	}
	for _, tc := range []struct {
		name string
		cfg  RetireAgentConfig
	}{
		{"no run directory", RetireAgentConfig{Entries: full.Entries, Ledger: full.Ledger}},
		{"no SPIRE client", RetireAgentConfig{Runs: full.Runs, Ledger: full.Ledger}},
		{"no ledger", RetireAgentConfig{Runs: full.Runs, Entries: full.Entries}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := ConfigureRetireAgent(tc.cfg)
			if err == nil {
				restore()
				t.Fatalf("ConfigureRetireAgent accepted a configuration with %s", tc.name)
			}
			if got := Classify(err).Class; got != ClassInvariantViolation {
				t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
			}
		})
	}

	// The restore function puts back what was installed before.
	restore, err := ConfigureRetireAgent(full)
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	retireMu.RLock()
	installed := retireActive
	retireMu.RUnlock()
	if installed == nil {
		t.Fatalf("ConfigureRetireAgent installed nothing")
	}
	restore()
	retireMu.RLock()
	after := retireActive
	retireMu.RUnlock()
	if after == installed {
		t.Errorf("restore() left the new configuration installed")
	}
}
