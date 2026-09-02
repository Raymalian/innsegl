// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// register_agent, RM-022 (#30). Doc 07: MCP-001 (schema conformance) and
// MCP-007 (same idempotency_key twice → same run_id and spiffe_id, exactly one
// SPIRE entry and one run_registered event).
//
// WHAT IS REAL HERE AND WHAT IS NOT
//
// The ledger and the idempotency store are REAL, on a real Postgres, because
// MCP-007's guarantee rests on them: the ledger's UNIQUE idempotency_key is
// what makes one key one event (LED-008), and the store's leased claim is what
// makes one key one reply (ADR-0017). An in-memory stand-in for either would
// assert the property and prove nothing.
//
// SPIRE is a fake. Doc 07 classes MCP-001 and MCP-007 as contract tests and
// IP §2 allows mocks for those; the SPIRE behaviour the fake imitates — one
// entry per run, a second RegisterRun for the same run reported as
// DUPLICATE_REQUEST rather than silently making a second identity — is
// measured against real containerised SPIRE by RM-015's
// TestRegisterRunIsOneEntryPerRun, and is not re-proved here. What is proved
// here is what the MCP does with that answer.

const (
	raTrustDomain = "innsegl.dev"
	// Golden fixture 01's own values: agent_type "fix-ci", task_ref
	// "JIRA-118", and a SPIFFE ID whose {task_id} is the lowercased "jira-118".
	raAgentType = "fix-ci"
	raTaskID    = "JIRA-118"
	raParentID  = "spiffe://innsegl.dev/spire/agent/x509pop/node-1"
)

// raSPIRE stands in for RM-015's admin client.
type raSPIRE struct {
	mu          sync.Mutex
	trustDomain string
	entries     map[string]spire.Entry
	seq         int
	attempts    int
	registerErr error
	lookupErr   error
	// forgetOnLookup makes an entry vanish between the duplicate report and
	// the lookup that follows it — what a concurrent retirement looks like.
	forgetOnLookup bool
	// entered and release, when both non-nil, hold every RegisterRun at the
	// door so a test can interleave two calls deterministically.
	entered chan struct{}
	release chan struct{}
}

func newRASPIRE(trustDomain string) *raSPIRE {
	return &raSPIRE{trustDomain: trustDomain, entries: make(map[string]spire.Entry)}
}

func (f *raSPIRE) TrustDomain() string { return f.trustDomain }

func (f *raSPIRE) gate() {
	f.mu.Lock()
	entered, release := f.entered, f.release
	f.mu.Unlock()
	if entered == nil {
		return
	}
	entered <- struct{}{}
	<-release
}

func (f *raSPIRE) RegisterRun(_ context.Context, reg spire.Registration) (spire.Entry, error) {
	f.gate()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.registerErr != nil {
		return spire.Entry{}, f.registerErr
	}
	id, err := reg.Run.SPIFFEID(f.trustDomain)
	if err != nil {
		return spire.Entry{}, err
	}
	if _, dup := f.entries[id]; dup {
		// Exactly what real SPIRE says, as RM-015 measured it.
		return spire.Entry{}, &spire.Error{
			Class: spire.ClassDuplicateRequest, Op: "register_agent", RunID: reg.Run.RunID,
			Message: "entry already exists", Retryable: false,
		}
	}
	f.seq++
	ttl := reg.TTL
	if ttl == 0 {
		ttl = spire.DefaultRunTTL
	}
	e := spire.Entry{
		ID: fmt.Sprintf("entry-%d", f.seq), SPIFFEID: id,
		ParentID: reg.ParentID, Selectors: reg.Selectors, TTL: ttl,
	}
	f.entries[id] = e
	return e, nil
}

func (f *raSPIRE) LookupRun(_ context.Context, run spire.RunRef) (spire.Entry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return spire.Entry{}, false, f.lookupErr
	}
	id, err := run.SPIFFEID(f.trustDomain)
	if err != nil {
		return spire.Entry{}, false, err
	}
	if f.forgetOnLookup {
		delete(f.entries, id)
	}
	e, ok := f.entries[id]
	return e, ok, nil
}

func (f *raSPIRE) entryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func (f *raSPIRE) holds(spiffeID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.entries[spiffeID]
	return ok
}

func (f *raSPIRE) registerAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

// raClock advances a second on every reading, so that two executions of one
// call cannot accidentally agree on expires_at. If a replay were recomputing
// its reply instead of reading the recorded one, the two would differ and the
// assertion would catch it.
type raClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *raClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(time.Second)
	return c.at
}

type raEnv struct {
	identities *raSPIRE
	ledger     *ledger.Store
	idem       *IdempotencyStore
	dsn        string
	clock      *raClock
	ttl        time.Duration
}

// raSetup wires register_agent onto a real ledger, a real idempotency store
// and a fake SPIRE, and installs the configuration for the test's duration.
func raSetup(t *testing.T, lease time.Duration, mutate func(*RegisterAgentConfig)) *raEnv {
	t.Helper()
	idem, dsn := newStore(t, WithIdempotencyLease(lease))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	env := &raEnv{
		identities: newRASPIRE(raTrustDomain),
		ledger:     lg,
		idem:       idem,
		dsn:        dsn,
		clock:      &raClock{at: time.Date(2026, 8, 29, 9, 14, 3, 0, time.UTC)},
		ttl:        5 * time.Minute,
	}
	// Identity mode `literal` unless a case says otherwise. Every assertion in
	// this file predates RM-079 (#116) and is about golden fixture 01's own
	// values — `fix-ci`, `jira-118` — so the fixture states the mode that
	// produces them rather than letting the assertions quietly become
	// assertions about a hash. PRI-003 is where `pseudonymous` is measured.
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	cfg := RegisterAgentConfig{
		Identities:  env.identities,
		Ledger:      env.ledger,
		Idempotency: env.idem,
		ParentID:    raParentID,
		TTL:         env.ttl,
		Now:         env.clock.Now,
		Pseudonyms:  literal,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	restore, err := ConfigureRegisterAgent(cfg)
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restore)
	return env
}

// runRegisteredFor returns every run_registered event in the chain for runID.
func (e *raEnv) runRegisteredFor(t *testing.T, runID string) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.ledger.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := e.ledger.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	var out []event.Fields
	for _, r := range records {
		if r[event.FieldEventType] == event.EventTypeRunRegistered && r[event.FieldRunID] == runID {
			out = append(out, r)
		}
	}
	return out
}

// raServe binds register_agent through the seam of ADR-0016 §5 and serves it
// over the real HTTP transport, so what a test calls is what an agent calls.
func raServe(t *testing.T) *sdk.ClientSession {
	t.Helper()
	withEmptyToolRegistry(t)
	RegisterTool(ToolRegisterAgent, bindRegisterAgent)
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

func raArgs(key string) map[string]any {
	return map[string]any{
		"agent_type":      raAgentType,
		"task_id":         raTaskID,
		"idempotency_key": key,
	}
}

func raCall(t *testing.T, session *sdk.ClientSession, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name: string(ToolRegisterAgent), Arguments: args,
	})
	if err != nil {
		t.Fatalf("tools/call register_agent: %v", err)
	}
	return res
}

// raCallOK decodes a successful reply into IP §4's documented result shape.
func raCallOK(t *testing.T, session *sdk.ClientSession, args map[string]any) registerAgentOut {
	t.Helper()
	res := raCall(t, session, args)
	if res.IsError {
		t.Fatalf("register_agent failed: %#v", res.StructuredContent)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encoding structuredContent: %v", err)
	}
	var out registerAgentOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding %s into IP §4's result shape: %v", raw, err)
	}
	return out
}

// raCallFail returns the IP §4 structured error a failing call produced.
func raCallFail(t *testing.T, session *sdk.ClientSession, args map[string]any) map[string]any {
	t.Helper()
	res := raCall(t, session, args)
	if !res.IsError {
		t.Fatalf("register_agent succeeded where it had to fail: %#v", res.StructuredContent)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want IP §4's error object", res.StructuredContent)
	}
	return wire
}

func raWireMembers(t *testing.T, wire map[string]any) []string {
	t.Helper()
	names := make([]string, 0, len(wire))
	for k := range wire {
		names = append(names, k)
	}
	return names
}

// TestMCP001RegisterAgentReturnsTheDocumentedShape. Doc 07 MCP-001: "valid
// input → documented result shape … Exact schema match", against IP §4's
// register_agent(agent_type, task_id, idempotency_key) →
// {spiffe_id, run_id, expires_at}.
func TestMCP001RegisterAgentReturnsTheDocumentedShape(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	res := raCall(t, session, raArgs("reg-mcp-001"))
	if res.IsError {
		t.Fatalf("register_agent failed on valid input: %#v", res.StructuredContent)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want a JSON object", res.StructuredContent)
	}
	for name := range wire {
		switch name {
		case "spiffe_id", "run_id", "expires_at":
		default:
			t.Errorf("result carries %q; IP §4 names three members and no more (got %v)",
				name, raWireMembers(t, wire))
		}
	}
	for _, want := range []string{"spiffe_id", "run_id", "expires_at"} {
		if _, present := wire[want]; !present {
			t.Errorf("result has no %q; IP §4 requires it (got %v)", want, raWireMembers(t, wire))
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	out := raCallOK(t, session, raArgs("reg-mcp-001"))
	if err := event.ValidateIdentifier(out.RunID); err != nil {
		t.Errorf("run_id %q is not doc 02 §5's identifier: %v", out.RunID, err)
	}
	if err := event.ValidateSPIFFEID(out.SPIFFEID); err != nil {
		t.Errorf("spiffe_id %q is not doc 02 §5's grammar: %v", out.SPIFFEID, err)
	}
	// PROTECTED STRING (doc 01 §1): the {task_id} component is the lowercased
	// task reference, exactly as golden fixture 01 spells it.
	want := "spiffe://" + raTrustDomain + "/agent/" + raAgentType + "/jira-118/" + out.RunID
	if out.SPIFFEID != want {
		t.Errorf("spiffe_id = %q, want %q", out.SPIFFEID, want)
	}
	ts, err := event.ParseTimestamp(out.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not doc 02 §1's timestamp: %v", out.ExpiresAt, err)
	}
	if got := ts.Time().Sub(env.clock.at.Truncate(time.Millisecond)); got > env.ttl || got <= 0 {
		t.Errorf("expires_at %s is %s past the clock, want at most the %s TTL",
			out.ExpiresAt, got, env.ttl)
	}
}

// TestMCP001RegisterAgentAdvertisesTheDocumentedSchemas: the shape a client
// reads off tools/list is IP §4's, in and out.
func TestMCP001RegisterAgentAdvertisesTheDocumentedSchemas(t *testing.T) {
	raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var tool *sdk.Tool
	for _, candidate := range res.Tools {
		if candidate.Name == string(ToolRegisterAgent) {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tools/list does not advertise register_agent: %+v", res.Tools)
	}
	assertSchemaProperties(t, "inputSchema", tool.InputSchema,
		[]string{"agent_type", "task_id", "idempotency_key"})
	assertSchemaProperties(t, "outputSchema", tool.OutputSchema,
		[]string{"spiffe_id", "run_id", "expires_at"})
}

// assertSchemaProperties reads the advertised schema the way a client does —
// as JSON off the wire — and holds its property names to IP §4's list.
func assertSchemaProperties(t *testing.T, what string, schema any, want []string) {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("re-encoding %s: %v", what, err)
	}
	var decoded struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding %s %s: %v", what, raw, err)
	}
	for _, name := range want {
		if _, present := decoded.Properties[name]; !present {
			t.Errorf("%s has no %q; IP §4 names it (schema: %s)", what, name, raw)
		}
	}
	for name := range decoded.Properties {
		if !slices.Contains(want, name) {
			t.Errorf("%s carries %q; IP §4 names %v and no more", what, name, want)
		}
	}
}

// TestMCP007SameKeyIsOneIdentityAndOneEvent. Doc 07 MCP-007: "register_agent
// same idempotency_key twice → Same run_id and spiffe_id; exactly one SPIRE
// entry and one run_registered event." IP §6.6.
//
// The first call is asserted to have CREATED an entry and an event before the
// replay is made. Without that, every assertion below passes when neither call
// created anything at all.
func TestMCP007SameKeyIsOneIdentityAndOneEvent(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)
	const key = "reg-mcp-007"

	first := raCallOK(t, session, raArgs(key))

	// The bite: prove the first call really minted something.
	if got := env.identities.entryCount(); got != 1 {
		t.Fatalf("after the FIRST call SPIRE holds %d entries, want 1; "+
			"the replay assertions below are vacuous unless the first call created an identity", got)
	}
	if !env.identities.holds(first.SPIFFEID) {
		t.Fatalf("after the FIRST call SPIRE does not hold %q", first.SPIFFEID)
	}
	firstEvents := env.runRegisteredFor(t, first.RunID)
	if len(firstEvents) != 1 {
		t.Fatalf("after the FIRST call the ledger holds %d run_registered events for %s, want 1; "+
			"the replay assertions below are vacuous unless the first call recorded one",
			len(firstEvents), first.RunID)
	}
	if got := firstEvents[0][event.FieldSpiffeID]; got != first.SPIFFEID {
		t.Fatalf("the recorded run_registered names spiffe_id %v, the reply says %q", got, first.SPIFFEID)
	}
	if got := firstEvents[0][event.FieldIdempotencyKey]; got != key {
		t.Errorf("the recorded run_registered names idempotency_key %v, want %q", got, key)
	}
	if got := firstEvents[0][event.FieldAgentType]; got != raAgentType {
		t.Errorf("the recorded run_registered names agent_type %v, want %q", got, raAgentType)
	}
	if got := firstEvents[0][event.FieldTaskRef]; got != raTaskID {
		t.Errorf("the recorded run_registered names task_ref %v, want the caller's %q", got, raTaskID)
	}

	// Replay the identical request under the identical key.
	second := raCallOK(t, session, raArgs(key))

	if second.RunID != first.RunID {
		t.Errorf("run_id: replay returned %q, first call returned %q — that is a second identity",
			second.RunID, first.RunID)
	}
	if second.SPIFFEID != first.SPIFFEID {
		t.Errorf("spiffe_id: replay returned %q, first call returned %q", second.SPIFFEID, first.SPIFFEID)
	}
	if second.ExpiresAt != first.ExpiresAt {
		t.Errorf("expires_at: replay returned %q, first call returned %q — the replay recomputed "+
			"its reply instead of returning the recorded one (IP §6.6, ADR-0017)",
			second.ExpiresAt, first.ExpiresAt)
	}
	if got := env.identities.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries after the replay, want exactly 1", got)
	}
	if got := len(env.runRegisteredFor(t, first.RunID)); got != 1 {
		t.Errorf("the ledger holds %d run_registered events for %s after the replay, want exactly 1",
			got, first.RunID)
	}
	if got := env.identities.registerAttempts(); got != 1 {
		t.Errorf("SPIRE saw %d RegisterRun attempts, want 1: the replay must be answered from the "+
			"recorded reply, not by running the tool again", got)
	}
}

// TestMCP007ATakenOverClaimStillMintsOneIdentity is MCP-007 under the one
// interleaving that actually runs the tool twice: ADR-0017's lease takeover,
// which is what a SIGKILLed replica leaves behind. Both executions are in
// flight at once, and the property must still hold.
func TestMCP007ATakenOverClaimStillMintsOneIdentity(t *testing.T) {
	// A zero lease makes every claim immediately takeable, which is the state
	// a crashed replica leaves.
	env := raSetup(t, 0, nil)
	session := raServe(t)
	const key = "reg-mcp-007-takeover"

	env.identities.mu.Lock()
	env.identities.entered = make(chan struct{}, 4)
	env.identities.release = make(chan struct{})
	env.identities.mu.Unlock()
	// Closing the gate releases every execution waiting at it at once. It is
	// also closed on the way out: without that, a failed assertion would leave
	// an HTTP request in flight, and httptest.Server.Close waits for those, so
	// a failing test would hang instead of reporting. Once either way.
	releaseBoth := sync.OnceFunc(func() { close(env.identities.release) })
	t.Cleanup(releaseBoth)

	type reply struct {
		out registerAgentOut
		err error
	}
	results := make(chan reply, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			res, err := session.CallTool(ctx, &sdk.CallToolParams{
				Name: string(ToolRegisterAgent), Arguments: raArgs(key),
			})
			if err != nil {
				results <- reply{err: err}
				return
			}
			if res.IsError {
				results <- reply{err: fmt.Errorf("%#v", res.StructuredContent)}
				return
			}
			raw, merr := json.Marshal(res.StructuredContent)
			if merr != nil {
				results <- reply{err: merr}
				return
			}
			var out registerAgentOut
			results <- reply{out: out, err: json.Unmarshal(raw, &out)}
		}()
	}

	// Both executions must be inside RegisterRun before either is let go, or
	// the second would find a completed row and never run at all.
	for i := 0; i < 2; i++ {
		select {
		case <-env.identities.entered:
		case <-time.After(45 * time.Second):
			t.Fatalf("only %d of 2 executions reached SPIRE; the claim was never taken over", i)
		}
	}

	// Both released at once, so the two executions race all the way to the
	// end: they append together and they record their replies together. That
	// last overlap used to hand the loser a NULL response out of the
	// idempotency store's pre-commit snapshot, so this test released them one
	// at a time; RM-066 (#83) fixed the store and the stagger is gone.
	releaseBoth()

	var outs []registerAgentOut
	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("call %d: %v", i, got.err)
			}
			outs = append(outs, got.out)
		case <-time.After(45 * time.Second):
			t.Fatalf("call %d never returned once both executions were released", i)
		}
	}

	if outs[0] != outs[1] {
		t.Errorf("two callers of one key were given different answers: %+v and %+v", outs[0], outs[1])
	}
	if got := env.identities.registerAttempts(); got != 2 {
		t.Fatalf("SPIRE saw %d RegisterRun attempts, want 2; this test proves nothing unless the "+
			"tool really ran twice", got)
	}
	if got := env.identities.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries, want exactly 1 — two executions minted two identities", got)
	}
	if got := len(env.runRegisteredFor(t, outs[0].RunID)); got != 1 {
		t.Errorf("the ledger holds %d run_registered events for %s, want exactly 1", got, outs[0].RunID)
	}
}

// raFailingLedger returns the same error from every append. It is how the
// "ledger did not classify its failure" path is reached — a real *ledger.Store
// classifies everything it can.
type raFailingLedger struct{ err error }

func (l raFailingLedger) Append(context.Context, event.Fields) (event.Fields, error) {
	return nil, l.err
}

// raRunID is the run id the tool derives for these arguments. Computed the
// same way the tool computes it, so a test can seed SPIRE with the entry the
// tool is about to ask for.
func raRunID(key string) string {
	return registerAgentRunID(registerAgentIn{
		AgentType: raAgentType, TaskID: raTaskID, IdempotencyKey: key,
	})
}

func raSPIFFEID(key string) string {
	return "spiffe://" + raTrustDomain + "/agent/" + raAgentType + "/jira-118/" + raRunID(key)
}

func raWireClass(t *testing.T, wire map[string]any, class Class, retryable bool) {
	t.Helper()
	if got := wire["error_class"]; got != string(class) {
		t.Errorf("error_class = %v, want %s (message: %v)", got, class, wire["message"])
	}
	if got := wire["retryable"]; got != retryable {
		t.Errorf("retryable = %v, want %v (ADR-0016)", got, retryable)
	}
}

// TestRegisterAgentRecordsBeforeItMintsWhenSPIREIsDown is IP §6.1 —
// "spire-server down at register_agent → IDENTITY_UNAVAILABLE, retryable. No
// queuing of identity issuance, no provisional identities" — and it is also
// where the ordering of ADR-0018 is visible: the `run_registered` event is in
// the ledger and no identity exists.
func TestRegisterAgentRecordsBeforeItMintsWhenSPIREIsDown(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)
	const key = "reg-spire-down"

	env.identities.mu.Lock()
	env.identities.registerErr = &spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "create_entry",
		Message: "connection refused", Retryable: true,
	}
	env.identities.mu.Unlock()

	wire := raCallFail(t, session, raArgs(key))
	raWireClass(t, wire, ClassIdentityUnavailable, true)

	if got := env.identities.entryCount(); got != 0 {
		t.Errorf("SPIRE holds %d entries after a refused registration, want 0: "+
			"nothing is queued and no provisional identity exists (IP §6.1)", got)
	}
	if got := len(env.runRegisteredFor(t, raRunID(key))); got != 1 {
		t.Errorf("the ledger holds %d run_registered events for the refused run, want 1: "+
			"the record is written before the identity (ADR-0018), so it survives the refusal", got)
	}
}

// TestRegisterAgentFailsClosedWhenTheLedgerIsDown is I3 and IP §6.4: no action
// without a record, so an unreachable ledger means no identity is minted at
// all.
func TestRegisterAgentFailsClosedWhenTheLedgerIsDown(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	// Only the ledger's pool is closed. The idempotency store has its own
	// pool and stays up, so what is under test is a ledger outage and not a
	// database outage.
	env.ledger.Close()

	wire := raCallFail(t, session, raArgs("reg-ledger-down"))
	raWireClass(t, wire, ClassLedgerUnavailable, true)

	if got := env.identities.registerAttempts(); got != 0 {
		t.Errorf("SPIRE saw %d RegisterRun attempts with the ledger down, want 0: "+
			"an identity that cannot be recorded is not issued (I3)", got)
	}
}

// TestRegisterAgentReportsAnUnclassifiedLedgerFailure: a failure the ledger did
// not name is INVARIANT_VIOLATION, never a guessed class.
func TestRegisterAgentReportsAnUnclassifiedLedgerFailure(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Ledger = raFailingLedger{err: errors.New("a ledger failure nobody classified")}
	})
	session := raServe(t)

	wire := raCallFail(t, session, raArgs("reg-ledger-unclassified"))
	raWireClass(t, wire, ClassInvariantViolation, false)
	if got := env.identities.registerAttempts(); got != 0 {
		t.Errorf("SPIRE saw %d RegisterRun attempts, want 0", got)
	}
}

// TestRegisterAgentRefusesArgumentsThatCannotNameARun. doc 02 §5's identifier
// grammar is what a SPIFFE ID path component has to satisfy; an argument that
// cannot be one is refused before anything is recorded or minted.
func TestRegisterAgentRefusesArgumentsThatCannotNameARun(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	cases := []struct {
		name string
		args map[string]any
	}{
		{"empty agent_type", map[string]any{
			"agent_type": "", "task_id": raTaskID, "idempotency_key": "k1"}},
		{"agent_type with a space", map[string]any{
			"agent_type": "fix ci", "task_id": raTaskID, "idempotency_key": "k2"}},
		{"agent_type upper case", map[string]any{
			"agent_type": "Fix-CI", "task_id": raTaskID, "idempotency_key": "k3"}},
		{"empty task_id", map[string]any{
			"agent_type": raAgentType, "task_id": "", "idempotency_key": "k4"}},
		{"task_id with a slash", map[string]any{
			"agent_type": raAgentType, "task_id": "JIRA/118", "idempotency_key": "k5"}},
		{"task_id longer than the grammar allows", map[string]any{
			"agent_type": raAgentType, "task_id": strings.Repeat("a", 64), "idempotency_key": "k6"}},
		{"empty idempotency_key", map[string]any{
			"agent_type": raAgentType, "task_id": raTaskID, "idempotency_key": ""}},
		{"idempotency_key over 128 bytes", map[string]any{
			"agent_type": raAgentType, "task_id": raTaskID,
			"idempotency_key": strings.Repeat("k", event.MaxIdempotencyKeyBytes+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := raCallFail(t, session, tc.args)
			raWireClass(t, wire, ClassInvariantViolation, false)
		})
	}
	if got := env.identities.registerAttempts(); got != 0 {
		t.Errorf("SPIRE saw %d RegisterRun attempts for refused arguments, want 0", got)
	}
	n, err := env.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n != 0 {
		t.Errorf("the ledger holds %d events after only refused calls, want 0", n)
	}
}

// TestRegisterAgentRefusesAKeyThatNamesADifferentRequest. ADR-0017 §3: the key
// dedupes one request; presented with another it is refused rather than
// answered.
func TestRegisterAgentRefusesAKeyThatNamesADifferentRequest(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)
	const key = "reg-same-key-other-request"

	first := raCallOK(t, session, raArgs(key))

	wire := raCallFail(t, session, map[string]any{
		"agent_type": "other-agent", "task_id": raTaskID, "idempotency_key": key,
	})
	raWireClass(t, wire, ClassDuplicateRequest, false)

	if got := env.identities.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries, want 1: the refused request minted nothing", got)
	}
	if got := len(env.runRegisteredFor(t, first.RunID)); got != 1 {
		t.Errorf("the ledger holds %d run_registered events for %s, want 1", got, first.RunID)
	}
}

// TestRegisterAgentIsNotServedUntilItIsConfigured: an advertised tool with no
// dependencies refuses loudly rather than half-working.
func TestRegisterAgentIsNotServedUntilItIsConfigured(t *testing.T) {
	registerAgentState.mu.Lock()
	saved := registerAgentState.cfg
	registerAgentState.cfg = nil
	registerAgentState.mu.Unlock()
	t.Cleanup(func() {
		registerAgentState.mu.Lock()
		registerAgentState.cfg = saved
		registerAgentState.mu.Unlock()
	})

	session := raServe(t)
	wire := raCallFail(t, session, raArgs("reg-unconfigured"))
	raWireClass(t, wire, ClassInvariantViolation, false)
}

// TestConfigureRegisterAgentRefusesAnIncompleteConfiguration.
func TestConfigureRegisterAgentRefusesAnIncompleteConfiguration(t *testing.T) {
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	complete := func() RegisterAgentConfig {
		return RegisterAgentConfig{
			Identities:  newRASPIRE(raTrustDomain),
			Ledger:      raFailingLedger{err: errors.New("unused")},
			Idempotency: &IdempotencyStore{},
			ParentID:    raParentID,
			Pseudonyms:  literal,
		}
	}
	cases := []struct {
		name string
		omit func(*RegisterAgentConfig)
	}{
		{"no SPIRE client", func(c *RegisterAgentConfig) { c.Identities = nil }},
		{"no ledger", func(c *RegisterAgentConfig) { c.Ledger = nil }},
		{"no idempotency store", func(c *RegisterAgentConfig) { c.Idempotency = nil }},
		{"no parent id", func(c *RegisterAgentConfig) { c.ParentID = "" }},
		// RM-079 (#116). A nil pseudonymiser cannot default to anything: the
		// two defaults available are "put the ticket reference in the
		// certificate" and "refuse to start", and only one of them is a
		// privacy control.
		{"no pseudonymiser", func(c *RegisterAgentConfig) { c.Pseudonyms = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := complete()
			tc.omit(&cfg)
			restore, err := ConfigureRegisterAgent(cfg)
			if err == nil {
				restore()
				t.Fatalf("ConfigureRegisterAgent accepted a configuration with %s", tc.name)
			}
			var classified *Error
			if !errors.As(err, &classified) {
				t.Fatalf("error %v (%T) carries no error_class", err, err)
			}
			if classified.Class != ClassInvariantViolation {
				t.Errorf("error_class = %s, want %s", classified.Class, ClassInvariantViolation)
			}
		})
	}

	// The whole configuration is accepted, and the previous one comes back.
	restore, cerr := ConfigureRegisterAgent(complete())
	if cerr != nil {
		t.Fatalf("ConfigureRegisterAgent refused a complete configuration: %v", cerr)
	}
	restore()
}

// TestRegisterAgentRefusesATrustDomainThatIsNotOne: a SPIFFE ID that cannot be
// built is refused before anything is recorded. PROTECTED STRING (doc 01 §1).
func TestRegisterAgentRefusesATrustDomainThatIsNotOne(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	env.identities.mu.Lock()
	env.identities.trustDomain = "INNSEGL.dev"
	env.identities.mu.Unlock()
	session := raServe(t)

	wire := raCallFail(t, session, raArgs("reg-bad-trust-domain"))
	raWireClass(t, wire, ClassInvariantViolation, false)

	n, err := env.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n != 0 {
		t.Errorf("the ledger holds %d events, want 0: nothing is recorded for a run that cannot be named", n)
	}
}

// TestRegisterAgentAdoptsTheEntryItAlreadyCreated: SPIRE reporting the run's
// entry as a duplicate is the inner idempotency ADR-0017 §5 relies on, not a
// failure. The reply names the entry that exists.
func TestRegisterAgentAdoptsTheEntryItAlreadyCreated(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)
	const key = "reg-adopt"

	// SPIRE already holds this run's entry and says so, which is what it does
	// after a claim was taken over and the tool ran a second time.
	env.identities.mu.Lock()
	env.identities.entries[raSPIFFEID(key)] = spire.Entry{
		ID: "entry-pre-existing", SPIFFEID: raSPIFFEID(key), TTL: 7 * time.Minute,
	}
	env.identities.registerErr = &spire.Error{
		Class: spire.ClassDuplicateRequest, Op: "register_agent", Message: "entry already exists",
	}
	env.identities.mu.Unlock()

	out := raCallOK(t, session, raArgs(key))
	if out.RunID != raRunID(key) {
		t.Errorf("run_id = %q, want the derived %q", out.RunID, raRunID(key))
	}
	if out.SPIFFEID != raSPIFFEID(key) {
		t.Errorf("spiffe_id = %q, want %q", out.SPIFFEID, raSPIFFEID(key))
	}
	if got := env.identities.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries, want 1", got)
	}
	// expires_at is read off the entry SPIRE holds, so it names the lifetime
	// that entry really has and not the one this call asked for.
	ts, err := event.ParseTimestamp(out.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q: %v", out.ExpiresAt, err)
	}
	if got := ts.Time().Sub(env.clock.at.Truncate(time.Millisecond)); got > 7*time.Minute || got <= env.ttl {
		t.Errorf("expires_at is %s past the clock; the adopted entry's TTL is 7m, not the %s asked for",
			got, env.ttl)
	}
}

// TestRegisterAgentReportsALookupFailureAfterADuplicate.
func TestRegisterAgentReportsALookupFailureAfterADuplicate(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	env.identities.mu.Lock()
	env.identities.registerErr = &spire.Error{
		Class: spire.ClassDuplicateRequest, Op: "register_agent", Message: "entry already exists",
	}
	env.identities.lookupErr = &spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "lookup_run",
		Message: "connection refused", Retryable: true,
	}
	env.identities.mu.Unlock()

	wire := raCallFail(t, session, raArgs("reg-lookup-fails"))
	raWireClass(t, wire, ClassIdentityUnavailable, true)
}

// TestRegisterAgentRefusesToResurrectARetiredRun. SPIRE says the entry exists
// and then holds none: the only things that remove a run's entry are
// retirement and the reaper, and both mean the run is over. IP §6.2 makes
// retirement effective immediately, so the key is not re-minted into an
// identity.
func TestRegisterAgentRefusesToResurrectARetiredRun(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)

	env.identities.mu.Lock()
	env.identities.registerErr = &spire.Error{
		Class: spire.ClassDuplicateRequest, Op: "register_agent", Message: "entry already exists",
	}
	env.identities.forgetOnLookup = true
	env.identities.mu.Unlock()

	wire := raCallFail(t, session, raArgs("reg-retired"))
	raWireClass(t, wire, ClassRunAlreadyRetired, false)
	if got := env.identities.entryCount(); got != 0 {
		t.Errorf("SPIRE holds %d entries, want 0: a retired run is not re-registered", got)
	}
}

// TestRegisterAgentRefusesAStoredReplyItCannotRead. A recorded reply that is
// not a register_agent result is a defect somewhere, and the tool says so
// rather than handing back a zero-valued identity.
func TestRegisterAgentRefusesAStoredReplyItCannotRead(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, nil)
	session := raServe(t)
	const key = "reg-unreadable-reply"

	call := Call{
		Tool: string(ToolRegisterAgent), Key: key,
		Params: map[string]any{"agent_type": raAgentType, "task_id": raTaskID},
	}
	digest, err := call.fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	conn := rawConn(t, env.dsn)
	if _, err := conn.Exec(context.Background(), `
		INSERT INTO innsegl.idempotency
		    (idempotency_key, tool, request_digest, status, response,
		     claimed_at, lease_expires_at, completed_at)
		VALUES ($1, $2, $3, 'completed', $4,
		     clock_timestamp(), clock_timestamp(), clock_timestamp())`,
		key, string(ToolRegisterAgent), digest, []byte("not a register_agent result")); err != nil {
		t.Fatalf("seeding a completed row: %v", err)
	}

	wire := raCallFail(t, session, raArgs(key))
	raWireClass(t, wire, ClassInvariantViolation, false)
	if got := env.identities.registerAttempts(); got != 0 {
		t.Errorf("SPIRE saw %d RegisterRun attempts, want 0", got)
	}
}

// TestRegisterAgentTakesItsSelectorsAndClockFromTheConfiguration exercises the
// two configured defaults from the other side: a deployment-supplied selector
// function, and no clock at all.
func TestRegisterAgentTakesItsSelectorsAndClockFromTheConfiguration(t *testing.T) {
	custom := []spire.Selector{{Type: "unix", Value: "uid:10001"}}
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Selectors = func(spire.RunRef) []spire.Selector { return custom }
		cfg.Now = nil
	})
	session := raServe(t)
	const key = "reg-custom-selectors"

	before := time.Now().UTC()
	out := raCallOK(t, session, raArgs(key))

	env.identities.mu.Lock()
	entry := env.identities.entries[out.SPIFFEID]
	env.identities.mu.Unlock()
	if len(entry.Selectors) != 1 || entry.Selectors[0] != custom[0] {
		t.Errorf("entry selectors = %v, want the configured %v", entry.Selectors, custom)
	}
	if entry.ParentID != raParentID {
		t.Errorf("entry parent = %q, want %q", entry.ParentID, raParentID)
	}
	ts, err := event.ParseTimestamp(out.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q: %v", out.ExpiresAt, err)
	}
	if ts.Time().Before(before.Add(env.ttl).Truncate(time.Millisecond)) {
		t.Errorf("expires_at %s predates the wall clock plus the TTL; the default clock was not used",
			out.ExpiresAt)
	}
}

// TestDefaultRegisterAgentSelectorsBindTheEntryToTheRun. I1: an entry a
// workload can match on the run id alone would be an identity any container
// carrying that label could pick up.
func TestDefaultRegisterAgentSelectorsBindTheEntryToTheRun(t *testing.T) {
	run := spire.RunRef{AgentType: "fix-ci", TaskID: "jira-118", RunID: "run-42"}
	got := DefaultRegisterAgentSelectors(run)
	want := []string{
		"docker:label:dev.innsegl.run-id:run-42",
		"docker:label:dev.innsegl.agent-type:fix-ci",
		"docker:label:dev.innsegl.task-id:jira-118",
	}
	if len(got) != len(want) {
		t.Fatalf("selectors = %v, want %d of them", got, len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("selector %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRegisterAgentRunIDIsAPureFunctionOfTheCallItNames is what makes a second
// EXECUTION of one call harmless (ADR-0018): the run id cannot depend on when
// or where the tool ran.
func TestRegisterAgentRunIDIsAPureFunctionOfTheCallItNames(t *testing.T) {
	base := registerAgentIn{AgentType: raAgentType, TaskID: raTaskID, IdempotencyKey: "reg-8f21c"}
	first := registerAgentRunID(base)
	if second := registerAgentRunID(base); second != first {
		t.Errorf("two derivations of one call gave %q and %q", first, second)
	}
	if err := event.ValidateIdentifier(first); err != nil {
		t.Errorf("run_id %q is not doc 02 §5's identifier: %v", first, err)
	}
	seen := map[string]string{first: "base"}
	for _, other := range []registerAgentIn{
		{AgentType: "other", TaskID: raTaskID, IdempotencyKey: "reg-8f21c"},
		{AgentType: raAgentType, TaskID: "JIRA-119", IdempotencyKey: "reg-8f21c"},
		{AgentType: raAgentType, TaskID: raTaskID, IdempotencyKey: "reg-8f21d"},
		// The quoting is what stops one triple spelling another.
		{AgentType: raAgentType, TaskID: raTaskID + `"` + `"`, IdempotencyKey: "reg-8f21c"},
	} {
		id := registerAgentRunID(other)
		if previous, clash := seen[id]; clash {
			t.Errorf("%+v derives the same run id as %s", other, previous)
		}
		seen[id] = fmt.Sprintf("%+v", other)
	}
}
