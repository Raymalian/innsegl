// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
)

// Rate limiting, RM-027 (#35). Doc 07 MCP-013 (F): "register_agent flood from
// one caller → rate limit engages; alert emitted; SPIRE and ledger unaffected
// beyond limit", against IP §6.10 and threat-model AB-07.
//
// WHAT IS REAL HERE AND WHAT IS NOT
//
// The ledger and the idempotency store are REAL, on a real Postgres, and the
// tool is reached over the real HTTP transport — because the claim under test
// is that a flood does not reach the ledger, and an in-memory stand-in for the
// ledger would be asserting the claim against the wrong thing. SPIRE is the
// same fake register_agent's own tests use, for the reason stated there; what
// this file needs from it is a count of how many times it was ASKED, which a
// fake reports exactly and a container reports only by inference.
//
// The clock is injected. A rate limit measured against the wall clock is a
// test that sleeps, and a test that sleeps is a test that is flaky on a busy
// CI runner in the direction that hides the bug.

const (
	// rlCalls and rlWindow are the limit under test. Small numbers so the
	// boundary is checked call by call rather than in aggregate.
	rlCalls  = 3
	rlWindow = time.Minute
	// rlFlood is how many calls the runaway loop makes after the limit is
	// reached. Larger than any bucket so a flood that leaked would be visible
	// as entries and events, not as a rounding difference.
	rlFlood = 20
	// The second caller. A limit that stops this one too is a global limit,
	// which turns one runaway agent into an outage for everybody — the attack
	// (AB-07), not the defence.
	rlOtherAgentType = "lint-fix"
	rlOtherTaskID    = "JIRA-999"
)

// rlClock is a clock a test moves by hand.
type rlClock struct {
	mu sync.Mutex
	at time.Time
}

func newRLClock() *rlClock {
	return &rlClock{at: time.Date(2026, 8, 29, 9, 14, 3, 0, time.UTC)}
}

func (c *rlClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *rlClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// rlAlerts is the alert sink, recording what an operator would have been paged
// with.
type rlAlerts struct {
	mu   sync.Mutex
	trip []RateLimitTrip
}

func (a *rlAlerts) sink(_ context.Context, trip RateLimitTrip) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trip = append(a.trip, trip)
}

func (a *rlAlerts) all() []RateLimitTrip {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]RateLimitTrip(nil), a.trip...)
}

// rlArgs is raArgs with the caller named, so a test can flood as one caller
// and call as another.
func rlArgs(agentType, taskID, key string) map[string]any {
	return map[string]any{
		"agent_type":      agentType,
		"task_id":         taskID,
		"idempotency_key": key,
	}
}

// rlLimiter builds the limiter under test.
func rlLimiter(t *testing.T, clock *rlClock, alerts *rlAlerts, maxCallers int) *RateLimiter {
	t.Helper()
	lim, err := NewRateLimiter(RateLimit{
		Tool:       ToolRegisterAgent,
		Calls:      rlCalls,
		Window:     rlWindow,
		MaxCallers: maxCallers,
		Alert:      alerts.sink,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	return lim
}

// rlSetup wires register_agent onto a metered ledger.
func rlSetup(t *testing.T, lim *RateLimiter) *raEnv {
	t.Helper()
	return raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		metered, err := RateLimitRegisterAgent(*cfg, lim)
		if err != nil {
			t.Fatalf("RateLimitRegisterAgent: %v", err)
		}
		*cfg = metered
	})
}

// rlChain returns every event in the chain, in position order.
func rlChain(t *testing.T, env *raEnv) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := env.ledger.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := env.ledger.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	return records
}

// rlRefused asserts that one call was refused the way IP §4 requires, and
// returns the wire object so the caller can read the rest of it.
func rlRefused(t *testing.T, session *sdk.ClientSession, args map[string]any) map[string]any {
	t.Helper()
	wire := raCallFail(t, session, args)
	if got := wire["error_class"]; got != string(ClassIdentityUnavailable) {
		t.Fatalf("error_class = %v, want %s (ADR-0025)", got, ClassIdentityUnavailable)
	}
	if got := wire["retryable"]; got != true {
		t.Fatalf("retryable = %v, want true: waiting is exactly what makes this call succeed", got)
	}
	return wire
}

// TestMCP013RegisterAgentFloodFromOneCallerTripsTheLimit. Doc 07 MCP-013,
// IP §6.10: "Rate-limit register_agent per caller; a runaway loop must not
// exhaust SPIRE or flood the ledger silently — test the limit and the alert."
// Threat model AB-07.
//
// The four claims, in order, and the trap each one avoids:
//
//  1. The calls WITHIN the limit succeed. A limiter that refused everything
//     would satisfy "the limit engaged" and be useless; this is asserted
//     first so that it cannot be satisfied vacuously.
//  2. The limit engages at the boundary — call rlCalls+1 and no earlier.
//  3. SPIRE and the ledger are untouched beyond the limit, asserted by
//     COUNTING what reached them, not by observing that calls were refused.
//  4. The trip is not silent, and the alert names the caller.
func TestMCP013RegisterAgentFloodFromOneCallerTripsTheLimit(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	env := rlSetup(t, lim)
	session := raServe(t)

	// 1. Every call within the limit SUCCEEDS, and each one is its own run.
	runs := make(map[string]bool, rlCalls)
	for i := range rlCalls {
		out := raCallOK(t, session, raArgs(rlKey(i)))
		if runs[out.RunID] {
			t.Fatalf("call %d returned run_id %q again; distinct keys must name distinct runs",
				i+1, out.RunID)
		}
		runs[out.RunID] = true
		if got := lim.Stats().Refused; got != 0 {
			t.Fatalf("after %d admitted calls the limiter has refused %d; "+
				"a limit of %d must admit the first %d", i+1, got, rlCalls, rlCalls)
		}
	}
	if len(runs) != rlCalls {
		t.Fatalf("%d distinct runs from %d calls", len(runs), rlCalls)
	}
	if trips := alerts.all(); len(trips) != 0 {
		t.Fatalf("%d alert(s) raised while the caller was inside its limit: %+v", len(trips), trips)
	}

	// 2. The very next call — the boundary — is refused, and so is the rest of
	//    the flood.
	for i := rlCalls; i < rlCalls+rlFlood; i++ {
		wire := rlRefused(t, session, raArgs(rlKey(i)))
		msg, isText := wire["message"].(string)
		if !isText || !strings.Contains(msg, "rate limit") {
			t.Errorf("call %d refused with message %q, which does not say why", i+1, msg)
		}
		if wire["run_id"] == nil || wire["run_id"] == "" {
			t.Errorf("call %d refused with no run_id; IP §4 scopes the failure to a run", i+1)
		}
	}

	// 3. SPIRE and the ledger, counted.
	//
	// registerAttempts is the strong form: the flood did not merely fail to
	// CREATE entries, it never reached SPIRE at all. That holds because
	// ADR-0018 fixes the order — the ledger is written before SPIRE is touched
	// — so a refusal at the metered appender is a refusal that reaches
	// neither. If that order is ever reversed, this assertion is what says so.
	if got := env.identities.entryCount(); got != rlCalls {
		t.Errorf("SPIRE holds %d entries after %d calls; the limit is %d",
			got, rlCalls+rlFlood, rlCalls)
	}
	if got := env.identities.registerAttempts(); got != rlCalls {
		t.Errorf("SPIRE was asked to register %d times after %d calls; the flood reached it",
			got, rlCalls+rlFlood)
	}
	chain := rlChain(t, env)
	if len(chain) != rlCalls {
		t.Errorf("the chain holds %d events after %d calls; the limit is %d",
			len(chain), rlCalls+rlFlood, rlCalls)
	}
	for i, e := range chain {
		if e[event.FieldEventType] != event.EventTypeRunRegistered {
			t.Errorf("chain position %d is a %v; the flood wrote something new",
				i+1, e[event.FieldEventType])
		}
	}

	// 4. The alert. Exactly one per trip episode: an alert per refused call is
	//    a log flood, which is the same failure in a different sink.
	trips := alerts.all()
	if len(trips) != 1 {
		t.Fatalf("%d alerts for one flood, want exactly 1: %+v", len(trips), trips)
	}
	trip := trips[0]
	if trip.Tool != ToolRegisterAgent {
		t.Errorf("alert names tool %q, want %q", trip.Tool, ToolRegisterAgent)
	}
	if trip.Caller.AgentType != raAgentType || trip.Caller.TaskRef != raTaskID {
		t.Errorf("alert names caller %+v, want agent_type %q task_ref %q",
			trip.Caller, raAgentType, raTaskID)
	}
	if trip.Calls != rlCalls || trip.Window != rlWindow {
		t.Errorf("alert reports a limit of %d per %v, want %d per %v",
			trip.Calls, trip.Window, rlCalls, rlWindow)
	}
	if trip.RetryAfter <= 0 || trip.RetryAfter > rlWindow {
		t.Errorf("alert RetryAfter = %v, want a wait inside the window", trip.RetryAfter)
	}
	if !trip.At.Equal(clock.Now()) {
		t.Errorf("alert At = %v, want the clock's %v", trip.At, clock.Now())
	}

	// The limit itself is monitored (doc 05 §2 names "rate-limit trips" among
	// the monitoring minimums).
	stats := lim.Stats()
	if stats.Admitted != rlCalls || stats.Refused != rlFlood || stats.Trips != 1 {
		t.Errorf("stats = %+v, want admitted %d refused %d trips 1", stats, rlCalls, rlFlood)
	}
}

// rlKey names the i'th call of the flood. Distinct keys, because a runaway
// loop that reuses ONE key is already harmless — the ledger's UNIQUE key and
// the idempotency store make it one event and one identity. The loop that
// exhausts SPIRE is the one that mints a new key every time, and that is the
// one metered here.
func rlKey(i int) string { return "flood-" + strconv.Itoa(i) }

// TestMCP013TheLimitIsPerCallerAndNotGlobal. A global limit converts one
// runaway agent into a denial of service against every other agent, which is
// AB-07 achieved rather than prevented.
func TestMCP013TheLimitIsPerCallerAndNotGlobal(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	env := rlSetup(t, lim)
	session := raServe(t)

	for i := range rlCalls + rlFlood {
		args := raArgs(rlKey(i))
		if i < rlCalls {
			raCallOK(t, session, args)
			continue
		}
		rlRefused(t, session, args)
	}

	// The second caller, mid-flood, is untouched by the first caller's limit.
	for i := range rlCalls {
		out := raCallOK(t, session, rlArgs(rlOtherAgentType, rlOtherTaskID, "other-"+strconv.Itoa(i)))
		if !strings.Contains(out.SPIFFEID, "/"+rlOtherAgentType+"/") {
			t.Errorf("second caller got spiffe_id %q, which is not its own identity", out.SPIFFEID)
		}
	}
	if got := env.identities.entryCount(); got != 2*rlCalls {
		t.Errorf("SPIRE holds %d entries; each of two callers is allowed %d", got, rlCalls)
	}
	if trips := alerts.all(); len(trips) != 1 {
		t.Fatalf("%d alerts, want 1 — only the flooding caller tripped: %+v", len(trips), trips)
	}
	if got := lim.Stats().Callers; got != 2 {
		t.Errorf("limiter tracks %d callers, want 2", got)
	}
}

// TestMCP013TheLimitRecoversAndTheAlertRearms. An alert that fires once and
// never again is an alert that stops being an alert after the first incident.
func TestMCP013TheLimitRecoversAndTheAlertRearms(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	env := rlSetup(t, lim)
	session := raServe(t)

	call := 0
	flood := func(wantTrips int) {
		t.Helper()
		for range rlCalls {
			raCallOK(t, session, raArgs(rlKey(call)))
			call++
		}
		rlRefused(t, session, raArgs(rlKey(call)))
		call++
		if got := alerts.all(); len(got) != wantTrips {
			t.Fatalf("%d alerts, want %d: %+v", len(got), wantTrips, got)
		}
	}

	flood(1)
	// A full window later the bucket has refilled and the caller is served
	// again — the limit paces a caller, it does not blacklist one.
	clock.advance(rlWindow)
	flood(2)

	if got := env.identities.entryCount(); got != 2*rlCalls {
		t.Errorf("SPIRE holds %d entries, want %d — %d admitted in each of two windows",
			got, 2*rlCalls, rlCalls)
	}
	if stats := lim.Stats(); stats.Trips != 2 || stats.Refused != 2 {
		t.Errorf("stats = %+v, want 2 trips and 2 refusals", stats)
	}
}

// TestMCP013AReplayIsNeverRateLimited. IP §6.6 requires a replayed call to
// return the original result. The meter sits inside the idempotency claim, so
// a replay — which never re-executes the tool — is answered from the record
// and never metered. A limiter placed ahead of the claim would refuse a
// crash-replay, which is IP §6.6 broken by the control that was meant to
// protect it.
func TestMCP013AReplayIsNeverRateLimited(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	env := rlSetup(t, lim)
	session := raServe(t)

	first := raCallOK(t, session, raArgs("replayed"))
	for range rlCalls + rlFlood {
		again := raCallOK(t, session, raArgs("replayed"))
		if again != first {
			t.Fatalf("replay returned %+v, want the original %+v", again, first)
		}
	}
	if got := env.identities.entryCount(); got != 1 {
		t.Errorf("SPIRE holds %d entries for one key, want 1", got)
	}
	if stats := lim.Stats(); stats.Admitted != 1 || stats.Refused != 0 {
		t.Errorf("stats = %+v, want exactly one admitted call and no refusal", stats)
	}
	if trips := alerts.all(); len(trips) != 0 {
		t.Errorf("a replay raised %d alert(s): %+v", len(trips), trips)
	}
}

// ---------------------------------------------------------------------------
// The limiter itself
// ---------------------------------------------------------------------------

func rlCaller() RateLimitCaller {
	return RateLimitCaller{AgentType: raAgentType, TaskRef: raTaskID}
}

// TestTheLimitEngagesAtTheBoundaryAndNotBefore checks the arithmetic call by
// call, without a database in the way.
func TestTheLimitEngagesAtTheBoundaryAndNotBefore(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	ctx := t.Context()

	for i := range rlCalls {
		if err := lim.Allow(ctx, rlCaller(), ""); err != nil {
			t.Fatalf("call %d of %d refused: %v", i+1, rlCalls, err)
		}
	}
	err := lim.Allow(ctx, rlCaller(), "")
	if err == nil {
		t.Fatalf("call %d admitted; the limit is %d", rlCalls+1, rlCalls)
	}
	e := mcpError(t, err)
	if e.Class != ClassIdentityUnavailable || !e.Retryable {
		t.Errorf("refusal is %s retryable=%v, want %s retryable=true",
			e.Class, e.Retryable, ClassIdentityUnavailable)
	}

	// One emission interval later exactly one more call fits, and no more:
	// the bucket refills continuously rather than all at once, so a caller
	// that waits is served at the sustained rate instead of being handed a
	// fresh burst.
	clock.advance(rlWindow / rlCalls)
	if err := lim.Allow(ctx, rlCaller(), ""); err != nil {
		t.Errorf("after one emission interval the call was still refused: %v", err)
	}
	if err := lim.Allow(ctx, rlCaller(), ""); err == nil {
		t.Errorf("a second call fitted in one emission interval")
	}
}

// TestAnIdleCallerIsNotChargedForTimeItDidNotUse.
func TestAnIdleCallerIsNotChargedForTimeItDidNotUse(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	ctx := t.Context()

	if err := lim.Allow(ctx, rlCaller(), ""); err != nil {
		t.Fatalf("first call refused: %v", err)
	}
	// Long idle: the bucket refills to full and no further, so a caller that
	// waits a week does not accumulate a week of credit.
	clock.advance(7 * 24 * time.Hour)
	for i := range rlCalls {
		if err := lim.Allow(ctx, rlCaller(), ""); err != nil {
			t.Fatalf("call %d after a long idle was refused: %v", i+1, err)
		}
	}
	if err := lim.Allow(ctx, rlCaller(), ""); err == nil {
		t.Errorf("an idle caller accumulated more than one bucket of credit")
	}
}

// TestAnUnnamedCallerIsRefused. A bucket keyed on nothing is one bucket every
// unnamed caller shares, which is a limit that either blocks everybody or
// nobody. It fails closed instead.
func TestAnUnnamedCallerIsRefused(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)

	for _, c := range []RateLimitCaller{
		{AgentType: "", TaskRef: raTaskID},
		{AgentType: raAgentType, TaskRef: ""},
	} {
		err := lim.Allow(t.Context(), c, "")
		if err == nil {
			t.Fatalf("caller %+v was admitted", c)
		}
		if got := mcpError(t, err).Class; got != ClassInvariantViolation {
			t.Errorf("caller %+v refused as %s, want %s", c, got, ClassInvariantViolation)
		}
	}
	if stats := lim.Stats(); stats.Refused != 0 || stats.Callers != 0 {
		t.Errorf("stats = %+v; an unnamed caller must not create a bucket", stats)
	}
}

// TestTheTrackedCallerTableIsBounded. The caller key is attacker-supplied
// (E1: the MCP does not authenticate its callers), so an unbounded map keyed
// on it is a memory-exhaustion vector — AB-07 again, one layer down.
func TestTheTrackedCallerTableIsBounded(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	const bound = 4
	lim := rlLimiter(t, clock, alerts, bound)
	ctx := t.Context()

	for i := range 200 {
		c := RateLimitCaller{AgentType: "agent-" + strconv.Itoa(i), TaskRef: "task-" + strconv.Itoa(i)}
		// Each fresh caller spends its whole bucket, so nothing in the table
		// is idle and eviction has to choose.
		for range rlCalls {
			if err := lim.Allow(ctx, c, ""); err != nil {
				t.Fatalf("caller %d was refused inside its own limit: %v", i, err)
			}
		}
		if got := lim.Stats().Callers; got > bound {
			t.Fatalf("after %d callers the table holds %d, the bound is %d", i+1, got, bound)
		}
	}
	if got := lim.Stats().Evicted; got == 0 {
		t.Errorf("200 callers through a table of %d evicted nothing", bound)
	}
}

// TestAnIdleBucketIsDroppedRatherThanEvicted. Dropping a bucket that has
// refilled changes no decision — a full bucket and an absent one admit
// identically — so it is the eviction that costs nothing.
func TestAnIdleBucketIsDroppedRatherThanEvicted(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 2)
	ctx := t.Context()

	for _, name := range []string{"one", "two"} {
		if err := lim.Allow(ctx, RateLimitCaller{AgentType: name, TaskRef: name}, ""); err != nil {
			t.Fatalf("caller %s refused: %v", name, err)
		}
	}
	clock.advance(rlWindow)
	if err := lim.Allow(ctx, RateLimitCaller{AgentType: "three", TaskRef: "three"}, ""); err != nil {
		t.Fatalf("third caller refused: %v", err)
	}
	if got := lim.Stats().Evicted; got != 0 {
		t.Errorf("Evicted = %d; two idle buckets were dropped, not evicted", got)
	}
	if got := lim.Stats().Callers; got != 1 {
		t.Errorf("table holds %d callers, want 1", got)
	}
}

// TestARefusedCallerKeepsItsBucketUnderPressure. Eviction must never pick the
// caller that is currently being limited: that would reset the flood's meter
// and hand the attacker a fresh burst on every cycle.
func TestARefusedCallerKeepsItsBucketUnderPressure(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 2)
	ctx := t.Context()

	flooder := RateLimitCaller{AgentType: "flooder", TaskRef: "flooder"}
	for range rlCalls {
		if err := lim.Allow(ctx, flooder, ""); err != nil {
			t.Fatalf("flooder refused inside its limit: %v", err)
		}
	}
	// Push other callers through the table. The flooder's bucket is the one
	// furthest from refilling, so it is the last thing eviction would choose.
	for i := range 20 {
		other := RateLimitCaller{AgentType: "other-" + strconv.Itoa(i), TaskRef: "t"}
		if err := lim.Allow(ctx, other, ""); err != nil {
			t.Fatalf("caller %d refused: %v", i, err)
		}
	}
	if err := lim.Allow(ctx, flooder, ""); err == nil {
		t.Fatalf("the flooder was admitted again; its meter was evicted")
	}
}

// TestNewRateLimiterRefusesAConfigurationItCannotEnforce. Every refusal is an
// INVARIANT_VIOLATION: a limiter that silently admits everything is a control
// that reports protection it never applied.
func TestNewRateLimiterRefusesAConfigurationItCannotEnforce(t *testing.T) {
	ok := RateLimit{Tool: ToolRegisterAgent, Calls: rlCalls, Window: rlWindow}
	for _, tc := range []struct {
		name string
		cfg  RateLimit
	}{
		{"no tool", RateLimit{Calls: rlCalls, Window: rlWindow}},
		{"a tool outside IP §4", RateLimit{Tool: "list_agents", Calls: rlCalls, Window: rlWindow}},
		{"no calls", RateLimit{Tool: ToolRegisterAgent, Window: rlWindow}},
		{"negative calls", RateLimit{Tool: ToolRegisterAgent, Calls: -1, Window: rlWindow}},
		{"no window", RateLimit{Tool: ToolRegisterAgent, Calls: rlCalls}},
		{"a window too short to divide", RateLimit{Tool: ToolRegisterAgent, Calls: 4, Window: 3}},
	} {
		lim, err := NewRateLimiter(tc.cfg)
		if err == nil {
			t.Errorf("%s was accepted: %+v", tc.name, lim)
			continue
		}
		if got := mcpError(t, err).Class; got != ClassInvariantViolation {
			t.Errorf("%s refused as %s, want %s", tc.name, got, ClassInvariantViolation)
		}
	}
	if _, err := NewRateLimiter(ok); err != nil {
		t.Errorf("a complete configuration was refused: %v", err)
	}
}

// TestTheDefaultLimiterUsesTheShippedDefaults.
func TestTheDefaultLimiterUsesTheShippedDefaults(t *testing.T) {
	lim, err := NewRateLimiter(RateLimit{
		Tool: ToolRegisterAgent, Calls: rlCalls, Window: rlWindow,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	// No Now and no Alert: both must be filled in, or the first refusal
	// panics on a nil sink in production and nowhere else.
	for range rlCalls {
		if err := lim.Allow(t.Context(), rlCaller(), ""); err != nil {
			t.Fatalf("call refused inside the limit: %v", err)
		}
	}
	if err := lim.Allow(t.Context(), rlCaller(), ""); err == nil {
		t.Fatalf("the limit did not engage")
	}
	if got := lim.Stats().Trips; got != 1 {
		t.Errorf("Trips = %d, want 1 through the default alert sink", got)
	}
	if DefaultRegisterAgentRateLimitCalls <= 0 || DefaultRegisterAgentRateLimitWindow <= 0 {
		t.Errorf("the shipped default is not a limit: %d per %v",
			DefaultRegisterAgentRateLimitCalls, DefaultRegisterAgentRateLimitWindow)
	}
	if DefaultRateLimitMaxCallers <= 0 {
		t.Errorf("the shipped caller bound is %d", DefaultRateLimitMaxCallers)
	}
}

// ---------------------------------------------------------------------------
// The seam onto register_agent
// ---------------------------------------------------------------------------

// rlLedger records what reached the ledger.
type rlLedger struct {
	mu   sync.Mutex
	seen []event.Fields
	err  error
}

func (l *rlLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	l.seen = append(l.seen, body)
	return body, nil
}

func (l *rlLedger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

// TestRateLimitRegisterAgentRefusesAConfigurationItCannotMeter.
func TestRateLimitRegisterAgentRefusesAConfigurationItCannotMeter(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	good := rlLimiter(t, clock, alerts, 0)
	wrongTool, err := NewRateLimiter(RateLimit{
		Tool: ToolRetireAgent, Calls: rlCalls, Window: rlWindow, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}

	for _, tc := range []struct {
		name string
		cfg  RegisterAgentConfig
		lim  *RateLimiter
	}{
		{"no limiter", RegisterAgentConfig{Ledger: &rlLedger{}}, nil},
		{"no ledger to meter", RegisterAgentConfig{}, good},
		{"a limiter for another tool", RegisterAgentConfig{Ledger: &rlLedger{}}, wrongTool},
	} {
		_, refused := RateLimitRegisterAgent(tc.cfg, tc.lim)
		if refused == nil {
			t.Errorf("%s was accepted", tc.name)
			continue
		}
		if got := mcpError(t, refused).Class; got != ClassInvariantViolation {
			t.Errorf("%s refused as %s, want %s", tc.name, got, ClassInvariantViolation)
		}
	}

	metered, err := RateLimitRegisterAgent(RegisterAgentConfig{Ledger: &rlLedger{}}, good)
	if err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
	if metered.Ledger == nil {
		t.Fatalf("the metered configuration has no ledger")
	}
}

// TestAnEventThatNamesNoCallerIsNotAppended. The meter reads the caller off
// the event it is about to admit, so what is limited and what is recorded
// cannot disagree. An event that names no caller cannot be attributed to one,
// and is refused rather than admitted unmetered.
func TestAnEventThatNamesNoCallerIsNotAppended(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	inner := &rlLedger{}
	metered, err := RateLimitRegisterAgent(RegisterAgentConfig{Ledger: inner}, lim)
	if err != nil {
		t.Fatalf("RateLimitRegisterAgent: %v", err)
	}

	for _, tc := range []struct {
		name string
		body event.Fields
	}{
		{"no agent_type", event.Fields{event.FieldTaskRef: raTaskID}},
		{"agent_type is not a string", event.Fields{
			event.FieldAgentType: 42, event.FieldTaskRef: raTaskID}},
		{"no task_ref", event.Fields{event.FieldAgentType: raAgentType}},
		{"task_ref is not a string", event.Fields{
			event.FieldAgentType: raAgentType, event.FieldTaskRef: 42}},
	} {
		_, err := metered.Ledger.Append(t.Context(), tc.body)
		if err == nil {
			t.Errorf("%s was appended", tc.name)
			continue
		}
		if got := mcpError(t, err).Class; got != ClassInvariantViolation {
			t.Errorf("%s refused as %s, want %s", tc.name, got, ClassInvariantViolation)
		}
	}
	if got := inner.count(); got != 0 {
		t.Errorf("%d unattributable event(s) reached the ledger", got)
	}
}

// TestAMeteredAppendReachesTheLedgerAndCarriesItsFailureBack.
func TestAMeteredAppendReachesTheLedgerAndCarriesItsFailureBack(t *testing.T) {
	clock, alerts := newRLClock(), &rlAlerts{}
	lim := rlLimiter(t, clock, alerts, 0)
	inner := &rlLedger{}
	metered, err := RateLimitRegisterAgent(RegisterAgentConfig{Ledger: inner}, lim)
	if err != nil {
		t.Fatalf("RateLimitRegisterAgent: %v", err)
	}
	body := event.Fields{event.FieldAgentType: raAgentType, event.FieldTaskRef: raTaskID}

	got, err := metered.Ledger.Append(t.Context(), body)
	if err != nil {
		t.Fatalf("a metered append inside the limit failed: %v", err)
	}
	if got[event.FieldAgentType] != raAgentType {
		t.Errorf("the appender returned %v, not the inner ledger's answer", got)
	}

	// A ledger failure is carried back untouched: the meter is not a place
	// where the ledger's own error class is rewritten.
	inner.mu.Lock()
	inner.err = errors.New("postgres is gone")
	inner.mu.Unlock()
	if _, err := metered.Ledger.Append(t.Context(), body); err == nil {
		t.Errorf("a failing ledger appended successfully")
	} else if !strings.Contains(err.Error(), "postgres is gone") {
		t.Errorf("the ledger's failure was replaced by %v", err)
	}
}

// TestRateLimitCallerRendersItselfForAnOperator.
func TestRateLimitCallerRendersItselfForAnOperator(t *testing.T) {
	got := rlCaller().String()
	if !strings.Contains(got, raAgentType) || !strings.Contains(got, raTaskID) {
		t.Errorf("caller renders as %q, which does not name agent_type %q and task_ref %q",
			got, raAgentType, raTaskID)
	}
}
