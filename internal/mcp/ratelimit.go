// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// Rate limiting — RM-027 (#35), IP §6.10:
//
//	Rate-limit `register_agent` per caller; a runaway loop must not exhaust
//	SPIRE or flood the ledger silently — test the limit and the alert.
//
// The threat is AB-07: "flood register_agent to exhaust SPIRE / bloat ledger",
// whose control doc 04 gives as "rate limit + alert" and whose test is
// MCP-013. Both halves are required. A limit with no alert converts a loud
// failure into a quiet one — the flood stops damaging the ledger and starts
// being invisible, which is the word "silently" in IP §6.10.
//
// # What a runaway loop actually does, and what is therefore worth metering
//
// A loop that repeats ONE call — same `idempotency_key` — is already harmless
// and is metered by nothing here. The ledger's UNIQUE idempotency_key makes it
// one event (LED-008) and ADR-0017's store makes it one reply, so the
// thousandth repeat costs a row read. It is not the attack.
//
// The attack is the loop that mints a NEW key every iteration. Each such call
// is, to every layer below, a legitimately different request: a different
// derived run id (see registerAgentRunID), a different SPIFFE ID, a new SPIRE
// registration entry, a new `run_registered` event in an append-only chain
// that I4 forbids anyone from ever deleting. That is the thing that has to be
// bounded, and it is what this file bounds.
//
// # What identifies a caller — stated plainly, including what it does not do
//
// A bucket is keyed on the pair (`agent_type`, `task_ref`): the two arguments
// of `register_agent` that name WHO is registering and WHAT FOR. The third,
// `idempotency_key`, is deliberately excluded — it is the value the attack
// varies, so keying on it would give every flooded call its own fresh bucket
// and produce a limiter that never limits anything.
//
// This is the honest ceiling of what can be keyed on today, and the honest
// statement of it is this:
//
//	The MCP does not authenticate its callers. E1 exempts authorization from
//	v0.1, and ADR-0019 already recorded that the *caller's* identity at the
//	MCP boundary is unowned — `get_credential` binds a credential to the run
//	named in the request, and nothing proves the requester is that run. So
//	(`agent_type`, `task_ref`) is a CLAIM, exactly as doc 04 §4 says
//	`task_ref` is "a claim, not a fact".
//
// What that buys: a runaway loop — the realistic AB-07, a bug rather than an
// adversary — is bounded, because a looping agent keeps asserting the same
// agent_type and task_ref while varying the key it cycles. Its blast radius is
// its own bucket and nobody else's.
//
// What it does NOT buy: an ADVERSARY who varies `agent_type` or `task_id` gets
// a fresh bucket per variation and defeats the limit entirely. Nothing in this
// file changes that, and nothing in this file pretends to. The control for
// that adversary is caller authentication, which is E1 work, and until it
// exists the limit below is a runaway-loop guard, not an anti-DoS control.
// ADR-0025 records this in full.
//
// # Per caller, never global
//
// There is no global counter here on purpose. A global limit converts one
// runaway agent into a refusal for every other agent in the deployment, which
// is AB-07's stated goal — resource exhaustion — achieved by the defence
// rather than prevented by it. The one global quantity is the SIZE of the
// caller table, which is bounded because the key is caller-supplied; see
// evict, which is written so that the bound can never itself become a refusal.
//
// # Where the meter sits, and why it is on the ledger appender
//
// `register_agent` does two things, in the order ADR-0018 fixed: it appends
// `run_registered`, and THEN it creates the SPIRE entry. So a refusal at the
// appender is a refusal that reaches neither system, and one meter protects
// both. MCP-013 asserts that positively — SPIRE is never even asked — so if
// that ordering is ever reversed the test says so rather than the protection
// quietly halving.
//
// The seam is a decorator over `RegisterAgentConfig.Ledger`, installed by
// RateLimitRegisterAgent. That places the meter INSIDE the idempotency claim,
// which has one cost and one benefit, both real:
//
//   - Benefit, and it is the decisive one: a REPLAY is never metered. ADR-0017
//     answers a completed key from the record without re-executing the tool,
//     so the meter never sees it. A limiter placed ahead of the claim would
//     refuse a crash-replay, and IP §6.6 requires that replay to return the
//     original result — the control would be breaking the invariant it exists
//     to protect. MCP-013's replay test pins this.
//   - Cost: a refused call still costs the claim and release of an idempotency
//     row, so a flood reaches Postgres as two cheap statements per call. It
//     reaches the LEDGER — the append-only chain MCP-013 is about, and the one
//     I4 makes permanent — not at all. Stated rather than hidden.
//
// # The alert, and the event type the closed schema does not have
//
// doc 02 §3 is closed and an implementation may not invent an event type. None
// of the eleven fits a rate-limit trip:
//
//	tool_call                the call did not happen; recording refusals as
//	                         invocations would make the chain claim work that
//	                         was never done. Worse, it is the ledger flood the
//	                         limit exists to prevent, written by the limit.
//	ledger_drift_detected    requires `subject_event_id`, and a refusal's
//	                         entire content is that no event was written, so
//	                         there is no subject. Its meaning — "ledger claim
//	                         with no external proof" — is also not this.
//	run_registered           the run was not registered.
//
// So the trip goes to an ALERT SINK and not to the ledger, which is the
// pattern RM-019 established for the one drift kind the schema cannot carry
// (ADR-0013), and which doc 05 §2 anticipates: its monitoring minimums list
// "rate-limit trips" beside "reconciler drift alerts", and say every alert in
// that list "corresponds to an event type **or test** in the catalog". This
// one corresponds to a test, MCP-013. Whether doc 02 §3 should gain a
// `rate_limit_exceeded` type is a protected-surface question for a human, and
// ADR-0025 flags it rather than answering it.
//
// One alert per trip EPISODE, not per refused call. An alert line per refusal
// is a log flood, which is the same failure in a different sink; the episode
// re-arms when the caller is served again, so a second incident pages again.
// The cumulative counters behind Stats are the monitored surface for the rest.

const (
	// DefaultRegisterAgentRateLimitCalls and
	// DefaultRegisterAgentRateLimitWindow are the shipped limit: one
	// registration a second, sustained, per caller.
	//
	// The number is chosen against measured intent rather than taste. doc 05
	// §4's sizing posture is 10⁶ runs a year, which is about 0.03 registrations
	// a second across the WHOLE deployment; one a second for a single caller is
	// some thirty times the entire projected fleet rate. A caller that exceeds
	// it is not working, it is looping. It is also far above any human-paced
	// burst — a CI matrix fanning out sixty jobs at once passes on the first
	// try, because the bucket is full.
	DefaultRegisterAgentRateLimitCalls  = 60
	DefaultRegisterAgentRateLimitWindow = time.Minute

	// DefaultRateLimitMaxCallers bounds the tracked caller table. The key is
	// caller-supplied and unauthenticated, so an unbounded map is a memory
	// exhaustion vector — AB-07 one layer down. Four thousand buckets is a few
	// hundred kilobytes and far more distinct (agent_type, task_ref) pairs than
	// a deployment sized by doc 05 §4 has active in one window.
	DefaultRateLimitMaxCallers = 4096

	// rateLimitSource names this layer in an operator-facing message.
	rateLimitSource = "the register_agent rate limit"
)

// RateLimitCaller is what one bucket is keyed on: the pair of `register_agent`
// arguments that name the caller. It is a claim and not an authenticated
// identity — see the note at the top of this file.
type RateLimitCaller struct {
	// AgentType is the caller's `agent_type`, the {agent_type} component of
	// every SPIFFE ID it registers.
	AgentType string
	// TaskRef is the caller's `task_id`, verbatim — the same value the event
	// records as `task_ref`.
	TaskRef string
}

// String renders the caller for an operator. It is not the bucket key: two
// callers whose components differ only in where a separator falls must not
// share a bucket, which is what key guarantees and this does not.
func (c RateLimitCaller) String() string { return c.AgentType + "/" + c.TaskRef }

// key is the map key. NUL-joined because neither component may contain a NUL:
// `agent_type` is held to doc 02 §5's identifier grammar, and `task_ref` is
// UTF-8 text whose NUL would be refused at append.
func (c RateLimitCaller) key() string { return c.AgentType + "\x00" + c.TaskRef }

// RateLimitTrip is one alert: a caller that has just gone over its limit.
type RateLimitTrip struct {
	// Tool is the metered tool.
	Tool ToolName
	// Caller is the bucket that tripped.
	Caller RateLimitCaller
	// Calls and Window are the limit that was exceeded, so an alert is
	// readable without the configuration beside it.
	Calls  int
	Window time.Duration
	// RetryAfter is how long until this caller is served again. IP §4's error
	// object has no field for it, so it reaches the operator here and the
	// caller only as message text — ADR-0025 flags the gap.
	RetryAfter time.Duration
	// At is when the trip happened, by the limiter's own clock.
	At time.Time
}

// RateLimitStats is the monitored surface. doc 05 §2 names "rate-limit trips"
// among the monitoring minimums; the rest is here because a trip count with no
// denominator cannot be read.
type RateLimitStats struct {
	// Admitted and Refused are calls, cumulative.
	Admitted int64
	Refused  int64
	// Trips is episodes, not refusals: one per transition from serving a
	// caller to refusing it. This is doc 05 §2's metric.
	Trips int64
	// Evicted is buckets discarded to stay inside MaxCallers while their
	// caller was still being limited. A non-zero value means the table is
	// under pressure and the limit is weaker than configured.
	Evicted int64
	// Callers is the table's current size.
	Callers int
}

// RateLimit configures a RateLimiter.
type RateLimit struct {
	// Tool is the metered tool. Required, and must be one of IP §4's five: a
	// limiter for a tool that does not exist is a control nothing enforces.
	Tool ToolName
	// Calls is how many calls one caller may make per Window. Required.
	Calls int
	// Window is the period Calls is measured over. Required.
	Window time.Duration
	// MaxCallers bounds the tracked caller table. Zero or less means
	// DefaultRateLimitMaxCallers.
	MaxCallers int
	// Alert receives every trip. Defaults to an error-level slog line. It is
	// the ONLY channel a trip has — the closed event schema has no type for
	// one — so a deployment that routes alerts anywhere else must set it.
	Alert func(context.Context, RateLimitTrip)
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// RateLimiter meters one tool, per caller.
//
// The algorithm is a generic cell rate algorithm — a leaky bucket kept as one
// timestamp per caller rather than as a counter and a window. Two properties
// are why:
//
//   - It has no window edge. A fixed window lets a caller spend its whole
//     allowance in the last instant of one window and again in the first
//     instant of the next, which is twice the configured rate at exactly the
//     moment a flood is starting.
//   - It is exact in integer time. There is no floating-point token count to
//     accumulate rounding, so the boundary MCP-013 asserts — call N admitted,
//     call N+1 refused — is the same on every platform.
//
// One state field per caller, `tat`, is the theoretical arrival time of the
// next conforming call. A call at time t is admitted when
// t ≥ tat − tolerance, and moves tat forward by one emission interval.
type RateLimiter struct {
	tool   ToolName
	calls  int
	window time.Duration
	// interval is the sustained rate: one call per interval.
	interval time.Duration
	// tolerance is the burst allowance, (calls-1) intervals, so exactly calls
	// requests fit in an empty bucket.
	tolerance  time.Duration
	maxCallers int
	alert      func(context.Context, RateLimitTrip)
	now        func() time.Time

	mu      sync.Mutex
	buckets map[string]*rateLimitBucket
	stats   RateLimitStats
}

// rateLimitBucket is one caller's state.
type rateLimitBucket struct {
	// tat is the theoretical arrival time of the next conforming call.
	tat time.Time
	// tripped is whether this caller is inside an alerting episode, so a
	// flood raises one alert and not one per refused call.
	tripped bool
}

// NewRateLimiter builds a limiter, or refuses.
//
// Every refusal is an INVARIANT_VIOLATION and not a default: a limiter that
// quietly admitted everything because its window was zero would report a
// control that is not there, which is worse than having no control, because
// AB-07 would then be recorded as mitigated.
func NewRateLimiter(cfg RateLimit) (*RateLimiter, error) {
	fail := func(format string, args ...any) (*RateLimiter, error) {
		return nil, Errorf(ClassInvariantViolation, "", "rate limit configuration: "+format, args...)
	}
	if !cfg.Tool.Valid() {
		return fail("%q is not one of the five IP §4 tool names; there is nothing to meter",
			string(cfg.Tool))
	}
	if cfg.Calls <= 0 {
		return fail("a limit of %d calls per caller admits nothing; use a positive limit", cfg.Calls)
	}
	if cfg.Window <= 0 {
		return fail("a window of %v is not a period; %d calls per nothing is not a rate",
			cfg.Window, cfg.Calls)
	}
	interval := cfg.Window / time.Duration(cfg.Calls)
	if interval <= 0 {
		return fail("%d calls per %v is finer than the clock; the emission interval rounds to zero "+
			"and the limit would admit everything", cfg.Calls, cfg.Window)
	}

	maxCallers := cfg.MaxCallers
	if maxCallers <= 0 {
		maxCallers = DefaultRateLimitMaxCallers
	}
	alert := cfg.Alert
	if alert == nil {
		alert = defaultRateLimitAlert
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		tool:   cfg.Tool,
		calls:  cfg.Calls,
		window: cfg.Window,
		// Integer division truncates, which makes the sustained rate very
		// slightly STRICTER than configured and never looser. The burst is
		// exactly cfg.Calls either way, which is the number MCP-013 asserts.
		interval:   interval,
		tolerance:  time.Duration(cfg.Calls-1) * interval,
		maxCallers: maxCallers,
		alert:      alert,
		now:        now,
		buckets:    make(map[string]*rateLimitBucket),
	}, nil
}

// Allow admits or refuses one call by caller, and raises the alert when a
// caller trips.
//
// runID scopes a refusal to the run the call would have acted on — IP §4's
// optional `run_id`, empty for none. It is deliberately NOT part of the bucket
// key: the run is what a flood varies and the caller is what it does not.
// `register_agent` already names the derived run on a failure that created no
// run (a ledger outage), and a refusal is the same shape — the same key
// retried later registers the same run.
//
// The alert is delivered OUTSIDE the lock. A sink that pages an operator over
// the network must not be able to hold every other caller's meter while it
// does so — a rate limiter that serialises on its own alerting is a new
// availability failure introduced by the availability control.
func (l *RateLimiter) Allow(ctx context.Context, caller RateLimitCaller, runID string) error {
	// A bucket keyed on nothing is one bucket every unnamed caller shares,
	// which limits all of them together or none of them. It fails closed
	// instead, and does not create the bucket.
	if caller.AgentType == "" || caller.TaskRef == "" {
		return Errorf(ClassInvariantViolation, runID,
			"%s cannot meter a call that names no caller: agent_type %q, task_ref %q",
			rateLimitSource, caller.AgentType, caller.TaskRef)
	}

	now := l.now()
	l.mu.Lock()
	wait, tripped := l.admit(caller, now)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	if tripped {
		l.alert(ctx, RateLimitTrip{
			Tool:       l.tool,
			Caller:     caller,
			Calls:      l.calls,
			Window:     l.window,
			RetryAfter: wait,
			At:         now,
		})
	}
	// IP §4's closed vocabulary has no class for "slow down"; ADR-0025 records
	// why this is IDENTITY_UNAVAILABLE and flags the missing twelfth class.
	// The class carries the retryable flag a caller's retry loop reads — true,
	// because waiting is exactly what makes this call succeed — and the
	// message carries the reason and the wait, which the class cannot.
	return Errorf(ClassIdentityUnavailable, runID,
		"rate limit: %s allows %d calls per %v to caller %s, which has reached it; "+
			"no identity was created and nothing was recorded — retry in %v",
		l.tool, l.calls, l.window, caller, wait)
}

// admit is Allow's decision, under the lock. It returns how long the caller
// must wait (zero or less when the call is admitted) and whether this refusal
// begins a new alerting episode.
func (l *RateLimiter) admit(caller RateLimitCaller, now time.Time) (time.Duration, bool) {
	key := caller.key()
	b, known := l.buckets[key]
	if !known {
		if len(l.buckets) >= l.maxCallers {
			l.evict(now)
		}
		b = &rateLimitBucket{tat: now}
		l.buckets[key] = b
	}
	// A bucket that has refilled is worth exactly one full bucket and no
	// more: a caller idle for a week does not accumulate a week of credit.
	if b.tat.Before(now) {
		b.tat = now
	}

	wait := b.tat.Sub(now) - l.tolerance
	if wait > 0 {
		l.stats.Refused++
		if b.tripped {
			return wait, false
		}
		b.tripped = true
		l.stats.Trips++
		return wait, true
	}

	// Conforming: consume one emission interval. tat is NOT reset to now, so
	// the credit a caller did not spend is what gives it its burst.
	b.tat = b.tat.Add(l.interval)
	// The episode is over. It re-arms, so a second incident pages again — an
	// alert that fires once per process lifetime stops being an alert.
	b.tripped = false
	l.stats.Admitted++
	return wait, false
}

// evict makes room for one more caller. Called under the lock.
//
// Two rules, and the second is the one that matters:
//
//  1. A bucket whose tat has passed has refilled, and a full bucket admits
//     exactly what an absent one admits. Dropping it changes no decision, so
//     every such bucket goes first and none of it is counted as eviction.
//  2. If that frees nothing, the bucket evicted is the one CLOSEST to
//     refilling — the least active caller — and never the one furthest from
//     it. The flooding caller's bucket is by construction the furthest from
//     refilling, so it is the last thing evicted: an attacker cannot cycle
//     keys to reset its own meter, which would turn the memory bound into a
//     way to defeat the limit.
//
// Eviction only ever GRANTS a caller credit; it never refuses one. That is
// deliberate. Refusing a new caller when the table is full would let anyone
// who can mint distinct keys deny service to every caller not already in the
// table — a global outage produced by the bound, which is AB-07 again. The
// bound costs accuracy under pressure, never availability, and Stats().Evicted
// is how an operator sees that it is costing anything at all.
func (l *RateLimiter) evict(now time.Time) {
	var (
		coldestKey string
		coldest    time.Time
	)
	for k, b := range l.buckets {
		if !b.tat.After(now) {
			delete(l.buckets, k)
			continue
		}
		if coldestKey == "" || b.tat.Before(coldest) {
			coldestKey, coldest = k, b.tat
		}
	}
	if len(l.buckets) >= l.maxCallers {
		delete(l.buckets, coldestKey)
		l.stats.Evicted++
	}
}

// Stats reports the counters. doc 05 §2 lists rate-limit trips among the
// monitoring minimums; this is where a metrics exporter reads them.
func (l *RateLimiter) Stats() RateLimitStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Callers = len(l.buckets)
	return s
}

// defaultRateLimitAlert is the sink a deployment gets if it names none. Error
// level, and it says explicitly that the ledger does not hold this: doc 04
// calls a rate-limit trip an alert (AB-07), doc 05 §2 lists it among the
// monitoring minimums, and doc 02 §3 has no event type for it.
func defaultRateLimitAlert(ctx context.Context, trip RateLimitTrip) {
	slog.ErrorContext(ctx,
		"rate limit engaged (AB-07): a caller exceeded its limit; the closed event schema "+
			"has no event type for this, so it is not in the ledger",
		"tool", string(trip.Tool),
		"agent_type", trip.Caller.AgentType,
		"task_ref", trip.Caller.TaskRef,
		"calls", trip.Calls,
		"window", trip.Window.String(),
		"retry_after", trip.RetryAfter.String())
}

// ---------------------------------------------------------------------------
// The seam onto register_agent
// ---------------------------------------------------------------------------

// RateLimitRegisterAgent returns a copy of cfg whose registrations are metered
// by lim, for installation with ConfigureRegisterAgent:
//
//	metered, err := mcp.RateLimitRegisterAgent(cfg, limiter)
//	if err != nil { … }
//	restore, err := mcp.ConfigureRegisterAgent(metered)
//
// It refuses rather than returning an unmetered configuration, because the
// failure mode of the alternative is a deployment that believes AB-07 is
// controlled and is not.
func RateLimitRegisterAgent(cfg RegisterAgentConfig, lim *RateLimiter) (RegisterAgentConfig, error) {
	fail := func(format string, args ...any) (RegisterAgentConfig, error) {
		return RegisterAgentConfig{}, Errorf(ClassInvariantViolation, "",
			"register_agent rate limit: "+format, args...)
	}
	if lim == nil {
		return fail("no limiter; a metered configuration with no meter is an unmetered one (AB-07)")
	}
	if lim.tool != ToolRegisterAgent {
		return fail("the limiter meters %s, not %s", lim.tool, ToolRegisterAgent)
	}
	if cfg.Ledger == nil {
		// ConfigureRegisterAgent refuses a nil ledger, and would not see this
		// one: it would see the wrapper. Refusing here keeps that check honest.
		return fail("no ledger to meter (I3)")
	}
	cfg.Ledger = meteredRegisterAgentLedger{inner: cfg.Ledger, limiter: lim}
	return cfg, nil
}

// meteredRegisterAgentLedger admits an append only if its caller is inside its
// limit.
//
// It reads the caller off the EVENT it is about to admit rather than off the
// request, because the event is what this seam is handed — and the property
// that falls out is worth more than the convenience: what is metered and what
// is recorded are read from the same bytes, so a limit applied to one caller
// and a record written for another is not expressible.
type meteredRegisterAgentLedger struct {
	inner   RegisterAgentLedger
	limiter *RateLimiter
}

func (m meteredRegisterAgentLedger) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	caller, err := registerAgentCallerOf(body)
	if err != nil {
		return nil, err
	}
	// The run the append would have created, read off the same bytes. Absent
	// or not a string leaves the refusal unscoped, which doc 02 §1's
	// absent-versus-empty rule renders as no `run_id` at all.
	runID, named := body[event.FieldRunID].(string)
	if !named {
		runID = ""
	}
	if err := m.limiter.Allow(ctx, caller, runID); err != nil {
		return nil, err
	}
	return m.inner.Append(ctx, body)
}

// registerAgentCallerOf reads the caller out of a `run_registered` body.
//
// An event that names no caller cannot be attributed to a bucket, and is
// refused rather than admitted unmetered: an unmeterable append through a
// metered appender is a hole, and IP §4 has one class for a defect inside the
// MCP. Both members are protected strings (doc 02 §3).
func registerAgentCallerOf(body event.Fields) (RateLimitCaller, error) {
	agentType, ok := body[event.FieldAgentType].(string)
	if !ok {
		return RateLimitCaller{}, Errorf(ClassInvariantViolation, "",
			"%s cannot read %s off the event it was asked to append, so the call names no caller",
			rateLimitSource, event.FieldAgentType)
	}
	taskRef, ok := body[event.FieldTaskRef].(string)
	if !ok {
		return RateLimitCaller{}, Errorf(ClassInvariantViolation, "",
			"%s cannot read %s off the event it was asked to append, so the call names no caller",
			rateLimitSource, event.FieldTaskRef)
	}
	return RateLimitCaller{AgentType: agentType, TaskRef: taskRef}, nil
}
