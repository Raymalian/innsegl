// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// limit.go is GW-013 (#375): a per-session request-rate guard, plugged into
// the chain guard.go describes -- see defaultGuards below, appended AFTER
// NewHarnessGuard() because this guard reads the session id the harness
// guard already attached to the request's context (WithIdentification,
// harness.go).
//
// # What this is, stated in ADR-0025's own terms
//
// ADR-0025 already drew this line for register_agent's own limiter and it
// applies here unchanged, because the same four forces apply: there is still
// no authenticated caller (E1), a global limit is still the attack and not
// the defence (one runaway session must never refuse every other session),
// and the session id this bucket is keyed on is still harness-ASSERTED, not
// SPIRE-attested (ADR-0058 decision 2). So, precisely:
//
//   - What this protects against: a session whose own traffic loops --
//     retries with no back-off, a bug that fires a request per tight
//     iteration rather than per turn. That is bounded to its own bucket and
//     has no effect on any other session (GW-013's own text: "other sessions
//     unaffected").
//   - What this does NOT protect against: an adversary who can mint a fresh
//     session id per request defeats this entirely, the same residual
//     ADR-0025 names for register_agent. This is a runaway-loop guard, not
//     an anti-DoS control, until callers are authenticated.
//
// # Why the defaults are generous, and the number behind them
//
// The bucket is keyed on Identification.SessionID (harness.go), and
// ADR-0058 decision 2 records that Claude Code sends the SAME session id on
// every request a main agent and every one of its subagents make -- there is
// one bucket per conversation, not one per agent inside it. A session
// running this project's own parallel-agent workflow (dispatch-wave) can
// have on the order of a few dozen subagents streaming at once, each making
// its own model requests, all landing in this one bucket.
//
// Two numbers, chosen against that concurrency rather than against a single
// caller's traffic:
//
//   - DefaultSessionRateLimitBurst (100) is what a session may spend in a
//     single instant. A large wave dispatch fires its subagents' first
//     requests within the same short window; a hundred admits that fan-out
//     several times over before this guard is even in play, mirroring the
//     margin ADR-0025 gives its own "sixty-way CI fan-out" case.
//   - DefaultSessionRateLimitRate (20 requests/second sustained) is what the
//     bucket refills at afterwards. Every model request this gateway relays
//     waits on a real model round trip -- seconds, not milliseconds -- so
//     ONE agent's own sustained rate in a tight tool-call loop is at most a
//     few requests a second; even a few dozen agents streaming concurrently
//     under one session id do not sustain twenty a second for long, because
//     each of them is itself gated by model latency. A caller that DOES
//     sustain twenty a second, indefinitely, is not doing agentic work
//     against a model provider -- it is looping with nothing to wait for,
//     which is exactly the runaway this guard exists to catch.
//
// Both are configurable ($INNSEGL_GATEWAY_RATE, $INNSEGL_GATEWAY_BURST --
// cmd/innsegl/gateway.go), validated at start-up there the same way
// -upstream already is: a non-positive value refuses before anything is
// relayed rather than shipping a limiter that quietly admits everything.
//
// # The algorithm
//
// The same generic-cell-rate shape ADR-0025 chose for register_agent's own
// limiter, for the same two reasons: no window edge (a fixed window lets a
// session spend a full allowance in the last instant of one window and
// again in the first instant of the next), and exact in integer time (the
// admitted/refused boundary is the same on every platform). One bucket per
// session id, one timestamp (tat, the theoretical arrival time of the next
// conforming request) plus a last-seen mark for idle eviction.
//
// # The alert
//
// One per session per TRIP EPISODE, never per refused request -- a line per
// refusal is the same log flood in a different sink, and the episode
// re-arms the moment the session is served again, so a second incident
// pages again. AlertSink is deliberately small and interface-shaped, not a
// bare slog call, because this gateway has no ledger yet (E15 wires
// identity and records): the default implementation logs at warn level and
// carries the session id -- the one piece of information a per-session
// alert exists to convey -- and NOTHING else off the request, no header
// among them, credential or otherwise. E15 replaces this default with an
// AlertSink that writes to the ledger's own alert path instead of stderr;
// nothing else about this file needs to change for that swap.
//
// # Idle eviction
//
// The session table is bounded two ways, not one. DefaultSessionRateLimitMaxSessions
// caps its size the way ADR-0025's own MaxCallers does -- the key is
// harness-asserted and unbounded key-minting is a memory-exhaustion vector
// one layer down from the request flood itself -- and evictFullest never
// evicts the bucket furthest from refilling (the flooding session's own),
// exactly ADR-0025's reasoning. Separately, and this is the part a
// request-count bound cannot give: a session that simply ENDS leaves a
// bucket behind that no later request will ever touch again, and nothing
// about being far from its cap makes that go away on its own. evictIdle
// sweeps buckets whose last request is older than IdleEvictAfter, so memory
// tracks live sessions rather than every session this process has ever
// seen.

const (
	// DefaultSessionRateLimitRate is the shipped sustained rate, in
	// requests per second, admitted from one session once its burst is
	// spent. See this file's own doc comment for the reasoning.
	DefaultSessionRateLimitRate = 20
	// DefaultSessionRateLimitBurst is the shipped burst: how many requests
	// one session may spend in a single instant before the sustained rate
	// applies.
	DefaultSessionRateLimitBurst = 100
	// DefaultSessionRateLimitMaxSessions bounds the tracked session table,
	// the same shape as ADR-0025's DefaultRateLimitMaxCallers and for the
	// same reason: the key is harness-asserted, not authenticated, so an
	// unbounded map is a memory-exhaustion vector of its own.
	DefaultSessionRateLimitMaxSessions = 4096
	// DefaultSessionRateLimitIdleEvictAfter is how long a session's bucket
	// survives with no request before it is swept, bounding memory by live
	// sessions rather than by every session ever seen.
	DefaultSessionRateLimitIdleEvictAfter = 30 * time.Minute

	sessionRateLimitSource = "the gateway's per-session rate limit"
)

// AlertSink receives one alert per session per trip episode -- see this
// file's own doc comment on why it is an interface and not a ledger write.
// E15 wires this to the ledger's alert path; DefaultAlertSink is what a
// deployment gets until then.
type AlertSink interface {
	Alert(ctx context.Context, trip SessionRateLimitTrip)
}

// SessionRateLimitTrip is one alert: a session that has just gone over its
// limit.
type SessionRateLimitTrip struct {
	// SessionID is the bucket that tripped -- Identification.SessionID,
	// harness.go.
	SessionID string
	// Rate and Burst are the limit that was exceeded, so an alert is
	// readable without the configuration beside it.
	Rate, Burst int
	// RetryAfter is how long until this session is served again -- the same
	// value the refused caller receives on the Retry-After header.
	RetryAfter time.Duration
	// At is when the trip happened, by the limiter's own clock.
	At time.Time
}

// DefaultAlertSink is the sink a SessionRateLimiter gets if none is
// configured. It logs at warn level and carries the session id and the
// limit that was exceeded -- and NOTHING else off the request. No header
// this request carried is ever read here, on principle this package already
// states elsewhere (proxy.go: "this package never logs or persists a
// header, on either side of the relay"); the session id is logged anyway
// because it is not a credential and it is the one fact a per-session alert
// exists to convey -- an alert that cannot name which session tripped is
// not actionable.
type DefaultAlertSink struct{}

// Alert implements AlertSink.
func (DefaultAlertSink) Alert(ctx context.Context, trip SessionRateLimitTrip) {
	slog.WarnContext(ctx,
		"gateway per-session rate limit engaged (GW-013): a session exceeded its request rate; "+
			"this is a runaway-loop guard (ADR-0025's framing extended to the gateway), not an "+
			"anti-DoS control -- there is no ledger yet for this alert to land in (E15 wires one)",
		"session_id", trip.SessionID,
		"rate_per_second", trip.Rate,
		"burst", trip.Burst,
		"retry_after", trip.RetryAfter.String())
}

// SessionRateLimitStats is the monitored surface, the same shape ADR-0025's
// own RateLimitStats gives register_agent's limiter.
type SessionRateLimitStats struct {
	// Admitted and Refused are requests, cumulative.
	Admitted, Refused int64
	// Trips is episodes, not refusals -- one per transition from serving a
	// session to refusing it.
	Trips int64
	// Evicted is buckets discarded to stay inside MaxSessions while their
	// session was still inside its window. EvictedIdle is buckets discarded
	// because their session went quiet for IdleEvictAfter. Both are
	// separate causes for the same effect (a bucket disappearing), kept
	// separate because they mean different things to an operator: Evicted
	// means the table is under pressure and the limit is weaker than
	// configured; EvictedIdle means nothing more than housekeeping.
	Evicted, EvictedIdle int64
	// Sessions is the table's current size.
	Sessions int
}

// SessionRateLimit configures a SessionRateLimiter. Every field is optional
// except Rate and Burst.
type SessionRateLimit struct {
	// Rate is the sustained requests-per-second admitted from one session.
	// Required, must be positive.
	Rate int
	// Burst is how many requests one session may spend in a single instant.
	// Required, must be positive.
	Burst int
	// MaxSessions bounds the tracked session table. Zero or less means
	// DefaultSessionRateLimitMaxSessions.
	MaxSessions int
	// IdleEvictAfter is how long an idle session's bucket survives before
	// being swept. Zero or less means DefaultSessionRateLimitIdleEvictAfter.
	IdleEvictAfter time.Duration
	// Alert receives every trip. Nil means DefaultAlertSink{}.
	Alert AlertSink
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// SessionRateLimiter meters requests per session id.
type SessionRateLimiter struct {
	rate  int
	burst int
	// interval is the sustained rate expressed as a duration: one
	// conforming request per interval.
	interval time.Duration
	// tolerance is the burst allowance, (burst-1) intervals, so exactly
	// burst requests fit in an empty bucket.
	tolerance      time.Duration
	maxSessions    int
	idleEvictAfter time.Duration
	alert          AlertSink
	now            func() time.Time

	mu      sync.Mutex
	buckets map[string]*sessionBucket
	stats   SessionRateLimitStats
}

// sessionBucket is one session's state.
type sessionBucket struct {
	// tat is the theoretical arrival time of the next conforming request.
	tat time.Time
	// lastSeen is when this session last made a request, admitted or
	// refused -- what evictIdle sweeps on.
	lastSeen time.Time
	// tripped is whether this session is inside an alerting episode, so a
	// flood raises one alert and not one per refused request.
	tripped bool
}

// NewSessionRateLimiter builds a limiter, or refuses.
//
// Every refusal is an error and never a silently-adjusted default: a
// limiter that quietly admitted everything because its rate was zero would
// report a control that is not there.
func NewSessionRateLimiter(cfg SessionRateLimit) (*SessionRateLimiter, error) {
	fail := func(format string, args ...any) (*SessionRateLimiter, error) {
		return nil, fmt.Errorf("%s: configuration: %s", sessionRateLimitSource, fmt.Sprintf(format, args...))
	}
	if cfg.Rate <= 0 {
		return fail("a rate of %d requests/second admits nothing; use a positive rate", cfg.Rate)
	}
	if cfg.Burst <= 0 {
		return fail("a burst of %d admits nothing; use a positive burst", cfg.Burst)
	}
	interval := time.Second / time.Duration(cfg.Rate)
	if interval <= 0 {
		return fail("%d requests/second is finer than the clock; the emission interval rounds to "+
			"zero and the limit would admit everything", cfg.Rate)
	}

	maxSessions := cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = DefaultSessionRateLimitMaxSessions
	}
	idleEvictAfter := cfg.IdleEvictAfter
	if idleEvictAfter <= 0 {
		idleEvictAfter = DefaultSessionRateLimitIdleEvictAfter
	}
	alert := cfg.Alert
	if alert == nil {
		alert = DefaultAlertSink{}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &SessionRateLimiter{
		rate:  cfg.Rate,
		burst: cfg.Burst,
		// Integer division truncates, which makes the sustained rate very
		// slightly STRICTER than configured and never looser -- the burst
		// admitted is still exactly cfg.Burst either way.
		interval:       interval,
		tolerance:      time.Duration(cfg.Burst-1) * interval,
		maxSessions:    maxSessions,
		idleEvictAfter: idleEvictAfter,
		alert:          alert,
		now:            now,
		buckets:        make(map[string]*sessionBucket),
	}, nil
}

// Allow admits or refuses one request from sessionID, raising the alert
// exactly once per trip episode.
//
// The alert is delivered OUTSIDE the lock, the same reasoning ADR-0025 gives
// its own limiter: a sink that pages an operator over the network must not
// be able to hold every other session's meter while it does so.
func (l *SessionRateLimiter) Allow(ctx context.Context, sessionID string) (retryAfter time.Duration, refused bool) {
	now := l.now()

	l.mu.Lock()
	l.evictIdle(now)
	wait, tripped := l.admit(sessionID, now)
	l.mu.Unlock()

	if wait <= 0 {
		return 0, false
	}
	if tripped {
		l.alert.Alert(ctx, SessionRateLimitTrip{
			SessionID:  sessionID,
			Rate:       l.rate,
			Burst:      l.burst,
			RetryAfter: wait,
			At:         now,
		})
	}
	return wait, true
}

// admit is Allow's decision, under the lock. See ADR-0025's own admit for
// the algorithm this mirrors.
func (l *SessionRateLimiter) admit(sessionID string, now time.Time) (time.Duration, bool) {
	b, known := l.buckets[sessionID]
	if !known {
		if len(l.buckets) >= l.maxSessions {
			l.evictFullest()
		}
		b = &sessionBucket{tat: now}
		l.buckets[sessionID] = b
	}
	b.lastSeen = now

	// A bucket that has refilled is worth exactly one full bucket and no
	// more: a session idle for an hour does not accumulate an hour of
	// credit.
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

	// Conforming: consume one emission interval. tat is NOT reset to now,
	// so the credit a session did not spend is what gives it its burst.
	b.tat = b.tat.Add(l.interval)
	// The episode is over. It re-arms, so a second incident pages again.
	b.tripped = false
	l.stats.Admitted++
	return wait, false
}

// evictFullest makes room for one more session. Called under the lock, and
// only when the table is already at MaxSessions.
//
// Same two rules as ADR-0025's own evict, and the same reason for the
// second one: a bucket that has refilled is dropped first, for free (a full
// bucket and an absent one admit identically). If that frees nothing, the
// bucket evicted is the one CLOSEST to refilling, never the one furthest
// from it -- the flooding session's own bucket is by construction the
// furthest from refilling, so eviction can never be how a session resets
// its own meter.
func (l *SessionRateLimiter) evictFullest() {
	now := l.now()
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
	if len(l.buckets) >= l.maxSessions && coldestKey != "" {
		delete(l.buckets, coldestKey)
		l.stats.Evicted++
	}
}

// evictIdle sweeps every bucket whose session has made no request in
// IdleEvictAfter. Called under the lock, on every Allow -- O(sessions),
// which MaxSessions already bounds, the same amortised cost ADR-0025's own
// evict accepts.
//
// This is a SEPARATE bound from evictFullest's: a session that simply ends
// leaves a bucket nothing will ever touch again, and being far from
// MaxSessions does not make that go away by itself. Unlike evictFullest,
// this never has to choose WHICH bucket to keep under pressure -- idle is
// idle, and dropping every one of them changes no admitted/refused decision
// any future request will make, because a fresh bucket and a refilled one
// admit identically.
func (l *SessionRateLimiter) evictIdle(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) >= l.idleEvictAfter {
			delete(l.buckets, k)
			l.stats.EvictedIdle++
		}
	}
}

// Stats reports the counters.
func (l *SessionRateLimiter) Stats() SessionRateLimitStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Sessions = len(l.buckets)
	return s
}

// ceilSeconds rounds d up to a whole number of seconds, never less than
// one. A Retry-After header (delay-seconds, RFC 7231 §7.1.3) that rounded
// DOWN could read zero for a session that in fact still has to wait, which
// invites the tight retry this guard exists to stop.
func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	sec := int64((d + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return int(sec)
}

// ---------------------------------------------------------------------------
// The Guard.
// ---------------------------------------------------------------------------

// SessionRateLimitGuard is GW-013: the per-session rate-limit guard. See
// defaultGuards (guard.go) for where it is installed by default, and this
// file's own doc comment for why it must run after the harness-shape guard.
type SessionRateLimitGuard struct {
	limiter *SessionRateLimiter
}

// NewSessionRateLimitGuard wraps limiter as a Guard.
func NewSessionRateLimitGuard(limiter *SessionRateLimiter) *SessionRateLimitGuard {
	return &SessionRateLimitGuard{limiter: limiter}
}

// Check implements Guard.
//
// A request with no Identification on its context -- meaning the
// harness-shape guard did not run ahead of this one, contrary to
// defaultGuards' own ordering (guard.go) -- is refused rather than guessed
// at: there is no session id to meter, and admitting it unmetered would be a
// rate limit silently not applied, which is worse than one applied to the
// wrong key.
func (g *SessionRateLimitGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	id, ok := IdentificationFromContext(r.Context())
	if !ok || id.SessionID == "" {
		return nil, &Refusal{
			Status: http.StatusInternalServerError,
			Reason: "innsegl gateway: the per-session rate limit guard found no session id on the " +
				"request's context -- it must run after the harness-shape guard, which is what " +
				"attaches one (see defaultGuards in guard.go); refusing rather than metering nothing",
		}
	}

	wait, refused := g.limiter.Allow(r.Context(), id.SessionID)
	if !refused {
		return r, nil
	}

	seconds := ceilSeconds(wait)
	if sig, ok := retryAfterSignalFromContext(r.Context()); ok {
		sig.set(seconds)
	}
	return nil, &Refusal{
		Status: http.StatusTooManyRequests,
		Reason: fmt.Sprintf(
			"innsegl gateway: this session has exceeded its request rate (%d requests/second, "+
				"burst %d) -- nothing was forwarded; retry in %ds (see the Retry-After header)",
			g.limiter.rate, g.limiter.burst, seconds),
	}
}

// ---------------------------------------------------------------------------
// Retry-After.
//
// guard.go's Refusal carries only Status and Reason -- ServeHTTP
// (proxy.go) turns those into the JSON body writeGatewayError sends, and
// nothing about that forwarding path needs to change for a new Guard to
// plug in (guard.go's own doc comment). A Retry-After header is a real HTTP
// response header, not body text, and Check has no access to the
// http.ResponseWriter to set one directly -- Guard's signature is
// deliberately request-only (guard.go). WithRetryAfterHeader closes that
// gap from OUTSIDE proxy.go: it wraps the ResponseWriter before
// Proxy.ServeHTTP ever sees it, and hands Check a place, via the request's
// own context, to leave the value for that wrapper to apply the moment the
// real WriteHeader call happens -- whichever status that call carries, so a
// non-429 response is untouched.
// ---------------------------------------------------------------------------

// retryAfterSignal is the shared cell a SessionRateLimitGuard writes to and
// the wrapped ResponseWriter below reads from, both reached through the one
// request's context. Guarded by a mutex defensively; in practice both sides
// run synchronously on the same goroutine within one request.
type retryAfterSignal struct {
	mu      sync.Mutex
	seconds int
}

func (s *retryAfterSignal) set(seconds int) {
	s.mu.Lock()
	s.seconds = seconds
	s.mu.Unlock()
}

func (s *retryAfterSignal) get() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seconds, s.seconds > 0
}

type retryAfterSignalContextKey struct{}

func withRetryAfterSignal(ctx context.Context, sig *retryAfterSignal) context.Context {
	return context.WithValue(ctx, retryAfterSignalContextKey{}, sig)
}

func retryAfterSignalFromContext(ctx context.Context) (*retryAfterSignal, bool) {
	sig, ok := ctx.Value(retryAfterSignalContextKey{}).(*retryAfterSignal)
	return sig, ok
}

// WithRetryAfterHeader wraps next so that a SessionRateLimitGuard further
// down the chain can cause a Retry-After header to be set on the actual
// response, without proxy.go needing to know this guard exists. Production
// wiring (cmd/innsegl/gateway.go's openGateway) wraps the whole handler with
// this; a Proxy served directly with no such wrapper (as several of this
// package's own tests do) still refuses correctly -- 429 status, JSON body
// naming the reason and the wait -- it just does not gain the header, which
// is why this package's own end-to-end tests for the header wrap with this
// function explicitly.
//
// The wrapped ResponseWriter forwards Flush (GW-002: an SSE reply must
// still be flushed as it streams) and Hijack (a future WebSocket upgrade,
// #372) to the underlying ResponseWriter exactly when it supports them, and
// exposes Unwrap so anything using net/http's own ResponseController can
// see through this wrapper too. Nothing here changes what bytes reach a
// caller on any path that is not itself a 429 refusal.
func WithRetryAfterHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig := &retryAfterSignal{}
		rw := &retryAfterResponseWriter{ResponseWriter: w, sig: sig}
		next.ServeHTTP(rw, r.WithContext(withRetryAfterSignal(r.Context(), sig)))
	})
}

// retryAfterResponseWriter sets Retry-After, once, immediately before the
// real WriteHeader call, if and only if a SessionRateLimitGuard left a wait
// on its signal during this request. A response that was never refused
// leaves the signal empty and this is a transparent pass-through.
type retryAfterResponseWriter struct {
	http.ResponseWriter
	sig         *retryAfterSignal
	wroteHeader bool
}

// WriteHeader implements http.ResponseWriter.
func (rw *retryAfterResponseWriter) WriteHeader(status int) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
		if seconds, set := rw.sig.get(); set {
			rw.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
		}
	}
	rw.ResponseWriter.WriteHeader(status)
}

// Flush implements http.Flusher when the wrapped ResponseWriter does,
// keeping a streamed reply (GW-002, proxy.go's own flushWriter) unbuffered
// even though it now passes through this wrapper first.
func (rw *retryAfterResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker when the wrapped ResponseWriter does --
// #372's WebSocket dispatch needs the raw connection, and this wrapper must
// not be the thing standing in its way.
func (rw *retryAfterResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

// Unwrap lets net/http's own http.ResponseController see through this
// wrapper to whatever the underlying ResponseWriter supports, the same
// protocol http.ResponseController has used since Go 1.20 to look past
// exactly this kind of middleware wrapping.
func (rw *retryAfterResponseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
