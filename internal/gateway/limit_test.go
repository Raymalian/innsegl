// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock for deterministic rate-limit tests -- no
// time.Sleep anywhere in this file.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// spyAlertSink records every trip it receives.
type spyAlertSink struct {
	mu    sync.Mutex
	trips []SessionRateLimitTrip
}

func (s *spyAlertSink) Alert(_ context.Context, trip SessionRateLimitTrip) {
	s.mu.Lock()
	s.trips = append(s.trips, trip)
	s.mu.Unlock()
}

func (s *spyAlertSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.trips)
}

// --- ceilSeconds: the Retry-After rounding rule ---

func TestCeilSeconds(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want int
	}{
		{0, 0},
		{-time.Second, 0},
		{time.Millisecond, 1},
		{500 * time.Millisecond, 1},
		{time.Second, 1},
		{time.Second + time.Millisecond, 2},
		{1500 * time.Millisecond, 2},
	}
	for _, tc := range cases {
		if got := ceilSeconds(tc.d); got != tc.want {
			t.Errorf("ceilSeconds(%v) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

// --- Config validation ---

func TestNewSessionRateLimiterValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  SessionRateLimit
	}{
		{"zero rate", SessionRateLimit{Rate: 0, Burst: 10}},
		{"negative rate", SessionRateLimit{Rate: -1, Burst: 10}},
		{"zero burst", SessionRateLimit{Rate: 10, Burst: 0}},
		{"negative burst", SessionRateLimit{Rate: 10, Burst: -1}},
		{"rate finer than the clock", SessionRateLimit{Rate: 2_000_000_000, Burst: 10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lim, err := NewSessionRateLimiter(tc.cfg)
			if err == nil {
				t.Fatalf("want an error, got a limiter: %+v", lim)
			}
			if !strings.Contains(err.Error(), sessionRateLimitSource) {
				t.Errorf("error %q does not name %q", err.Error(), sessionRateLimitSource)
			}
		})
	}
}

func TestNewSessionRateLimiterAcceptsAValidConfig(t *testing.T) {
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 5})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	if lim == nil {
		t.Fatal("want a limiter, got nil")
	}
}

// TestDefaultSessionRateLimitSettingsAreValid pins the guarantee guard.go's
// newDefaultSessionRateLimitGuard leans on: the package's own shipped
// defaults always build a valid limiter, so that constructor's panic path
// is unreachable in this build.
func TestDefaultSessionRateLimitSettingsAreValid(t *testing.T) {
	lim, err := NewSessionRateLimiter(SessionRateLimit{
		Rate:  DefaultSessionRateLimitRate,
		Burst: DefaultSessionRateLimitBurst,
	})
	if err != nil {
		t.Fatalf("the shipped defaults do not build a valid limiter: %v", err)
	}
	if lim == nil {
		t.Fatal("want a limiter, got nil")
	}
}

// --- GW-013: the core admit/refuse boundary ---

func TestSessionRateLimiterAdmitsUpToBurstThenRefuses(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 3, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if wait, refused := lim.Allow(t.Context(), "session-a"); refused {
			t.Fatalf("call %d: refused (wait %v), want admitted (burst is 3)", i, wait)
		}
	}
	wait, refused := lim.Allow(t.Context(), "session-a")
	if !refused {
		t.Fatal("4th call: admitted, want refused -- burst is 3")
	}
	if wait <= 0 {
		t.Errorf("wait = %v, want > 0 on a refusal", wait)
	}

	stats := lim.Stats()
	if stats.Admitted != 3 {
		t.Errorf("Admitted = %d, want 3", stats.Admitted)
	}
	if stats.Refused != 1 {
		t.Errorf("Refused = %d, want 1", stats.Refused)
	}
	if stats.Trips != 1 {
		t.Errorf("Trips = %d, want 1", stats.Trips)
	}
}

// TestSessionRateLimiterSessionsAreIndependent is GW-013's own acceptance
// text: "other sessions unaffected". Flooding one session's bucket must
// have no effect on a different session's.
func TestSessionRateLimiterSessionsAreIndependent(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 2, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	// Flood session-a well past its burst.
	for i := 0; i < 10; i++ {
		lim.Allow(t.Context(), "session-a")
	}
	if _, refused := lim.Allow(t.Context(), "session-a"); !refused {
		t.Fatal("session-a: admitted after flooding, want refused")
	}

	// session-b has made no requests at all and must be unaffected.
	for i := 1; i <= 2; i++ {
		if _, refused := lim.Allow(t.Context(), "session-b"); refused {
			t.Fatalf("session-b call %d: refused, want admitted -- session-a's flood must not reach it", i)
		}
	}
}

// --- Alert: once per episode, not once per refusal ---

func TestSessionRateLimiterAlertFiresOncePerEpisode(t *testing.T) {
	clock := newFakeClock(time.Now())
	sink := &spyAlertSink{}
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 1, Alert: sink, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	// Spend the one-request burst, then refuse five times in a row without
	// ever being served again -- one episode, one alert.
	lim.Allow(t.Context(), "session-a")
	for i := 0; i < 5; i++ {
		if _, refused := lim.Allow(t.Context(), "session-a"); !refused {
			t.Fatalf("call %d: admitted, want refused", i)
		}
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("alerts after one episode of 5 refusals = %d, want 1", got)
	}

	// Let the bucket refill and get served again -- the episode ends.
	clock.Advance(time.Second)
	if _, refused := lim.Allow(t.Context(), "session-a"); refused {
		t.Fatal("after the bucket refilled: refused, want admitted")
	}

	// Trip it again: a second, independent episode must page again.
	if _, refused := lim.Allow(t.Context(), "session-a"); !refused {
		t.Fatal("second flood: admitted, want refused")
	}
	if got := sink.count(); got != 2 {
		t.Fatalf("alerts after a second episode = %d, want 2 (the episode must re-arm)", got)
	}
}

func TestSessionRateLimiterAlertCarriesSessionRateBurstAndRetryAfter(t *testing.T) {
	clock := newFakeClock(time.Now())
	sink := &spyAlertSink{}
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 5, Burst: 1, Alert: sink, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	lim.Allow(t.Context(), "session-a")
	lim.Allow(t.Context(), "session-a")

	if got := sink.count(); got != 1 {
		t.Fatalf("alerts = %d, want 1", got)
	}
	trip := sink.trips[0]
	if trip.SessionID != "session-a" {
		t.Errorf("SessionID = %q, want session-a", trip.SessionID)
	}
	if trip.Rate != 5 {
		t.Errorf("Rate = %d, want 5", trip.Rate)
	}
	if trip.Burst != 1 {
		t.Errorf("Burst = %d, want 1", trip.Burst)
	}
	if trip.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want > 0", trip.RetryAfter)
	}
}

// --- Idle eviction: bounded memory ---

func TestSessionRateLimiterEvictsIdleSessions(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{
		Rate: 10, Burst: 5, IdleEvictAfter: time.Minute, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	lim.Allow(t.Context(), "session-idle")
	if got := lim.Stats().Sessions; got != 1 {
		t.Fatalf("Sessions after one request = %d, want 1", got)
	}

	// Not yet idle long enough: a request from an unrelated session must
	// not sweep it.
	clock.Advance(30 * time.Second)
	lim.Allow(t.Context(), "session-other")
	if got := lim.Stats().Sessions; got != 2 {
		t.Fatalf("Sessions at 30s (below the 1-minute idle threshold) = %d, want 2 -- nothing should be evicted yet", got)
	}

	// Past the idle threshold now: the NEXT call (for any session) must
	// sweep session-idle's bucket, even though this call does not touch it.
	clock.Advance(45 * time.Second)
	lim.Allow(t.Context(), "session-other")

	stats := lim.Stats()
	if stats.Sessions != 1 {
		t.Fatalf("Sessions after the idle sweep = %d, want 1 (only session-other, still active)", stats.Sessions)
	}
	if stats.EvictedIdle < 1 {
		t.Errorf("EvictedIdle = %d, want at least 1", stats.EvictedIdle)
	}
}

// TestSessionRateLimiterIdleEvictionBoundsMemoryAcrossManySessions is the
// "bounded memory" half of GW-013's idle-eviction requirement: a large
// number of sessions that each make one request and then go quiet must not
// make the table grow without bound.
func TestSessionRateLimiterIdleEvictionBoundsMemoryAcrossManySessions(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{
		Rate: 10, Burst: 5, IdleEvictAfter: time.Minute, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	for i := 0; i < 500; i++ {
		lim.Allow(t.Context(), "session-"+strconv.Itoa(i))
		clock.Advance(time.Second)
	}
	if got := lim.Stats().Sessions; got == 0 {
		t.Fatal("Sessions = 0 after a burst of activity, want at least the still-recent sessions")
	}

	// Go quiet for well past the idle window, then make one more call.
	clock.Advance(2 * time.Minute)
	lim.Allow(t.Context(), "session-final")

	if got := lim.Stats().Sessions; got > 2 {
		t.Errorf("Sessions after every earlier session went idle = %d, want at most 2 (session-final and, "+
			"transiently, whichever bucket the sweep is still processing)", got)
	}
}

// --- MaxSessions: the other bound, never a refusal by itself ---

func TestSessionRateLimiterEvictFullestNeverEvictsTheFloodingSession(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{
		Rate: 1, Burst: 5, MaxSessions: 2, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	// session-flood spends its burst of 5 and keeps going: its bucket ends
	// up with a tat several seconds in the future -- far from refilling --
	// which is exactly what "the flooding session's own bucket" means here.
	for i := 0; i < 10; i++ {
		lim.Allow(t.Context(), "session-flood")
	}
	if _, refused := lim.Allow(t.Context(), "session-flood"); !refused {
		t.Fatal("session-flood: admitted after 11 calls against a burst of 5, want refused")
	}

	// session-b makes exactly one call: its bucket's tat is only one
	// interval out, i.e. CLOSE to refilling -- the opposite end of the
	// table from session-flood's.
	lim.Allow(t.Context(), "session-b")
	if got := lim.Stats().Sessions; got != 2 {
		t.Fatalf("Sessions = %d, want 2 (table is at MaxSessions)", got)
	}

	// A third, brand-new session forces an eviction. It must evict
	// session-b (closest to refilling), never session-flood -- if it
	// evicted session-flood, session-flood would get a fresh, full bucket,
	// i.e. its own flood would have reset its meter.
	lim.Allow(t.Context(), "session-c")

	if got := lim.Stats().Evicted; got != 1 {
		t.Fatalf("Evicted = %d, want 1", got)
	}
	if _, refused := lim.Allow(t.Context(), "session-flood"); !refused {
		t.Fatal("session-flood: admitted after the table evicted for a new session, " +
			"want still refused -- eviction must never pick the flooding session's own bucket")
	}
	if _, refused := lim.Allow(t.Context(), "session-b"); refused {
		t.Error("session-b: refused, want admitted -- it should have been the one evicted, " +
			"and a fresh bucket admits its first call")
	}
}

// --- The Guard ---

func TestSessionRateLimitGuardRefusesWithStatus429AndNothingForwarded(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 1, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	guard := NewSessionRateLimitGuard(lim)
	gw, counter := newCountingProxy(t, []Guard{NewHarnessGuard(), guard})

	fx := loadHarnessFixture(t, "claude-code-2.1", "main-agent.json")

	// First request: burst is 1, admitted, forwarded.
	resp1, err := http.DefaultClient.Do(fx.networkRequest(t, gw.URL))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", resp1.StatusCode)
	}

	// Second request from the SAME session, same instant: over the burst.
	resp2, err := http.DefaultClient.Do(fx.networkRequest(t, gw.URL))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want %d", resp2.StatusCode, http.StatusTooManyRequests)
	}
	errMsg := decodeGatewayError(t, resp2)
	if !strings.Contains(errMsg, "innsegl") {
		t.Errorf("error body %q does not name innsegl", errMsg)
	}
	if !strings.Contains(errMsg, "exceeded its request rate") {
		t.Errorf("error body %q does not name the reason", errMsg)
	}
	if got := counter.requests(); got != 1 {
		t.Errorf("upstream received %d requests, want 1 -- the refused request must not be forwarded", got)
	}
}

// TestSessionRateLimitGuardFailsClosedWithNoIdentification is the defensive
// branch: this guard depends on the harness-shape guard running first
// (guard.go's defaultGuards ordering). Run alone, it must refuse rather
// than meter nothing.
func TestSessionRateLimitGuardFailsClosedWithNoIdentification(t *testing.T) {
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 10, Burst: 10})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	guard := NewSessionRateLimitGuard(lim)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	_, refusal := guard.Check(req)
	if refusal == nil {
		t.Fatal("want a refusal, got none")
	}
	if refusal.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusInternalServerError)
	}
	if !strings.Contains(refusal.Reason, "harness-shape guard") {
		t.Errorf("reason = %q, want it to explain the ordering requirement", refusal.Reason)
	}
}

// TestDefaultGuardsRunsHarnessShapeBeforeRateLimit proves ordering: an
// unrecognised harness shape is refused as GW-011 (400), never metered or
// mistaken for a rate-limit refusal (429), regardless of how much traffic
// the (unidentifiable) caller has sent.
func TestDefaultGuardsRunsHarnessShapeBeforeRateLimit(t *testing.T) {
	gw, counter := newCountingProxy(t, nil) // nil -> defaultGuards

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// No session header at all: the harness guard must refuse this before
	// the rate limiter ever runs.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (GW-011, not a rate-limit refusal)", resp.StatusCode, http.StatusBadRequest)
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("upstream received %d requests, want 0", got)
	}
}

// --- Retry-After header ---

func TestWithRetryAfterHeaderSetsHeaderOnRefusal(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 1, Burst: 1, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	guard := NewSessionRateLimitGuard(lim)

	upstream, counter := newCountingUpstreamServer(t)
	t.Cleanup(upstream.Close)
	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	proxy := &Proxy{Upstream: up, Guards: []Guard{NewHarnessGuard(), guard}}
	gw := httptest.NewServer(WithRetryAfterHeader(proxy))
	t.Cleanup(gw.Close)

	fx := loadHarnessFixture(t, "claude-code-2.1", "main-agent.json")

	resp1, err := http.DefaultClient.Do(fx.networkRequest(t, gw.URL))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	_ = resp1.Body.Close()
	if got := resp1.Header.Get("Retry-After"); got != "" {
		t.Errorf("first (admitted) request carries Retry-After = %q, want none", got)
	}

	resp2, err := http.DefaultClient.Do(fx.networkRequest(t, gw.URL))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d", resp2.StatusCode, http.StatusTooManyRequests)
	}
	ra := resp2.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("Retry-After header is missing on a rate-limit refusal")
	}
	seconds, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer number of seconds: %v", ra, err)
	}
	if seconds < 1 {
		t.Errorf("Retry-After = %d, want at least 1", seconds)
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
		t.Fatalf("decode JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") {
		t.Errorf("error body %q does not name innsegl", body.Error)
	}
	if got := counter.requests(); got != 1 {
		t.Errorf("upstream received %d requests, want 1 (only the admitted one)", got)
	}
}

// TestWithRetryAfterHeaderIsTransparentOnSuccess proves the wrapper is a
// no-op for a response the guard chain never refused -- status, headers and
// body reach the caller unchanged.
func TestWithRetryAfterHeaderIsTransparentOnSuccess(t *testing.T) {
	upstream, counter := newCountingUpstreamServer(t)
	t.Cleanup(upstream.Close)
	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	proxy := &Proxy{Upstream: up, Guards: []Guard{}} // no guards: everything is forwarded
	gw := httptest.NewServer(WithRetryAfterHeader(proxy))
	t.Cleanup(gw.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on a non-refused response, want none", got)
	}
	if got := counter.requests(); got != 1 {
		t.Errorf("upstream received %d requests, want 1", got)
	}
}

// TestWithRetryAfterHeaderPassesThroughFlush is GW-002's own regression
// check applied to this wrapper: an SSE reply forwarded through it must
// still be flushable, or a streamed reply would sit buffered. It actually
// calls Flush, not merely the type assertion, so the wrapper's own Flush
// method runs and forwards to the underlying Flusher.
func TestWithRetryAfterHeaderPassesThroughFlush(t *testing.T) {
	h := WithRetryAfterHeader(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("the handler's ResponseWriter does not implement http.Flusher through the wrapper")
			return
		}
		f.Flush()
	}))

	rec := httptest.NewRecorder() // implements http.Flusher
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	h.ServeHTTP(rec, req)

	if !rec.Flushed {
		t.Error("Flush() did not reach the underlying ResponseRecorder")
	}
}

// TestWithRetryAfterHeaderFlushIsANoOpWhenTheUnderlyingWriterIsNotAFlusher
// proves the defensive half of Flush: a ResponseWriter that does not
// support flushing must not make the wrapper panic or error, only do
// nothing.
func TestWithRetryAfterHeaderFlushIsANoOpWhenTheUnderlyingWriterIsNotAFlusher(t *testing.T) {
	rw := &retryAfterResponseWriter{ResponseWriter: nonFlushingWriter{httptest.NewRecorder()}, sig: &retryAfterSignal{}}
	rw.Flush() // must not panic
}

// nonFlushingWriter wraps an http.ResponseWriter without exposing Flush,
// even though the one underneath (httptest.ResponseRecorder) has it.
type nonFlushingWriter struct{ http.ResponseWriter }

// TestWithRetryAfterHeaderHijackPassesThrough proves the Hijacker
// passthrough #372's future WebSocket dispatch needs: a ResponseWriter that
// supports hijacking is still hijackable through this wrapper.
func TestWithRetryAfterHeaderHijackPassesThrough(t *testing.T) {
	// done carries the handler's own result back to the test goroutine --
	// the HTTP client's Do() returning is not synchronised with the
	// handler goroutine finishing its Hijack, and a bare shared bool raced
	// under -race when this was first written.
	done := make(chan error, 1)
	h := WithRetryAfterHeader(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			done <- fmt.Errorf("the handler's ResponseWriter does not implement http.Hijacker through the wrapper")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			done <- fmt.Errorf("Hijack: %w", err)
			return
		}
		_ = conn.Close()
		done <- nil
	}))

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, doErr := http.DefaultClient.Do(req)
	if doErr == nil {
		_ = resp.Body.Close()
	}

	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never finished")
	}
}

// TestWithRetryAfterHeaderHijackRefusesWhenUnderlyingIsNotAHijacker proves
// the defensive half: a ResponseWriter that does not support hijacking
// returns http.ErrNotSupported through the wrapper rather than panicking.
func TestWithRetryAfterHeaderHijackRefusesWhenUnderlyingIsNotAHijacker(t *testing.T) {
	rw := &retryAfterResponseWriter{ResponseWriter: httptest.NewRecorder(), sig: &retryAfterSignal{}}
	_, _, err := rw.Hijack()
	if err == nil {
		t.Fatal("want an error, got none -- httptest.ResponseRecorder does not implement Hijacker")
	}
}

// TestWithRetryAfterHeaderPassesThroughUnwrap pins the http.ResponseController
// escape hatch: anything that walks Unwrap() must reach the real
// ResponseWriter, not this wrapper.
func TestWithRetryAfterHeaderPassesThroughUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	var got http.ResponseWriter
	h := WithRetryAfterHeader(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		type unwrapper interface{ Unwrap() http.ResponseWriter }
		u, ok := w.(unwrapper)
		if !ok {
			t.Error("wrapped ResponseWriter does not implement Unwrap")
			return
		}
		got = u.Unwrap()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	h.ServeHTTP(rec, req)

	if got != http.ResponseWriter(rec) {
		t.Error("Unwrap() did not return the original ResponseWriter")
	}
}

// --- Concurrency ---

// TestSessionRateLimiterConcurrentSessionsAreRaceSafe drives many sessions
// from many goroutines at once -- the shape a main agent and several
// parallel subagents sharing one session id actually produce -- under
// go test -race.
func TestSessionRateLimiterConcurrentSessionsAreRaceSafe(t *testing.T) {
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 1000, Burst: 50})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}

	var wg sync.WaitGroup
	for s := 0; s < 8; s++ {
		sessionID := "session-" + strconv.Itoa(s)
		for c := 0; c < 20; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				lim.Allow(t.Context(), sessionID)
			}()
		}
	}
	wg.Wait()

	stats := lim.Stats()
	if stats.Sessions != 8 {
		t.Errorf("Sessions = %d, want 8", stats.Sessions)
	}
	if stats.Admitted+stats.Refused != 8*20 {
		t.Errorf("Admitted+Refused = %d, want %d", stats.Admitted+stats.Refused, 8*20)
	}
}
