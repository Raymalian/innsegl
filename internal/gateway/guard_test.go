// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingUpstream counts every request it receives, so a test can assert
// nothing reached it (GW-011) or exactly what should have (GW-012).
type countingUpstream struct {
	mu    sync.Mutex
	count int
}

func newCountingUpstreamServer(t *testing.T) (*httptest.Server, *countingUpstream) {
	t.Helper()
	c := &countingUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		c.count++
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return srv, c
}

func (c *countingUpstream) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// newCountingProxy wires a Proxy (guards as given, nil for the default) in
// front of a counting upstream, both closed by t.Cleanup.
func newCountingProxy(t *testing.T, guards []Guard) (*httptest.Server, *countingUpstream) {
	t.Helper()
	upstream, counter := newCountingUpstreamServer(t)
	t.Cleanup(upstream.Close)

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up, Guards: guards})
	t.Cleanup(gw.Close)
	return gw, counter
}

func decodeGatewayError(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the JSON error body: %v", err)
	}
	return body.Error
}

// --- GW-011: a request whose harness shape is not recognised is refused,
// naming the reason, and nothing reaches the upstream. Guards is left nil
// on every case here (the default), which is itself part of what GW-011
// requires: refusal with no wiring needed at the call site. ---

func TestGW011MissingSessionHeaderIsRefused(t *testing.T) {
	gw, counter := newCountingProxy(t, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	errMsg := decodeGatewayError(t, resp)
	if !strings.Contains(errMsg, "innsegl") {
		t.Errorf("error body %q does not name innsegl", errMsg)
	}
	if !strings.Contains(errMsg, reasonMissingSessionID) {
		t.Errorf("error body %q does not carry the reason %q", errMsg, reasonMissingSessionID)
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("upstream received %d requests, want 0 -- nothing should be forwarded", got)
	}
}

func TestGW011MalformedSessionIDIsRefused(t *testing.T) {
	gw, counter := newCountingProxy(t, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set(headerClaudeCodeSessionID, "not-a-uuid")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	errMsg := decodeGatewayError(t, resp)
	if !strings.Contains(errMsg, reasonMalformedSessionID) {
		t.Errorf("error body %q does not carry the reason %q", errMsg, reasonMalformedSessionID)
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("upstream received %d requests, want 0", got)
	}
}

func TestGW011UnknownPathIsRefused(t *testing.T) {
	gw, counter := newCountingProxy(t, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/not-a-model-path", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// A valid session id is set deliberately, to isolate the path as the
	// one thing this request gets wrong.
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	errMsg := decodeGatewayError(t, resp)
	if !strings.Contains(errMsg, reasonUnknownPath) {
		t.Errorf("error body %q does not carry the reason %q", errMsg, reasonUnknownPath)
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("upstream received %d requests, want 0", got)
	}
}

// --- GW-012: recognised requests -- every recorded Claude Code 2.1 shape
// -- are forwarded, end to end through Proxy.ServeHTTP. ---

func TestGW012RecognisedClaudeCode21FixturesAreForwarded(t *testing.T) {
	gw, counter := newCountingProxy(t, nil)

	for _, name := range []string{"main-agent.json", "subagent.json", "count-tokens.json"} {
		fx := loadHarnessFixture(t, "claude-code-2.1", name)
		req := fx.networkRequest(t, gw.URL)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: gateway request: %v", name, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (forwarded, not refused)", name, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	if got := counter.requests(); got != 3 {
		t.Errorf("upstream received %d requests, want 3 -- every recognised fixture should reach it", got)
	}
}

// --- The opt-out: an explicit empty Guards slice forwards even an
// unrecognised shape. This is the control against every GW-011 case above:
// it proves the refusal there comes from the guard, not from something
// else in the forwarding path, and it is the mechanism a caller who needs
// to bypass every default guard uses. ---

func TestProxyForwardsUnrecognisedShapeWhenGuardsAreExplicitlyEmptied(t *testing.T) {
	gw, counter := newCountingProxy(t, []Guard{})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// Deliberately no session header: this shape is unrecognised, and with
	// Guards explicitly emptied nothing refuses it.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (forwarded; Guards was explicitly emptied)", resp.StatusCode)
	}
	if got := counter.requests(); got != 1 {
		t.Errorf("upstream received %d requests, want 1", got)
	}
}

// --- The chain itself: order, short-circuit, and context propagation --
// what #375 and E15 plug into. ---

// refusingGuard always refuses with a fixed Refusal, for pinning ordering.
type refusingGuard struct{ refusal *Refusal }

func (g refusingGuard) Check(r *http.Request) (*http.Request, *Refusal) { return r, g.refusal }

// spyGuard records whether it ran and what Identification (if any) it found
// already attached to the request's context, then permits the request.
type spyGuard struct {
	called bool
	seen   Identification
	seenOK bool
}

func (s *spyGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	s.called = true
	s.seen, s.seenOK = IdentificationFromContext(r.Context())
	return r, nil
}

func TestGuardChainStopsAtTheFirstRefusalAndNeverCallsALaterGuard(t *testing.T) {
	first := refusingGuard{refusal: &Refusal{Status: http.StatusForbidden, Reason: "innsegl gateway: test refusal from the first guard"}}
	second := &spyGuard{}
	gw, counter := newCountingProxy(t, []Guard{first, second})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d (the first guard's own status)", resp.StatusCode, http.StatusForbidden)
	}
	if second.called {
		t.Error("the second guard ran after the first refused -- it must not")
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("upstream received %d requests, want 0", got)
	}
}

// TestHarnessGuardFallsBackToAGenericReasonWhenARecogniserGivesNone pins
// Check's own defensive fallback: a harnessRecogniser is contracted to name
// a reason on every refusal (see harness.go), but Check does not trust that
// blindly -- a recogniser that breaks the contract still gets a usable
// refusal, not an empty one.
func TestHarnessGuardFallsBackToAGenericReasonWhenARecogniserGivesNone(t *testing.T) {
	g := &HarnessGuard{recognisers: []harnessRecogniser{
		func(*http.Request) (Identification, bool, string) { return Identification{}, false, "" },
	}}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	_, refusal := g.Check(req)
	if refusal == nil {
		t.Fatal("want a refusal, got none")
	}
	if refusal.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusBadRequest)
	}
	if !strings.Contains(refusal.Reason, "did not match any supported harness version") {
		t.Errorf("reason = %q, want the generic fallback wording", refusal.Reason)
	}
}

func TestGuardChainAttachesIdentificationForALaterGuard(t *testing.T) {
	spy := &spyGuard{}
	gw, counter := newCountingProxy(t, []Guard{NewHarnessGuard(), spy})

	fx := loadHarnessFixture(t, "claude-code-2.1", "subagent.json")
	req := fx.networkRequest(t, gw.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !spy.called {
		t.Fatal("the second guard never ran")
	}
	if !spy.seenOK {
		t.Fatal("the second guard found no Identification on the request's context")
	}
	if spy.seen.SessionID != fx.Headers[headerClaudeCodeSessionID] {
		t.Errorf("SessionID seen by the later guard = %q, want %q", spy.seen.SessionID, fx.Headers[headerClaudeCodeSessionID])
	}
	if spy.seen.AgentID != fx.Headers[headerClaudeCodeAgentID] {
		t.Errorf("AgentID seen by the later guard = %q, want %q", spy.seen.AgentID, fx.Headers[headerClaudeCodeAgentID])
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (both guards permitted the request)", resp.StatusCode)
	}
	if got := counter.requests(); got != 1 {
		t.Errorf("upstream received %d requests, want 1", got)
	}
}

// --- ONE guard list (guard.go's own history is what this pins): harness
// shape, identity, rate limit, then every witness, in that order, and a
// witness the way this codebase actually ships one never refuses. ---

// TestGuardsOrdersHarnessIdentityRateLimitThenWitnesses pins guard.go's own
// Guards function: harness shape first, then the identity guard handed in
// (when non-nil), then the per-session rate-limit guard built from the
// limiter handed in, then every witness in the order given -- the ONE
// ordered list every future guard is added inside (that function's own doc
// comment). RM-236's ToolCallRecordGuard and RM-237's MessageRecorder are
// exercised here as the witnesses, rather than a generic stub, so this
// test also pins the property their own doc comments claim: neither
// refuses a request that reaches it, identity-less or not.
func TestGuardsOrdersHarnessIdentityRateLimitThenWitnesses(t *testing.T) {
	limiter := defaultSessionRateLimiter()
	identity := &spyGuard{}

	toolCalls := &fakeRecordCalls{}
	toolCallWitness := NewToolCallRecordGuard(NewToolCallRecorder(ToolCallRecorderConfig{record: toolCalls.fn}))
	messageWitness, err := NewMessageRecorder(MessageRecorderConfig{Recorder: newFakeAgentMessageRecorder()})
	if err != nil {
		t.Fatalf("NewMessageRecorder: %v", err)
	}

	guards := Guards(limiter, identity, toolCallWitness, messageWitness)

	if len(guards) != 5 {
		t.Fatalf("len(Guards(...)) = %d, want 5 (harness, identity, rate limit, and two witnesses)", len(guards))
	}
	if _, ok := guards[0].(*HarnessGuard); !ok {
		t.Errorf("guards[0] = %T, want *HarnessGuard", guards[0])
	}
	if guards[1] != Guard(identity) {
		t.Errorf("guards[1] is not the identity guard that was handed in")
	}
	if _, ok := guards[2].(*SessionRateLimitGuard); !ok {
		t.Errorf("guards[2] = %T, want *SessionRateLimitGuard", guards[2])
	}
	if guards[3] != Guard(toolCallWitness) {
		t.Errorf("guards[3] is not the tool-call-record witness, in the order it was handed in")
	}
	if guards[4] != Guard(messageWitness) {
		t.Errorf("guards[4] is not the message-recorder witness, in the order it was handed in")
	}

	// Every witness in this chain, exercised on a request with no identity
	// resolved at all (the harshest case: neither RunIDFromContext nor
	// RequestFactsFromContext finds anything), must never refuse.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", nil)
	for i, w := range guards[3:] {
		if _, refusal := w.Check(req); refusal != nil {
			t.Errorf("witness %d (%T) refused: %+v -- a witness must never refuse", i, w, refusal)
		}
	}
}

// TestGuardsSkipsNilWitnesses: a nil witness among several (the shape a
// caller with an optional one, built only when its own dependencies are
// configured, hands in unfiltered) is skipped rather than appended.
func TestGuardsSkipsNilWitnesses(t *testing.T) {
	limiter := defaultSessionRateLimiter()
	only := &spyGuard{}

	guards := Guards(limiter, nil, nil, only, nil)

	if len(guards) != 3 {
		t.Fatalf("len(Guards(...)) = %d, want 3 (harness, rate limit, the one surviving witness): %v",
			len(guards), guards)
	}
	if guards[2] != Guard(only) {
		t.Errorf("guards[2] is not the one witness that was not nil")
	}
}

// retryGuard refuses every request with a Retry-After.
type retryGuard struct{}

func (retryGuard) Check(*http.Request) (*http.Request, *Refusal) {
	return nil, &Refusal{Status: http.StatusServiceUnavailable, Reason: "not yet", RetryAfter: 1500 * time.Millisecond}
}

// A refusal with RetryAfter carries the header, rounded up to whole seconds,
// so the harness retries instead of failing the turn.
func TestARefusalWithRetryAfterSendsTheHeader(t *testing.T) {
	gw, counter := newCountingProxy(t, []Guard{retryGuard{}})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want \"2\"", got)
	}
	if counter.requests() != 0 {
		t.Error("the refused request reached the upstream")
	}
}
