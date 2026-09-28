// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GW-010: a canary credential sent through the gateway reaches no log, no
// file, and no response the caller was not the one to send it in the first
// place -- across every shape a request through this package can take: an
// ordinary reply, a streamed one, an unreachable upstream, and an upstream
// that answers with its own error status.
//
// Every scenario below also proves the canary WAS forwarded to the
// upstream (where one exists to receive it): a test that could pass by
// silently dropping the header would prove nothing about redaction and
// everything wrong about GW-001's byte-for-byte contract, which this issue
// does not get to break to satisfy this one.
//
// This package writes to no logger of its own today -- see proxy.go's own
// package doc comment, "What this package does not do yet" -- so there is
// no *slog.Logger or stderr handle here to capture. The process-level
// equivalent, which captures the real logger cmd/innsegl/gateway.go wires
// up, lives in cmd/innsegl/gatewaycanary_test.go; if this package ever
// gains a logger of its own, extend assertCredentialCanaryNowhere below to
// take a logOutput []byte parameter the same shape that file's copy
// already does, and wire it from whatever captures this package's new
// logger.

// newCredentialCanary returns a fresh, unpredictable credential pair: a
// bearer token shaped like the ones ADR-0057's spike actually forwarded,
// and a second, independently-random value carried the way an API key
// header carries one -- because a redaction rule that only catches
// Authorization would miss X-Api-Key, and this package forwards both
// unchanged (GW-001). Fresh per call so a match in any assertion below can
// only be THIS test's own credential, never a stale value another test run
// left behind or a literal in the source that happens to look like one.
func newCredentialCanary(t *testing.T) (bearer, apiKey string) {
	t.Helper()
	return "innsegl-canary-" + randomCanarySuffix(t), randomCanarySuffix(t)
}

func randomCanarySuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate a random canary suffix: %v", err)
	}
	return hex.EncodeToString(b)
}

// assertCredentialCanaryNowhere fails t if canary appears in any response
// body in bodies, or in any file under any directory in dirs (walked
// recursively; a directory that does not exist is not an error -- this
// package configures none today). label identifies the scenario in a
// failure message. An empty canary fails t outright, since every check
// below would otherwise pass vacuously.
//
// dirs is how GW-010 stays checking something real as this package grows a
// place to write to. It holds nothing today (see this file's own package
// doc comment above), and each call site below passes a fresh t.TempDir()
// anyway -- proving the walk itself works on a real, empty directory
// rather than skipping it -- so that when E15's body store or E16's
// snapshots add a directory this package is configured to use, the fix is
// pointing that directory's own test double at the slice a call site here
// builds, not writing a new scan.
func assertCredentialCanaryNowhere(t *testing.T, label, canary string, bodies map[string][]byte, dirs []string) {
	t.Helper()
	if canary == "" {
		t.Fatalf("%s: the canary itself is empty; every check below would pass vacuously", label)
	}
	for name, body := range bodies {
		if strings.Contains(string(body), canary) {
			t.Errorf("%s: canary %q found in %s:\n%s", label, canary, name, body)
		}
	}
	for _, dir := range dirs {
		walkForCanary(t, label, canary, dir)
	}
}

// walkForCanary fails t if any file under dir (recursively) contains
// canary. A dir that does not exist is silently skipped: this package
// configures no directory of its own yet, so every call site today passes
// only a t.TempDir() nothing writes into, and a missing directory is not
// itself evidence of anything.
func walkForCanary(t *testing.T, label, canary, dir string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), canary) {
			t.Errorf("%s: canary %q found in file %s", label, canary, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("%s: walk %s for the canary: %v", label, dir, err)
	}
}

// assertCredentialCanaryDeliveredUpstream fails t if canary is absent from
// what the upstream actually received in its Authorization or X-Api-Key
// headers. See this file's own package doc comment for why this check
// exists alongside assertCredentialCanaryNowhere rather than being
// optional.
func assertCredentialCanaryDeliveredUpstream(t *testing.T, label, canary string, upstreamHeaders http.Header) {
	t.Helper()
	if upstreamHeaders == nil {
		t.Fatalf("%s: no headers were captured from the upstream; the request may never have arrived", label)
	}
	auth, apiKey := upstreamHeaders.Get("Authorization"), upstreamHeaders.Get("X-Api-Key")
	if !strings.Contains(auth, canary) && !strings.Contains(apiKey, canary) {
		t.Errorf("%s: canary %q was NOT delivered to the upstream (Authorization=%q X-Api-Key=%q); "+
			"a test that can pass by dropping the header proves nothing about redaction",
			label, canary, auth, apiKey)
	}
}

// TestGW010CanarySuccessReachesNoFileOrResponse: an ordinary request and
// reply, both ends of which carry the canary -- the request because that
// is GW-001's contract, the reply never, because nothing in an upstream's
// own JSON reply is this credential to begin with. What this scenario
// pins is that forwarding the request does not also leak the credential
// into what the CALLER gets back or into a file.
func TestGW010CanarySuccessReachesNoFileOrResponse(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":"msg_01","content":[{"type":"text","text":"hello back"}]}`)); err != nil {
			t.Errorf("upstream: write reply: %v", err)
		}
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		gw.URL+"/v1/messages", strings.NewReader(`{"model":"claude-3"}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "success", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "success", canary, map[string][]byte{"response body": body}, dirs)
	}
}

// TestGW010CanaryStreamedReachesNoFileOrResponse: the same proof against
// GW-002's streamed path, where the reply is forwarded chunk by chunk
// through Proxy.stream rather than copied once -- and, when the reply is
// an Anthropic Messages SSE stream, also parsed by messagesInterpreter off
// a copy of those same bytes. Neither path has any business touching the
// REQUEST'S headers at all, but this is the scenario that would catch it
// if one ever did.
func TestGW010CanaryStreamedReachesNoFileOrResponse(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream: ResponseWriter is not a Flusher")
		}
		for _, line := range []string{
			"event: content_block_start\ndata: {\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"x\"}}\n\n",
			"event: content_block_stop\ndata: {\"index\":0}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		} {
			if _, err := io.WriteString(w, line); err != nil {
				t.Errorf("upstream: write event: %v", err)
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	// A ToolUseObserver is wired too: this is the one place a witness reads
	// a copy of the streamed bytes (see sse.go), and the canary must not
	// reach it or anything it is handed to either.
	var observedInputs [][]byte
	gw := httptest.NewServer(&Proxy{
		Upstream: up,
		ToolUse: ToolUseObserverFunc(func(tu ToolUse) {
			observedInputs = append(observedInputs, tu.Input)
		}),
	})
	defer gw.Close()

	reqCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed reply: %v", err)
	}

	var observed []byte
	for _, in := range observedInputs {
		observed = append(observed, in...)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "streamed", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "streamed", canary, map[string][]byte{
			"streamed response body":     body,
			"tool_use observer input(s)": observed,
		}, dirs)
	}
}

// TestGW010CanaryUnreachableUpstreamReachesNoErrorBody: the dial itself
// fails (port 1 is reserved; nothing answers there), so there is no
// upstream to receive anything -- proxy.go's own error path, not #371's
// certificate or https-only rule, is what runs. What proves this case is
// not passing by silently dropping the header instead of forwarding it is
// buildRequest, called directly against the same *Proxy this test then
// drives through ServeHTTP: the outgoing request IS constructed with the
// canary before the dial that never completes is even attempted.
func TestGW010CanaryUnreachableUpstreamReachesNoErrorBody(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	up, err := NewUpstream("http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	up.Client.Timeout = 3 * time.Second
	p := &Proxy{Upstream: up}

	probe, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	probe.Header.Set("Authorization", "Bearer "+bearer)
	probe.Header.Set("X-Api-Key", apiKey)
	outReq, err := p.buildRequest(probe)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "unreachable upstream (constructed request)", canary, outReq.Header)
	}

	gw := httptest.NewServer(p)
	defer gw.Close()

	reqCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read error body: %v", err)
	}
	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		t.Errorf("status = %d, want a 5xx", resp.StatusCode)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryNowhere(t, "unreachable upstream", canary,
			map[string][]byte{"error response body": body}, dirs)
	}
}

// TestGW010CanaryUpstreamErrorStatusReachesNoResponseBeyondWhatItSent: the
// upstream is reachable and answers, just with its own error status --
// relayed unchanged, per GW-001, status and body both. The canary reaches
// the upstream (this scenario's request headers) and comes back in
// nothing the upstream's own reply did not already contain.
func TestGW010CanaryUpstreamErrorStatusReachesNoResponseBeyondWhatItSent(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	const upstreamErrBody = `{"error":{"type":"internal_server_error","message":"upstream had a problem"}}`
	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(upstreamErrBody)); err != nil {
			t.Errorf("upstream: write error reply: %v", err)
		}
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		gw.URL+"/v1/messages", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (the upstream's own status, relayed unchanged)",
			resp.StatusCode, http.StatusInternalServerError)
	}
	if string(body) != upstreamErrBody {
		t.Errorf("body = %q, want the upstream's own error body %q unchanged", body, upstreamErrBody)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "upstream error status", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "upstream error status", canary, map[string][]byte{"response body": body}, dirs)
	}
}
