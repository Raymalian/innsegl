// SPDX-License-Identifier: Apache-2.0

package main

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

// GW-010, run through the PRODUCTION command wiring -- openGateway,
// unfaked, listening on a real address, logging through the same
// *serveLog runGateway builds for a deployment -- rather than through
// internal/gateway's own package-level tests (internal/gateway/canary_test.go),
// which cover the same four scenarios against the Proxy directly. Both
// files exist because "no credential ever reaches a file" is a claim about
// the WHOLE process this issue's acceptance criteria names, and the
// package-level tests alone cannot see this file's own log line
// (runGateway logs "relaying model traffic" with the configured upstream,
// never a request's own headers, but nothing proves that except running
// the real thing and reading what it wrote).
//
// gatewayOptions carries no state, log or body directory of its own today
// -- see cmd/innsegl/gateway.go's own doc comment, "What this file wires,
// and what it does not". credentialCanaryDirs below is empty for the same
// reason internal/gateway/canary_test.go's is: when E15's body store or
// E16's snapshots add a flag and an environment variable (following
// envObserveBodyDir's own shape in serve.go), point it at a t.TempDir()
// in each scenario below the same way runGatewayForCanary already points
// -listen and -upstream, and append that directory to the dirs slice each
// scenario builds.

// newCredentialCanary and randomCanarySuffix mirror
// internal/gateway/canary_test.go's own copies exactly; see that file for
// why: a bearer token and an independently-random API key, fresh per call
// so a match can only be this test's own credential.
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

// assertCredentialCanaryNowhere fails t if canary appears in logOutput, in
// any response body in bodies, or in any file under any directory in dirs
// (walked recursively; a missing directory is not an error). label
// identifies the scenario in a failure message. An empty canary fails t
// outright, since every check below would otherwise pass vacuously.
func assertCredentialCanaryNowhere(t *testing.T, label, canary string, logOutput []byte, bodies map[string][]byte, dirs []string) {
	t.Helper()
	if canary == "" {
		t.Fatalf("%s: the canary itself is empty; every check below would pass vacuously", label)
	}
	if strings.Contains(string(logOutput), canary) {
		t.Errorf("%s: canary %q found in the gateway's log output:\n%s", label, canary, logOutput)
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
// canary. A missing directory is silently skipped.
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
// what the upstream actually received. Without this, every check above
// would also pass if the gateway silently dropped the header instead of
// forwarding it.
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

// runGatewayForCanary runs the real `innsegl gateway` command (runGateway,
// the same function gatewayCommand and runGatewayCommand both call) against
// upstreamURL, waits for it to publish its bound address the way
// TestGatewayCommandRelaysRealTrafficEndToEnd (gateway_test.go) does, and
// returns that address, the syncBuffer (api_test.go) its *serveLog is
// writing to, and a stop func that cancels it and waits for it to exit.
func runGatewayForCanary(t *testing.T, upstreamURL string, client *http.Client) (addr string, stderr *syncBuffer, stop func()) {
	t.Helper()

	stderr = &syncBuffer{}
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		// An https upstream is required (#371); a test server's own client
		// is the one seam that lets it be trusted, as in gateway_test.go.
		o.upstreamClient = client
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{"-listen", "127.0.0.1:0", "-upstream", upstreamURL}
	done := make(chan int, 1)
	go func() { done <- runGateway(ctx, args, io.Discard, stderr, deps) }()

	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the gateway never announced a bound address")
	}

	stop = func() {
		cancel()
		select {
		case code := <-done:
			if code != exitOK {
				t.Errorf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the gateway did not stop within 5s of its context being cancelled")
		}
	}
	return addr, stderr, stop
}

// TestGW010CommandCanarySuccessReachesNoFileLogOrResponse runs the ordinary
// path through the production command.
func TestGW010CommandCanarySuccessReachesNoFileLogOrResponse(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	var upstreamHeaders http.Header
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":"msg_01","content":[{"type":"text","text":"hello back"}]}`)); err != nil {
			t.Errorf("upstream: write reply: %v", err)
		}
	}))
	defer upstream.Close()

	addr, stderr, stop := runGatewayForCanary(t, upstream.URL, upstream.Client())
	defer stop()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+addr+"/v1/messages", strings.NewReader(`{"model":"claude-3"}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("X-Claude-Code-Session-Id", "7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f") // a recognised harness shape (#374)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "command/success", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "command/success", canary,
			[]byte(stderr.String()), map[string][]byte{"response body": body}, dirs)
	}
}

// TestGW010CommandCanaryStreamedReachesNoFileLogOrResponse runs GW-002's
// streamed path through the production command.
func TestGW010CommandCanaryStreamedReachesNoFileLogOrResponse(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	var upstreamHeaders http.Header
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream: ResponseWriter is not a Flusher")
		}
		for _, line := range []string{
			"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		} {
			if _, err := io.WriteString(w, line); err != nil {
				t.Errorf("upstream: write event: %v", err)
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	addr, stderr, stop := runGatewayForCanary(t, upstream.URL, upstream.Client())
	defer stop()

	reqCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("X-Claude-Code-Session-Id", "7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f") // a recognised harness shape (#374)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streamed reply: %v", err)
	}

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "command/streamed", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "command/streamed", canary,
			[]byte(stderr.String()), map[string][]byte{"streamed response body": body}, dirs)
	}
}

// TestGW010CommandCanaryUnreachableUpstreamReachesNoErrorBodyOrLog points
// the production command's OWN -upstream flag at an address nothing
// answers (port 1 is reserved), so openGateway's real client -- built
// inside the production wiring, not swapped out for a test double -- is
// what dials and fails. The delivery-to-upstream proof for this scenario
// (buildRequest, called directly before the dial that never completes) is
// internal/gateway/canary_test.go's, which has access to the unexported
// method; this file's own job is the process-level log and error-body
// check that requires the real command wiring to exist at all.
func TestGW010CommandCanaryUnreachableUpstreamReachesNoErrorBodyOrLog(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	addr, stderr, stop := runGatewayForCanary(t, "https://127.0.0.1:1", nil)
	defer stop()

	reqCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("X-Claude-Code-Session-Id", "7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f") // a recognised harness shape (#374)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v (want a response from the gateway, not a transport error)", err)
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
		assertCredentialCanaryNowhere(t, "command/unreachable upstream", canary,
			[]byte(stderr.String()), map[string][]byte{"error response body": body}, dirs)
	}
}

// TestGW010CommandCanaryUpstreamErrorStatusReachesNoResponseOrLogBeyondWhatItSent
// runs the case where the upstream is reachable and answers with its own
// error status, relayed unchanged (GW-001) rather than produced by
// proxy.go's own error path.
func TestGW010CommandCanaryUpstreamErrorStatusReachesNoResponseOrLogBeyondWhatItSent(t *testing.T) {
	bearer, apiKey := newCredentialCanary(t)

	const upstreamErrBody = `{"error":{"type":"internal_server_error","message":"upstream had a problem"}}`
	var upstreamHeaders http.Header
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(upstreamErrBody)); err != nil {
			t.Errorf("upstream: write error reply: %v", err)
		}
	}))
	defer upstream.Close()

	addr, stderr, stop := runGatewayForCanary(t, upstream.URL, upstream.Client())
	defer stop()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+addr+"/v1/messages", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("X-Claude-Code-Session-Id", "7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f") // a recognised harness shape (#374)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
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

	dirs := []string{t.TempDir()}
	for _, canary := range []string{bearer, apiKey} {
		assertCredentialCanaryDeliveredUpstream(t, "command/upstream error status", canary, upstreamHeaders)
		assertCredentialCanaryNowhere(t, "command/upstream error status", canary,
			[]byte(stderr.String()), map[string][]byte{"response body": body}, dirs)
	}
}
