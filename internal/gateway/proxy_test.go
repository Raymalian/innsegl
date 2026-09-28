// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GW-001: the gateway relays a request and its reply byte for byte -- the
// method, the path and query, every header (credentials included), and the
// body, in both directions -- with nothing added and nothing dropped beyond
// the hop-by-hop headers RFC 7230 says do not survive a hop.
func TestGW001RelaysRequestAndReplyByteForByte(t *testing.T) {
	const reqBody = `{"model":"claude-3","messages":[{"role":"user","content":"café ☃"}]}`
	const respBody = `{"id":"msg_01","content":[{"type":"text","text":"hello back"}]}`

	var (
		gotMethod, gotPath, gotQuery string
		gotHeaders                   http.Header
		gotBody                      []byte
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotHeaders = r.Header.Clone()
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream: read request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Reply", "yes")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(respBody)); err != nil {
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
		gw.URL+"/v1/messages?beta=tools-2024", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-ant-test-credential")
	req.Header.Set("X-Api-Key", "sk-ant-test-credential-2")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	gotReply, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	// What the upstream received.
	if gotMethod != http.MethodPost {
		t.Errorf("upstream saw method %q, want POST", gotMethod)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("upstream saw path %q, want /v1/messages", gotPath)
	}
	if gotQuery != "beta=tools-2024" {
		t.Errorf("upstream saw query %q, want beta=tools-2024", gotQuery)
	}
	if !bytes.Equal(gotBody, []byte(reqBody)) {
		t.Errorf("upstream saw body %q, want %q", gotBody, reqBody)
	}
	for _, want := range []struct{ key, val string }{
		{"Authorization", "Bearer sk-ant-test-credential"},
		{"X-Api-Key", "sk-ant-test-credential-2"},
		{"Content-Type", "application/json"},
		{"Anthropic-Version", "2023-06-01"},
	} {
		if got := gotHeaders.Get(want.key); got != want.val {
			t.Errorf("upstream saw %s = %q, want %q", want.key, got, want.val)
		}
	}

	// What the client received back.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("client saw status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Custom-Reply"); got != "yes" {
		t.Errorf("client saw X-Custom-Reply = %q, want yes", got)
	}
	if !bytes.Equal(gotReply, []byte(respBody)) {
		t.Errorf("client saw reply %q, want %q", gotReply, respBody)
	}
}

// GW-002: the first SSE event reaches the client before the upstream
// finishes the stream -- a streamed reply is forwarded chunk by chunk, not
// buffered until the connection closes.
func TestGW002FirstSSEEventReachesClientBeforeUpstreamFinishes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream: ResponseWriter is not a Flusher")
		}
		if _, err := io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"); err != nil {
			t.Errorf("upstream: write first event: %v", err)
		}
		flusher.Flush()

		<-release // held open: the upstream has NOT finished the stream.

		if _, err := io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"); err != nil {
			t.Errorf("upstream: write final event: %v", err)
		}
		flusher.Flush()
	}))
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		upstream.Close()
	}()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	// Bounded end to end, not only on the body read below: an
	// implementation that buffers so completely it never even flushes a
	// status line must fail this test on ITS OWN 5s bound rather than hang
	// until go test's outer -timeout kills the whole binary. Without this,
	// a total-buffering regression is still caught, but as a goroutine-dump
	// panic instead of a readable assertion.
	reqCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a prompt response with the reply streamed after, "+
			"not one that hangs while the whole reply is buffered)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	type readResult struct {
		line string
		err  error
	}
	reader := bufio.NewReader(resp.Body)
	firstLine := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		firstLine <- readResult{line, err}
	}()

	select {
	case r := <-firstLine:
		if r.err != nil {
			t.Fatalf("read the first SSE line: %v", r.err)
		}
		if !strings.Contains(r.line, "message_start") {
			t.Fatalf("first line = %q, want the message_start event", r.line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client read nothing within 5s; the reply is being buffered rather than streamed")
	}

	// The upstream is still blocked on <-release at this point: the client
	// saw the first event while it was.
	close(release)

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain the rest of the reply: %v", err)
	}
}

// TestProxyBuildRequestRefusesWhatNewRequestRefuses. buildRequest wraps
// http.NewRequestWithContext, and an invalid method -- one a caller cannot
// normally produce through http.Client, but ServeHTTP must still handle
// safely rather than panic on -- is refused the same way.
func TestProxyBuildRequestRefusesWhatNewRequestRefuses(t *testing.T) {
	up, err := NewUpstream("https://example.invalid", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	p := &Proxy{Upstream: up}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	req.Method = "BAD METHOD" // a space is not a valid token character (RFC 7230 §3.1.1)

	if _, err := p.buildRequest(req); err == nil {
		t.Fatal("buildRequest accepted an invalid method, want a refusal")
	}
}

// TestProxyServeHTTPReturnsAJSONErrorWhenTheRequestCannotBeBuilt covers
// ServeHTTP's OWN refusal branch, end to end through the handler rather
// than by calling buildRequest directly.
func TestProxyServeHTTPReturnsAJSONErrorWhenTheRequestCannotBeBuilt(t *testing.T) {
	up, err := NewUpstream("https://example.invalid", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	p := &Proxy{Upstream: up}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	req.Method = "BAD METHOD"
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Errorf("status = %d, want a 5xx", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") {
		t.Errorf("error body %q does not name innsegl", body.Error)
	}
}

// TestGatewayUpstreamFailureReturnsAJSONErrorNotADroppedConnection.
//
// The full error-class vocabulary is #371's; this is the minimal clean
// response this issue owns: an upstream the gateway cannot reach at all
// gets a JSON body naming innsegl and a 5xx status, not a connection the
// caller has to interpret the silence of.
func TestGatewayUpstreamFailureReturnsAJSONErrorNotADroppedConnection(t *testing.T) {
	// Port 1 is reserved; nothing answers there, so the dial itself fails
	// (typically ECONNREFUSED) rather than timing out.
	up, err := NewUpstream("http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	up.Client.Timeout = 3 * time.Second
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		t.Errorf("status = %d, want a 5xx", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") {
		t.Errorf("error body %q does not name innsegl", body.Error)
	}
}

// nonFlushingResponseWriter is an http.ResponseWriter that does NOT
// implement http.Flusher, unlike every real ResponseWriter this gateway is
// handed in production. It exists to pin stream's defensive fallback: a
// reply is still forwarded in full even without a Flush call after each
// chunk.
type nonFlushingResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newNonFlushingResponseWriter() *nonFlushingResponseWriter {
	return &nonFlushingResponseWriter{header: make(http.Header)}
}

func (w *nonFlushingResponseWriter) Header() http.Header         { return w.header }
func (w *nonFlushingResponseWriter) WriteHeader(code int)        { w.status = code }
func (w *nonFlushingResponseWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

func TestProxyStreamForwardsEverythingWithoutAFlusher(t *testing.T) {
	const respBody = "no flusher here, still forwarded in full"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(respBody)); err != nil {
			t.Errorf("upstream: write reply: %v", err)
		}
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	p := &Proxy{Upstream: up}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://gateway.invalid/x", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	rec := newNonFlushingResponseWriter()
	p.ServeHTTP(rec, req)

	if rec.body.String() != respBody {
		t.Errorf("body = %q, want %q", rec.body.String(), respBody)
	}
}

// TestGatewayStripsHopByHopHeadersButForwardsEverythingElse pins the RFC
// 7230 §6.1 boundary the scope names explicitly: a hop-by-hop header (and
// anything the request's own Connection header lists) is not forwarded,
// while an ordinary header -- including one a naive implementation might
// mistake for special, like Content-Type -- is.
func TestGatewayStripsHopByHopHeadersButForwardsEverythingElse(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("X-Custom", "keep-me")
	req.Header.Set("Connection", "X-Should-Drop")
	req.Header.Set("X-Should-Drop", "gone")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := gotHeaders.Get("X-Custom"); got != "keep-me" {
		t.Errorf("upstream saw X-Custom = %q, want keep-me", got)
	}
	if gotHeaders.Get("X-Should-Drop") != "" {
		t.Error("upstream saw X-Should-Drop, which the request's own Connection header named as hop-by-hop")
	}
}
