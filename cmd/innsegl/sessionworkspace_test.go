// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/gateway"
)

const testSessionID = "d5a6a1a0-0000-4000-8000-0000000000cc"

func sessionWorkspaceTestHandler(t *testing.T) (http.HandlerFunc, *gateway.SessionWorkspaces) {
	t.Helper()
	ws := gateway.NewSessionWorkspaces(0)
	local := localCallers{host: net.ParseIP("172.28.0.1")}
	return sessionWorkspaceHandler(ws, newTestSessionEndRateLimiter(t), local, newServeLog(io.Discard)), ws
}

func sessionWorkspaceRequest(t *testing.T, method, remoteAddr, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, gatewaySessionWorkspacePath, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	return req
}

// The hook, from the host, records the session's directory.
func TestSessionWorkspaceHandlerRecordsTheHostsStatement(t *testing.T) {
	h, ws := sessionWorkspaceTestHandler(t)
	rec := httptest.NewRecorder()
	h(rec, sessionWorkspaceRequest(t, http.MethodPost, "[::ffff:172.28.0.1]:40000",
		`{"session_id":"`+testSessionID+`","cwd":"/workspace/repo"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body: %s", rec.Code, rec.Body.String())
	}
	if got, ok := ws.Lookup(testSessionID, "main"); !ok || got != "/workspace/repo" {
		t.Fatalf("Lookup = %q, %v; want /workspace/repo", got, ok)
	}
}

func TestSessionWorkspaceHandlerRecordsASubagentsOwnDirectory(t *testing.T) {
	h, ws := sessionWorkspaceTestHandler(t)
	rec := httptest.NewRecorder()
	h(rec, sessionWorkspaceRequest(t, http.MethodPost, "127.0.0.1:40000",
		`{"session_id":"`+testSessionID+`","agent_id":"aa328d4891c7406b1","cwd":"/workspace/sub"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body: %s", rec.Code, rec.Body.String())
	}
	if got, _ := ws.Lookup(testSessionID, "aa328d4891c7406b1"); got != "/workspace/sub" {
		t.Fatalf("Lookup = %q, want /workspace/sub", got)
	}
}

func TestSessionWorkspaceHandlerRefusesWhatItCannotAccept(t *testing.T) {
	for _, tc := range []struct {
		name, method, addr, body string
		want                     int
	}{
		{"not POST", http.MethodGet, "127.0.0.1:1", "", http.StatusMethodNotAllowed},
		{"another container", http.MethodPost, "172.28.0.9:1",
			`{"session_id":"` + testSessionID + `","cwd":"/w"}`, http.StatusForbidden},
		{"not JSON", http.MethodPost, "127.0.0.1:1", "nope", http.StatusBadRequest},
		{"bad session id", http.MethodPost, "127.0.0.1:1", `{"session_id":"x","cwd":"/w"}`, http.StatusBadRequest},
		{"bad agent id", http.MethodPost, "127.0.0.1:1",
			`{"session_id":"` + testSessionID + `","agent_id":"main","cwd":"/w"}`, http.StatusBadRequest},
		{"relative cwd", http.MethodPost, "127.0.0.1:1",
			`{"session_id":"` + testSessionID + `","cwd":"repo"}`, http.StatusBadRequest},
		{"empty cwd", http.MethodPost, "127.0.0.1:1", `{"session_id":"` + testSessionID + `"}`, http.StatusBadRequest},
		{"unclean cwd", http.MethodPost, "127.0.0.1:1",
			`{"session_id":"` + testSessionID + `","cwd":"/w/../etc"}`, http.StatusBadRequest},
		{"overlong cwd", http.MethodPost, "127.0.0.1:1",
			`{"session_id":"` + testSessionID + `","cwd":"/` + strings.Repeat("a", 5000) + `"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ws := sessionWorkspaceTestHandler(t)
			rec := httptest.NewRecorder()
			h(rec, sessionWorkspaceRequest(t, tc.method, tc.addr, tc.body))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if _, ok := ws.Lookup(testSessionID, "main"); ok {
				t.Error("a refused statement was recorded")
			}
		})
	}
}

// The session-end endpoint admits the host the same way: before this, every
// hook from the host was refused as non-loopback.
func TestSessionEndHandlerAcceptsTheHost(t *testing.T) {
	signals := gateway.NewSessionEndSignals(0)
	ender := gateway.NewSessionEnder(signals, noopMappingStore{}, noopRegistrar{}, 0, nil)
	h := sessionEndHandler(ender, newTestSessionEndRateLimiter(t), localCallers{host: net.ParseIP("172.28.0.1")}, newServeLog(io.Discard))
	rec := httptest.NewRecorder()
	h(rec, sessionWorkspaceRequest(t, http.MethodPost, "[::ffff:172.28.0.1]:40000", `{"session_id":"`+testSessionID+`"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body: %s", rec.Code, rec.Body.String())
	}
}
