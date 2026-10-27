// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// OAI-005: the Codex root shape must be identified as itself, never Claude.
// These are contract examples; live supported-version fixtures remain a gate.
func TestOAI005CodexRootRecognition(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", nil)
	r.Header.Set("Session-Id", "11111111-1111-4111-8111-111111111111")
	r.Header.Set("Thread-Id", "11111111-1111-4111-8111-111111111111")
	r.Header.Set("User-Agent", "codex_exec/0.163.0 (Generic OS; generic)")
	next, refusal := NewHarnessGuard().Check(r)
	if refusal != nil {
		t.Fatalf("refused Codex: %+v", refusal)
	}
	id, ok := IdentificationFromContext(next.Context())
	if !ok || id.Harness != "codex" || id.Version != "0.163.0" || id.AgentID != "main" {
		t.Fatalf("identification %+v", id)
	}
	for _, change := range []string{"session", "version", "child", "subagent header", "parent header", "child metadata", "method"} {
		t.Run(change, func(t *testing.T) {
			bad := r.Clone(r.Context())
			bad.Header = r.Header.Clone()
			switch change {
			case "session":
				bad.Header.Set("Session-Id", "not-uuid")
			case "version":
				bad.Header.Set("User-Agent", "unknown/0.163.0")
			case "child":
				bad.Header.Set("Thread-Id", "22222222-2222-4222-8222-222222222222")
			case "subagent header":
				bad.Header.Set("X-OpenAI-Subagent", "worker")
			case "parent header":
				bad.Header.Set("X-Codex-Parent-Thread-Id", "22222222-2222-4222-8222-222222222222")
			case "child metadata":
				bad.Header.Set("X-Codex-Turn-Metadata", `{"session_id":"11111111-1111-4111-8111-111111111111","thread_id":"11111111-1111-4111-8111-111111111111","agent_name":"/root/worker"}`)
			case "method":
				bad.Method = http.MethodGet
			}
			if _, f := NewHarnessGuard().Check(bad); f == nil {
				t.Fatal("accepted unverified shape")
			}
		})
	}
}

// OAI-005: recognized Codex client identifiers retain their reported version.
func TestOAI005CodexInteractiveRecognition(t *testing.T) {
	for _, tc := range []struct{ userAgent, version string }{
		{"codex_exec/0.163.0 (Generic OS; generic)", "0.163.0"},
		{"codex_cli_rs/0.164.0 (Generic OS; generic)", "0.164.0"},
		{"codex-tui/1.2.3-beta.1+build.7 (Generic OS; generic)", "1.2.3-beta.1+build.7"},
	} {
		t.Run(tc.userAgent, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", nil)
			r.Header.Set("Session-Id", "11111111-1111-4111-8111-111111111111")
			r.Header.Set("Thread-Id", "11111111-1111-4111-8111-111111111111")
			r.Header.Set("User-Agent", tc.userAgent)
			next, f := NewHarnessGuard().Check(r)
			if f != nil {
				t.Fatalf("Codex version refused: %+v", f)
			}
			id, ok := IdentificationFromContext(next.Context())
			if !ok || id.Version != tc.version {
				t.Fatalf("reported Codex version not retained: %+v", id)
			}
		})
	}
	for _, userAgent := range []string{"unknown/0.164.0", "codex-tui/0.164", "codex_exec/not-a-version"} {
		t.Run("reject "+userAgent, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", nil)
			r.Header.Set("Session-Id", "11111111-1111-4111-8111-111111111111")
			r.Header.Set("Thread-Id", "11111111-1111-4111-8111-111111111111")
			r.Header.Set("User-Agent", userAgent)
			if _, f := NewHarnessGuard().Check(r); f == nil {
				t.Fatal("accepted unknown product or malformed version")
			}
		})
	}
}

// OAI-006: actual CLI metadata distinguishes each child thread in one session.
func TestOAI006CodexChildRecognition(t *testing.T) {
	r := codexChildRequest(t, "22222222-2222-4222-8222-222222222222", "/root/worker", "11111111-1111-4111-8111-111111111111")
	next, refusal := NewHarnessGuard().Check(r)
	if refusal != nil {
		t.Fatalf("measured child refused: %+v", refusal)
	}
	id, _ := IdentificationFromContext(next.Context())
	if id.SessionID != "11111111-1111-4111-8111-111111111111" || id.AgentID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("child identification: %+v", id)
	}
	for _, name := range []string{"parent disagreement", "self parent", "missing marker", "root name", "bad name"} {
		t.Run(name, func(t *testing.T) {
			bad := r.Clone(r.Context())
			bad.Header = r.Header.Clone()
			switch name {
			case "parent disagreement":
				bad.Header.Set("X-Codex-Parent-Thread-Id", "33333333-3333-4333-8333-333333333333")
			case "self parent":
				bad.Header.Set("X-Codex-Parent-Thread-Id", "22222222-2222-4222-8222-222222222222")
			case "missing marker":
				bad.Header.Del("X-OpenAI-Subagent")
			case "root name":
				bad.Header.Set("X-Codex-Turn-Metadata", strings.ReplaceAll(bad.Header.Get("X-Codex-Turn-Metadata"), "/root/worker", "/root"))
			case "bad name":
				bad.Header.Set("X-Codex-Turn-Metadata", strings.ReplaceAll(bad.Header.Get("X-Codex-Turn-Metadata"), "/root/worker", "/root/../worker"))
			}
			if _, f := NewHarnessGuard().Check(bad); f == nil {
				t.Fatal("accepted inconsistent child")
			}
		})
	}
}

func codexChildRequest(t *testing.T, thread, name, parent string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", strings.NewReader(`{"input":[]}`))
	r.Header.Set("User-Agent", "codex_exec/0.163.0 (Generic OS; generic)")
	r.Header.Set("X-OpenAI-Subagent", "collab_spawn")
	r.Header.Set("X-Codex-Parent-Thread-Id", parent)
	b, err := json.Marshal(map[string]string{"session_id": "11111111-1111-4111-8111-111111111111", "thread_id": thread, "agent_name": name, "parent_thread_id": parent, "subagent_kind": "thread_spawn", "thread_source": "subagent"})
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Codex-Turn-Metadata", string(b))
	return r
}

// OAI-006: sanitized captures from actual child-thread creation, including
// nested and live-provider traffic, pass through the same recognizer.
func TestOAI006CodexMeasuredThreadFixtures(t *testing.T) {
	// The live recorder retained identity headers only. The version header
	// below is a separate actual capture from the same installed CLI, not a
	// claim that the live fixture retained it.
	captured, err := os.ReadFile("testdata/codex-child-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var versionCapture struct {
		Requests []struct {
			Headers map[string]string `json:"headers"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(captured, &versionCapture); err != nil {
		t.Fatal(err)
	}
	userAgent := versionCapture.Requests[0].Headers["user-agent"]
	for _, path := range []string{"testdata/codex-child-contract.json", "testdata/codex-child-live-contract.json", "testdata/codex-child-live-direct-contract.json"} {
		t.Run(path, func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Requests []struct {
					Headers map[string]string `json:"headers"`
				} `json:"requests"`
			}
			if err = json.Unmarshal(b, &fixture); err != nil {
				t.Fatal(err)
			}
			if len(fixture.Requests) == 0 {
				t.Fatal("fixture has no measured requests")
			}
			for _, rec := range fixture.Requests {
				r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", nil)
				for k, v := range rec.Headers {
					r.Header.Set(k, v)
				}
				if r.UserAgent() == "" {
					r.Header.Set("User-Agent", userAgent)
				}
				next, refusal := NewHarnessGuard().Check(r)
				if refusal != nil {
					t.Fatalf("measured request refused: %+v", refusal)
				}
				var meta CodexThreadIdentity
				if err = json.Unmarshal([]byte(r.Header.Get("X-Codex-Turn-Metadata")), &meta); err != nil {
					t.Fatal(err)
				}
				id, _ := IdentificationFromContext(next.Context())
				wantAgent := meta.ThreadID
				if meta.AgentName == "/root" {
					wantAgent = "main"
				}
				if id.SessionID != meta.SessionID || id.AgentID != wantAgent {
					t.Fatalf("identity=%+v metadata=%+v", id, meta)
				}
			}
		})
	}
}
