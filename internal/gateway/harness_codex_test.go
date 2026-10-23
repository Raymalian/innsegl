// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// OAI-005: measured interactive 0.163.0 uses a distinct originator token.
func TestOAI005CodexInteractiveRecognition(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/backend-api/codex/responses", nil)
	r.Header.Set("Session-Id", "11111111-1111-4111-8111-111111111111")
	r.Header.Set("Thread-Id", "11111111-1111-4111-8111-111111111111")
	r.Header.Set("User-Agent", "codex-tui/0.163.0 (Generic OS; generic)")
	if _, f := NewHarnessGuard().Check(r); f != nil {
		t.Fatalf("measured interactive shape refused: %+v", f)
	}
	r.Header.Set("User-Agent", "codex-tui/0.164.0")
	if _, f := NewHarnessGuard().Check(r); f == nil {
		t.Fatal("unverified version accepted")
	}
}
