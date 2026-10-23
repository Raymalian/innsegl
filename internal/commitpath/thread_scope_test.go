// SPDX-License-Identifier: Apache-2.0

package commitpath

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// OAI-016: a pending child's call is eligible only in its observed session
// and thread. These values are harness assertions, not independent credentials.
func TestOAI016ThreadScopedCommitResolution(t *testing.T) {
	now := time.Now()
	child := RelayedCall{Harness: "codex", WireType: "function_call", Namespace: "functions", Tool: "functions.exec_command", Input: json.RawMessage(`{"cmd":"git commit -m child"}`), ObservedAt: now, SessionID: "session-a", ThreadID: "child-a"}
	root := child
	root.ThreadID = "session-a"
	missing := child
	missing.ThreadID = ""
	missingSession := child
	missingSession.SessionID = ""
	claude := RelayedCall{Tool: "Bash", Input: json.RawMessage(`{"command":"git commit -m claude"}`), ObservedAt: now}
	base := fakeResolver{"call_child": child, "call_root": root, "call_unbound": missing, "call_sessionless": missingSession, "toolu_claude": claude}
	for _, tc := range []struct {
		name, id, session, thread string
		allowed                   bool
	}{
		{"child own", "call_child", "session-a", "child-a", true},
		{"sibling borrow", "call_child", "session-a", "child-b", false},
		{"parent borrow", "call_child", "session-a", "session-a", false},
		{"root own", "call_root", "session-a", "session-a", true},
		{"child borrows root", "call_root", "session-a", "child-a", false},
		{"different session", "call_child", "session-b", "child-a", false},
		{"missing session", "call_child", "", "child-a", false},
		{"missing thread", "call_child", "session-a", "", false},
		{"missing context", "call_child", "", "", false},
		{"unbound call", "call_unbound", "session-a", "child-a", false},
		{"sessionless call", "call_sessionless", "session-a", "child-a", false},
		{"claude unchanged", "toolu_claude", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(ThreadScopedResolver(base, tc.session, tc.thread), tc.id, now)
			if (err == nil) != tc.allowed {
				t.Fatalf("Resolve error = %v; allowed=%v", err, tc.allowed)
			}
		})
	}
}

// OAI-014/016: both commit requests carry only the context captured by the
// hook's explicit environment, with no cross-request transport mutation.
func TestOAI016ClientForwardsThreadContextPerRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantSession, wantThread := "session-a", "child-a"
		if r.URL.Query().Get("unbound") == "1" {
			wantSession, wantThread = "", ""
		}
		if got := r.Header.Get(HeaderCodexSessionID); got != wantSession {
			t.Errorf("session header=%q, want %q", got, wantSession)
		}
		if got := r.Header.Get(HeaderCodexThreadID); got != wantThread {
			t.Errorf("thread header=%q, want %q", got, wantThread)
		}
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	c := ClientFromEnv(func(k string) string {
		switch k {
		case EnvCoreURL:
			return srv.URL
		case EnvCodexSessionID:
			return "session-a"
		case EnvCodexThreadID:
			return "child-a"
		}
		return ""
	})
	c.HTTP = srv.Client()
	if _, err := c.Trailers(t.Context(), TrailersRequest{ToolUseID: "call_child"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(t.Context(), SignRequest{ToolUseID: "call_child"}); err != nil {
		t.Fatal(err)
	}
	// A second client sharing the HTTP transport carries no inherited scope.
	plain := Client{BaseURL: srv.URL, HTTP: c.HTTP}
	if err := plain.call(t.Context(), SignPath+"?unbound=1", SignRequest{}, &SignResponse{}); err != nil {
		t.Fatal(err)
	}
}
