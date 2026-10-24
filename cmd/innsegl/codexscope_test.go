// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

type codexScopeResolver map[string]commitpath.RelayedCall

func (r codexScopeResolver) LookupPending(id string) (commitpath.RelayedCall, bool) {
	v, ok := r[id]
	return v, ok
}

// OAI-021: both commit endpoints use the same originating thread filter.
func TestOAI021CommitPathRejectsSiblingThread(t *testing.T) {
	const session = "11111111-1111-4111-8111-111111111111"
	const child = "22222222-2222-4222-8222-222222222222"
	resolver := codexScopeResolver{"call_child": {Harness: "codex", SessionID: session, ThreadID: child, WireType: "function_call", Tool: "exec_command", Input: json.RawMessage(`{"cmd":"git commit -m child"}`), ObservedAt: time.Now()}}
	for _, path := range []string{commitpath.TrailersPath, commitpath.SignPath} {
		for _, thread := range []string{child, session, ""} {
			t.Run(path+"/"+thread, func(t *testing.T) {
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := commitpath.Resolve(commitpath.ResolverFrom(r.Context(), resolver), "call_child", time.Now()); err != nil {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				})
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
				req.Header.Set(commitpath.HeaderCodexSessionID, session)
				req.Header.Set(commitpath.HeaderCodexThreadID, thread)
				out := httptest.NewRecorder()
				scopeCommitPath(resolver, next).ServeHTTP(out, req)
				want := http.StatusForbidden
				if thread == child {
					want = http.StatusNoContent
				}
				if out.Code != want {
					t.Fatalf("status=%d want=%d", out.Code, want)
				}
			})
		}
	}
}
