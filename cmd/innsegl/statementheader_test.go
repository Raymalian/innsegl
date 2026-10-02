// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
)

// RM-313: the statement the client service attaches to a model request is
// validated exactly like the session-workspace endpoint's body, and admitted
// by the same rule.

const (
	shInstA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shInstB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shRepo     = "github.com/acme/app"
	shRival    = "github.com/rival/held"
	shSubagent = "aa328d4891c7406b1"
)

type shScope map[string]bool // installation + " " + repo

func (s shScope) InScope(_ context.Context, inst, repo string) (bool, error) {
	return s[inst+" "+repo], nil
}

func shHeader(body string) string { return base64.RawURLEncoding.EncodeToString([]byte(body)) }

func shRequest(header string, agent string) (*http.Request, gateway.Identification) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	if header != "" {
		r.Header.Set(gateway.StatementHeader, header)
	}
	if agent == "" {
		agent = "main"
	}
	return r, gateway.Identification{SessionID: testSessionID, AgentID: agent}
}

// The client service and the core name the same header and the same path.
func TestRM313TheClientAndTheCoreAgreeOnTheWire(t *testing.T) {
	if client.StatementHeader != gateway.StatementHeader {
		t.Fatalf("client header %q, core header %q", client.StatementHeader, gateway.StatementHeader)
	}
	if client.SessionStatementPath != gatewaySessionWorkspacePath {
		t.Fatalf("client path %q, core path %q", client.SessionStatementPath, gatewaySessionWorkspacePath)
	}
}

func TestRM313HeaderStatementDecodesOnlyWhatTheEndpointAccepts(t *testing.T) {
	inRepo := `{"session_id":"` + testSessionID + `","cwd":"/w/app","repo":"` + shRepo + `","branch":"main","task":"t1"}`
	for _, tc := range []struct {
		name, header, agent string
		ok                  bool
		wantAgent, wantRepo string
	}{
		{"the main agent's statement", shHeader(inRepo), "", true, "", shRepo},
		{"a directory alone", shHeader(`{"session_id":"` + testSessionID + `","cwd":"/w"}`), "", true, "", ""},
		{"the session's statement on a subagent's request", shHeader(inRepo), shSubagent, true, "", shRepo},
		{"the subagent's own", shHeader(`{"session_id":"` + testSessionID + `","agent_id":"` + shSubagent + `","cwd":"/w/sub"}`),
			shSubagent, true, shSubagent, ""},
		{"no header", "", "", false, "", ""},
		{"not base64", "%%%", "", false, "", ""},
		{"not JSON", shHeader("nope"), "", false, "", ""},
		{"another session", shHeader(`{"session_id":"d5a6a1a0-0000-4000-8000-0000000000dd","cwd":"/w"}`), "", false, "", ""},
		{"another agent", shHeader(`{"session_id":"` + testSessionID + `","agent_id":"bb328d4891c7406b1","cwd":"/w"}`),
			shSubagent, false, "", ""},
		{"a subagent's statement on the main agent's request",
			shHeader(`{"session_id":"` + testSessionID + `","agent_id":"` + shSubagent + `","cwd":"/w"}`), "", false, "", ""},
		{"a relative cwd", shHeader(`{"session_id":"` + testSessionID + `","cwd":"w"}`), "", false, "", ""},
		{"a half-derived repository", shHeader(`{"session_id":"` + testSessionID + `","cwd":"/w","repo":"` + shRepo + `"}`), "", false, "", ""},
		{"oversized", shHeader(`{"session_id":"` + testSessionID + `","cwd":"/` + strings.Repeat("a", 20000) + `"}`), "", false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, id := shRequest(tc.header, tc.agent)
			agent, st, ok := (headerStatements{callers: localCallers{}}).Decode(r, id)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (%+v)", ok, tc.ok, st)
			}
			if ok && (agent != tc.wantAgent || st.Repo != tc.wantRepo) {
				t.Fatalf("agent %q repo %q, want %q %q", agent, st.Repo, tc.wantAgent, tc.wantRepo)
			}
		})
	}
}

func TestRM313HeaderStatementIsAdmittedLikeTheEndpoint(t *testing.T) {
	pins := gateway.NewSessionPins(0)
	hosted := headerStatements{callers: hostedCallers{scope: shScope{shInstA + " " + shRepo: true}, pins: pins}}
	ctxA := gateway.WithInstallation(context.Background(), shInstA)
	inRepo := gateway.StatedWorkspace{Cwd: "/w", Repo: shRepo, Branch: "main", Task: "t1"}
	rival := gateway.StatedWorkspace{Cwd: "/w", Repo: shRival, Branch: "main", Task: "t1"}

	for _, tc := range []struct {
		name string
		ctx  context.Context
		st   gateway.StatedWorkspace
		want gateway.StatementVerdict
	}{
		{"in scope", ctxA, inRepo, gateway.StatementAdmitted},
		{"outside any repository", ctxA, gateway.StatedWorkspace{Cwd: "/w"}, gateway.StatementAdmitted},
		{"another organisation's repository", ctxA, rival, gateway.StatementOutOfScope},
		{"another installation's session", gateway.WithInstallation(context.Background(), shInstB), inRepo, gateway.StatementRefused},
		{"no installation", context.Background(), inRepo, gateway.StatementRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hosted.Admit(tc.ctx, testSessionID, tc.st)
			if err != nil || got != tc.want {
				t.Fatalf("verdict %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	if got, err := (headerStatements{callers: localCallers{}}).Admit(context.Background(), testSessionID, rival); err != nil ||
		got != gateway.StatementAdmitted {
		t.Fatalf("single host: %v, %v; want admitted", got, err)
	}
}

// The endpoint still answers an out-of-scope statement with the client
// refusal, so the hook can say so, records nothing, and logs the finding.
func TestRM313OutOfScopeStatementIsRefusedAndLogged(t *testing.T) {
	ws := gateway.NewSessionWorkspaces(0)
	var logs bytes.Buffer
	callers := hostedCallers{scope: shScope{shInstA + " " + shRepo: true}, pins: gateway.NewSessionPins(0)}
	h := sessionWorkspaceHandler(ws, newTestSessionEndRateLimiter(t), callers, newServeLog(&logs))
	body := `{"session_id":"` + testSessionID + `","cwd":"/w","repo":"` + shRival + `","branch":"main","task":"t1"}`
	req := httptest.NewRequestWithContext(gateway.WithInstallation(context.Background(), shInstA), http.MethodPost,
		gatewaySessionWorkspacePath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if ws.Knows(testSessionID, "") {
		t.Fatal("an out-of-scope statement was recorded")
	}
	for _, want := range []string{testSessionID, shRival, "out-of-scope"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log %q does not name %q", logs.String(), want)
		}
	}
}

// A finding is logged with the session, the installation and the reason.
func TestRM313UnrecordedFindingsAreLogged(t *testing.T) {
	var logs bytes.Buffer
	logUnrecorded(newServeLog(&logs))(gateway.UnrecordedFinding{
		SessionID: testSessionID, AgentID: "main", Installation: shInstA, Repo: shRival, Reason: gateway.UnrecordedOutOfScope,
	})
	for _, want := range []string{testSessionID, shInstA, shRival, "out-of-scope", "unrecorded"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log %q does not name %q", logs.String(), want)
		}
	}
	_ = io.Discard
}
