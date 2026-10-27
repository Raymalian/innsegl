// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// CodexThreadIdentity is the harness-asserted thread metadata. ParentThreadID
// selects an observed spawn to check; it is never itself proof of a parent run.
type CodexThreadIdentity struct {
	SessionID      string `json:"session_id"`
	ThreadID       string `json:"thread_id"`
	AgentName      string `json:"agent_name"`
	ParentThreadID string `json:"parent_thread_id"`
	SubagentKind   string `json:"subagent_kind"`
	ThreadSource   string `json:"thread_source"`
}

type codexThreadContextKey struct{}

// CodexThreadFromContext returns the recognized wire thread, including its
// opaque thread id for independently checking command attribution.
func CodexThreadFromContext(ctx context.Context) (CodexThreadIdentity, bool) {
	t, ok := ctx.Value(codexThreadContextKey{}).(CodexThreadIdentity)
	return t, ok
}

func codexThread(r *http.Request) (CodexThreadIdentity, bool) {
	var t CodexThreadIdentity
	metadata := r.Header.Get("X-Codex-Turn-Metadata")
	if metadata != "" {
		if len(metadata) > 16384 || json.Unmarshal([]byte(metadata), &t) != nil {
			return t, false
		}
	} else {
		t.SessionID, t.ThreadID, t.AgentName = r.Header.Get("Session-Id"), r.Header.Get("Thread-Id"), "/root"
	}
	if !isUUID(t.SessionID) || !isUUID(t.ThreadID) {
		return t, false
	}
	if s := r.Header.Get("Session-Id"); s != "" && s != t.SessionID {
		return t, false
	}
	if s := r.Header.Get("Thread-Id"); s != "" && s != t.ThreadID {
		return t, false
	}
	if t.ThreadID == t.SessionID {
		return t, t.AgentName == "/root" && t.ParentThreadID == "" && t.SubagentKind == "" &&
			r.Header.Get("X-OpenAI-Subagent") == "" && r.Header.Get("X-Codex-Parent-Thread-Id") == ""
	}
	return t, validCodexAgentName(t.AgentName) && t.AgentName != "/root" &&
		isUUID(t.ParentThreadID) && t.ParentThreadID != t.ThreadID &&
		t.SubagentKind == "thread_spawn" && t.ThreadSource == "subagent" &&
		r.Header.Get("X-OpenAI-Subagent") == "collab_spawn" &&
		r.Header.Get("X-Codex-Parent-Thread-Id") == t.ParentThreadID
}

func validCodexAgentName(name string) bool {
	if len(name) > 1024 || !strings.HasPrefix(name, "/root") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] != "" || parts[1] != "root" {
		return false
	}
	for _, part := range parts[2:] {
		if part == "" || len(part) > 128 {
			return false
		}
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

var codexUserAgent = regexp.MustCompile(`^(codex_exec|codex_cli_rs|codex-tui)/([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?)$`)

// recogniseCodex recognizes Codex CLI Responses requests across semantic
// versions. The adapter is selected by the route and validated request shape;
// the reported version is retained for recording and diagnosis.
func recogniseCodex(r *http.Request) (Identification, bool, string) {
	if !isResponsesPath(r.URL.Path) || (r.Method != http.MethodPost && !isWebSocketUpgrade(r)) {
		return Identification{}, false, reasonUnknownPath
	}
	ua, _, _ := strings.Cut(r.UserAgent(), " ")
	match := codexUserAgent.FindStringSubmatch(ua)
	if match == nil {
		return Identification{}, false, "unsupported Codex client version"
	}
	t, ok := codexThread(r)
	if !ok {
		return Identification{}, false, "unsupported or inconsistent Codex thread metadata"
	}
	agent := mainAgentID
	if t.ThreadID != t.SessionID {
		agent = t.ThreadID
	}
	return Identification{Harness: "codex", Version: match[2], SessionID: t.SessionID, AgentID: agent}, true, ""
}
