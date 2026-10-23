// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

// recogniseCodex163 recognises the measured CLI root shape. Child threads
// deliberately remain unsupported until their independent association is
// established; an arbitrary header is not permission to guess their parent.
func recogniseCodex163(r *http.Request) (Identification, bool, string) {
	if r.Method != http.MethodPost || !isResponsesPath(r.URL.Path) {
		return Identification{}, false, reasonUnknownPath
	}
	session, thread := r.Header.Get("Session-Id"), r.Header.Get("Thread-Id")
	if !isUUID(session) || !isUUID(thread) || session != thread {
		return Identification{}, false, "unsupported Codex session/thread shape"
	}
	ua, _, _ := strings.Cut(r.UserAgent(), " ")
	if ua != "codex_exec/0.163.0" && ua != "codex_cli_rs/0.163.0" && ua != "codex-tui/0.163.0" {
		return Identification{}, false, "unsupported Codex client version"
	}
	if r.Header.Get("X-OpenAI-Subagent") != "" || r.Header.Get("X-Codex-Parent-Thread-Id") != "" {
		return Identification{}, false, "Codex subagent correlation is not supported by this build"
	}
	if metadata := r.Header.Get("X-Codex-Turn-Metadata"); metadata != "" {
		var m struct {
			Session string `json:"session_id"`
			Thread  string `json:"thread_id"`
			Agent   string `json:"agent_name"`
		}
		if json.Unmarshal([]byte(metadata), &m) != nil || m.Session != session || m.Thread != thread || m.Agent != "/root" {
			return Identification{}, false, "inconsistent Codex turn metadata"
		}
	}
	return Identification{Harness: "codex", Version: "0.163.0", SessionID: session, AgentID: mainAgentID}, true, ""
}
