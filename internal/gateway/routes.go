// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ResponsesRoutes shares the gateway's guards/recorders and chooses an
// upstream solely from exact configured routes. Model discovery is relayed
// without a run; it never reaches conversation observers.
func ResponsesRoutes(base *Proxy, api, chatgpt *Upstream) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var up *Upstream
		model := false
		switch r.URL.Path {
		case "/v1/responses":
			up = api
		case "/backend-api/codex/responses":
			up = chatgpt
		case "/v1/models":
			up = api
			model = true
		case "/backend-api/codex/models":
			up = chatgpt
			model = true
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/responses/") || strings.HasPrefix(r.URL.Path, "/backend-api/codex/") {
				writeGatewayError(w, http.StatusNotFound, "innsegl gateway: unsupported model route")
				return
			}
			base.ServeHTTP(w, r)
			return
		}
		method := http.MethodPost
		if model {
			method = http.MethodGet
		}
		websocket := !model && isWebSocketUpgrade(r)
		if r.Method != method && !websocket {
			allow := method
			if !model {
				allow += ", GET (WebSocket upgrade)"
			}
			w.Header().Set("Allow", allow)
			writeGatewayError(w, http.StatusMethodNotAllowed, "innsegl gateway: unsupported method for this Responses route")
			return
		}
		if up == nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "innsegl gateway: Responses capture is not configured")
			return
		}
		// Never follow a provider redirect while carrying live credentials.
		client := *up.Client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		selected := *up
		selected.Client = &client
		proxy := *base
		proxy.Upstream = &selected
		proxy.ResponsesWebSocket = websocket
		if model {
			proxy.Guards = []Guard{}
			proxy.ToolUse = nil
			proxy.ReplyText = nil
			proxy.SubagentEnds = nil
		}
		proxy.ServeHTTP(w, r)
	})
}

// ResponsesCapabilities advertises only implemented transports and scope.
func ResponsesCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"formats": []string{"responses-http", "responses-websocket"}, "agents": "linked-threads", "signing": true, "signing_mode": "structured"}); err != nil {
		return
	}
}
