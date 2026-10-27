// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestOAI024ModelDiscoveryUsesTheAuthModeRouteWithoutRecording(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/v1/models", want: "api"},
		{path: "/backend-api/codex/models", want: "chatgpt"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			seen := make(chan string, 1)
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Errorf("read provider request: %v", readErr)
					return
				}
				seen <- r.Method + " " + r.URL.Path + " " + r.Header.Get("Authorization") + " " + string(body)
				w.Header().Set("Content-Type", "application/json")
				if _, writeErr := io.WriteString(w, `{"data":[{"id":"model-a"}]}`); writeErr != nil {
					t.Errorf("write provider response: %v", writeErr)
				}
			}))
			defer provider.Close()
			api, err := NewUpstream(provider.URL, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			chatgpt, err := NewUpstream(provider.URL, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			base := &Proxy{Guards: []Guard{}, ToolUse: ToolUseObserverFunc(func(ToolUse) { calls++ })}
			front := httptest.NewServer(ResponsesRoutes(base, api, chatgpt))
			defer front.Close()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer synthetic-local-test")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, copyErr := io.Copy(io.Discard, resp.Body); copyErr != nil {
				t.Errorf("read model catalog response: %v", copyErr)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d", resp.StatusCode)
			}
			got := <-seen
			wantPath := "/v1/models"
			if tc.want == "chatgpt" {
				wantPath = "/backend-api/codex/models"
			}
			if got != "GET "+wantPath+" Bearer synthetic-local-test " {
				t.Fatalf("provider request=%q", got)
			}
			if calls != 0 {
				t.Fatalf("model discovery invoked tool observer %d times", calls)
			}
			if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				t.Fatal("model catalog response was not passed through")
			}
		})
	}
}

func TestOAI022ResponsesWebSocketRouteRelaysAndObservesUpstreamEvents(t *testing.T) {
	srv, provider, tlsConfig := startEchoWSUpstream(t)
	provider.onConnect = func(w io.Writer) {
		payload := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_route12345678","name":"exec_command","arguments":"{\"cmd\":\"pwd\"}"}}`)
		if err := writeTestWSFrame(w, wsOpcodeText, payload, false); err != nil {
			t.Errorf("write provider event: %v", err)
		}
	}
	upstream, err := NewUpstream(srv.URL, &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []ToolUse
	messages := &wsMessageCapture{}
	base := &Proxy{ToolUse: CombineToolUseObservers(ToolUseObserverFunc(func(call ToolUse) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call)
	}), messages)}
	front := httptest.NewServer(ResponsesRoutes(base, upstream, upstream))
	defer front.Close()
	client, resp := dialWSHarnessClient(t, front.URL+"/v1/responses", map[string]string{
		"Authorization":         "Bearer synthetic-ws-key",
		"User-Agent":            "codex_exec/0.163.0",
		"Session-Id":            "00000000-0000-4000-8000-000000000001",
		"Thread-Id":             "00000000-0000-4000-8000-000000000001",
		"X-Codex-Turn-Metadata": `{"session_id":"00000000-0000-4000-8000-000000000001","thread_id":"00000000-0000-4000-8000-000000000001","agent_name":"/root"}`,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d, want WebSocket upgrade", resp.StatusCode)
	}
	got, err := client.recvWithTimeout(t, 2e9)
	if err != nil || !strings.Contains(string(got.payload), "call_route12345678") {
		t.Fatalf("provider event was not relayed: frame=%q err=%v", got.payload, err)
	}
	clientMessage := []byte(`{"type":"response.create","response":{"input":[{"type":"function_call_output","call_id":"call_route12345678","output":"/workspace"}]}}`)
	client.send(t, wsOpcodeText, clientMessage)
	echoedMessage, messageErr := client.recvWithTimeout(t, 2e9)
	if messageErr != nil || string(echoedMessage.payload) != string(clientMessage) {
		t.Fatalf("client response.create message was not relayed: frame=%q err=%v", echoedMessage.payload, messageErr)
	}
	observedMessages := messages.snapshot()
	if len(observedMessages) != 1 || observedMessages[0] != string(clientMessage) {
		t.Fatalf("client tool-result observations=%q", observedMessages)
	}
	client.send(t, wsOpcodeClose, nil)
	if closeFrame, closeErr := client.recvWithTimeout(t, 2e9); closeErr != nil || closeFrame.opcode != wsOpcodeClose {
		t.Fatalf("close relay: frame=%+v err=%v", closeFrame, closeErr)
	}
	mu.Lock()
	if len(calls) != 1 || calls[0].ID != "call_route12345678" || string(calls[0].Input) != `{"cmd":"pwd"}` {
		mu.Unlock()
		t.Fatalf("observed calls=%+v", calls)
	}
	mu.Unlock()
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.path != "/v1/responses" || provider.auth != "Bearer synthetic-ws-key" {
		t.Fatalf("provider saw path=%q auth=%q", provider.path, provider.auth)
	}
}

func TestOAI006ResponsesCapabilitiesAdvertiseLinkedThreads(t *testing.T) {
	recorder := httptest.NewRecorder()
	ResponsesCapabilities(recorder, httptest.NewRequestWithContext(context.Background(), "GET", "/_gateway/capabilities", nil))
	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	var agents string
	if err := json.Unmarshal(capabilities["agents"], &agents); err != nil {
		t.Fatal(err)
	}
	if agents != "linked-threads" {
		t.Fatalf("agents capability=%q, want linked-threads", agents)
	}
	if _, pinned := capabilities["codex_versions"]; pinned {
		t.Fatal("capabilities response still pins Codex to an exact CLI version")
	}
}
