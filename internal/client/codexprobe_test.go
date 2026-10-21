// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
)

// OAI-020: opt-in local transport measurement against the installed CLI.
// The responder is synthetic, with a synthetic API key: no model provider,
// user auth file or deployed identity/signing service is involved.
func TestOAI020InstalledCodexHTTPProbe(t *testing.T) {
	if os.Getenv("INNSEGL_CODEX_PROBE") != "1" {
		t.Skip("set INNSEGL_CODEX_PROBE=1 for installed CLI transport probe")
	}
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 4)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" {
			http.NotFound(w, r)
			return
		}
		if _, copyErr := io.Copy(io.Discard, r.Body); copyErr != nil {
			t.Error(copyErr)
			return
		}
		if r.Header.Get("Session-Id") == "" || r.Header.Get("Thread-Id") != r.Header.Get("Session-Id") {
			t.Error("unrecognised root metadata")
		}
		seen <- r.UserAgent()
		w.Header().Set("Content-Type", "text/event-stream")
		response := map[string]any{"id": "resp_probe", "object": "response", "status": "completed", "output": []any{map[string]any{"id": "msg_probe", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "gateway-probe", "annotations": []any{}}}}}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
		for _, event := range []any{map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_probe", "status": "in_progress", "output": []any{}}}, map[string]any{"type": "response.completed", "response": response}} {
			data, marshalErr := json.Marshal(event)
			if marshalErr != nil {
				t.Error(marshalErr)
				return
			}
			if _, writeErr := w.Write(append(append([]byte("data: "), data...), []byte("\n\n")...)); writeErr != nil {
				t.Error(writeErr)
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer provider.Close()
	upstream, upstreamErr := gateway.NewUpstream(provider.URL, provider.Client())
	if upstreamErr != nil {
		t.Fatal(upstreamErr)
	}
	proxy := &gateway.Proxy{Upstream: upstream}
	server := httptest.NewServer(gateway.ResponsesRoutes(proxy, upstream, upstream))
	defer server.Close()
	home := t.TempDir()
	hook := filepath.Join(home, "hook")
	if err = os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	args, err := CodexLaunchArgs(server.URL, hook, true)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "exec", "--ephemeral", "--skip-git-repo-check", "-s", "read-only", "-m", "gpt-6.1-sol", "Reply exactly gateway-probe; do not use tools.")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = home
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			continue
		}
		cmd.Env = append(cmd.Env, value)
	}
	cmd.Env = append(cmd.Env, "CODEX_HOME="+home, "OPENAI_API_KEY=synthetic-canary-no-provider-access")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Codex configuration/transport probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "gateway-probe") {
		t.Fatal("probe did not complete")
	}
	select {
	case ua := <-seen:
		t.Logf("HTTP root request: %s", strings.Fields(ua)[0])
	default:
		t.Fatal("no model request reached configured route")
	}
	// Hook execution/trust and real provider parity are separate gates.
}
