// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	for _, api := range []bool{false, true} {
		t.Run(map[bool]string{false: "chatgpt-route", true: "api-route"}[api], func(t *testing.T) {
			installedCodexHTTPProbe(t, api)
		})
	}
}

func installedCodexHTTPProbe(t *testing.T, api bool) {
	t.Helper()
	basePath := "/backend-api/codex"
	if api {
		basePath = "/v1"
	}
	responsePath := basePath + "/responses"
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 16)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path + " upgrade=" + r.Header.Get("Upgrade")
		if r.Method == http.MethodGet && r.URL.Path == responsePath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != responsePath {
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
	args, err := CodexLaunchArgs(server.URL, hook, api)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	started := time.Now()
	var environment []string
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "HOME", "CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			continue
		}
		environment = append(environment, value)
	}
	environment = append(environment, "HOME="+home, "CODEX_HOME="+home, "OPENAI_API_KEY=synthetic-canary-no-provider-access")
	if isolationErr := checkCodexProbeRoute(ctx, binary, args, home, environment, server.URL+basePath); isolationErr != nil {
		t.Fatal(isolationErr)
	}
	args = append(args, "exec", "--ephemeral", "--skip-git-repo-check", "-s", "read-only", "Reply exactly gateway-probe; do not use tools.")
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = home, environment
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Codex configuration/transport probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "gateway-probe") {
		t.Fatal("probe did not complete")
	}
	var requests []string
	for len(seen) > 0 {
		requests = append(requests, <-seen)
	}
	if len(requests) == 0 {
		t.Fatal("no model request reached configured route")
	}
	for _, request := range requests {
		if strings.Contains(request, "GET "+responsePath+" upgrade=websocket") {
			t.Fatalf("supports_websockets=false still attempted WebSockets: %v", requests)
		}
	}
	if !slices.Contains(requests, "POST "+responsePath+" upgrade=") {
		t.Fatalf("HTTP Responses route was not used: %v", requests)
	}
	t.Logf("installed CLI HTTP-only turn completed in %s; requests: %v", time.Since(started), requests)
	// Hook execution/trust and real provider parity are separate gates.
}

// Check the resolved configuration before any model turn. System-managed
// settings can outrank per-invocation settings even with an empty CODEX_HOME.
func checkCodexProbeRoute(parent context.Context, binary string, args []string, home string, environment []string, expected string) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append(append([]string{}, args...), "app-server", "--stdio")...)
	command.Dir, command.Env = home, environment
	command.WaitDelay = 250 * time.Millisecond
	in, err := command.StdinPipe()
	if err != nil {
		return err
	}
	out, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	stopClosing := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stopClosing()
	defer func() {
		cancel()
		_ = out.Close()
		if waitErr := command.Wait(); waitErr != nil {
			return // cancellation deliberately terminates this read-only probe
		}
	}()
	encoder := json.NewEncoder(in)
	if err := encoder.Encode(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "innsegl-isolation-check", "version": "1"}}}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(io.LimitReader(out, 8<<20))
	scanner.Buffer(make([]byte, 4096), 8<<20)
	for scanner.Scan() {
		var message struct {
			ID     int             `json:"id"`
			Error  json.RawMessage `json:"error"`
			Result struct {
				Config struct {
					Provider  string `json:"model_provider"`
					Providers map[string]struct {
						BaseURL string `json:"base_url"`
					} `json:"model_providers"`
				} `json:"config"`
			} `json:"result"`
		}
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			return errors.New("installed Codex returned an invalid isolation check")
		}
		if len(message.Error) > 0 && string(message.Error) != "null" {
			return errors.New("installed Codex refused the isolation check")
		}
		if message.ID == 1 {
			if err := encoder.Encode(map[string]string{"method": "initialized"}); err != nil {
				return err
			}
			if err := encoder.Encode(map[string]any{"id": 2, "method": "config/read", "params": map[string]bool{"includeLayers": false}}); err != nil {
				return err
			}
		}
		if message.ID == 2 {
			config := message.Result.Config
			if config.Provider != "innsegl" || config.Providers["innsegl"].BaseURL != expected {
				return errors.New("installed Codex probe requires isolation: effective managed settings override its synthetic endpoint; no model turn was sent")
			}
			return nil
		}
	}
	return errors.New("installed Codex did not return its effective route; no model turn was sent")
}

func TestOAI020ProbeRejectsOverriddenEffectiveRoute(t *testing.T) {
	const expected = "http://127.0.0.1:28495/v1"
	for _, tc := range []struct {
		name, provider, base string
		wantError            bool
	}{
		{"isolated", "innsegl", expected, false},
		{"managed-route", "innsegl", "http://127.0.0.1:28195/backend-api/codex", true},
		{"other-provider", "openai", expected, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			result, err := json.Marshal(map[string]any{"id": 2, "result": map[string]any{"config": map[string]any{
				"model_provider": tc.provider, "model_providers": map[string]any{"innsegl": map[string]string{"base_url": tc.base}},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, "codex")
			script := "#!/bin/sh\nIFS= read -r initialize\nprintf '%s\\n' '{\"id\":1,\"result\":{}}'\nIFS= read -r initialized\nIFS= read -r configuration\nprintf '%s\\n' '" + string(result) + "'\n"
			if writeErr := os.WriteFile(binary, []byte(script), 0700); writeErr != nil {
				t.Fatal(writeErr)
			}
			err = checkCodexProbeRoute(t.Context(), binary, nil, dir, os.Environ(), expected)
			if (err != nil) != tc.wantError {
				t.Fatalf("effective route check: %v, want error=%v", err, tc.wantError)
			}
		})
	}
}
