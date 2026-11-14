// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// OAI-020/025: installed-CLI config/read fixture, with unrelated
// defaults retained. Setup must prove effective routing and hooks, not just
// that it wrote a file. No exact CLI version is part of this contract.
func TestOAI025CodexEffectiveManagedSettings(t *testing.T) {
	b, err := os.ReadFile("testdata/codex-managed-config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28495", HookBin: "/qa/innsegl", API: true}
	if err := checkCodexEffectiveConfig(b, cfg); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"model_providers", "hooks", "features", "otel", "agents"} {
		var v map[string]map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		delete(v["config"], key)
		bad, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkCodexEffectiveConfig(bad, cfg); err == nil {
			t.Errorf("accepted missing %s", key)
		}
	}
	if err := checkCodexEffectiveConfig([]byte(`{"config":null}`), cfg); err == nil {
		t.Fatal("accepted absent configuration")
	}
	for _, modifier := range []string{"matcher", "async", "statusMessage"} {
		var value struct {
			Config map[string]json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(b, &value); err != nil {
			t.Fatal(err)
		}
		var hooks map[string][]struct {
			Matcher any              `json:"matcher"`
			Hooks   []map[string]any `json:"hooks"`
		}
		if err := json.Unmarshal(value.Config["hooks"], &hooks); err != nil {
			t.Fatal(err)
		}
		groups := hooks["SubagentStart"]
		switch modifier {
		case "matcher":
			groups[0].Matcher = "one-agent-only"
		case "async":
			groups[0].Hooks[0]["async"] = true
		case "statusMessage":
			groups[0].Hooks[0]["statusMessage"] = ""
		}
		hooks["SubagentStart"] = groups
		rawHooks, err := json.Marshal(hooks)
		if err != nil {
			t.Fatal(err)
		}
		value.Config["hooks"] = rawHooks
		changed, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkCodexEffectiveConfig(changed, cfg); err == nil {
			t.Errorf("accepted modified hook %s", modifier)
		}
	}
}

// OAI-019/025: checking the default provider alone misses explicitly resumed
// built-in threads. A missing or conflicting built-in route is not ready.
func TestOAI019CodexEffectiveBuiltinRoute(t *testing.T) {
	body, err := os.ReadFile("testdata/codex-managed-config.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"", "https://example.invalid/v1", "http://127.0.0.1:28495/v1"} {
		t.Run(route, func(t *testing.T) {
			var value struct {
				Config map[string]any `json:"config"`
			}
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatal(err)
			}
			delete(value.Config, "openai_base_url")
			if route != "" {
				value.Config["openai_base_url"] = route
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			cfg := client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28495", HookBin: "/qa/innsegl", API: true}
			err = checkCodexEffectiveConfig(raw, cfg)
			if ready := route == "http://127.0.0.1:28495/v1"; (err == nil) != ready {
				t.Fatalf("route %q: ready=%v, error=%v", route, ready, err)
			}
		})
	}
}

func TestOAI019CodexEffectiveProviderChoiceRemainsRouted(t *testing.T) {
	body, err := os.ReadFile("testdata/codex-managed-config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28495", HookBin: "/qa/innsegl", API: true}
	for _, provider := range []any{nil, "openai", "innsegl", "unrouted-provider"} {
		var value map[string]map[string]any
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatal(err)
		}
		value["config"]["model_provider"] = provider
		changed, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		got := checkCodexEffectiveConfig(changed, cfg)
		if (got == nil) != (provider != "unrouted-provider") {
			t.Fatalf("provider=%v effective configuration: %v", provider, got)
		}
	}
}

func TestOAI025CodexManagedProbeDeadlineIncludesDescendants(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	script := "#!/bin/sh\nread -r init\n('" + sleep + "' 4; printf held) &\nprintf ready > '" + marker + "'\nexit 0\n"
	if err = os.WriteFile(filepath.Join(dir, "codex"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- loadCodexSettings(ctx, client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28495", HookBin: "/qa/innsegl", API: true})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, statErr := os.Stat(marker); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("probe launcher did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	cancel()
	err = <-done
	if err == nil {
		t.Fatal("probe with no response succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("probe escaped its deadline through inherited pipes: %s", elapsed)
	}
}

// OAI-020/025: the setup check uses the CLI's configuration RPC, completes
// initialization first, and makes no model or account request.
func TestOAI025CodexManagedConfigurationProcess(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile("testdata/codex-managed-config.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err = json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(map[string]any{"id": 2, "result": value})
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nread -r init\nprintf '%s\\n' '{\"id\":1,\"result\":{}}'\nread -r ready\nread -r request\ncase \"$request\" in *config/read*) ;; *) exit 1;; esac\nprintf '%s\\n' '" + strings.ReplaceAll(string(response), "'", "'\\''") + "'\nwhile read -r line; do :; done\n"
	if err = os.WriteFile(filepath.Join(dir, "codex"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	cfg := client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28495", HookBin: "/qa/innsegl", API: true}
	if err := loadCodexSettings(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.LocalURL = "http://127.0.0.1:28496"
	if err := loadCodexSettings(context.Background(), cfg); err == nil {
		t.Fatal("accepted different effective endpoint")
	}
}
