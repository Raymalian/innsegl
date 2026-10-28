// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"time"

	"github.com/pelletier/go-toml/v2"

	"innsegl.dev/innsegl/internal/client"
)

// loadCodexSettings asks the installed CLI to resolve its real configuration.
// No model call is made. Configuration can contain credentials: read it only
// in bounded memory, and never include its contents or stderr in diagnostics.
func loadCodexSettings(parent context.Context, cfg client.CodexManagedConfig) (resultErr error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "codex", "app-server")
	configureCodexProbe(cmd)
	cmd.WaitDelay = 250 * time.Millisecond
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting Codex configuration check: %w", err)
	}
	stopClosing := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	defer stopClosing()
	defer func() {
		cancel()
		waitErr := cmd.Wait()
		var exitErr *exec.ExitError
		if waitErr != nil && !errors.As(waitErr, &exitErr) && resultErr == nil {
			resultErr = fmt.Errorf("stopping Codex configuration check: %w", waitErr)
		}
	}()
	scan := bufio.NewScanner(io.LimitReader(stdout, 8<<20))
	scan.Buffer(make([]byte, 4096), 8<<20)
	send := func(method string, id int, params any) error {
		return json.NewEncoder(stdin).Encode(map[string]any{"method": method, "id": id, "params": params})
	}
	if err := send("initialize", 1, map[string]any{"clientInfo": map[string]string{"name": "innsegl", "version": "1"}}); err != nil {
		return err
	}
	for scan.Scan() {
		var message struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(scan.Bytes(), &message) != nil {
			return errors.New("the Codex configuration check returned invalid JSON")
		}
		if message.ID != 1 && message.ID != 2 {
			continue
		}
		if len(message.Error) > 0 && string(message.Error) != "null" {
			return errors.New("the installed Codex CLI refused its configuration check; inspect its configuration and managed policies")
		}
		if message.ID == 1 {
			if err := json.NewEncoder(stdin).Encode(map[string]string{"method": "initialized"}); err != nil {
				return err
			}
			if err := send("config/read", 2, map[string]bool{"includeLayers": false}); err != nil {
				return err
			}
			continue
		}
		return checkCodexEffectiveConfig(message.Result, cfg)
	}
	return errors.New("the installed Codex CLI did not return its effective configuration within the setup check; check that the installed CLI supports managed configuration and config/read")
}

func checkCodexEffectiveConfig(raw []byte, cfg client.CodexManagedConfig) error {
	var got struct {
		Config map[string]any `json:"config"`
	}
	if json.Unmarshal(raw, &got) != nil || got.Config == nil {
		return errors.New("the installed Codex CLI returned no effective configuration")
	}
	settings, err := client.CodexManagedTOML(cfg)
	if err != nil {
		return err
	}
	var want map[string]any
	if err = toml.Unmarshal(settings, &want); err != nil {
		return err
	}
	// Normalize TOML integer types to the JSON types config/read uses.
	normalized, err := json.Marshal(want)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(normalized, &want); err != nil {
		return err
	}
	if err := normalizeCodexHookSemantics(want); err != nil {
		return err
	}
	if err := normalizeCodexHookSemantics(got.Config); err != nil {
		return err
	}
	if !codexConfigContains(got.Config, want) {
		return errors.New("the installed Codex CLI did not load Innsegl's managed route, lifecycle and telemetry settings; inspect higher-priority managed policies and the installed CLI's supported settings")
	}
	return nil
}

func normalizeCodexHookSemantics(config map[string]any) error {
	hooks, ok := config["hooks"].(map[string]any)
	if !ok {
		return errors.New("configuration contains no Codex hook table")
	}
	for _, value := range hooks {
		groups, ok := value.([]any)
		if !ok {
			continue
		} // Other hook configuration keys are not event groups.
		for _, value := range groups {
			group, ok := value.(map[string]any)
			if !ok {
				return errors.New("invalid Codex hook group")
			}
			matcher := group["matcher"]
			if matcher == nil || matcher == "" || matcher == "*" {
				group["matcher"] = nil
			}
			handlers, ok := group["hooks"].([]any)
			if !ok {
				return errors.New("invalid Codex hook handlers")
			}
			for _, value := range handlers {
				handler, ok := value.(map[string]any)
				if !ok {
					return errors.New("invalid Codex hook handler")
				}
				if _, exists := handler["async"]; !exists {
					handler["async"] = false
				}
			}
		}
	}
	return nil
}

func codexConfigContains(got, want any) bool {
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range expected {
			if !codexConfigContains(actual[key], value) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := got.([]any)
		if !ok {
			return false
		}
		for _, value := range expected {
			found := false
			for _, candidate := range actual {
				found = found || codexConfigContains(candidate, value)
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(got, want)
	}
}
