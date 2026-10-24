// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
)

// Codex requires allow alongside updatedInput. This adapter adds that field
// only to an actual commit rewrite; the existing Claude hook is unchanged.
func runCodexPreToolUse(stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	base := getenv(commitpath.EnvCoreURL)
	if _, err := client.CodexLaunchArgs(base, "/innsegl", false); err != nil {
		fmt.Fprintln(stderr, "innsegl Codex hook:", err)
		return exitBlock
	}
	const maxInput = 1 << 20
	data, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil || len(data) > maxInput {
		return exitBlock
	}
	var event struct {
		ID        string `json:"tool_use_id"`
		SessionID string `json:"session_id"`
		AgentID   string `json:"agent_id"`
	}
	if json.Unmarshal(data, &event) != nil {
		return exitBlock
	}
	if !strings.HasPrefix(event.ID, "call_") || !commitpath.IsToolUseID(event.ID) {
		return exitOK
	}
	var out bytes.Buffer
	code := runHookPreToolUse(bytes.NewReader(data), &out, stderr)
	if code != exitOK || out.Len() == 0 {
		return code
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &v) != nil {
		return exitBlock
	}
	var h map[string]json.RawMessage
	if json.Unmarshal(v["hookSpecificOutput"], &h) != nil {
		return exitBlock
	}
	var input map[string]json.RawMessage
	if raw, ok := h["updatedInput"]; ok && json.Unmarshal(raw, &input) == nil {
		var command string
		if json.Unmarshal(input["command"], &command) != nil {
			return exitBlock
		}
		thread := event.AgentID
		if thread == "" {
			thread = event.SessionID
		}
		if !gateway.IsSessionID(event.SessionID) || !gateway.IsSessionID(thread) {
			fmt.Fprintln(stderr, "innsegl Codex hook: missing or invalid originating session/thread")
			return exitBlock
		}
		// Base is validated as loopback above; session/thread are UUIDs.
		prefix := "export INNSEGL_CORE_URL='" + strings.TrimSuffix(base, "/") + "' " + commitpath.EnvCodexSessionID + "='" + event.SessionID + "' " + commitpath.EnvCodexThreadID + "='" + thread + "'; "
		input["command"], err = json.Marshal(prefix + command)
		if err != nil {
			return exitBlock
		}
		h["updatedInput"], err = json.Marshal(input)
		if err != nil {
			return exitBlock
		}
		h["permissionDecision"] = json.RawMessage(`"allow"`)
		v["hookSpecificOutput"], err = json.Marshal(h)
		if err != nil {
			return exitBlock
		}
	}
	if err := json.NewEncoder(stdout).Encode(v); err != nil {
		return exitBlock
	}
	return code
}
