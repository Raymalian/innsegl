// SPDX-License-Identifier: Apache-2.0

package commitpath

import (
	"encoding/json"
	"testing"
	"time"
)

// OAI-013/014/021: a direct structured call can authorize signing; an
// outer script, mismatched harness or expired/completed call cannot.
func TestOAI014DirectCodexCommitResolution(t *testing.T) {
	now := time.Now()
	base := RelayedCall{RunID: "run-direct", Harness: "codex", WireType: "function_call", Namespace: "functions", Tool: "functions.exec_command", Input: json.RawMessage(`{"cmd":"git commit -m change"}`), ObservedAt: now}
	cases := []struct {
		name, id, tool, input            string
		old, truncated, missing, foreign bool
		want                             bool
	}{
		{name: "direct", id: "call_direct", want: true},
		{name: "wrong harness", id: "call_foreign", foreign: true},
		{name: "foreign namespace", id: "call_foreign_namespace", tool: "mcp_tools.exec_command"},
		{name: "outer script", id: "call_outer", tool: "exec", input: `{"input":"await tools.exec_command({cmd:'git commit'})"}`},
		{name: "wrong argument", id: "call_wrong", input: `{"command":"git commit"}`},
		{name: "not a commit", id: "call_status", input: `{"cmd":"git status"}`},
		{name: "wrong id family", id: "toolu_direct"},
		{name: "malformed id", id: "call_x;echo"},
		{name: "expired", id: "call_old", old: true},
		{name: "truncated", id: "call_partial", truncated: true},
		{name: "completed or unknown", id: "call_missing", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			if tc.foreign {
				c.Harness = "claude-code"
			}
			if tc.tool != "" {
				c.Tool = tc.tool
			}
			if tc.input != "" {
				c.Input = json.RawMessage(tc.input)
			}
			if tc.old {
				c.ObservedAt = now.Add(-Window - time.Second)
			}
			c.Truncated = tc.truncated
			r := fakeResolver{}
			if !tc.missing {
				r[tc.id] = c
			}
			got, err := Resolve(r, tc.id, now)
			if (err == nil) != tc.want {
				t.Fatalf("Resolve = %+v, %v; want allowed=%v", got, err, tc.want)
			}
		})
	}
}
