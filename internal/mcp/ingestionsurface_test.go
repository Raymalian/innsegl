// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"slices"
	"strings"
	"testing"
)

// RM-131 (#210), E11. The three harness-neutral ingestion tools of doc 01 §4.
//
// The surface was closed at five names: Bind refused a sixth and ToolNames()
// was asserted at five. That is what made it impossible for a second harness
// to participate — not the idea, the registry. These tests open it to eight
// and prove it is still CLOSED at eight, which is the whole point: doc 08
// surface 4 protects the names, and a surface that merely stopped refusing
// would protect nothing.

// ingestionTools are the three names added by E11.
var ingestionTools = []ToolName{ToolDescribeWorkspace, ToolObserveToolCall, ToolObserveSession}

// MCP-055: the surface is exactly the eight names of doc 01 §4, in §4 order.
func TestMCP055ToolSurfaceIsExactlyTheEightNames(t *testing.T) {
	want := []string{
		"register_agent", "get_credential", "record_event", "sign_commit", "retire_agent",
		"describe_workspace", "observe_tool_call", "observe_session",
	}
	got := ToolNames()
	if len(got) != len(want) {
		t.Fatalf("ToolNames() has %d members, doc 01 §4 lists %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("ToolNames()[%d] = %q, doc 01 §4 says %q", i, got[i], want[i])
		}
		if !ToolName(want[i]).Valid() {
			t.Errorf("ToolName(%q).Valid() = false", want[i])
		}
	}
}

// MCP-056: the three ingestion tools are admin-side only.
//
// Same reasoning that moved record_event to the admin side in #171: these are
// driven by the harness observing the agent, never by the model reporting on
// itself. A model that could call observe_tool_call could write its own
// activity log, which is the gap doc 04 AB-14 names.
func TestMCP056IngestionToolsAreAdminOnly(t *testing.T) {
	admin, agent := AdminTools(), AgentTools()
	for _, n := range ingestionTools {
		if !slices.Contains(admin, n) {
			t.Errorf("AdminTools() does not contain %q; the harness drives it", n)
		}
		if slices.Contains(agent, n) {
			t.Errorf("AgentTools() contains %q; a model must not write its own activity log", n)
		}
	}
	if len(admin)+len(agent) != len(ToolNames()) {
		t.Errorf("caller split covers %d of %d tools", len(admin)+len(agent), len(ToolNames()))
	}
}

// MCP-057: the surface is opened, not unlocked. A ninth name is still refused.
func TestMCP057SurfaceStillRefusesAnUnknownName(t *testing.T) {
	for _, bad := range []ToolName{"", "list_runs", "describeWorkspace", "observe_tool_call "} {
		if bad.Valid() {
			t.Errorf("ToolName(%q).Valid() = true; it is not on the surface", string(bad))
		}
	}

	withEmptyToolRegistry(t)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("RegisterTool accepted a name outside the surface; the surface is unlocked, not opened")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("RegisterTool panicked with %T, want a string naming the tool", r)
		}
		if !strings.Contains(msg, "list_runs") {
			t.Errorf("panic %q does not name the offending tool", msg)
		}
	}()
	RegisterTool(ToolName("list_runs"), func(*Server) error { return nil })
}
