// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"
)

// withEmptyToolRegistry swaps the package's tool registry for an empty one for
// the duration of the test. The registry is populated by each tool file's
// init (RM-022..025, RM-033); a test that wants to bind a probe under a real
// tool name must not collide with whichever of those are compiled in.
func withEmptyToolRegistry(t *testing.T) {
	t.Helper()
	toolMu.Lock()
	saved := toolBinders
	toolBinders = make(map[ToolName]ToolBinder)
	toolMu.Unlock()
	t.Cleanup(func() {
		toolMu.Lock()
		toolBinders = saved
		toolMu.Unlock()
	})
}

// TestRegisterToolIsTheSeamFourAgentsShare: a tool file registers its own
// binder from its own init, touching no shared list.
func TestRegisterToolIsTheSeamFourAgentsShare(t *testing.T) {
	withEmptyToolRegistry(t)

	var order []ToolName
	// Deliberately registered out of IP §4 order, as four independent init
	// functions in four files would be.
	for _, n := range []ToolName{ToolRetireAgent, ToolRegisterAgent, ToolRecordEvent} {
		name := n
		RegisterTool(name, func(*Server) error {
			order = append(order, name)
			return nil
		})
	}

	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Binders run in IP §4 order regardless of registration order, so the
	// advertised surface does not depend on Go's file ordering.
	if want := []ToolName{ToolRegisterAgent, ToolRecordEvent, ToolRetireAgent}; !equalToolNames(order, want) {
		t.Errorf("binders ran in order %v, want IP §4 order %v", order, want)
	}
	// The three E11 ingestion tools have no binder in this test's empty
	// registry either, and MissingTools names every unbound tool on the
	// surface — that is its whole duty (ADR-0024).
	want2 := []ToolName{ToolGetCredential, ToolSignCommit,
		ToolDescribeWorkspace, ToolObserveToolCall, ToolObserveSession}
	if want := want2; !equalToolNames(srv.MissingTools(), want) {
		t.Errorf("MissingTools() = %v, want %v", srv.MissingTools(), want)
	}
}

// TestRegisterToolPanicsOnAnUnknownName keeps a ninth tool off the surface.
func TestRegisterToolPanicsOnAnUnknownName(t *testing.T) {
	withEmptyToolRegistry(t)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("RegisterTool with an off-surface name did not panic")
		}
	}()
	RegisterTool("list_runs", func(*Server) error { return nil })
}

// TestRegisterToolPanicsOnADuplicate is the collision detector: two agents
// claiming the same tool name fail loudly at init, not silently at run time.
func TestRegisterToolPanicsOnADuplicate(t *testing.T) {
	withEmptyToolRegistry(t)
	RegisterTool(ToolRecordEvent, func(*Server) error { return nil })
	defer func() {
		if recover() == nil {
			t.Fatalf("a second binder for record_event did not panic")
		}
	}()
	RegisterTool(ToolRecordEvent, func(*Server) error { return nil })
}

// TestRegisterToolPanicsOnANilBinder.
func TestRegisterToolPanicsOnANilBinder(t *testing.T) {
	withEmptyToolRegistry(t)
	defer func() {
		if recover() == nil {
			t.Fatalf("a nil binder did not panic")
		}
	}()
	RegisterTool(ToolSignCommit, nil)
}

// TestNewReportsABinderFailure rather than serving a half-built surface.
func TestNewReportsABinderFailure(t *testing.T) {
	withEmptyToolRegistry(t)
	RegisterTool(ToolGetCredential, func(*Server) error { return Errorf(ClassInvariantViolation, "", "binder refused") })
	if _, err := New(Config{}); err == nil {
		t.Fatalf("New succeeded with a failing binder")
	}
}

// TestEveryRegisteredBinderNamesASurfaceTool holds whatever the compiled-in
// tool files registered — this is the assertion that catches a sixth tool
// added by a future agent without going through ToolNames.
func TestEveryRegisteredBinderNamesASurfaceTool(t *testing.T) {
	toolMu.Lock()
	names := make([]ToolName, 0, len(toolBinders))
	for n := range toolBinders {
		names = append(names, n)
	}
	toolMu.Unlock()
	for _, n := range names {
		if !n.Valid() {
			t.Errorf("registry holds a binder for %q, which is not one of the five IP §4 tool names", string(n))
		}
	}
}

func equalToolNames(a, b []ToolName) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
