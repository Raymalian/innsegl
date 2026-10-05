// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ADR-0071: describe_workspace and observe_session are deprecated. Their names
// are a protected surface (VERSIONING.md surface 4), so they stay bound until
// the next major release, and every call is refused with the existing
// INVARIANT_VIOLATION class and a message naming the ADR. These tests pin the
// refusal over the real transport, against the shipped binders.

// serveShipped serves the shipped tool registry, unconfigured.
func serveShipped(t *testing.T) *sdk.ClientSession {
	t.Helper()
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

// assertDeprecatedRefusal calls tool with args and requires the ADR-0071
// refusal: a tool error, class INVARIANT_VIOLATION, not retryable, no run id,
// and a message that says the tool is deprecated and names the ADR.
func assertDeprecatedRefusal(t *testing.T, session *sdk.ClientSession, tool ToolName, args map[string]any) {
	t.Helper()
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: string(tool), Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s: %v", tool, err)
	}
	if !res.IsError {
		t.Fatalf("%s answered %v; a deprecated tool must refuse every call", tool, res.StructuredContent)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want the IP §4 error object", res.StructuredContent)
	}
	if got := wire["error_class"]; got != string(ClassInvariantViolation) {
		t.Errorf("error_class = %v, want %s", got, ClassInvariantViolation)
	}
	if got := wire["retryable"]; got != false {
		t.Errorf("retryable = %v; a retry can never succeed against a deprecated tool", got)
	}
	if _, present := wire["run_id"]; present {
		t.Errorf("run_id present; the refusal is about the tool, not a run")
	}
	msg, isString := wire["message"].(string)
	if !isString {
		t.Fatalf("message is %T, want a string", wire["message"])
	}
	for _, want := range []string{string(tool), "deprecated", "ADR-0071"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
}

func TestADR0071DescribeWorkspaceRefusesAsDeprecated(t *testing.T) {
	session := serveShipped(t)
	assertDeprecatedRefusal(t, session, ToolDescribeWorkspace, map[string]any{"cwd": "/srv/example"})
	assertDeprecatedRefusal(t, session, ToolDescribeWorkspace, map[string]any{"cwd": ""})
}

func TestADR0071ObserveSessionRefusesAsDeprecated(t *testing.T) {
	session := serveShipped(t)
	assertDeprecatedRefusal(t, session, ToolObserveSession, map[string]any{
		"session_id": "s-1", "phase": "start", "cwd": "/srv/example",
	})
	assertDeprecatedRefusal(t, session, ToolObserveSession, map[string]any{
		"session_id": "s-1", "phase": "stop",
	})
}

// The deprecation is announced in the tool descriptions as well as in
// CHANGELOG.md, as VERSIONING.md requires.
func TestADR0071DeprecatedToolsSayItInTheirDescriptions(t *testing.T) {
	session := serveShipped(t)
	list, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	seen := map[string]string{}
	for _, tool := range list.Tools {
		seen[tool.Name] = tool.Description
	}
	for _, name := range []ToolName{ToolDescribeWorkspace, ToolObserveSession} {
		desc, ok := seen[string(name)]
		if !ok {
			t.Errorf("%s is not advertised; the name stays bound until the next major", name)
			continue
		}
		if !strings.HasPrefix(desc, "Deprecated") || !strings.Contains(desc, "ADR-0071") {
			t.Errorf("%s description %q does not announce the deprecation", name, desc)
		}
	}
}

// observe_tool_call's session_id path registered a run through observe_session.
// With observe_session deprecated it meets the same refusal, before anything
// is written.
func TestADR0071ObserveToolCallSessionPathRefusesAsDeprecated(t *testing.T) {
	for _, in := range []observeToolCallIn{
		{SessionID: "s-1", CWD: "/srv/example"},
		{SessionID: "s-1", RunID: "run-1"},
	} {
		assertSessionPathRefused(t, observeNamedIdentity(in))
	}
}

func assertSessionPathRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a session_id call resolved a run; observe_session is deprecated")
	}
	var e *Error
	if !errors.As(err, &e) || e.Class != ClassInvariantViolation {
		t.Fatalf("err = %v, want %s", err, ClassInvariantViolation)
	}
	for _, want := range []string{"session_id", "deprecated", "ADR-0071"} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("message %q does not contain %q", e.Error(), want)
		}
	}
}

// MCP-064, kept after its session-path rows went: a call naming no run is
// refused as malformed, never answered RUN_NOT_FOUND about a run nobody named.
func TestObserveToolCallNamingNoRunIsRefused(t *testing.T) {
	err := observeNamedIdentity(observeToolCallIn{Tool: "Edit", Body: "{}"})
	var e *Error
	if !errors.As(err, &e) || e.Class != ClassInvariantViolation || !strings.Contains(e.Message, "run_id is required") {
		t.Fatalf("err = %v, want %s naming run_id", err, ClassInvariantViolation)
	}
}
