// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP-024 through MCP-027 (proposed for doc 07; doc 07 is not modified here).
//
// #170 (RM-105): the MCP has no caller authentication. Every one of the five
// tools is served on one listener, so anything that can open a socket to it
// may call `register_agent` — which means a model can mint identities for
// itself, with any agent_type and any task_id it likes, and the ledger records
// each one as a legitimate run. Doc 04's AB-13 and AB-15 name this; #171's
// harness-issued identity is worth nothing until it is closed, because the
// harness would issue one identity and the model could issue five beside it.
//
// # What the split is, and why it falls where it does
//
// #170 as filed proposed leaving the model only `sign_commit`. That is too
// aggressive for a first cut: it breaks every existing orchestrator before the
// hooks of #171 exist to replace them. The leak is narrower than the issue
// assumed.
//
// `register_agent` CREATES an identity. `retire_agent` DESTROYS one. Those two
// are the identity lifecycle, and they are what a caller must not reach.
//
// The other three take a `run_id` as an argument and can only act on a run
// that already exists. A caller holding a run_id it was given can use them;
// it cannot conjure a run to use them against. That is the property that makes
// the split safe to draw here rather than around `sign_commit` alone.
//
// # The distinction these tests exist to protect
//
// A tool that is deliberately not served here is NOT a missing tool.
//
// `MissingTools` means the registered surface is incomplete — a binder was
// never registered, so the server is advertising a contract it cannot fulfil,
// which `New` treats as a defect. A tool withheld by configuration is the
// opposite: a decision. Conflating them would make a correctly split server
// report itself broken through /readyz, and an operator would learn to ignore
// the field that says so. MCP-025 is the test that keeps them apart.

// The split under test is the package's own, not a copy: a test that restated
// the sets would keep passing after production changed one of them.
var (
	agentTools = AgentTools()
	adminTools = AdminTools()
)

// serveProbeSet is serveProbes with a chosen tool set. Every one of the five
// binders is registered, exactly as in production; only Config.Tools differs,
// so these tests measure the configuration and not a rigged registry.
func serveProbeSet(t *testing.T, tools []ToolName) (*Server, string) {
	t.Helper()
	withEmptyToolRegistry(t)
	for _, n := range ToolNames() {
		name := n
		RegisterTool(name, func(s *Server) error {
			return Bind(s, &sdk.Tool{
				Name:        string(name),
				Description: "probe for " + string(name),
			}, probeHandler(name))
		})
	}
	srv, err := New(Config{Version: "v0.0.0-test", Tools: tools})
	if err != nil {
		t.Fatalf("New(Tools=%v): %v", tools, err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv.URL
}

// advertised returns the tool names tools/list reports over the real transport.
func advertised(t *testing.T, url string) map[string]bool {
	t.Helper()
	res, err := connect(t, url).ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	return got
}

// TestMCP024AgentListenerDoesNotServeTheIdentityLifecycle is the headline
// property of #170: a caller reaching the agent listener cannot create an
// identity, whatever it asks for.
func TestMCP024AgentListenerDoesNotServeTheIdentityLifecycle(t *testing.T) {
	srv, url := serveProbeSet(t, agentTools)

	got := advertised(t, url)
	for _, want := range agentTools {
		if !got[string(want)] {
			t.Errorf("tools/list does not advertise %q, which the agent listener must serve", want)
		}
	}
	for _, forbidden := range adminTools {
		if got[string(forbidden)] {
			t.Errorf("the agent listener advertises %q; identity lifecycle belongs to the admin listener only (#170)", forbidden)
		}
	}
	if !equalToolNames(srv.BoundTools(), agentTools) {
		t.Errorf("BoundTools() = %v, want %v", srv.BoundTools(), agentTools)
	}
}

// TestMCP025AWithheldToolIsNotAMissingTool. A configured split is a decision;
// a missing binder is a defect. /readyz reports both, and a server that called
// its own deliberate configuration a defect would teach operators to ignore
// the field that reports real ones.
func TestMCP025AWithheldToolIsNotAMissingTool(t *testing.T) {
	srv, _ := serveProbeSet(t, agentTools)
	if len(srv.MissingTools()) != 0 {
		t.Errorf("MissingTools() = %v after a deliberate split; a withheld tool is a decision, not an incomplete surface",
			srv.MissingTools())
	}
}

// TestMCP026AdminListenerServesTheIdentityLifecycleAndNothingElse. The other
// half of the split, asserted in its own right: the admin listener is not
// "everything", it is the two tools the model may not have.
func TestMCP026AdminListenerServesTheIdentityLifecycleAndNothingElse(t *testing.T) {
	srv, url := serveProbeSet(t, adminTools)

	got := advertised(t, url)
	for _, want := range adminTools {
		if !got[string(want)] {
			t.Errorf("the admin listener does not advertise %q", want)
		}
	}
	for _, extra := range agentTools {
		if got[string(extra)] {
			t.Errorf("the admin listener advertises %q; it serves the identity lifecycle only", extra)
		}
	}
	if !equalToolNames(srv.BoundTools(), adminTools) {
		t.Errorf("BoundTools() = %v, want %v", srv.BoundTools(), adminTools)
	}
	if len(srv.MissingTools()) != 0 {
		t.Errorf("MissingTools() = %v, want none", srv.MissingTools())
	}
}

// TestMCP027AnUnsetToolSetStillServesAllFive is the anti-regression control.
// IP §2 fixes the surface at five names and doc 08 protects them; a
// configuration field that silently narrowed the default would remove tools
// from every deployment that did not opt in. The zero value serves everything,
// as it did before #170.
func TestMCP027AnUnsetToolSetStillServesAllFive(t *testing.T) {
	srv, url := serveProbeSet(t, nil)

	got := advertised(t, url)
	for _, want := range ToolNames() {
		if !got[string(want)] {
			t.Errorf("an unconfigured server does not advertise %q; the default must stay the full IP §4 surface", want)
		}
		delete(got, string(want))
	}
	for extra := range got {
		t.Errorf("tools/list advertises %q, which is not one of the five IP §4 names", extra)
	}
	if !equalToolNames(srv.BoundTools(), ToolNames()) {
		t.Errorf("BoundTools() = %v, want all five %v", srv.BoundTools(), ToolNames())
	}
}
