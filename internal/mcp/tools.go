// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"slices"
	"sync"
)

// ToolName is one of the five MCP tool names of IP §4.
//
// The names are a PROTECTED SURFACE (VERSIONING.md surface 4, doc 08 §3). The
// surface is closed: Bind refuses anything that is not one of these five, so a
// sixth tool cannot be advertised by adding a file.
type ToolName string

// The five tool names of IP §4.
const (
	// ToolRegisterAgent: register_agent(agent_type, task_id, idempotency_key)
	// → {spiffe_id, run_id, expires_at}. RM-022.
	ToolRegisterAgent ToolName = "register_agent"
	// ToolGetCredential: get_credential(run_id, audience) → {jwt_svid,
	// expires_at}. RM-023.
	//nolint:gosec // G101: this is a protected IP §4 tool name, not a credential.
	ToolGetCredential ToolName = "get_credential"
	// ToolRecordEvent: record_event(run_id, event_type, payload_digest,
	// idempotency_key) → {event_id, chain_position}. RM-024.
	ToolRecordEvent ToolName = "record_event"
	// ToolSignCommit: sign_commit(run_id, repo, staged_ref, message, task_ref,
	// idempotency_key) → {commit_sha, rekor_entry, trailers}. RM-033, E5.
	ToolSignCommit ToolName = "sign_commit"
	// ToolRetireAgent: retire_agent(run_id) → {retired_at}. RM-025.
	ToolRetireAgent ToolName = "retire_agent"
)

// toolOrder is the surface in IP §4 order. Binders run in this order, so the
// advertised surface does not depend on which file Go initialises first.
var toolOrder = []ToolName{
	ToolRegisterAgent,
	ToolGetCredential,
	ToolRecordEvent,
	ToolSignCommit,
	ToolRetireAgent,
}

// ToolNames returns the five tool names of IP §4, in IP §4 order.
func ToolNames() []ToolName { return slices.Clone(toolOrder) }

// Valid reports whether n is one of the five.
func (n ToolName) Valid() bool { return slices.Contains(toolOrder, n) }

// ToolBinder attaches one tool to a server, normally with a single call to
// Bind. It is the seam between this package's transport and the five tool
// implementations, which live in five separate files.
//
// A tool file owns exactly one file and registers itself from that file's
// init, so four agents can add four tools concurrently without any of them
// editing a shared list:
//
//	// internal/mcp/register_agent.go   (RM-022, #30)
//	func init() { RegisterTool(ToolRegisterAgent, bindRegisterAgent) }
//
//	func bindRegisterAgent(s *Server) error {
//	        return Bind(s, &sdk.Tool{
//	                Name:        string(ToolRegisterAgent),
//	                Description: "…",
//	        }, registerAgent)
//	}
//
//	func registerAgent(ctx context.Context, req *sdk.CallToolRequest, in registerAgentIn) (registerAgentOut, error)
//
// Two files claiming one tool name panic at init rather than one silently
// replacing the other.
type ToolBinder func(*Server) error

var (
	toolMu      sync.Mutex
	toolBinders = make(map[ToolName]ToolBinder)
)

// RegisterTool records the binder for name, to be run by New.
//
// It panics — at init, before any request is served — if name is not one of
// the five IP §4 tool names, if bind is nil, or if a binder for name is
// already registered. All three are programming errors in the tool surface
// itself, and a server that served a partial or doubled surface would be
// advertising a contract it does not implement.
func RegisterTool(name ToolName, bind ToolBinder) {
	if !name.Valid() {
		panic(fmt.Sprintf("mcp.RegisterTool: %q is not one of the five IP §4 tool names %v", string(name), toolOrder))
	}
	if bind == nil {
		panic(fmt.Sprintf("mcp.RegisterTool: nil binder for %s", name))
	}
	toolMu.Lock()
	defer toolMu.Unlock()
	if _, dup := toolBinders[name]; dup {
		panic(fmt.Sprintf("mcp.RegisterTool: %s is already registered; two files claim one tool name", name))
	}
	toolBinders[name] = bind
}

// lookupToolBinder returns the registered binder for name.
func lookupToolBinder(name ToolName) (ToolBinder, bool) {
	toolMu.Lock()
	defer toolMu.Unlock()
	bind, ok := toolBinders[name]
	return bind, ok
}
