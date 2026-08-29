// SPDX-License-Identifier: Apache-2.0

// Package contract holds the MCP tool × error-class contract matrix: doc 07
// MCP-006 and MCP-010 (RM-028, #36).
//
// It has no production code and never will. The file you are reading exists so
// that `go build ./...` has something to build in this directory; everything
// else here is a _test.go file.
//
// # Why this is a package outside internal/mcp
//
// RM-020 already built the matrix's first half inside internal/mcp:
// TestMCP006EveryErrorClassIsReachableOverTheTransport binds a probe under
// each of the five IP §4 tool names, has it return Errorf(class, …), and
// asserts the wire shape that comes back — 5 tools × 11 classes × {run_id, no
// run_id}. What that proves is that every class is RENDERABLE over the
// transport by a tool bound to return it.
//
// It cannot prove the other half, because a probe is not a tool. The four
// shipped tools now exist (RM-022..025), and the question MCP-006 actually
// asks — "every documented error class REACHABLE per tool" — is whether a
// caller can drive the real register_agent, get_credential, record_event and
// retire_agent to each class. A class IP §4 lists for a tool that no input can
// make that tool produce is a documentation error, and it is worth more to
// name it than to manufacture a path to it.
//
// The tests live outside internal/mcp so that they can only reach the tools
// the way a caller does: over the HTTP transport, through mcp.New and the
// exported Configure* seams. Nothing here can call an unexported helper to
// shortcut a class into existence, which is exactly the property a
// reachability claim needs. Coverage is unaffected: scripts/coverage-floors.sh
// instruments with -coverpkg=./..., so what this package exercises counts
// towards internal/mcp's line floor.
package contract
