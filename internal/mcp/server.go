// SPDX-License-Identifier: Apache-2.0

// Package mcp is the Innsegl MCP server: the remote HTTP transport, the seam
// the five tools bind themselves to, and the structured error every tool
// returns.
//
// IP §1 states what this component is:
//
//	Innsegl MCP server (server name `innsegl`) — remote MCP server (HTTP
//	transport), the only component holding SPIRE server admin credentials.
//	Tool surface: register_agent, get_credential, record_event, sign_commit,
//	retire_agent. Agents talk only to the MCP; they never see SPIRE admin
//	APIs.
//
// Two consequences shape this package. The admin credential never leaves the
// process, so the transport publishes no resource and no prompt surface — the
// five tools are the entire read and write surface, and there is no second
// door through which a credential could be fetched. And the MCP holds no
// signing keys (E8): the surface below carries tokens and metadata only.
//
// The server name, the five tool names and the eleven error classes are
// PROTECTED SURFACES (VERSIONING.md, doc 08 §3).
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/version"
)

// ServerName is the name this server registers under. IP §1: "The MCP server
// registers under the name `innsegl`". It is a protected string
// (VERSIONING.md surface 5) and a client reads it off the initialize
// handshake.
const ServerName = "innsegl"

// Config configures a server. The zero value is usable.
type Config struct {
	// Version is advertised in the initialize handshake. Empty means the
	// build version stamped into internal/version.
	Version string
	// Instructions is the optional MCP `instructions` string.
	Instructions string
	// Logger receives server and transport logging. Nil disables it.
	Logger *slog.Logger
	// TrustedOrigins are browser origins allowed to make state-changing
	// requests. Requests carrying no Origin and no Sec-Fetch-Site — which is
	// every non-browser MCP client — are unaffected.
	TrustedOrigins []string
	// SessionTimeout closes sessions idle for this long. Zero never closes
	// them.
	SessionTimeout time.Duration
	// Tools is the subset of the IP §4 surface this server serves. Nil or
	// empty serves all five, which is what every deployment before #170 did
	// and what any deployment that does not opt in keeps doing.
	//
	// It exists so one process can run two listeners with different reach
	// (#170, RM-105): the identity lifecycle — register_agent and
	// retire_agent, which CREATE and DESTROY identities — on a listener the
	// model's MCP client is never pointed at, and the remaining three, which
	// can only act on a run_id that already exists, on the one it is.
	//
	// This narrows WHO MAY CALL a tool. It does not change what the tools are:
	// the five names are IP §2's surface and doc 08 protects them, so a name
	// here that is not one of the five fails New rather than being ignored.
	//
	// A tool withheld through this field is NOT reported by MissingTools. That
	// field means the registered surface is incomplete, which is a defect; a
	// tool left out here is a decision. Conflating them would make a correctly
	// configured server report itself broken.
	Tools []ToolName
}

// Server is the innsegl MCP server. Build one with New and serve
// Server.Handler over HTTP.
type Server struct {
	sdk     *sdk.Server
	handler http.Handler
	version string
	bound   []ToolName
	missing []ToolName
}

// New builds the server and runs every registered tool binder, in IP §4 order.
//
// A binder that fails fails New: a server that advertised four of five tools,
// or advertised a tool it could not serve, would be publishing a contract it
// does not implement.
func New(cfg Config) (*Server, error) {
	advertised := cfg.Version
	if advertised == "" {
		advertised = version.Version()
	}

	s := &Server{version: advertised}
	s.sdk = sdk.NewServer(&sdk.Implementation{
		Name:    ServerName,
		Title:   "Innsegl",
		Version: advertised,
	}, &sdk.ServerOptions{
		Instructions: cfg.Instructions,
		Logger:       cfg.Logger,
	})

	serve, err := selectedTools(cfg.Tools)
	if err != nil {
		return nil, err
	}
	for _, name := range serve {
		bind, ok := lookupToolBinder(name)
		if !ok {
			s.missing = append(s.missing, name)
			continue
		}
		if err := bind(s); err != nil {
			return nil, fmt.Errorf("binding tool %s: %w", name, err)
		}
	}

	// Cross-origin protection. A remote MCP server reachable from a browser is
	// a CSRF and DNS-rebinding target; a state-changing cross-site POST must
	// be refused by the transport rather than executed and then explained.
	// Non-browser clients send neither Origin nor Sec-Fetch-Site and are
	// unaffected.
	crossOrigin := http.NewCrossOriginProtection()
	for _, origin := range cfg.TrustedOrigins {
		if err := crossOrigin.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("trusted origin %q: %w", origin, err)
		}
	}

	s.handler = crossOrigin.Handler(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return s.sdk },
		&sdk.StreamableHTTPOptions{
			Logger:         cfg.Logger,
			SessionTimeout: cfg.SessionTimeout,
		}))
	return s, nil
}

// selectedTools resolves Config.Tools to the surface a server serves, in IP §4
// order so that two listeners advertise their tools in the same order the
// single listener always did.
//
// Nil or empty means all five. An unknown name is an error rather than a
// silent omission: a typo in a deployment's tool list would otherwise remove a
// tool from the surface and look exactly like a deliberate split (#170).
func selectedTools(want []ToolName) ([]ToolName, error) {
	if len(want) == 0 {
		return ToolNames(), nil
	}
	chosen := make(map[ToolName]bool, len(want))
	for _, name := range want {
		if !name.Valid() {
			return nil, fmt.Errorf(
				"mcp.Config.Tools: %q is not one of the five IP §4 tool names %v", string(name), ToolNames())
		}
		chosen[name] = true
	}
	out := make([]ToolName, 0, len(chosen))
	for _, name := range ToolNames() {
		if chosen[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

// Name returns the protected server name.
func (s *Server) Name() string { return ServerName }

// Version returns the version advertised in the initialize handshake.
func (s *Server) Version() string { return s.version }

// BoundTools returns the tool names bound on this server, in IP §4 order.
func (s *Server) BoundTools() []ToolName { return slices.Clone(s.bound) }

// MissingTools returns the IP §4 tool names with no registered binder, in
// IP §4 order. It is not an error for the surface to be incomplete while the
// tools are still being built; it is an error to be silent about it, so
// readiness reporting (RM-026) names them.
func (s *Server) MissingTools() []ToolName { return slices.Clone(s.missing) }

// Handler returns the HTTP transport handler. The same handler is returned on
// every call: it owns the live sessions.
func (s *Server) Handler() http.Handler { return s.handler }

// Handler is one tool's implementation: typed arguments in, a typed result or
// a classified error out.
//
// A tool returns an ordinary Go error and never renders it. Bind runs every
// error through Classify, so the IP §4 wire shape is produced in one place for
// all five tools and cannot drift between them.
type Handler[In, Out any] func(ctx context.Context, req *sdk.CallToolRequest, in In) (Out, error)

// Bind attaches one tool to the server. It is what a ToolBinder calls.
//
// The input schema is derived from In and the result schema from Out, so the
// documented result shape MCP-001..005 assert is generated from the handler's
// own types rather than written twice.
//
// Bind refuses a name outside the five of IP §4, and refuses to bind one name
// twice: the tool surface is protected and closed.
func Bind[In, Out any](s *Server, tool *sdk.Tool, h Handler[In, Out]) error {
	name := ToolName(tool.Name)
	if !name.Valid() {
		return Errorf(ClassInvariantViolation, "",
			"tool %q is not one of the five IP §4 tool names %v", tool.Name, toolOrder)
	}
	if slices.Contains(s.bound, name) {
		return Errorf(ClassInvariantViolation, "", "tool %s is already bound", name)
	}
	if tool.OutputSchema == nil {
		schema, err := jsonschema.For[Out](nil)
		if err != nil {
			return Errorf(ClassInvariantViolation, "",
				"tool %s: no JSON schema for its result type: %w", name, err)
		}
		tool.OutputSchema = schema
	}

	// The wrapped handler is registered with an untyped result so that the
	// SDK does not overwrite an error result's structured content with a zero
	// success value: on the error path it returns a nil output, which the SDK
	// leaves alone.
	sdk.AddTool(s.sdk, tool,
		func(ctx context.Context, req *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
			out, err := h(ctx, req, in)
			if err != nil {
				return errorResult(Classify(err)), nil, nil
			}
			return nil, out, nil
		})

	s.bound = append(s.bound, name)
	return nil
}

// errorResult renders a classified error as an MCP tool error.
//
// The structured content is the IP §4 object and nothing else. The text
// content exists because MCP requires a tool error to be legible to the model
// as content — an error only a program can read is one the agent cannot
// self-correct from.
func errorResult(e *Error) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: e.Error()}},
		StructuredContent: e,
		IsError:           true,
	}
}
