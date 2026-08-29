// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/version"
)

// probeIn drives a bound tool to whichever outcome a case needs. It stands in
// for the five real tools (RM-022..025, RM-033), which do not exist yet: what
// is under test here is the transport and the error rendering they share, not
// any tool's own logic.
type probeIn struct {
	Class        string `json:"class,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	Unclassified bool   `json:"unclassified,omitempty"`
}

type probeOut struct {
	Tool string `json:"tool"`
}

func probeHandler(name ToolName) Handler[probeIn, probeOut] {
	return func(_ context.Context, _ *sdk.CallToolRequest, in probeIn) (probeOut, error) {
		switch {
		case in.Unclassified:
			return probeOut{}, errors.New("a failure nobody classified")
		case in.Class != "":
			return probeOut{}, Errorf(Class(in.Class), in.RunID, "probe failure for %s", in.Class)
		default:
			return probeOut{Tool: string(name)}, nil
		}
	}
}

// serveProbes binds a probe under every one of the five IP §4 tool names,
// through exactly the seam RM-022..025 will use, and serves the result over
// the HTTP transport.
func serveProbes(t *testing.T) (*Server, string) {
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
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv.URL
}

func connect(t *testing.T, url string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-contract-test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: url}, nil)
	if err != nil {
		t.Fatalf("connecting to %s: %v", url, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestServerRegistersUnderTheProtectedName. IP §1: "Innsegl MCP server (server
// name `innsegl`) — remote MCP server (HTTP transport)". The name is a
// protected surface (doc 08 §3, VERSIONING.md surface 5) and it is what a
// client reads off the initialize handshake.
func TestServerRegistersUnderTheProtectedName(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	init := session.InitializeResult()
	if init == nil {
		t.Fatalf("no initialize result")
	}
	if init.ServerInfo == nil {
		t.Fatalf("initialize result carries no serverInfo")
	}
	if init.ServerInfo.Name != "innsegl" {
		t.Errorf("serverInfo.name = %q, IP §1 says %q", init.ServerInfo.Name, "innsegl")
	}
	if init.ServerInfo.Version != "v0.0.0-test" {
		t.Errorf("serverInfo.version = %q, want the configured version", init.ServerInfo.Version)
	}
	if ServerName != "innsegl" {
		t.Errorf("ServerName = %q, IP §1 says %q", ServerName, "innsegl")
	}
}

// TestServerVersionDefaultsToTheBuildVersion.
func TestServerVersionDefaultsToTheBuildVersion(t *testing.T) {
	withEmptyToolRegistry(t)
	srv, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, want := srv.Version(), version.Version(); got != want {
		t.Errorf("Version() = %q, want the build version %q", got, want)
	}
	if got := srv.Name(); got != ServerName {
		t.Errorf("Name() = %q, want %q", got, ServerName)
	}
}

// TestToolsListAdvertisesTheBoundSurface.
func TestToolsListAdvertisesTheBoundSurface(t *testing.T) {
	srv, url := serveProbes(t)
	session := connect(t, url)
	res, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range ToolNames() {
		if !got[string(want)] {
			t.Errorf("tools/list does not advertise %q", want)
		}
		delete(got, string(want))
	}
	for extra := range got {
		t.Errorf("tools/list advertises %q, which is not one of the five IP §4 names", extra)
	}
	if want := ToolNames(); !equalToolNames(srv.BoundTools(), want) {
		t.Errorf("BoundTools() = %v, want %v", srv.BoundTools(), want)
	}
	if len(srv.MissingTools()) != 0 {
		t.Errorf("MissingTools() = %v, want none", srv.MissingTools())
	}
}

// TestMCP006EveryErrorClassIsReachableOverTheTransport is the matrix doc 07
// MCP-006 asks for: every one of the eleven IP §4 classes, produced by a bound
// tool, carried over the real HTTP transport, decoded by a real client, with
// the retryable flag IP §4 requires. Run against all five tool names, because
// the rendering is the transport's and must not vary by tool.
func TestMCP006EveryErrorClassIsReachableOverTheTransport(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)

	for _, tool := range ToolNames() {
		for _, row := range ip4Classes {
			for _, runID := range []string{"", "run-42"} {
				name := fmt.Sprintf("%s/%s/run=%q", tool, row.class, runID)
				t.Run(name, func(t *testing.T) {
					res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
						Name:      string(tool),
						Arguments: probeIn{Class: string(row.class), RunID: runID},
					})
					if err != nil {
						t.Fatalf("tools/call: %v", err)
					}
					if !res.IsError {
						t.Fatalf("isError = false; a classified failure must be a tool error")
					}
					wire, ok := res.StructuredContent.(map[string]any)
					if !ok {
						t.Fatalf("structuredContent is %T, want a JSON object carrying the IP §4 error", res.StructuredContent)
					}
					if got := wire["error_class"]; got != string(row.class) {
						t.Errorf("error_class = %v, want %q", got, row.class)
					}
					if got := wire["retryable"]; got != row.retryable {
						t.Errorf("retryable = %v, want %v — %s", got, row.retryable, row.why)
					}
					msg, isString := wire["message"].(string)
					if !isString {
						t.Fatalf("message is %T, want a string", wire["message"])
					}
					if !strings.Contains(msg, string(row.class)) {
						t.Errorf("message = %q, want it to describe the failure", msg)
					}
					gotRun, present := wire["run_id"]
					switch runID {
					case "":
						if present {
							t.Errorf("run_id present as %#v with no run; doc 02 §1 distinguishes absent from empty", gotRun)
						}
					default:
						if gotRun != runID {
							t.Errorf("run_id = %v, want %q", gotRun, runID)
						}
					}
					for k := range wire {
						switch k {
						case "error_class", "message", "retryable", "run_id":
						default:
							t.Errorf("wire error carries %q; IP §4 names four fields and no more", k)
						}
					}
				})
			}
		}
	}
}

// TestUnclassifiedToolFailureReachesTheClientAsInvariantViolation. A tool that
// returns a bare Go error must not escape the taxonomy.
func TestUnclassifiedToolFailureReachesTheClientAsInvariantViolation(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolRecordEvent),
		Arguments: probeIn{Unclassified: true},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !res.IsError {
		t.Fatalf("isError = false for an unclassified failure")
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T", res.StructuredContent)
	}
	if wire["error_class"] != "INVARIANT_VIOLATION" {
		t.Errorf("error_class = %v, want INVARIANT_VIOLATION", wire["error_class"])
	}
	if wire["retryable"] != false {
		t.Errorf("retryable = %v, want false", wire["retryable"])
	}
}

// TestSuccessReachesTheClientAsStructuredContent: the error path must not have
// broken the ordinary one.
func TestSuccessReachesTheClientAsStructuredContent(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	for _, tool := range ToolNames() {
		res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
			Name:      string(tool),
			Arguments: probeIn{},
		})
		if err != nil {
			t.Fatalf("tools/call %s: %v", tool, err)
		}
		if res.IsError {
			t.Fatalf("%s: isError = true on the success path: %+v", tool, res.Content)
		}
		out, ok := res.StructuredContent.(map[string]any)
		if !ok {
			t.Fatalf("%s: structuredContent is %T", tool, res.StructuredContent)
		}
		if out["tool"] != string(tool) {
			t.Errorf("%s: structuredContent = %v", tool, out)
		}
	}
}

// TestErrorResultCarriesTextContentForTheModel. MCP requires a tool error to
// be legible in Content, not only in structuredContent, or a model cannot see
// it and self-correct.
func TestErrorResultCarriesTextContentForTheModel(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolGetCredential),
		Arguments: probeIn{Class: string(ClassAudienceMismatch), RunID: "run-5"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("error result carries no content")
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want text", res.Content[0])
	}
	for _, want := range []string{"AUDIENCE_MISMATCH", "run-5"} {
		if !strings.Contains(text.Text, want) {
			t.Errorf("content text = %q, missing %q", text.Text, want)
		}
	}
}

// TestBindRefusesANameOutsideTheProtectedSurface. The tool surface is five
// names (IP §4); a sixth never reaches a client.
func TestBindRefusesANameOutsideTheProtectedSurface(t *testing.T) {
	withEmptyToolRegistry(t)
	srv, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := Bind(srv, &sdk.Tool{Name: "list_runs"}, probeHandler("list_runs")); err == nil {
		t.Errorf("Bind accepted the off-surface name list_runs")
	}
	if err := Bind(srv, &sdk.Tool{Name: string(ToolRecordEvent)}, probeHandler(ToolRecordEvent)); err != nil {
		t.Fatalf("Bind(record_event): %v", err)
	}
	if err := Bind(srv, &sdk.Tool{Name: string(ToolRecordEvent)}, probeHandler(ToolRecordEvent)); err == nil {
		t.Errorf("Bind accepted a second binding for record_event")
	}
}

// TestBindRefusesAnUnrepresentableResultType: a tool whose result has no JSON
// schema is a contract that cannot be published (MCP-001..005).
func TestBindRefusesAnUnrepresentableResultType(t *testing.T) {
	withEmptyToolRegistry(t)
	srv, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := func(context.Context, *sdk.CallToolRequest, probeIn) (chan int, error) { return nil, nil }
	if err := Bind(srv, &sdk.Tool{Name: string(ToolSignCommit)}, Handler[probeIn, chan int](h)); err == nil {
		t.Errorf("Bind accepted a result type with no JSON schema")
	}
}

// TestBindPublishesInputAndOutputSchemas — MCP-001..005 need a documented
// result shape per tool, and the seam derives both from the handler's types.
func TestBindPublishesInputAndOutputSchemas(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	res, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.InputSchema == nil {
			t.Errorf("%s has no input schema", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", tool.Name)
		}
	}
}

// TestBindKeepsAnExplicitResultSchema. A tool that publishes a hand-written
// contract keeps it; the seam derives a schema only where none was given.
func TestBindKeepsAnExplicitResultSchema(t *testing.T) {
	withEmptyToolRegistry(t)
	srv, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	explicit := &jsonschema.Schema{
		Type:        "object",
		Description: "hand-written contract",
		Properties:  map[string]*jsonschema.Schema{"tool": {Type: "string"}},
	}
	tool := &sdk.Tool{Name: string(ToolRetireAgent), OutputSchema: explicit}
	if err := Bind(srv, tool, probeHandler(ToolRetireAgent)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if tool.OutputSchema != any(explicit) {
		t.Errorf("Bind replaced the hand-written result schema with %#v", tool.OutputSchema)
	}
}

// TestServerAdvertisesToolsAndNoOtherSurface. IP §1 makes the MCP the only
// component holding SPIRE admin credentials, and E8 forbids it holding signing
// keys; the transport must therefore advertise no capability beyond the tools.
// A resource or prompt capability would be a second door to read state
// through. This does not prove the five tools are safe — it proves there is no
// second door beside them.
func TestServerAdvertisesToolsAndNoOtherSurface(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	caps := session.InitializeResult().Capabilities
	if caps == nil {
		t.Fatalf("initialize result declares no capabilities")
	}
	if caps.Tools == nil {
		t.Errorf("the server does not advertise a tools capability")
	}
	if caps.Resources != nil {
		t.Errorf("the server advertises a resources capability: %+v", caps.Resources)
	}
	if caps.Prompts != nil {
		t.Errorf("the server advertises a prompts capability: %+v", caps.Prompts)
	}
	if caps.Completions != nil {
		t.Errorf("the server advertises a completions capability: %+v", caps.Completions)
	}
	if len(caps.Experimental) != 0 {
		t.Errorf("the server advertises experimental capabilities: %+v", caps.Experimental)
	}
	if listed, err := session.ListResources(t.Context(), nil); err == nil && len(listed.Resources) != 0 {
		t.Errorf("resources/list returned %d resources", len(listed.Resources))
	}
}

// TestNewRejectsAnInvalidTrustedOrigin fails the server at construction rather
// than serving with cross-origin protection that silently did not apply.
func TestNewRejectsAnInvalidTrustedOrigin(t *testing.T) {
	withEmptyToolRegistry(t)
	if _, err := New(Config{TrustedOrigins: []string{"not an origin"}}); err == nil {
		t.Errorf("New accepted an unparseable trusted origin")
	}
	if _, err := New(Config{TrustedOrigins: []string{"https://mcp.innsegl.dev"}}); err != nil {
		t.Errorf("New rejected a valid trusted origin: %v", err)
	}
}

// TestHandlerRejectsACrossSiteBrowserPost. A remote MCP server reachable from
// a browser is a CSRF target; the transport must refuse a cross-site
// state-changing request rather than execute a tool for it.
func TestHandlerRejectsACrossSiteBrowserPost(t *testing.T) {
	_, url := serveProbes(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("cross-site POST returned 200; cross-origin protection is not applied")
	}
}

// TestRawTransportWireShape drives the HTTP transport with no client library
// at all and reads the bytes off the wire, so the IP §4 field names, their
// order and the absence of run_id are asserted as they are actually
// serialized rather than after a round trip through a decoder.
func TestRawTransportWireShape(t *testing.T) {
	_, url := serveProbes(t)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"v0"}}}`
	initResp, session := rawRPC(t, url, "", initBody)
	if !strings.Contains(string(initResp), `"name":"innsegl"`) {
		t.Errorf("initialize result does not name the server innsegl: %s", initResp)
	}
	if session == "" {
		t.Fatalf("no Mcp-Session-Id on the initialize response: %s", initResp)
	}
	rawRPC(t, url, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"record_event","arguments":{"class":"LEDGER_UNAVAILABLE"}}}`
	body, _ := rawRPC(t, url, session, call)
	const want = `"structuredContent":{"error_class":"LEDGER_UNAVAILABLE","message":"probe failure for LEDGER_UNAVAILABLE","retryable":true}`
	if !strings.Contains(string(body), want) {
		t.Errorf("tools/call body does not carry the IP §4 wire shape.\n got: %s\nwant substring: %s", body, want)
	}
	if strings.Contains(string(body), `"run_id"`) {
		t.Errorf("wire carries run_id with no run: %s", body)
	}

	call = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"retire_agent","arguments":{"class":"RUN_ALREADY_RETIRED","run_id":"run-77"}}}`
	body, _ = rawRPC(t, url, session, call)
	const wantRun = `"structuredContent":{"error_class":"RUN_ALREADY_RETIRED","message":"probe failure for RUN_ALREADY_RETIRED","retryable":false,"run_id":"run-77"}`
	if !strings.Contains(string(body), wantRun) {
		t.Errorf("tools/call body does not carry run_id in IP §4 order.\n got: %s\nwant substring: %s", body, wantRun)
	}
}

// rawRPC posts one JSON-RPC message over the streamable HTTP transport and
// returns the JSON payload of the response together with the session id.
func rawRPC(t *testing.T, url, session, body string) ([]byte, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting %s: %v", body, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		t.Fatalf("POST %s: status %d: %s", body, resp.StatusCode, raw)
	}
	return sseData(t, raw), resp.Header.Get("Mcp-Session-Id")
}

// sseData extracts the JSON payload from a text/event-stream frame, or returns
// the body unchanged when it is already JSON.
func sseData(t *testing.T, raw []byte) []byte {
	t.Helper()
	for line := range strings.SplitSeq(string(raw), "\n") {
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			return []byte(strings.TrimSpace(after))
		}
	}
	if json.Valid(raw) {
		return raw
	}
	return raw
}
