// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// record_event, RM-024 (#32). Doc 07: MCP-003 (schema conformance), and the
// per-tool halves of MCP-006 (every reachable error class), MCP-009 (a retired
// run) and MCP-010 (an unknown run).
//
// WHAT IS REAL HERE AND WHAT IS NOT
//
// The ledger and the idempotency store are REAL, on a real Postgres, wherever
// the claim is about them: E4 is enforced by the ledger's CLOSED SCHEMA
// (doc 02 §1, RM-007), so "no payload reaches the ledger" is only proved
// against the schema that would have refused one. IP §6.6's replay guarantee
// rests on the ledger's UNIQUE idempotency_key (LED-008) and the store's
// leased claim (ADR-0017); an in-memory stand-in would assert both and prove
// neither.
//
// The run directory is a fake. Nothing implements it yet — register_agent
// (RM-022) writes `run_registered` and the directory that reads those back is
// RM-026's — and doc 07 classes these cases at layer C, where IP §2 admits
// mocks. A fake ledger appears only where the case is about a ledger FAILURE,
// which a healthy Postgres cannot be made to produce on demand.

const (
	// reToolName is an agent tool name: what IP §4's `event_type` argument
	// carries and what doc 02 §3 records as the `tool_call` event's
	// `tool_name`. See ADR-0021.
	reToolName = "bash"
	reRunID    = "run-rm-024"
	// rePayloadDigest is a well-formed doc 02 §1 digest: the POSITIVE CONTROL
	// every refusal case is paired against, so that "the body was rejected"
	// cannot pass because the call was failing for some unrelated reason.
	rePayloadDigest = "sha256:" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// reBody is a tool-call body: exactly the thing E4 keeps out of the ledger.
const reBody = `{"cmd":"rm -rf /","stdout":"deleted 4211 files\nfreed 8.1GB\n"}`

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

// reEnv is record_event wired onto a real ledger and a real idempotency store,
// with a fake run directory in front of them.
type reEnv struct {
	runs   *credRuns
	ledger *ledger.Store
	idem   *IdempotencyStore
}

// reSetup installs record_event for the test's duration. mutate, when
// non-nil, is the seam a test uses to swap a dependency out for a failing one.
func reSetup(t *testing.T, mutate func(*RecordEventConfig)) *reEnv {
	t.Helper()
	idem, dsn := newStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	env := &reEnv{runs: newCredRuns(credRun(reRunID)), ledger: lg, idem: idem}
	cfg := RecordEventConfig{Runs: env.runs, Ledger: env.ledger, Idempotency: env.idem}
	if mutate != nil {
		mutate(&cfg)
	}
	restore, err := ConfigureRecordEvent(cfg)
	if err != nil {
		t.Fatalf("ConfigureRecordEvent: %v", err)
	}
	t.Cleanup(restore)
	return env
}

// reServe binds record_event through the seam of ADR-0016 §5 and serves it
// over the real HTTP transport, so what a test calls is what an agent calls.
func reServe(t *testing.T) *sdk.ClientSession {
	t.Helper()
	withEmptyToolRegistry(t)
	RegisterTool(ToolRecordEvent, bindRecordEvent)
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

func reArgs(key string) map[string]any {
	return map[string]any{
		"run_id":          reRunID,
		"event_type":      reToolName,
		"payload_digest":  rePayloadDigest,
		"idempotency_key": key,
	}
}

func reCall(t *testing.T, session *sdk.ClientSession, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name: string(ToolRecordEvent), Arguments: args,
	})
	if err != nil {
		t.Fatalf("tools/call record_event: %v", err)
	}
	return res
}

// reCallOK decodes a successful reply into IP §4's documented result shape.
func reCallOK(t *testing.T, session *sdk.ClientSession, args map[string]any) recordEventOut {
	t.Helper()
	res := reCall(t, session, args)
	if res.IsError {
		t.Fatalf("record_event failed where it had to succeed: %#v", res.StructuredContent)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encoding structuredContent: %v", err)
	}
	var out recordEventOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding %s into IP §4's result shape: %v", raw, err)
	}
	return out
}

// reCallFail returns the IP §4 structured error a failing call produced, having
// checked that the error class is the one the case is about. Asserting the
// CLASS is the whole point: a refusal that happened for an unrelated reason
// would otherwise pass every "it was rejected" assertion in this file.
func reCallFail(t *testing.T, session *sdk.ClientSession, args map[string]any, want Class) map[string]any {
	t.Helper()
	res := reCall(t, session, args)
	if !res.IsError {
		t.Fatalf("record_event succeeded where it had to fail: %#v", res.StructuredContent)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want IP §4's error object: %+v",
			res.StructuredContent, res.Content)
	}
	if got := wire["error_class"]; got != string(want) {
		t.Fatalf("error_class is %v, want %s (message: %v)", got, want, wire["message"])
	}
	if got, want := wire["retryable"], want.Retryable(); got != want {
		t.Errorf("retryable is %v, want %v (ADR-0016)", got, want)
	}
	return wire
}

// reMessage reads IP §4's `message` off a structured error.
func reMessage(t *testing.T, wire map[string]any) string {
	t.Helper()
	msg, ok := wire["message"].(string)
	if !ok {
		t.Fatalf("the error object's message is %T, want a string (IP §4)", wire["message"])
	}
	return msg
}

// toolCalls returns every tool_call event in the chain, in position order.
func (e *reEnv) toolCalls(t *testing.T) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.ledger.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := e.ledger.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	var out []event.Fields
	for _, r := range records {
		if r[event.FieldEventType] == event.EventTypeToolCall {
			out = append(out, r)
		}
	}
	return out
}

func (e *reEnv) count(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.ledger.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// MCP-003 — schema conformance.
// ---------------------------------------------------------------------------

// TestMCP003RecordEventReturnsTheDocumentedShape. Doc 07 MCP-003: "valid input
// → documented result shape … Exact schema match", against IP §4's
// record_event(run_id, event_type, payload_digest, idempotency_key) →
// {event_id, chain_position}.
func TestMCP003RecordEventReturnsTheDocumentedShape(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	out := reCallOK(t, session, reArgs("rec-mcp-003"))

	if err := event.ValidateEventID(out.EventID); err != nil {
		t.Errorf("event_id %q: %v (doc 02 §1: a lowercase UUIDv7)", out.EventID, err)
	}
	if out.ChainPosition < 1 {
		t.Errorf("chain_position is %d; doc 02 §2 makes it 1-based", out.ChainPosition)
	}

	appended := env.toolCalls(t)
	if len(appended) != 1 {
		t.Fatalf("the ledger holds %d tool_call events, want exactly 1", len(appended))
	}
	rec := appended[0]
	if rec[event.FieldEventID] != out.EventID {
		t.Errorf("the reply names event_id %q, the ledger holds %v", out.EventID, rec[event.FieldEventID])
	}
	if rec[event.FieldChainPosition] != out.ChainPosition {
		t.Errorf("the reply names chain_position %d, the ledger holds %v",
			out.ChainPosition, rec[event.FieldChainPosition])
	}
	if rec[event.FieldToolName] != reToolName {
		t.Errorf("tool_name is %v, want %q (ADR-0021)", rec[event.FieldToolName], reToolName)
	}
	if rec[event.FieldPayloadDigest] != rePayloadDigest {
		t.Errorf("payload_digest is %v, want %q", rec[event.FieldPayloadDigest], rePayloadDigest)
	}
	if rec[event.FieldSource] != event.SourceMCP {
		t.Errorf("source is %v, want %q", rec[event.FieldSource], event.SourceMCP)
	}
	if rec[event.FieldSpiffeID] != credSPIFFEID(reRunID) {
		t.Errorf("spiffe_id is %v, want %q", rec[event.FieldSpiffeID], credSPIFFEID(reRunID))
	}
}

// TestMCP003RecordEventAdvertisesTheDocumentedSchemas holds the advertised
// tool surface to IP §4's argument list and result shape. It is the first line
// of E4's defence at the tool: a member IP §4 does not name is not advertised,
// so a client's own validation refuses `payload`, `body`, `diff` and `stdout`
// before a request is ever sent.
func TestMCP003RecordEventAdvertisesTheDocumentedSchemas(t *testing.T) {
	reSetup(t, nil)
	session := reServe(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var tool *sdk.Tool
	for _, candidate := range res.Tools {
		if candidate.Name == string(ToolRecordEvent) {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tools/list does not advertise record_event: %+v", res.Tools)
	}
	assertSchemaProperties(t, "inputSchema", tool.InputSchema,
		[]string{"run_id", "event_type", "payload_digest", "idempotency_key"})
	assertSchemaProperties(t, "outputSchema", tool.OutputSchema,
		[]string{"event_id", "chain_position"})
}

// ---------------------------------------------------------------------------
// E4 — the ledger stores references and hashes, never payloads.
// ---------------------------------------------------------------------------

// TestE4RecordEventRefusesABodyWhereADigestBelongs. IP E4 and doc 02 §1:
// payload_digest is `sha256:` + 64 lowercase hex and nothing else.
//
// Every case is paired with the POSITIVE CONTROL on the same run, in the same
// process, against the same ledger: a well-formed digest succeeds and is
// appended. Without it, every refusal below would also pass on a tool that
// refused everything.
func TestE4RecordEventRefusesABodyWhereADigestBelongs(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	bodies := map[string]string{
		"a json body":              reBody,
		"a diff":                   "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n",
		"plain text":               "deleted 4211 files",
		"a digest with no prefix":  strings.TrimPrefix(rePayloadDigest, "sha256:"),
		"an uppercase digest":      strings.ToUpper(rePayloadDigest),
		"a truncated digest":       rePayloadDigest[:40],
		"a digest with a body":     rePayloadDigest + " " + reBody,
		"another algorithm":        "sha512:" + strings.Repeat("a", 128),
		"four kilobytes of body":   strings.Repeat("x", 4096),
		"a digest-shaped sentence": "sha256:the quick brown fox jumped over thirteen lazy dogs and slept",
	}

	before := env.count(t)
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			args := reArgs("rec-e4-digest-" + strings.ReplaceAll(name, " ", "-"))
			args["payload_digest"] = body
			wire := reCallFail(t, session, args, ClassInvariantViolation)

			// The refusal must not quote the body back: an error message is a
			// second place a payload could come to rest.
			msg := reMessage(t, wire)
			if strings.Contains(msg, "stdout") || strings.Contains(msg, "freed 8.1GB") {
				t.Errorf("the refusal quotes the body back: %q", msg)
			}
		})
	}
	if after := env.count(t); after != before {
		t.Errorf("the ledger grew by %d events while every call was refused", after-before)
	}

	// POSITIVE CONTROL — the same run, the same session, a well-formed digest.
	out := reCallOK(t, session, reArgs("rec-e4-digest-control"))
	if out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
	if got := env.count(t); got != before+1 {
		t.Errorf("the ledger holds %d events, want %d: exactly the control appended", got, before+1)
	}
}

// TestE4RecordEventRefusesABodyWhereAToolNameBelongs. The `event_type`
// argument names the agent tool (ADR-0021) and is recorded as doc 02 §3's
// `tool_name`. A name is short and has no line breaks; a body is neither.
func TestE4RecordEventRefusesABodyWhereAToolNameBelongs(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	names := map[string]string{
		"empty":                    "",
		"a json body":              reBody,
		"a multi-line body":        "bash\nstdout: deleted 4211 files\n",
		"a tab-separated body":     "bash\tdeleted 4211 files",
		"a carriage return":        "bash\rdeleted",
		"a NUL byte":               "bash\x00deleted",
		"over the reference bound": strings.Repeat("t", event.MaxReferenceBytes+1),
		"four kilobytes":           strings.Repeat("x", 4096),
		"invalid utf-8":            "bash\xff\xfe",
	}

	before := env.count(t)
	for name, toolName := range names {
		t.Run(name, func(t *testing.T) {
			args := reArgs("rec-e4-name-" + strings.ReplaceAll(name, " ", "-"))
			args["event_type"] = toolName
			reCallFail(t, session, args, ClassInvariantViolation)
		})
	}
	if after := env.count(t); after != before {
		t.Errorf("the ledger grew by %d events while every call was refused", after-before)
	}

	// POSITIVE CONTROL.
	if out := reCallOK(t, session, reArgs("rec-e4-name-control")); out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
}

// TestE4TheRecordedEventCarriesNoPayloadAndNoUnknownMember is the assertion
// the issue asks for directly: the TOOL must not become a hole in RM-007's
// closed schema. Members that carry a body are sent alongside IP §4's four
// arguments, over the real transport, and the event that lands is held to the
// exact member set doc 02 §2 and §3 allow.
func TestE4TheRecordedEventCarriesNoPayloadAndNoUnknownMember(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	// POSITIVE CONTROL first: a clean call lands an event, so the member-set
	// assertions below run against something rather than against nothing.
	if out := reCallOK(t, session, reArgs("rec-e4-clean")); out.ChainPosition < 1 {
		t.Fatalf("the clean call did not append: %+v", out)
	}

	args := reArgs("rec-e4-smuggle")
	smuggled := map[string]any{
		"payload":     reBody,
		"body":        reBody,
		"diff":        "--- a/main.go\n+++ b/main.go\n",
		"stdout":      "deleted 4211 files",
		"tool_name":   "not-the-caller's-to-set",
		"source":      event.SourceSystem,
		"event_hash":  rePayloadDigest,
		"supersedes":  "0192f0a0-0000-7000-8000-000000000001",
		"spiffe_id":   "spiffe://evil.example/agent/a/b/c",
		"schema_vers": "2",
	}
	for k, v := range smuggled {
		args[k] = v
	}

	// The transport refuses the call outright: the input schema derived from
	// IP §4's four arguments is closed, so a member IP §4 does not name is
	// rejected before the tool is entered. Measured, not assumed —
	//
	//	validating "arguments": validating root: unexpected additional
	//	properties ["schema_vers" "supersedes" "payload" "source" "spiffe_id"
	//	"stdout" "tool_name" "body" "diff" "event_hash"]
	//
	// — and asserted here so that loosening the schema fails this test rather
	// than quietly opening a second way into the chain.
	res := reCall(t, session, args)
	if !res.IsError {
		t.Errorf("the tool accepted arguments IP §4 does not name: %#v", res.StructuredContent)
	}
	for _, c := range res.Content {
		if text, isText := c.(*sdk.TextContent); isText {
			if !strings.Contains(text.Text, "additional properties") {
				t.Errorf("the refusal does not name the extra arguments: %s", text.Text)
			}
			t.Logf("the transport refused the call outright: %s", text.Text)
		}
	}

	recorded := env.toolCalls(t)
	if len(recorded) == 0 {
		t.Fatalf("no tool_call reached the ledger; the assertions below would be vacuous")
	}
	for _, rec := range recorded {
		allowed, err := event.AllowedFields(event.EventTypeToolCall)
		if err != nil {
			t.Fatalf("event.AllowedFields: %v", err)
		}
		for name, value := range rec {
			if !slices.Contains(allowed, name) {
				t.Errorf("the recorded event carries %q = %v; doc 02 allows %v", name, value, allowed)
			}
		}
		if rec[event.FieldSource] != event.SourceMCP {
			t.Errorf("source is %v; the caller does not choose it", rec[event.FieldSource])
		}
		if rec[event.FieldToolName] != reToolName {
			t.Errorf("tool_name is %v; the caller sets it through event_type and nowhere else",
				rec[event.FieldToolName])
		}
		if rec[event.FieldSpiffeID] != credSPIFFEID(reRunID) {
			t.Errorf("spiffe_id is %v; the run directory decides it", rec[event.FieldSpiffeID])
		}
		canonical, err := rec.Preimage()
		if err != nil {
			t.Fatalf("Preimage: %v", err)
		}
		for _, fragment := range []string{"rm -rf", "stdout", "deleted 4211", "8.1GB", "main.go"} {
			if strings.Contains(string(canonical), fragment) {
				t.Errorf("the canonical event contains %q: %s", fragment, canonical)
			}
		}
	}
}

// TestRecordEventOmitsPayloadDigestWhenThereIsNoPayload. doc 02 §2:
// payload_digest is "Present iff a payload exists", and doc 02 §1 admits no
// empty-string placeholder for an absent member.
func TestRecordEventOmitsPayloadDigestWhenThereIsNoPayload(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	args := reArgs("rec-no-payload")
	args["payload_digest"] = ""
	if out := reCallOK(t, session, args); out.ChainPosition < 1 {
		t.Fatalf("a tool call with no body was refused: %+v", out)
	}

	recs := env.toolCalls(t)
	if len(recs) != 1 {
		t.Fatalf("the ledger holds %d tool_call events, want 1", len(recs))
	}
	if v, present := recs[0][event.FieldPayloadDigest]; present {
		t.Errorf("payload_digest is present as %#v; doc 02 §1 has no empty-string placeholder", v)
	}
}

// ---------------------------------------------------------------------------
// The event type the caller may record.
// ---------------------------------------------------------------------------

// TestRecordEventWritesToolCallAndTheCallerCannotForgeAnotherType. ADR-0021:
// record_event writes exactly one of doc 02 §3's eleven types, `tool_call`,
// and the caller does not select it. Passing an event_type spelling — the
// literal reading of IP §4 — is refused loudly rather than recorded as a tool
// named after an event type.
func TestRecordEventWritesToolCallAndTheCallerCannotForgeAnotherType(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	before := env.count(t)
	for _, eventType := range event.EventTypes() {
		t.Run(eventType, func(t *testing.T) {
			args := reArgs("rec-type-" + eventType)
			args["event_type"] = eventType
			wire := reCallFail(t, session, args, ClassInvariantViolation)
			msg := reMessage(t, wire)
			if !strings.Contains(msg, event.EventTypeToolCall) {
				t.Errorf("the refusal does not say what record_event writes: %q", msg)
			}
		})
	}
	if after := env.count(t); after != before {
		t.Errorf("the ledger grew by %d events; no caller-named event type is recordable", after-before)
	}

	// POSITIVE CONTROL — an agent tool name on the same run succeeds, and what
	// lands is a tool_call and nothing else.
	if out := reCallOK(t, session, reArgs("rec-type-control")); out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
	recs := env.toolCalls(t)
	if len(recs) != 1 {
		t.Fatalf("the ledger holds %d tool_call events, want 1", len(recs))
	}
	if got := env.count(t); got != before+1 {
		t.Errorf("the ledger holds %d events, want %d", got, before+1)
	}
}

// ---------------------------------------------------------------------------
// Fail closed: the run, and the ledger.
// ---------------------------------------------------------------------------

// TestMCP010RecordEventAgainstAnUnknownRun. Doc 07 MCP-010.
func TestMCP010RecordEventAgainstAnUnknownRun(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	args := reArgs("rec-unknown")
	args["run_id"] = "run-nobody"
	reCallFail(t, session, args, ClassRunNotFound)

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after a refusal for an unknown run", n)
	}
}

// TestRecordEventRefusesARunIDThatNamesNoRun. A run id outside doc 02 §5's
// grammar names no run, and is refused before any dependency is consulted.
func TestRecordEventRefusesARunIDThatNamesNoRun(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	for _, runID := range []string{"", "Run-42", "run 42", strings.Repeat("r", 64), "-run"} {
		args := reArgs("rec-badrun-" + runID)
		args["run_id"] = runID
		reCallFail(t, session, args, ClassRunNotFound)
	}
	if env.runs.calls != 0 {
		t.Errorf("the run directory was consulted %d times for ids that name no run", env.runs.calls)
	}
}

// TestMCP009RecordEventAgainstARetiredRun. Doc 07 MCP-009: "Any tool against
// retired run → RUN_ALREADY_RETIRED." I4: retirement removes the identity and
// never the record, so a retired run's history stays readable — it just stops
// growing.
func TestMCP009RecordEventAgainstARetiredRun(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	// A live run records first, so the refusal below is measured against a
	// tool that was working a moment earlier.
	if out := reCallOK(t, session, reArgs("rec-retired-before")); out.ChainPosition < 1 {
		t.Fatalf("the run would not record while live: %+v", out)
	}

	env.runs.retire(reRunID, time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC))
	reCallFail(t, session, reArgs("rec-retired-after"), ClassRunAlreadyRetired)

	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events, want the 1 from before retirement", n)
	}
}

// TestRecordEventFailsClosedWhenTheLedgerIsDown. IP §6.4: "Postgres down at
// any record_event → LEDGER_UNAVAILABLE", and I3 admits no action without a
// record, so there is nothing to hand back.
func TestRecordEventFailsClosedWhenTheLedgerIsDown(t *testing.T) {
	broken := &credLedger{}
	broken.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: fmt.Errorf("dial tcp 127.0.0.1:5432: connect: connection refused"),
	})
	reSetup(t, func(cfg *RecordEventConfig) { cfg.Ledger = broken })
	session := reServe(t)

	reCallFail(t, session, reArgs("rec-ledger-down"), ClassLedgerUnavailable)
}

// TestRecordEventReportsAnUnclassifiedLedgerFailure. IP §4's vocabulary is
// closed and has no "internal error": a failure the ledger did not name is a
// defect inside the MCP, which is alert-level (ADR-0016).
func TestRecordEventReportsAnUnclassifiedLedgerFailure(t *testing.T) {
	broken := &credLedger{}
	broken.fail(fmt.Errorf("something nothing classified"))
	reSetup(t, func(cfg *RecordEventConfig) { cfg.Ledger = broken })
	session := reServe(t)

	reCallFail(t, session, reArgs("rec-ledger-unclassified"), ClassInvariantViolation)
}

// TestRecordEventReportsAFailingRunDirectoryAsTheLedgerFailureItIs. The
// directory reads the chain, so its failures are the ledger's.
func TestRecordEventReportsAFailingRunDirectoryAsTheLedgerFailureItIs(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)
	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})

	reCallFail(t, session, reArgs("rec-directory-down"), ClassLedgerUnavailable)
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after a refusal", n)
	}
}

// TestRecordEventRefusesADirectoryThatAnswersForTheWrongRun. The directory's
// answer is checked, not trusted: an event attributed to another run's
// identity is an attribution this system exists to prevent (I2).
func TestRecordEventRefusesADirectoryThatAnswersForTheWrongRun(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)
	env.runs.putAs(reRunID, credRun("run-somebody-else"))

	reCallFail(t, session, reArgs("rec-wrong-run"), ClassInvariantViolation)
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after a refusal", n)
	}

	// POSITIVE CONTROL — the same tool, the same session, a directory that
	// answers for the run that was asked about.
	env.runs.putAs(reRunID, credRun(reRunID))
	if out := reCallOK(t, session, reArgs("rec-wrong-run-control")); out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
}

// TestRecordEventRefusesARunWithNoUsableIdentity. A run the directory cannot
// name a valid SPIFFE ID for cannot have an event attributed to it: doc 02 §2
// makes spiffe_id required on a tool_call.
func TestRecordEventRefusesARunWithNoUsableIdentity(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	broken := credRun(reRunID)
	broken.SPIFFEID = "not-a-spiffe-id"
	env.runs.putAs(reRunID, broken)
	reCallFail(t, session, reArgs("rec-bad-identity"), ClassInvariantViolation)

	elsewhere := credRun(reRunID)
	elsewhere.SPIFFEID = "spiffe://innsegl.dev/agent/demo/rm-023/run-somebody-else"
	env.runs.putAs(reRunID, elsewhere)
	reCallFail(t, session, reArgs("rec-other-identity"), ClassInvariantViolation)

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after two refusals", n)
	}

	// POSITIVE CONTROL — the run's own identity, restored.
	env.runs.putAs(reRunID, credRun(reRunID))
	if out := reCallOK(t, session, reArgs("rec-identity-control")); out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
}

// ---------------------------------------------------------------------------
// IP §6.6 — one key, one event, one reply.
// ---------------------------------------------------------------------------

// TestRecordEventSameKeyIsOneEventAndOneReply. IP §6.6: "replaying any request
// after a crash returns the original result, never a second identity, second
// event, or second commit." Two layers hold it: the store's recorded reply
// (ADR-0017) and the ledger's UNIQUE idempotency_key (LED-008).
func TestRecordEventSameKeyIsOneEventAndOneReply(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)
	const key = "rec-idem-1"

	first := reCallOK(t, session, reArgs(key))
	if n := len(env.toolCalls(t)); n != 1 {
		t.Fatalf("the first call appended %d tool_call events, want 1", n)
	}

	second := reCallOK(t, session, reArgs(key))
	if first != second {
		t.Errorf("the replay returned %+v, the original returned %+v", second, first)
	}
	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events after a replay, want 1", n)
	}
}

// TestRecordEventRefusesAKeyThatNamesADifferentRequest. ADR-0017 §3: the key
// has one job, dedupe, and answering a question the caller did not ask is
// worse than refusing.
func TestRecordEventRefusesAKeyThatNamesADifferentRequest(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)
	const key = "rec-idem-2"

	reCallOK(t, session, reArgs(key))

	other := reArgs(key)
	other["event_type"] = "grep"
	reCallFail(t, session, other, ClassDuplicateRequest)

	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events, want 1", n)
	}
}

// TestRecordEventRefusesAKeyItCannotRecord. The store owns doc 02 §2's bound
// on the key, and a key it accepted that the ledger later refused would be a
// recorded reply for an action with no record (I3).
func TestRecordEventRefusesAKeyItCannotRecord(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)

	for _, key := range []string{"", strings.Repeat("k", event.MaxIdempotencyKeyBytes+1)} {
		reCallFail(t, session, reArgs(key), ClassInvariantViolation)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after two refusals", n)
	}

	// POSITIVE CONTROL — a key of the same shape, inside the bound.
	if out := reCallOK(t, session, reArgs(strings.Repeat("k", event.MaxIdempotencyKeyBytes))); out.ChainPosition < 1 {
		t.Fatalf("the positive control did not append: %+v", out)
	}
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

// TestRecordEventIsNotServedUntilItIsConfigured. A bound tool with no
// dependencies behind it refuses rather than improvising: IP §4 has no
// "internal error" class, so a wiring defect is alert-level (ADR-0016).
func TestRecordEventIsNotServedUntilItIsConfigured(t *testing.T) {
	recordEventMu.Lock()
	saved := recordEventActive
	recordEventActive = nil
	recordEventMu.Unlock()
	t.Cleanup(func() {
		recordEventMu.Lock()
		recordEventActive = saved
		recordEventMu.Unlock()
	})

	session := reServe(t)
	reCallFail(t, session, reArgs("rec-unwired"), ClassInvariantViolation)
}

// TestConfigureRecordEventRefusesAnIncompleteConfiguration. Each dependency is
// a gate, and a missing gate is an open door rather than a degraded mode. An
// operator finds out at start-up, not when an agent does.
func TestConfigureRecordEventRefusesAnIncompleteConfiguration(t *testing.T) {
	idem, dsn := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	full := RecordEventConfig{Runs: newCredRuns(), Ledger: lg, Idempotency: idem}
	for name, mutate := range map[string]func(*RecordEventConfig){
		"no run directory":     func(c *RecordEventConfig) { c.Runs = nil },
		"no ledger":            func(c *RecordEventConfig) { c.Ledger = nil },
		"no idempotency store": func(c *RecordEventConfig) { c.Idempotency = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			restore, cerr := ConfigureRecordEvent(cfg)
			if cerr == nil {
				restore()
				t.Fatalf("ConfigureRecordEvent accepted a configuration with %s", name)
			}
			if got := mcpError(t, cerr).Class; got != ClassInvariantViolation {
				t.Errorf("class is %s, want %s", got, ClassInvariantViolation)
			}
		})
	}

	restore, err := ConfigureRecordEvent(full)
	if err != nil {
		t.Fatalf("ConfigureRecordEvent refused a complete configuration: %v", err)
	}
	restore()
}

// TestRecordEventRefusesALedgerRecordItCannotRead. The reply is read off the
// appended record, so a record missing the two members IP §4 promises is a
// defect the tool must not paper over with a zero value.
func TestRecordEventRefusesALedgerRecordItCannotRead(t *testing.T) {
	for name, mangle := range map[string]func(event.Fields){
		"no event_id":                  func(f event.Fields) { delete(f, event.FieldEventID) },
		"a malformed event_id":         func(f event.Fields) { f[event.FieldEventID] = "not-a-uuid" },
		"a non-string event_id":        func(f event.Fields) { f[event.FieldEventID] = int64(7) },
		"no chain_position":            func(f event.Fields) { delete(f, event.FieldChainPosition) },
		"a non-integer chain_position": func(f event.Fields) { f[event.FieldChainPosition] = "twelve" },
	} {
		t.Run(name, func(t *testing.T) {
			reSetup(t, func(cfg *RecordEventConfig) { cfg.Ledger = &reMangledLedger{mangle: mangle} })
			session := reServe(t)
			reCallFail(t, session, reArgs("rec-mangled"), ClassInvariantViolation)
		})
	}
}

// reMangledLedger appends nothing and returns a record with one member of the
// reply broken, so the tool's reading of its own append is exercised.
type reMangledLedger struct{ mangle func(event.Fields) }

func (l *reMangledLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	rec := body.Clone()
	rec[event.FieldEventID] = "0192f0a0-0000-7000-8000-000000000001"
	rec[event.FieldChainPosition] = int64(1)
	l.mangle(rec)
	return rec, nil
}

// TestRecordEventRefusesAStoredReplyItCannotRead. ADR-0017 returns the recorded
// reply byte for byte; a row that is not a record_event reply is a defect, not
// a result to decode leniently.
//
// The store is seeded under the SAME request fingerprint the tool computes —
// tool name and the three checked parameters — so the replay reaches the
// decode rather than being turned away as a different request.
func TestRecordEventRefusesAStoredReplyItCannotRead(t *testing.T) {
	env := reSetup(t, nil)
	session := reServe(t)
	const key = "rec-poisoned"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := env.idem.Do(ctx, Call{
		Tool: string(ToolRecordEvent), Key: key,
		Params: map[string]any{
			"run_id":         reRunID,
			"tool_name":      reToolName,
			"payload_digest": rePayloadDigest,
		},
	}, func(context.Context) (any, error) {
		// Canonicalizes cleanly, decodes into nothing IP §4 documents.
		return map[string]any{"event_id": int64(7), "chain_position": "twelve"}, nil
	}); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	reCallFail(t, session, reArgs(key), ClassInvariantViolation)

	// POSITIVE CONTROL — a key whose recorded reply IS a record_event result
	// replays cleanly through the same path.
	first := reCallOK(t, session, reArgs("rec-poisoned-control"))
	if second := reCallOK(t, session, reArgs("rec-poisoned-control")); first != second {
		t.Errorf("the replay returned %+v, the original returned %+v", second, first)
	}
}

// TestRecordEventErrorClassMatrix. Doc 07 MCP-006, this tool's row: every
// error class record_event can produce is produced, and its retryable flag is
// the one ADR-0016 fixes for the class.
func TestRecordEventErrorClassMatrix(t *testing.T) {
	want := []Class{
		ClassRunNotFound,
		ClassRunAlreadyRetired,
		ClassLedgerUnavailable,
		ClassDuplicateRequest,
		ClassInvariantViolation,
	}
	env := reSetup(t, nil)
	session := reServe(t)

	seen := map[Class]bool{}

	// RUN_NOT_FOUND — a run nothing knows.
	unknown := reArgs("rec-matrix-notfound")
	unknown["run_id"] = "run-nobody"
	reCallFail(t, session, unknown, ClassRunNotFound)
	seen[ClassRunNotFound] = true

	// INVARIANT_VIOLATION — a body where a digest belongs.
	body := reArgs("rec-matrix-invariant")
	body["payload_digest"] = reBody
	reCallFail(t, session, body, ClassInvariantViolation)
	seen[ClassInvariantViolation] = true

	// DUPLICATE_REQUEST — one key, two requests.
	reCallOK(t, session, reArgs("rec-matrix-dup"))
	dup := reArgs("rec-matrix-dup")
	dup["event_type"] = "grep"
	reCallFail(t, session, dup, ClassDuplicateRequest)
	seen[ClassDuplicateRequest] = true

	// RUN_ALREADY_RETIRED.
	env.runs.retire(reRunID, time.Now())
	reCallFail(t, session, reArgs("rec-matrix-retired"), ClassRunAlreadyRetired)
	seen[ClassRunAlreadyRetired] = true

	// LEDGER_UNAVAILABLE — the directory reads the chain and it is down.
	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	reCallFail(t, session, reArgs("rec-matrix-ledger"), ClassLedgerUnavailable)
	seen[ClassLedgerUnavailable] = true

	for _, c := range want {
		if !seen[c] {
			t.Errorf("%s is documented as reachable from record_event and was not produced", c)
		}
	}
}
