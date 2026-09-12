// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// observe_tool_call, RM-127 (#206), E11. Doc 07 MCP-044 … MCP-049.
//
// WHAT IS REAL HERE AND WHAT IS NOT
//
// The ledger, the idempotency store and the body volume are REAL: a real
// Postgres for the first two, a real directory on a real filesystem for the
// third. That is deliberate for each of them.
//
//   - "exactly one tool_call" (MCP-044) and "no second event" (MCP-045) rest
//     on the ledger's UNIQUE idempotency_key (LED-008) and the store's leased
//     claim (ADR-0017). An in-memory stand-in would assert both and prove
//     neither.
//   - "the body is on the operator's volume" (MCP-044, MCP-046) is a claim
//     about a file. It is checked by opening the file, at the path the
//     reference shim's layout puts it — the same path internal/api/runlog.go
//     and internal/reconciler/writes.go already read.
//   - "the volume is unwritable" (MCP-049) is a real filesystem refusal, not a
//     stubbed error: the run directory's parent is a regular file, so MkdirAll
//     cannot succeed whatever the uid.
//
// The run directory is a fake, as it is for record_event: doc 07 classes these
// cases at layer C, where IP §2 admits mocks, and what they are about is this
// tool's own decision procedure.

const (
	otcRunID = "run-rm-127"
	// otcTool is what the harness observed being invoked. It becomes doc 02
	// §3's `tool_name`, exactly as record_event's `event_type` argument does.
	otcTool = "Edit"
	// otcSecret keys the per-run token. Any string: the property under test is
	// that a caller cannot derive the token from the public run id.
	otcSecret = "deployment-secret-for-rm-127"
)

// otcBody is a tool-call body of the kind the reference shim forwards: a file
// write, carrying the file's contents and its path. It is the thing doc 05
// says never leaves the operator's machine, so every assertion about "the body
// did not leak" searches for these bytes specifically.
const otcBody = `{"tool_name":"Edit","tool_input":{"file_path":"/w/secrets.go",` +
	`"old_string":"apiKey := \"\"","new_string":"apiKey := \"sk-live-41d9\""},` +
	`"tool_response":{"success":true}}`

// otcSecretBytes is the substring of otcBody that must never appear anywhere
// but the volume. A search for the whole body would pass on a leak that
// re-encoded it; this is a string no encoding changes.
const otcSecretBytes = "sk-live-41d9"

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

// otcEnv is observe_tool_call wired onto a real ledger, a real idempotency
// store and a real body volume, with a fake run directory in front of them.
type otcEnv struct {
	runs    *credRuns
	ledger  *otcSpyLedger
	store   *ledger.Store
	idem    *IdempotencyStore
	bodyDir string
}

// otcSetup installs observe_tool_call for the test's duration. mutate, when
// non-nil, is the seam a test uses to swap a dependency out for a failing one.
func otcSetup(t *testing.T, mutate func(*ObserveToolCallConfig)) *otcEnv {
	t.Helper()
	idem, dsn := newStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	env := &otcEnv{
		runs:    newCredRuns(credRun(otcRunID)),
		ledger:  &otcSpyLedger{inner: lg},
		store:   lg,
		idem:    idem,
		bodyDir: t.TempDir(),
	}
	cfg := ObserveToolCallConfig{
		Runs: env.runs, Ledger: env.ledger, Idempotency: env.idem, BodyDir: env.bodyDir,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	restore, err := ConfigureObserveToolCall(cfg)
	if err != nil {
		t.Fatalf("ConfigureObserveToolCall: %v", err)
	}
	t.Cleanup(restore)
	return env
}

// otcSpyLedger is the ledger, plus a record of everything that was handed to
// it. It is how MCP-046 asks "what left this process?" of the one dependency
// this tool can send anything to.
type otcSpyLedger struct {
	mu       sync.Mutex
	inner    ObserveToolCallLedger
	appended []event.Fields
	err      error
}

func (l *otcSpyLedger) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	l.appended = append(l.appended, body.Clone())
	failure := l.err
	l.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	return l.inner.Append(ctx, body)
}

func (l *otcSpyLedger) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

// sent returns everything this tool asked the ledger to write.
func (l *otcSpyLedger) sent(t *testing.T) []byte {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, f := range l.appended {
		canonical, err := event.Canonicalize(map[string]any(f))
		if err != nil {
			// Not every mangled fixture canonicalizes; the raw rendering is
			// still a superset of the bytes that would have gone out.
			fmt.Fprintf(&b, "%v", f)
			continue
		}
		b.Write(canonical)
	}
	return []byte(b.String())
}

// otcServe binds observe_tool_call through the seam of ADR-0016 §5 and serves
// it over the real HTTP transport, so what a test calls is what a shim calls.
func otcServe(t *testing.T) *sdk.ClientSession {
	t.Helper()
	withEmptyToolRegistry(t)
	RegisterTool(ToolObserveToolCall, bindObserveToolCall)
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

func otcArgs() map[string]any {
	return map[string]any{"run_id": otcRunID, "tool": otcTool, "body": otcBody}
}

func otcCall(t *testing.T, session *sdk.ClientSession, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name: string(ToolObserveToolCall), Arguments: args,
	})
	if err != nil {
		t.Fatalf("tools/call observe_tool_call: %v", err)
	}
	return res
}

// otcCallOK decodes a successful reply into IP §4's documented result shape.
func otcCallOK(t *testing.T, session *sdk.ClientSession, args map[string]any) observeToolCallOut {
	t.Helper()
	res := otcCall(t, session, args)
	if res.IsError {
		t.Fatalf("observe_tool_call failed where it had to succeed: %#v", res.StructuredContent)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encoding structuredContent: %v", err)
	}
	var out observeToolCallOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding %s into IP §4's result shape: %v", raw, err)
	}
	return out
}

// otcCallFail returns the IP §4 structured error a failing call produced,
// having checked the class. Asserting the CLASS is the point: a refusal that
// happened for an unrelated reason would pass every "it was rejected" check.
func otcCallFail(t *testing.T, session *sdk.ClientSession, args map[string]any, want Class) map[string]any {
	t.Helper()
	res := otcCall(t, session, args)
	if !res.IsError {
		t.Fatalf("observe_tool_call succeeded where it had to fail: %#v", res.StructuredContent)
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

// toolCalls returns every tool_call event in the chain, in position order.
func (e *otcEnv) toolCalls(t *testing.T) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.store.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := e.store.Events(ctx, 1, n)
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

func (e *otcEnv) count(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.store.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	return n
}

// bodyPath is the layout the reference shim wrote and the two readers already
// read: one directory per run, one file per digest, the digest's hex as the
// file name. Written here as a literal join rather than by calling the
// production helper, so a change to that helper fails this test instead of
// moving the goalposts with it.
func (e *otcEnv) bodyPath(runID, digest string) string {
	return filepath.Join(e.bodyDir, runID, strings.TrimPrefix(digest, event.HashPrefix)+".json")
}

// storedFiles lists every file under the body volume, as relative paths.
func (e *otcEnv) storedFiles(t *testing.T) []string {
	t.Helper()
	var found []string
	err := filepath.Walk(e.bodyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(e.bodyDir, path)
		if rerr != nil {
			return rerr
		}
		found = append(found, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the body volume: %v", err)
	}
	return found
}

// ---------------------------------------------------------------------------
// MCP-044 — a body is stored and exactly one tool_call is appended.
// ---------------------------------------------------------------------------

// TestMCP044ObserveToolCallStoresABodyAndAppendsOneToolCall. Doc 07 MCP-044:
// "Digest returned; body written under the MCP volume; exactly one event."
func TestMCP044ObserveToolCallStoresABodyAndAppendsOneToolCall(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	out := otcCallOK(t, session, otcArgs())

	// The digest is doc 02 §1's hash form over the body's own bytes — the same
	// construction `shasum -a 256` gave the shim, so a body digested by either
	// lands at the same path and verifies against the same chain entry.
	want := event.Digest([]byte(otcBody))
	if out.Digest != want {
		t.Errorf("digest is %q, want %q (sha256 over the body's bytes)", out.Digest, want)
	}
	if err := event.ValidateDigest(out.Digest); err != nil {
		t.Errorf("digest %q: %v", out.Digest, err)
	}
	if !out.Stored {
		t.Error("stored is false on a call that succeeded; a reply is only produced once the body is on the volume")
	}

	// The body is on the volume, byte for byte, at the ported path.
	raw, err := os.ReadFile(env.bodyPath(otcRunID, want))
	if err != nil {
		t.Fatalf("reading the stored body: %v (files: %v)", err, env.storedFiles(t))
	}
	if string(raw) != otcBody {
		t.Errorf("the stored body is %q, want the bytes that were sent", raw)
	}
	// And nothing else is: a temporary file left behind would be a second copy
	// of a body on the operator's disk that nothing ever deletes.
	if files := env.storedFiles(t); len(files) != 1 {
		t.Errorf("the volume holds %v, want exactly one file", files)
	}

	// Exactly one tool_call, carrying the digest and the tool name and nothing
	// that could hold a body (doc 02 §3, IP E4).
	appended := env.toolCalls(t)
	if len(appended) != 1 {
		t.Fatalf("the ledger holds %d tool_call events, want exactly 1", len(appended))
	}
	rec := appended[0]
	if rec[event.FieldPayloadDigest] != want {
		t.Errorf("payload_digest is %v, want %q", rec[event.FieldPayloadDigest], want)
	}
	if rec[event.FieldToolName] != otcTool {
		t.Errorf("tool_name is %v, want %q", rec[event.FieldToolName], otcTool)
	}
	if rec[event.FieldRunID] != otcRunID {
		t.Errorf("run_id is %v, want %q", rec[event.FieldRunID], otcRunID)
	}
	if rec[event.FieldSpiffeID] != credSPIFFEID(otcRunID) {
		t.Errorf("spiffe_id is %v, want %q", rec[event.FieldSpiffeID], credSPIFFEID(otcRunID))
	}
	if rec[event.FieldSource] != event.SourceMCP {
		t.Errorf("source is %v, want %q", rec[event.FieldSource], event.SourceMCP)
	}
	// ADR-0004 requires the key on a tool_call appended by an MCP tool. This
	// tool takes none from its caller, so it derives one; absent, a replay
	// could append a second event.
	if key, ok := rec[event.FieldIdempotencyKey].(string); !ok || key == "" {
		t.Errorf("idempotency_key is %v, want the derived key (ADR-0004)", rec[event.FieldIdempotencyKey])
	}
}

// TestObserveToolCallAdvertisesTheDocumentedSchemas holds the advertised
// surface to doc 01 §4's argument list and result shape. It is E4's first line
// of defence at the tool: a member doc 01 §4 does not name is not advertised.
func TestObserveToolCallAdvertisesTheDocumentedSchemas(t *testing.T) {
	otcSetup(t, nil)
	session := otcServe(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var tool *sdk.Tool
	for _, candidate := range res.Tools {
		if candidate.Name == string(ToolObserveToolCall) {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tools/list does not advertise observe_tool_call: %+v", res.Tools)
	}
	assertSchemaProperties(t, "inputSchema", tool.InputSchema,
		[]string{"run_id", "tool", "body", "run_token"})
	assertSchemaProperties(t, "outputSchema", tool.OutputSchema,
		[]string{"digest", "stored"})
}

// ---------------------------------------------------------------------------
// MCP-045 — a replay is one observation, not two.
// ---------------------------------------------------------------------------

// TestMCP045AReplayReturnsTheStoredResultAndAppendsNothing. Doc 07 MCP-045 and
// doc 01 §4: "Idempotent on (run_id, digest): a replay returns the stored
// result and appends nothing." A second event would be a second claim about
// one observed call.
func TestMCP045AReplayReturnsTheStoredResultAndAppendsNothing(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	first := otcCallOK(t, session, otcArgs())
	if n := len(env.toolCalls(t)); n != 1 {
		t.Fatalf("the first call appended %d tool_call events, want 1", n)
	}

	second := otcCallOK(t, session, otcArgs())
	if first != second {
		t.Errorf("the replay returned %+v, the original returned %+v", second, first)
	}
	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events after a replay, want 1", n)
	}
	if files := env.storedFiles(t); len(files) != 1 {
		t.Errorf("the volume holds %v after a replay, want one file", files)
	}

	// A DIFFERENT body under the same run is a different observation, and gets
	// its own digest, its own file and its own event.
	other := otcArgs()
	other["body"] = `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
	third := otcCallOK(t, session, other)
	if third.Digest == first.Digest {
		t.Fatalf("two different bodies produced one digest %q", third.Digest)
	}
	if n := len(env.toolCalls(t)); n != 2 {
		t.Errorf("the ledger holds %d tool_call events, want 2", n)
	}
}

// TestObserveToolCallRefusesAKeyThatNamesADifferentRequest. The derived key
// names (run_id, digest); the store fingerprints the whole request. Two
// observations that agree on the key and disagree on what was observed are
// refused rather than answered — returning the first one's reply would attest
// a tool the caller never named.
func TestObserveToolCallRefusesAKeyThatNamesADifferentRequest(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	otcCallOK(t, session, otcArgs())

	other := otcArgs()
	other["tool"] = "Bash"
	otcCallFail(t, session, other, ClassDuplicateRequest)

	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// MCP-046 — the body never leaves the machine.
// ---------------------------------------------------------------------------

// TestMCP046TheBodyNeverLeavesTheMachine. Doc 07 MCP-046: "Body bytes absent
// from every outbound request; assertion on the stored path." Doc 05 is
// explicit that tool-call bodies stay on the operator's machine; the MCP is a
// local container, so it may WRITE one to a volume the operator controls and
// may send it nowhere.
//
// Every place this process could put bytes is checked: what it handed the
// ledger, what the idempotency store recorded, and the reply itself.
func TestMCP046TheBodyNeverLeavesTheMachine(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	res := otcCall(t, session, otcArgs())
	if res.IsError {
		t.Fatalf("observe_tool_call failed: %#v", res.StructuredContent)
	}

	// 1. The ledger is the one dependency this tool sends anything to.
	if sent := env.ledger.sent(t); strings.Contains(string(sent), otcSecretBytes) {
		t.Errorf("the body reached the ledger: %s", sent)
	}
	// The digest did, which is what makes the stored body checkable later.
	digest := event.Digest([]byte(otcBody))
	if sent := env.ledger.sent(t); !strings.Contains(string(sent), digest) {
		t.Errorf("the ledger was not given the digest %q: %s", digest, sent)
	}

	// 2. The idempotency store records a reply and a request FINGERPRINT. A
	// body in either would be a second copy in a second database.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, found, err := env.idem.Lookup(ctx, observeIdempotencyKey(otcRunID, digest))
	if err != nil || !found {
		t.Fatalf("the call recorded no idempotency row (found=%v): %v", found, err)
	}
	if strings.Contains(string(rec.Response), otcSecretBytes) {
		t.Errorf("the body is in the recorded reply: %s", rec.Response)
	}
	if strings.Contains(rec.RequestDigest, otcSecretBytes) {
		t.Errorf("the body is in the request digest: %s", rec.RequestDigest)
	}

	// 3. The reply the caller gets back carries a digest and a boolean.
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encoding structuredContent: %v", err)
	}
	if strings.Contains(string(raw), otcSecretBytes) {
		t.Errorf("the body is in the reply: %s", raw)
	}
	for _, c := range res.Content {
		text, ok := c.(*sdk.TextContent)
		if ok && strings.Contains(text.Text, otcSecretBytes) {
			t.Errorf("the body is in the reply's text content: %s", text.Text)
		}
	}

	// 4. And it IS on the volume — otherwise every assertion above passes on a
	// tool that dropped the body on the floor.
	stored, err := os.ReadFile(env.bodyPath(otcRunID, digest))
	if err != nil {
		t.Fatalf("reading the stored body: %v", err)
	}
	if string(stored) != otcBody {
		t.Errorf("the stored body is %q, want the bytes that were sent", stored)
	}
}

// TestMCP046TheToolHasNoOutboundPathAtAll is the other half of the same claim,
// made against the SOURCE rather than one execution: this file may not import
// anything that can open a connection. A test that only watches one call can
// be satisfied by a leak on a path that call did not take; this cannot.
func TestMCP046TheToolHasNoOutboundPathAtAll(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "observe.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing observe.go: %v", err)
	}
	// Anything that could carry bytes off the machine. The ledger reaches
	// Postgres, but through an interface this file is HANDED — it never dials
	// anything itself, which is why no database driver is on the list either.
	outbound := []string{"net", "net/http", "net/url", "os/exec", "google.golang.org/grpc"}
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		for _, bad := range outbound {
			if path == bad || strings.HasPrefix(path, bad+"/") {
				t.Errorf("observe.go imports %q; a body must have no outbound path (doc 05)", path)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// MCP-047 — the run token, and the refusal that is not an oracle.
// ---------------------------------------------------------------------------

// TestMCP047ABadRunTokenIsAnsweredExactlyLikeAnUnknownRun. Doc 07 MCP-047:
// "Refused before any lookup, answered identically to an unknown run."
//
// A run_id is public — it is in the Agent-Run trailer of every commit — so a
// refusal that distinguished "wrong token" from "no such run" would tell an
// unauthenticated caller which run ids are real. This is get_credential's rule
// and get_credential's implementation of it, unchanged.
func TestMCP047ABadRunTokenIsAnsweredExactlyLikeAnUnknownRun(t *testing.T) {
	env := otcSetup(t, func(cfg *ObserveToolCallConfig) { cfg.RunTokenSecret = otcSecret })
	session := otcServe(t)

	absent := otcArgs()

	wrong := otcArgs()
	wrong["run_token"] = RunToken(otcSecret, "run-somebody-else")

	// A well-formed token for a run the directory has never heard of. The
	// answer must be the same as the two above, and the run id is the same in
	// all three so the messages are comparable at all.
	unknown := otcArgs()
	unknown["run_id"] = otcRunID
	unknown["run_token"] = "0" + strings.Repeat("f", 63)

	messages := map[string]string{}
	for name, args := range map[string]map[string]any{
		"no token":    absent,
		"wrong token": wrong,
		"bad token":   unknown,
	} {
		messages[name] = reMessage(t, otcCallFail(t, session, args, ClassRunNotFound))
	}
	// One refusal, character for character. A caller learns the same thing
	// from all three, which is nothing it did not already know.
	for name, msg := range messages {
		if msg != messages["no token"] {
			t.Errorf("the refusals differ and are therefore an oracle:\n  no token: %q\n  %s: %q",
				messages["no token"], name, msg)
		}
	}

	// Refused BEFORE any lookup: the run directory was never asked, so nothing
	// about which runs exist was consulted, let alone reported.
	env.runs.mu.Lock()
	calls := env.runs.calls
	env.runs.mu.Unlock()
	if calls != 0 {
		t.Errorf("the run directory was consulted %d times on a refused token", calls)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after three refusals", n)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after three refusals", files)
	}

	// POSITIVE CONTROL — the run's own token, and the same call succeeds.
	ok := otcArgs()
	ok["run_token"] = RunToken(otcSecret, otcRunID)
	if out := otcCallOK(t, session, ok); !out.Stored {
		t.Fatalf("the positive control did not store: %+v", out)
	}
}

// TestObserveToolCallRequiresNoTokenWhenNoSecretIsConfigured. Empty means no
// authentication, which is the state every deployment before run tokens was
// in. Enabling it is an operator's decision and not a silent break of every
// running shim.
func TestObserveToolCallRequiresNoTokenWhenNoSecretIsConfigured(t *testing.T) {
	otcSetup(t, nil)
	session := otcServe(t)

	if out := otcCallOK(t, session, otcArgs()); !out.Stored {
		t.Fatalf("a call with no token was refused where no secret is configured: %+v", out)
	}
}

// ---------------------------------------------------------------------------
// MCP-048 — an oversized body.
// ---------------------------------------------------------------------------

// TestMCP048AnOversizedBodyIsRefusedAndNothingIsStored. Doc 07 MCP-048: "Own
// error class; nothing stored, nothing appended."
//
// The bound is on the body the caller sends, so it is checked before the body
// is digested, before the volume is touched and before the run is looked up: a
// caller cannot make the MCP commit an unbounded amount of the operator's disk
// in one call.
func TestMCP048AnOversizedBodyIsRefusedAndNothingIsStored(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	args := otcArgs()
	args["body"] = strings.Repeat("x", MaxObservedBodyBytes+1)
	wire := otcCallFail(t, session, args, ClassInvariantViolation)

	msg := reMessage(t, wire)
	if !strings.Contains(msg, fmt.Sprint(MaxObservedBodyBytes)) {
		t.Errorf("the refusal does not name the bound it enforced: %q", msg)
	}
	// The refusal must not quote the body back: an error message is a second
	// place a payload could come to rest.
	if strings.Contains(msg, strings.Repeat("x", 64)) {
		t.Errorf("the refusal quotes the body back: %q", msg)
	}

	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after an oversized body was refused", files)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after an oversized body was refused", n)
	}

	// POSITIVE CONTROL — a body of exactly the bound is stored.
	atBound := otcArgs()
	atBound["body"] = strings.Repeat("x", MaxObservedBodyBytes)
	if out := otcCallOK(t, session, atBound); !out.Stored {
		t.Fatalf("a body of exactly the bound was refused: %+v", out)
	}
}

// TestObserveToolCallRefusesAnEmptyBody. There is no observation without one,
// and storing zero bytes under a digest of zero bytes would put a file on the
// operator's disk that proves nothing about what the agent did.
func TestObserveToolCallRefusesAnEmptyBody(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	args := otcArgs()
	args["body"] = ""
	otcCallFail(t, session, args, ClassInvariantViolation)

	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after an empty body was refused", files)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after an empty body was refused", n)
	}
}

// ---------------------------------------------------------------------------
// MCP-049 — the volume is unwritable.
// ---------------------------------------------------------------------------

// TestMCP049AnUnwritableVolumeAppendsNoToolCall. Doc 07 MCP-049: "Own error
// class, retryable; no `tool_call` appended (I3)."
//
// I3 admits no action without a record, and the converse is what this case
// holds: no record of an observation that was not actually kept. A `tool_call`
// naming a digest whose body was never written would be an entry in an
// append-only chain pointing at a file that does not exist and never did.
//
// The volume is REALLY unwritable — the run directory's parent is a regular
// file, so MkdirAll cannot succeed whatever the uid the tests run as.
func TestMCP049AnUnwritableVolumeAppendsNoToolCall(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("the volume is not mounted"), 0o600); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}

	env := otcSetup(t, func(cfg *ObserveToolCallConfig) {
		cfg.BodyDir = filepath.Join(blocked, "bodies")
	})
	session := otcServe(t)

	wire := otcCallFail(t, session, otcArgs(), ClassLedgerUnavailable)
	if msg := reMessage(t, wire); !strings.Contains(msg, "body") {
		t.Errorf("the refusal does not say the body could not be stored: %q", msg)
	}

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although no body was stored (I3)", n)
	}
	if got := len(env.ledger.appended); got != 0 {
		t.Errorf("the ledger was asked to append %d times although no body was stored", got)
	}
}

// TestObserveToolCallReportsAVolumeItCannotWriteInto covers the two remaining
// ways the write can fail, each on its own line of the store: a run directory
// that exists and refuses a new file, and a destination that cannot be moved
// onto. All three refuse the same way, so a shim needs one branch and not
// three.
func TestObserveToolCallReportsAVolumeItCannotWriteInto(t *testing.T) {
	t.Run("the run directory refuses a new file", func(t *testing.T) {
		env := otcSetup(t, nil)
		session := otcServe(t)

		runDir := filepath.Join(env.bodyDir, otcRunID)
		if err := os.MkdirAll(runDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(runDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(runDir, 0o700); err != nil {
				t.Errorf("restoring %s: %v", runDir, err)
			}
		})

		otcCallFail(t, session, otcArgs(), ClassLedgerUnavailable)
		if n := env.count(t); n != 0 {
			t.Errorf("the ledger holds %d events although no body was stored (I3)", n)
		}
	})

	t.Run("the body's own path is a directory", func(t *testing.T) {
		env := otcSetup(t, nil)
		session := otcServe(t)

		// Something else already holds the name the body must take. The
		// temporary file is written, and the move onto it fails.
		occupied := env.bodyPath(otcRunID, event.Digest([]byte(otcBody)))
		if err := os.MkdirAll(occupied, 0o700); err != nil {
			t.Fatal(err)
		}

		otcCallFail(t, session, otcArgs(), ClassLedgerUnavailable)
		if n := env.count(t); n != 0 {
			t.Errorf("the ledger holds %d events although no body was stored (I3)", n)
		}
		// The half-written temporary file is cleaned up: a body that was not
		// stored must not be left lying on the operator's disk under a name
		// nothing will ever read or expire.
		for _, f := range env.storedFiles(t) {
			t.Errorf("the volume holds %q after a failed store", f)
		}
	})
}

// ---------------------------------------------------------------------------
// The run, and the order the gates run in.
// ---------------------------------------------------------------------------

// TestObserveToolCallRefusesARunIDThatNamesNoRun covers both halves of
// RUN_NOT_FOUND: an id that cannot be one (doc 02 §5's grammar), and one that
// could be and is not.
func TestObserveToolCallRefusesARunIDThatNamesNoRun(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	for name, runID := range map[string]string{
		"not an identifier": "Run With Spaces",
		"empty":             "",
		"too long":          strings.Repeat("r", 64),
		"unknown":           "run-nobody",
	} {
		t.Run(name, func(t *testing.T) {
			args := otcArgs()
			args["run_id"] = runID
			otcCallFail(t, session, args, ClassRunNotFound)
		})
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after four refusals", n)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after four refusals", files)
	}
}

// TestObserveToolCallRefusesARetiredRun. I4: retirement removes the identity,
// never the record. A retired run's history stays readable; it stops growing.
func TestObserveToolCallRefusesARetiredRun(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	env.runs.retire(otcRunID, time.Now())
	otcCallFail(t, session, otcArgs(), ClassRunAlreadyRetired)

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events for a retired run", n)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v for a retired run", files)
	}
}

// TestObserveToolCallRefusesADirectoryThatAnsweredForAnotherRun. The
// directory's answer is checked, not trusted — the same check get_credential
// makes, from the one implementation of it, so that an observation cannot be
// attributed to another run's identity (I2).
func TestObserveToolCallRefusesADirectoryThatAnsweredForAnotherRun(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	env.runs.putAs(otcRunID, credRun("run-somebody-else"))
	otcCallFail(t, session, otcArgs(), ClassInvariantViolation)

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after a misattributed answer", n)
	}
}

// TestObserveToolCallRefusesABodyWhereAToolNameBelongs. `tool` names the agent
// tool that was invoked and is recorded as doc 02 §3's `tool_name`, under the
// same grammar record_event holds its own argument to (ADR-0021): a name is
// short, has no line breaks, and is not one of doc 02 §3's event types.
func TestObserveToolCallRefusesABodyWhereAToolNameBelongs(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	names := map[string]string{
		"empty":                    "",
		"a json body":              otcBody,
		"a multi-line body":        "Edit\nstdout: wrote 41 lines\n",
		"a tab-separated body":     "Edit\twrote 41 lines",
		"over the reference bound": strings.Repeat("t", event.MaxReferenceBytes+1),
		"invalid utf-8":            "Edit\xff\xfe",
		"an event type":            event.EventTypeToolCall,
		"another event type":       event.EventTypeCommitRecorded,
	}
	for name, tool := range names {
		t.Run(name, func(t *testing.T) {
			args := otcArgs()
			args["tool"] = tool
			wire := otcCallFail(t, session, args, ClassInvariantViolation)
			if msg := reMessage(t, wire); strings.Contains(msg, otcSecretBytes) {
				t.Errorf("the refusal quotes the body back: %q", msg)
			}
		})
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after every name was refused", n)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after every name was refused", files)
	}

	// POSITIVE CONTROL — the same call with a name.
	if out := otcCallOK(t, session, otcArgs()); !out.Stored {
		t.Fatalf("the positive control did not store: %+v", out)
	}
}

// ---------------------------------------------------------------------------
// The ledger, and what happens when it is the half that fails.
// ---------------------------------------------------------------------------

// TestObserveToolCallReportsALedgerItCannotAppendTo. The body is already on the
// volume when the append is attempted, which is the safe order: a body with no
// event is an unreferenced file the retention window collects, while an event
// with no body is a permanent claim about evidence that never existed.
func TestObserveToolCallReportsALedgerItCannotAppendTo(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	env.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	otcCallFail(t, session, otcArgs(), ClassLedgerUnavailable)

	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although the append failed", n)
	}

	// The claim was released, so the retry that follows a retryable refusal
	// actually runs the tool again rather than replaying a failure.
	env.ledger.fail(nil)
	if out := otcCallOK(t, session, otcArgs()); !out.Stored {
		t.Fatalf("the retry after a retryable failure did not succeed: %+v", out)
	}
	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("the ledger holds %d tool_call events after one retry, want 1", n)
	}
}

// TestObserveToolCallReportsARunDirectoryItCannotRead. The directory reads the
// chain, so its failure is the ledger's and is carried across with the
// ledger's own classification rather than reclassified here.
func TestObserveToolCallReportsARunDirectoryItCannotRead(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	otcCallFail(t, session, otcArgs(), ClassLedgerUnavailable)

	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v although the run could not be resolved", files)
	}
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

// TestObserveToolCallIsNotServedUntilItIsConfigured. A bound tool with no
// dependencies behind it refuses rather than improvising: IP §4 has no
// "internal error" class, so a wiring defect is alert-level (ADR-0016).
func TestObserveToolCallIsNotServedUntilItIsConfigured(t *testing.T) {
	observeMu.Lock()
	saved := observeActive
	observeActive = nil
	observeMu.Unlock()
	t.Cleanup(func() {
		observeMu.Lock()
		observeActive = saved
		observeMu.Unlock()
	})

	session := otcServe(t)
	otcCallFail(t, session, otcArgs(), ClassInvariantViolation)
}

// TestConfigureObserveToolCallRefusesAnIncompleteConfiguration. Each
// dependency is a gate, and a missing gate is an open door rather than a
// degraded mode. The body volume is one of them: a deployment that cannot
// store bodies must say so at start-up, not by appending events for
// observations it kept nothing of.
func TestConfigureObserveToolCallRefusesAnIncompleteConfiguration(t *testing.T) {
	idem, dsn := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	full := ObserveToolCallConfig{
		Runs: newCredRuns(), Ledger: lg, Idempotency: idem, BodyDir: t.TempDir(),
	}
	for name, mutate := range map[string]func(*ObserveToolCallConfig){
		"no run directory":     func(c *ObserveToolCallConfig) { c.Runs = nil },
		"no ledger":            func(c *ObserveToolCallConfig) { c.Ledger = nil },
		"no idempotency store": func(c *ObserveToolCallConfig) { c.Idempotency = nil },
		"no body volume":       func(c *ObserveToolCallConfig) { c.BodyDir = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			restore, cerr := ConfigureObserveToolCall(cfg)
			if cerr == nil {
				restore()
				t.Fatalf("ConfigureObserveToolCall accepted a configuration with %s", name)
			}
			if got := mcpError(t, cerr).Class; got != ClassInvariantViolation {
				t.Errorf("class is %s, want %s", got, ClassInvariantViolation)
			}
		})
	}

	restore, err := ConfigureObserveToolCall(full)
	if err != nil {
		t.Fatalf("ConfigureObserveToolCall refused a complete configuration: %v", err)
	}
	restore()
}

// TestObserveToolCallRefusesAStoredReplyItCannotRead. ADR-0017 returns the
// recorded reply byte for byte; a row that is not an observe_tool_call reply is
// a defect, not a result to decode leniently.
//
// The store is seeded under the SAME key and the SAME request fingerprint the
// tool computes, so the replay reaches the decode rather than being turned away
// as a different request.
func TestObserveToolCallRefusesAStoredReplyItCannotRead(t *testing.T) {
	env := otcSetup(t, nil)
	session := otcServe(t)

	digest := event.Digest([]byte(otcBody))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := env.idem.Do(ctx, Call{
		Tool: string(ToolObserveToolCall),
		Key:  observeIdempotencyKey(otcRunID, digest),
		Params: map[string]any{
			"run_id":         otcRunID,
			"tool_name":      otcTool,
			"payload_digest": digest,
		},
	}, func(context.Context) (any, error) {
		// Canonicalizes cleanly, decodes into nothing doc 01 §4 documents.
		return map[string]any{"digest": int64(7), "stored": "probably"}, nil
	}); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	otcCallFail(t, session, otcArgs(), ClassInvariantViolation)
}

// TestObserveToolCallErrorClassMatrix. Doc 07 MCP-006, this tool's row: every
// error class observe_tool_call can produce is produced, and its retryable flag
// is the one ADR-0016 fixes for the class. No new class is invented — the
// vocabulary is a protected surface (doc 08 §3).
func TestObserveToolCallErrorClassMatrix(t *testing.T) {
	want := []Class{
		ClassRunNotFound,
		ClassRunAlreadyRetired,
		ClassLedgerUnavailable,
		ClassDuplicateRequest,
		ClassInvariantViolation,
	}
	env := otcSetup(t, nil)
	session := otcServe(t)
	seen := map[Class]bool{}

	// RUN_NOT_FOUND — a run nothing knows.
	unknown := otcArgs()
	unknown["run_id"] = "run-nobody"
	otcCallFail(t, session, unknown, ClassRunNotFound)
	seen[ClassRunNotFound] = true

	// INVARIANT_VIOLATION — a body where a tool name belongs.
	named := otcArgs()
	named["tool"] = otcBody
	otcCallFail(t, session, named, ClassInvariantViolation)
	seen[ClassInvariantViolation] = true

	// DUPLICATE_REQUEST — one derived key, two different observations.
	otcCallOK(t, session, otcArgs())
	dup := otcArgs()
	dup["tool"] = "Bash"
	otcCallFail(t, session, dup, ClassDuplicateRequest)
	seen[ClassDuplicateRequest] = true

	// RUN_ALREADY_RETIRED.
	env.runs.retire(otcRunID, time.Now())
	retired := otcArgs()
	retired["body"] = `{"tool_name":"Read","tool_input":{"file_path":"/w/a.go"}}`
	otcCallFail(t, session, retired, ClassRunAlreadyRetired)
	seen[ClassRunAlreadyRetired] = true

	// LEDGER_UNAVAILABLE — the directory reads the chain and it is down.
	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	down := otcArgs()
	down["body"] = `{"tool_name":"Read","tool_input":{"file_path":"/w/b.go"}}`
	otcCallFail(t, session, down, ClassLedgerUnavailable)
	seen[ClassLedgerUnavailable] = true

	for _, c := range want {
		if !seen[c] {
			t.Errorf("%s is documented as reachable from observe_tool_call and was not produced", c)
		}
	}
}

// TestObserveIdempotencyKeyNamesTheObservationAndFitsTheColumn. The key is
// DERIVED, because doc 01 §4 gives this tool no idempotency_key argument and
// ADR-0004 requires one on the tool_call it appends. It must name exactly
// (run_id, digest) — the pair doc 01 §4 makes this tool idempotent on — and it
// must fit doc 02 §2's bound on the member it becomes.
func TestObserveIdempotencyKeyNamesTheObservationAndFitsTheColumn(t *testing.T) {
	longest := strings.Repeat("r", 63)
	digest := event.Digest([]byte(otcBody))
	other := event.Digest([]byte("a different body"))

	key := observeIdempotencyKey(longest, digest)
	if len(key) > event.MaxIdempotencyKeyBytes {
		t.Errorf("the derived key is %d bytes, doc 02 §2 bounds it at %d",
			len(key), event.MaxIdempotencyKeyBytes)
	}
	if key == "" {
		t.Error("the derived key is empty; ADR-0004 requires one on the tool_call this tool appends")
	}
	if same := observeIdempotencyKey(longest, digest); same != key {
		t.Errorf("the same observation derived two keys: %q and %q", key, same)
	}
	if key == observeIdempotencyKey(longest, other) {
		t.Errorf("two bodies under one run derived one key %q", key)
	}
	if key == observeIdempotencyKey("run-someone-else", digest) {
		t.Errorf("two runs observing one body derived one key %q", key)
	}

	// A digest shorter than the truncation is not a shape event.Digest can
	// produce, and the key derivation must still return one rather than panic
	// slicing past the end: the guard that makes it so is only load-bearing on
	// this input, and a branch nothing reaches is a branch nothing checks.
	if short := observeIdempotencyKey(longest, event.HashPrefix+"abc"); short == "" {
		t.Error("a short digest derived no key at all")
	}
}
