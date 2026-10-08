// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// gatewayrecord_test.go — #381 (RM-236), E16. Doc 07 TC-GREC: GREC-001,
// GREC-002, GREC-004, GREC-007 at this layer (the gateway's own end-to-end
// claim through the real openGateway is cmd/innsegl/gatewayrecord_test.go's;
// this file is the in-process seam RecordGatewayToolCall reuses
// observe_tool_call's own service through — same body store, same digest,
// same idempotency claim, ADR-0017).
//
// Reuses observe_test.go's own fixture (otcSetup, otcRunID, otcEnv) rather
// than building a second one: this file's whole point is that
// RecordGatewayToolCall runs on the SAME configured service observe_tool_call
// itself runs on, so a second fixture would prove nothing about that.

const (
	grecTool     = "Bash"
	grecTreeHash = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
)

func grecBody(input, result string, isError bool) []byte {
	return []byte(fmt.Sprintf(
		`{"tool":"Bash","input":%s,"result":%s,"is_error":%t,"result_observed":true}`,
		input, result, isError))
}

// TestGREC001RecordGatewayToolCallAppendsOneToolCallCarryingTheTreeHash.
// Doc 07 GREC-001 (its own layer): one tool_call, tool_name the tool,
// payload_digest over the stored body, body in the existing body store — and
// this file's own addition, ADR-0061 member 3: workspace_tree_hash carried
// when the caller has one.
func TestGREC001RecordGatewayToolCallAppendsOneToolCallCarryingTheTreeHash(t *testing.T) {
	env := otcSetup(t, nil)
	body := grecBody(`{"file_path":"/w/a.go"}`, `{"success":true}`, false)

	out, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: body, WorkspaceTreeHash: grecTreeHash,
	})
	if err != nil {
		t.Fatalf("RecordGatewayToolCall: %v", err)
	}
	if !out.Stored {
		t.Fatalf("Stored = false, want true: %+v", out)
	}
	if want := event.Digest(body); out.Digest != want {
		t.Errorf("Digest = %s, want %s", out.Digest, want)
	}

	calls := env.toolCalls(t)
	if len(calls) != 1 {
		t.Fatalf("%d tool_call events, want 1: %+v", len(calls), calls)
	}
	got := calls[0]
	if got[event.FieldToolName] != grecTool {
		t.Errorf("tool_name = %v, want %s", got[event.FieldToolName], grecTool)
	}
	if got[event.FieldPayloadDigest] != out.Digest {
		t.Errorf("payload_digest = %v, want %s", got[event.FieldPayloadDigest], out.Digest)
	}
	if got[event.FieldWorkspaceTreeHash] != grecTreeHash {
		t.Errorf("workspace_tree_hash = %v, want %s", got[event.FieldWorkspaceTreeHash], grecTreeHash)
	}
	if got[event.FieldRunID] != otcRunID {
		t.Errorf("run_id = %v, want %s", got[event.FieldRunID], otcRunID)
	}

	// The body landed on the same volume, at the same path the two production
	// readers already read from, byte for byte.
	stored, rerr := grecReadFile(t, env.bodyPath(otcRunID, out.Digest))
	if rerr != nil {
		t.Fatalf("reading the stored body: %v", rerr)
	}
	if string(stored) != string(body) {
		t.Errorf("stored body = %q, want %q", stored, body)
	}
}

// TestGREC001RecordGatewayToolCallOmitsAnAbsentTreeHash. ADR-0061 member 3 is
// optional: a snapshot that never happened must not fabricate a value.
func TestGREC001RecordGatewayToolCallOmitsAnAbsentTreeHash(t *testing.T) {
	env := otcSetup(t, nil)
	body := grecBody(`{"file_path":"/w/b.go"}`, `{"success":true}`, false)

	out, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: body,
	})
	if err != nil {
		t.Fatalf("RecordGatewayToolCall: %v", err)
	}
	if !out.Stored {
		t.Fatalf("Stored = false, want true")
	}

	calls := env.toolCalls(t)
	if len(calls) != 1 {
		t.Fatalf("%d tool_call events, want 1: %+v", len(calls), calls)
	}
	if _, present := calls[0][event.FieldWorkspaceTreeHash]; present {
		t.Errorf("workspace_tree_hash = %v, want absent", calls[0][event.FieldWorkspaceTreeHash])
	}
}

// TestGREC002RecordGatewayToolCallRecordsAFailedAndARefusedResultAsTheirOwnCalls.
// Doc 07 GREC-002: a failed tool result and a refused one each recorded as
// their own tool_call, with the outcome provable from the stored body's
// digest — is_error and the harness's own refusal text are ordinary content,
// not something this path treats specially.
func TestGREC002RecordGatewayToolCallRecordsAFailedAndARefusedResultAsTheirOwnCalls(t *testing.T) {
	env := otcSetup(t, nil)

	failed := grecBody(`{"command":"go test ./..."}`, `{"stderr":"FAIL"}`, true)
	refused := grecBody(`{"command":"rm -rf /"}`, `{"stderr":"permission denied by policy"}`, true)

	for _, body := range [][]byte{failed, refused} {
		if _, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
			RunID: otcRunID, Tool: grecTool, Body: body,
		}); err != nil {
			t.Fatalf("RecordGatewayToolCall(%s): %v", body, err)
		}
	}

	calls := env.toolCalls(t)
	if len(calls) != 2 {
		t.Fatalf("%d tool_call events, want 2: %+v", len(calls), calls)
	}
	wantDigests := map[string]bool{
		event.Digest(failed):  true,
		event.Digest(refused): true,
	}
	for _, c := range calls {
		digest, ok := c[event.FieldPayloadDigest].(string)
		if !ok || !wantDigests[digest] {
			t.Errorf("unexpected payload_digest %v (present: %v)", digest, ok)
		}
		delete(wantDigests, digest)
	}
	if len(wantDigests) != 0 {
		t.Errorf("missing tool_call events for digests %v", wantDigests)
	}

	stored, err := grecReadFile(t, env.bodyPath(otcRunID, event.Digest(refused)))
	if err != nil {
		t.Fatalf("reading the refused call's stored body: %v", err)
	}
	if !strings.Contains(string(stored), "permission denied by policy") {
		t.Errorf("stored body does not carry the refusal text: %q", stored)
	}
}

// TestGREC004RecordGatewayToolCallIsIdempotentOnRunIDAndDigest. Doc 07
// GREC-004: a replay of the identical (run_id, body) pair appends nothing a
// second time — ADR-0017's own guarantee, reached through this seam exactly
// as observe_tool_call's own replay already reaches it.
func TestGREC004RecordGatewayToolCallIsIdempotentOnRunIDAndDigest(t *testing.T) {
	env := otcSetup(t, nil)
	body := grecBody(`{"file_path":"/w/c.go"}`, `{"success":true}`, false)
	in := GatewayToolCallInput{RunID: otcRunID, Tool: grecTool, Body: body, WorkspaceTreeHash: grecTreeHash}

	first, err := RecordGatewayToolCall(context.Background(), in)
	if err != nil {
		t.Fatalf("first RecordGatewayToolCall: %v", err)
	}
	second, err := RecordGatewayToolCall(context.Background(), in)
	if err != nil {
		t.Fatalf("replayed RecordGatewayToolCall: %v", err)
	}
	if second != first {
		t.Errorf("replay = %+v, want the original reply %+v", second, first)
	}
	if n := len(env.toolCalls(t)); n != 1 {
		t.Errorf("%d tool_call events after a replay, want 1", n)
	}
}

// TestGREC007RecordGatewayToolCallStatesATruncationInTheBodyItStores. Doc 07
// GREC-007: this file records exactly the bytes it is given — truncation
// markers are internal/gateway/record.go's own job to state inside Body — and
// never presents a partial body as though it were complete; it only checks
// that whatever the caller marked as truncated reaches the volume unaltered.
func TestGREC007RecordGatewayToolCallStatesATruncationInTheBodyItStores(t *testing.T) {
	env := otcSetup(t, nil)
	body := []byte(`{"tool":"Write","input_truncated":true,` +
		`"note":"this tool_use's input exceeded the recorder's bound and was dropped, not reassembled"}`)

	out, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: "Write", Body: body,
	})
	if err != nil {
		t.Fatalf("RecordGatewayToolCall: %v", err)
	}
	stored, rerr := grecReadFile(t, env.bodyPath(otcRunID, out.Digest))
	if rerr != nil {
		t.Fatalf("reading the stored body: %v", rerr)
	}
	if string(stored) != string(body) {
		t.Errorf("stored body = %q, want the exact truncation-marked body %q", stored, body)
	}
}

// ---------------------------------------------------------------------------
// Error paths — 100% branch, per this repository's coverage floor on a new
// MCP error-return path.
// ---------------------------------------------------------------------------

func TestGREC001RecordGatewayToolCallIsNotServedUntilObserveToolCallIsConfigured(t *testing.T) {
	t.Cleanup(install(&active.observe, nil))

	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

func TestGREC001RecordGatewayToolCallRefusesAMalformedRunID(t *testing.T) {
	otcSetup(t, nil)
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: "Run With Spaces", Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassRunNotFound {
		t.Errorf("class = %s, want %s", got, ClassRunNotFound)
	}
}

func TestGREC001RecordGatewayToolCallRefusesABodyWhereAToolNameBelongs(t *testing.T) {
	otcSetup(t, nil)
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: otcBody, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

func TestGREC001RecordGatewayToolCallRefusesAnEmptyBody(t *testing.T) {
	otcSetup(t, nil)
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: nil,
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

func TestGREC001RecordGatewayToolCallRefusesAnOversizedBody(t *testing.T) {
	otcSetup(t, nil)
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: make([]byte, MaxObservedBodyBytes+1),
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

func TestGREC001RecordGatewayToolCallRefusesARunNothingKnows(t *testing.T) {
	otcSetup(t, nil)
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: "run-nobody-grec", Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassRunNotFound {
		t.Errorf("class = %s, want %s", got, ClassRunNotFound)
	}
}

func TestGREC001RecordGatewayToolCallRefusesARetiredRun(t *testing.T) {
	env := otcSetup(t, nil)
	env.runs.retire(otcRunID, time.Now())
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassRunAlreadyRetired {
		t.Errorf("class = %s, want %s", got, ClassRunAlreadyRetired)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events for a retired run", n)
	}
}

func TestGREC001RecordGatewayToolCallRefusesADirectoryThatAnsweredForAnotherRun(t *testing.T) {
	env := otcSetup(t, nil)
	env.runs.putAs(otcRunID, credRun("run-somebody-else-grec"))
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

func TestGREC001RecordGatewayToolCallReportsAVolumeItCannotWriteInto(t *testing.T) {
	blocked := t.TempDir() + "/not-a-directory"
	if err := grecWriteFile(t, blocked, []byte("the volume is not mounted")); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}

	env := otcSetup(t, func(cfg *ObserveToolCallConfig) {
		// A regular file where the run directory would go, the same
		// technique MCP-049's own test uses: MkdirAll then fails whatever
		// the uid.
		cfg.BodyDir = blocked + "/bodies"
	})
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class = %s, want %s", got, ClassLedgerUnavailable)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although the body could not be written", n)
	}
}

func TestGREC001RecordGatewayToolCallReportsALedgerItCannotAppendTo(t *testing.T) {
	env := otcSetup(t, nil)
	env.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class = %s, want %s", got, ClassLedgerUnavailable)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although the append failed", n)
	}
}

func TestGREC001RecordGatewayToolCallReportsARunDirectoryItCannotRead(t *testing.T) {
	env := otcSetup(t, nil)
	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: []byte("x"),
	})
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class = %s, want %s", got, ClassLedgerUnavailable)
	}
}

// TestGREC001RecordGatewayToolCallRefusesAStoredReplyItCannotRead exercises
// the json.Unmarshal branch: a row recorded under this call's own key by
// something other than this path is a defect, not a lenient decode.
func TestGREC001RecordGatewayToolCallRefusesAStoredReplyItCannotRead(t *testing.T) {
	env := otcSetup(t, nil)
	body := []byte("x")
	digest := event.Digest(body)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := env.idem.Do(ctx, Call{
		Tool: string(ToolObserveToolCall),
		Key:  observeIdempotencyKey(otcRunID, digest),
		Params: map[string]any{
			"run_id":         otcRunID,
			"tool_name":      grecTool,
			"payload_digest": digest,
		},
	}, func(context.Context) (any, error) {
		return map[string]any{"digest": int64(7), "stored": "probably"}, nil
	}); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	_, err := RecordGatewayToolCall(context.Background(), GatewayToolCallInput{
		RunID: otcRunID, Tool: grecTool, Body: body,
	})
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class = %s, want %s", got, ClassInvariantViolation)
	}
}

// ---------------------------------------------------------------------------
// Small file helpers, local to this file rather than reused from
// observe_test.go's own otcEnv methods: those read back through env's own
// bookkeeping, and this file's readers just need a path and its bytes.
// ---------------------------------------------------------------------------

func grecReadFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}

func grecWriteFile(t *testing.T, path string, data []byte) error {
	t.Helper()
	return os.WriteFile(path, data, 0o600)
}
