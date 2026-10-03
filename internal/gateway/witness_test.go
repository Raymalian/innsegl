// SPDX-License-Identifier: Apache-2.0

package gateway

// witness_test.go — #392 (RM-247), E18. OTW-001 (doc 07): "the harness
// exports its telemetry to the core -- each tool_result event is kept with
// its tool_use_id, session and outcome."
//
// TestOTW001TelemetryHandlerKeepsToolResultRecords runs against
// testdata/otel/tool_result_real.json, a REAL OTLP/HTTP JSON logs export
// payload: captured once, on 2026-09-30, by running
//
//	CLAUDE_CODE_ENABLE_TELEMETRY=1 OTEL_LOGS_EXPORTER=otlp \
//	OTEL_EXPORTER_OTLP_PROTOCOL=http/json \
//	OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:<a throwaway capture server> \
//	OTEL_LOGS_EXPORT_INTERVAL=1000 \
//	claude -p 'run: echo hi' --allowedTools Bash --model haiku
//
// twice -- once for a successful Bash call, once for a Bash call that failed
// (a nonexistent command) -- against a tiny local Python capture server in a
// throwaway repository outside this one, entirely offline from this
// package's own tests. The two `claude_code.tool_decision` /
// `claude_code.tool_result` log records from each real run were extracted
// verbatim (same keys, same value SHAPES -- notably `success`, `duration_ms`
// and the size fields all arrive as OTLP stringValue, never boolValue or
// intValue, which is why otlpAnyValue.asString below reads every shape
// rather than assuming one) and every account-identifying attribute
// (user.id, user.email, user.account_id, user.account_uuid,
// organization.id, session.id, prompt.id) was replaced with a fixed,
// obviously-synthetic placeholder. Nothing else about the payload's shape,
// keys or types was hand-edited.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	otwRealToolUseIDOK   = "toolu_01Wg6NEU5T2zAUXSUYpqoxC9"
	otwRealSessionOK     = "11111111-1111-1111-1111-111111111111"
	otwRealToolUseIDFail = "toolu_01GUEaszGyx8aMRXspTgrT4W"
	otwRealSessionFail   = "33333333-3333-3333-3333-333333333333"
)

func otwPost(t *testing.T, h http.Handler, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, TelemetryLogsPath, strings.NewReader(string(body)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func otwReadRealFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "otel", "tool_result_real.json"))
	if err != nil {
		t.Fatalf("reading the real OTW-001 fixture: %v", err)
	}
	return raw
}

// otwStoredRecord is telemetryRecord's own shape, restated for the test's
// own decode -- both live in this package, but restating pins the ON-DISK
// JSON contract independently of whatever field order or helper the
// implementation happens to use internally.
type otwStoredRecord struct {
	ToolUseID string    `json:"tool_use_id"`
	ToolName  string    `json:"tool_name"`
	Success   bool      `json:"success"`
	SessionID string    `json:"session_id"`
	Time      time.Time `json:"time"`
}

func otwReadStored(t *testing.T, dir, toolUseID string) otwStoredRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "telemetry", toolUseID+".json"))
	if err != nil {
		t.Fatalf("reading the stored telemetry record for %s: %v", toolUseID, err)
	}
	var rec otwStoredRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("the stored telemetry record for %s is not JSON: %v\n%s", toolUseID, err, raw)
	}
	return rec
}

// TestOTW001TelemetryHandlerKeepsToolResultRecords is OTW-001 (I) itself,
// against the real captured payload described above.
func TestOTW001TelemetryHandlerKeepsToolResultRecords(t *testing.T) {
	dir := t.TempDir()
	h := TelemetryHandler(TelemetryConfig{Dir: dir})

	rec := otwPost(t, h, "application/json", otwReadRealFixture(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	ok := otwReadStored(t, dir, otwRealToolUseIDOK)
	if ok.ToolUseID != otwRealToolUseIDOK {
		t.Errorf("tool_use_id = %q, want %q", ok.ToolUseID, otwRealToolUseIDOK)
	}
	if ok.ToolName != "Bash" {
		t.Errorf("tool_name = %q, want %q", ok.ToolName, "Bash")
	}
	if !ok.Success {
		t.Errorf("success = false, want true (the real successful run)")
	}
	if ok.SessionID != otwRealSessionOK {
		t.Errorf("session_id = %q, want %q", ok.SessionID, otwRealSessionOK)
	}
	if ok.Time.IsZero() {
		t.Errorf("time is zero, want the record's own kept time")
	}

	failed := otwReadStored(t, dir, otwRealToolUseIDFail)
	if failed.Success {
		t.Errorf("success = true, want false (the real failed run: a nonexistent command)")
	}
	if failed.SessionID != otwRealSessionFail {
		t.Errorf("session_id = %q, want %q", failed.SessionID, otwRealSessionFail)
	}
}

// TestOTW001TelemetryHandlerAnswersOTLPSuccess: the OTLP/HTTP JSON logs
// export success reply is 200, Content-Type application/json, and an empty
// ExportLogsServiceResponse body -- so the harness's own exporter never logs
// an export failure for a batch this receiver in fact kept.
func TestOTW001TelemetryHandlerAnswersOTLPSuccess(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{Dir: t.TempDir()})
	rec := otwPost(t, h, "application/json", otwReadRealFixture(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if len(body) != 0 {
		t.Errorf("response body = %v, want an empty ExportLogsServiceResponse", body)
	}
}

// TestOTW001TelemetryHandlerRejectsProtobufContentType: OTLP/HTTP supports
// both a JSON and a protobuf encoding of the identical message; this
// receiver understands JSON only and refuses protobuf CLEARLY (415) rather
// than attempting to parse binary as JSON and silently keeping nothing.
func TestOTW001TelemetryHandlerRejectsProtobufContentType(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{Dir: t.TempDir()})
	rec := otwPost(t, h, "application/x-protobuf", []byte{0x0a, 0x02, 0x08, 0x01})

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "protobuf") {
		t.Errorf("refusal does not name protobuf clearly: %s", rec.Body.String())
	}
}

// TestOTW001TelemetryHandlerRejectsUnknownContentType: neither JSON nor
// protobuf -- still 415, still clear, never a guess at the body's shape.
func TestOTW001TelemetryHandlerRejectsUnknownContentType(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{Dir: t.TempDir()})
	rec := otwPost(t, h, "text/plain", []byte("not otlp at all"))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

// TestOTW001TelemetryHandlerBoundsBody: an export body over the bound is
// refused (413) rather than partially parsed.
func TestOTW001TelemetryHandlerBoundsBody(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{Dir: t.TempDir()})
	oversized := make([]byte, maxTelemetryBodyBytes+1)
	rec := otwPost(t, h, "application/json", oversized)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// TestOTW001TelemetryHandlerDropsOtherEventTypes: this receiver's own
// privacy contract -- every OTLP event type besides claude_code.tool_result
// is silently dropped, even though the SAME log record carries the exact
// account-identifying attributes (user.email among them) a tool_result
// record does. Nothing is stored for it, under any key.
func TestOTW001TelemetryHandlerDropsOtherEventTypes(t *testing.T) {
	dir := t.TempDir()
	h := TelemetryHandler(TelemetryConfig{Dir: dir})

	payload := `{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{},"logRecords":[` +
		`{"timeUnixNano":"1","body":{"stringValue":"claude_code.managed_settings_resolved"},"attributes":[` +
		`{"key":"user.email","value":{"stringValue":"should-never-be-kept@example.invalid"}},` +
		`{"key":"event.name","value":{"stringValue":"managed_settings_resolved"}}` +
		`]}]}]}]}`

	rec := otwPost(t, h, "application/json", []byte(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	entries, err := os.ReadDir(filepath.Join(dir, "telemetry"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading the telemetry directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d file(s) kept for a non-tool_result event, want 0: %v", len(entries), entries)
	}
}

// TestOTW001TelemetryHandlerNeverKeepsProhibitedFields: even for a
// tool_result record, only the five documented fields (tool_use_id,
// tool_name, success, session id, time) ever reach disk -- the stored
// file's own bytes never contain the payload's user.email, user.id,
// user.account_id, user.account_uuid or organization.id.
func TestOTW001TelemetryHandlerNeverKeepsProhibitedFields(t *testing.T) {
	dir := t.TempDir()
	h := TelemetryHandler(TelemetryConfig{Dir: dir})
	otwPost(t, h, "application/json", otwReadRealFixture(t))

	raw, err := os.ReadFile(filepath.Join(dir, "telemetry", otwRealToolUseIDOK+".json"))
	if err != nil {
		t.Fatalf("reading the stored record: %v", err)
	}
	for _, prohibited := range []string{
		"scrubbed@example.invalid", "scrubbed-user-id", "scrubbed-account-id",
		"organization.id", "user.email", "user.id", "user.account",
		"22222222-2222-2222-2222-222222222222", // prompt.id
	} {
		if strings.Contains(string(raw), prohibited) {
			t.Errorf("stored record contains %q, want it never kept: %s", prohibited, raw)
		}
	}
}

// TestOTW001TelemetryHandlerIgnoresARecordWithNoUsableToolUseID: a
// tool_result log record missing tool_use_id (or carrying one that does not
// have the harness's own shape, commitpath.IsToolUseID) is dropped rather
// than written under an empty or attacker-chosen filename.
func TestOTW001TelemetryHandlerIgnoresARecordWithNoUsableToolUseID(t *testing.T) {
	dir := t.TempDir()
	h := TelemetryHandler(TelemetryConfig{Dir: dir})

	payload := `{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{},"logRecords":[` +
		`{"timeUnixNano":"1","body":{"stringValue":"claude_code.tool_result"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_result"}},` +
		`{"key":"tool_name","value":{"stringValue":"Bash"}},` +
		`{"key":"success","value":{"stringValue":"true"}},` +
		`{"key":"session.id","value":{"stringValue":"ffffffff-ffff-ffff-ffff-ffffffffffff"}}` +
		`]}]}]}]}`

	rec := otwPost(t, h, "application/json", []byte(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a witness never refuses on what it cannot use): %s",
			rec.Code, rec.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(dir, "telemetry"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading the telemetry directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d file(s) kept with no usable tool_use_id, want 0", len(entries))
	}
}

// TestOTW001TelemetryHandlerRequiresDir: a handler with nowhere to write
// refuses clearly rather than silently discarding every record it is handed.
func TestOTW001TelemetryHandlerRequiresDir(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{})
	rec := otwPost(t, h, "application/json", otwReadRealFixture(t))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a handler with no Dir configured", rec.Code)
	}
}

// TestOTW001TelemetryHandlerGetIsNotAllowed: OTLP/HTTP is POST-only.
func TestOTW001TelemetryHandlerGetIsNotAllowed(t *testing.T) {
	h := TelemetryHandler(TelemetryConfig{Dir: t.TempDir()})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, TelemetryLogsPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// A tool call the harness stopped before it ran -- a permission the person
// refused, a hook's deny, an interrupt, a cancelled sibling -- has no
// tool_result: the harness reports it as a tool_decision with decision
// "reject", under the same tool_use_id (code.claude.com/docs, monitoring).
// Measured 2026-10-03: nine drift alerts on real sessions said such calls had
// no witness. The decision is kept as the witness; an accept is not, since
// the tool_result follows it.
func TestOTW001TelemetryHandlerKeepsARejectedToolDecision(t *testing.T) {
	dir := t.TempDir()
	h := TelemetryHandler(TelemetryConfig{Dir: dir})
	payload := `{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{},"logRecords":[` +
		`{"timeUnixNano":"1","body":{"stringValue":"claude_code.tool_decision"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_decision"}},` +
		`{"key":"tool_use_id","value":{"stringValue":"toolu_01RejectedByHook000000"}},` +
		`{"key":"tool_name","value":{"stringValue":"Bash"}},` +
		`{"key":"decision","value":{"stringValue":"reject"}},` +
		`{"key":"source","value":{"stringValue":"hook"}}]},` +
		`{"timeUnixNano":"2","body":{"stringValue":"claude_code.tool_decision"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_decision"}},` +
		`{"key":"tool_use_id","value":{"stringValue":"toolu_01AcceptedWillHaveResult"}},` +
		`{"key":"decision","value":{"stringValue":"accept"}}]}` +
		`]}]}]}`
	if rec := otwPost(t, h, "application/json", []byte(payload)); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := otwReadStored(t, dir, "toolu_01RejectedByHook000000")
	if got.ToolName != "Bash" || got.Success {
		t.Errorf("stored %+v, want the Bash call, not a success", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "telemetry", "toolu_01RejectedByHook000000.json"))
	if err != nil || !strings.Contains(string(raw), `"decision":"reject"`) {
		t.Errorf("the record does not say the call was rejected: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry", "toolu_01AcceptedWillHaveResult.json")); err == nil {
		t.Error("an accepted decision was kept; its tool_result is the witness")
	}
}
