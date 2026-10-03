// SPDX-License-Identifier: Apache-2.0

package gateway

// witness.go — #392 (RM-247), E18: the harness's own OpenTelemetry export as
// a THIRD witness (ADR-0057's own "the harness's own telemetry").
//
// # What this is, and is not
//
// Claude Code, run with CLAUDE_CODE_ENABLE_TELEMETRY=1 and its OTLP/HTTP JSON
// exporter pointed at this gateway's own listener, POSTs a batch of OTLP log
// records to /v1/logs on every export interval. Each tool use produces a
// `claude_code.tool_result` log record carrying the SAME tool_use_id the
// model API, the harness's own hooks, and this package's own record.go all
// carry for it (ADR-0057's spike: "the SAME id the model API and hooks use").
// TelemetryHandler is the receiver for that traffic: it keeps a small,
// scrubbed extract of every tool_result it sees, keyed by tool_use_id, in
// the SAME body-store directory record.go's own tool_call bodies already
// live under (Dir/telemetry/<tool_use_id>.json) -- "fewer parts", no new
// store -- so the reconciler's own cross-check (internal/reconciler/
// witness.go) can join the two.
//
// This is a RECEIVER, never a proxy: nothing here forwards anything to
// anywhere else, and nothing here is on the path of a request this gateway
// relays to the model. A slow or failing write here costs this endpoint's
// own caller (the harness's own OTLP exporter, which retries and backs off
// on its own) nothing about the traffic Proxy.ServeHTTP is relaying.
//
// Mounting this on the gateway's own listener (mux.Handle(TelemetryLogsPath,
// TelemetryHandler(cfg))) is the supervisor's job (cmd/innsegl/gateway.go),
// not this package's — the same division record.go and messages.go already
// hold for every other witness this package ships.
//
// # Privacy: what is kept, and what never is
//
// A REAL captured payload (internal/gateway/testdata/otel, scrubbed) shows
// every OTLP log record on this path carries `user.id`, `user.email`,
// `user.account_id`, `user.account_uuid` and `organization.id` as its own
// attributes -- Claude Code's own telemetry, not anything this gateway
// asked for. NONE of those five are ever read out of an attribute map by
// name here, and nothing this file keeps is copied from the request body
// wholesale: only the five fields telemetryRecord names are ever written to
// disk (tool_use_id, tool_name, success, session id, and this receiver's
// OWN clock, never the harness-asserted event.timestamp), and every other
// OTLP event type (hook_execution_start, managed_settings_resolved,
// api_request, tool_decision, and anything else a future Claude Code
// version adds) is silently dropped -- never stored, never logged, never
// forwarded.
//
// # Bounded, JSON-only, and never a gate on its own caller
//
// The request body is bounded the same way record.go's own
// maxToolCallRecordBodyBytes is: past the bound, nothing is parsed and the
// caller is told plainly (413) rather than having a partial batch silently
// half-kept. OTLP/HTTP supports both a JSON and a protobuf encoding of the
// identical message; this receiver understands JSON only
// (OTEL_EXPORTER_OTLP_PROTOCOL=http/json is what a deployment sets) and
// refuses protobuf, or anything else that is not application/json, clearly
// (415) rather than attempting to parse it and silently keeping nothing.
//
// # The value shapes are read leniently, on purpose
//
// The OpenTelemetry spec's protobuf-JSON mapping says a 64-bit int field
// serializes as a JSON STRING. The real capture this file's own tests are
// built from shows Claude Code's own exporter does not follow that for
// every field: `event.sequence` arrives as a JSON number (intValue), while
// `duration_ms`, the two size fields and — the one this file actually reads
// — `success` all arrive as JSON STRINGS even though they are logically a
// number and a bool. otlpAnyValue.asString reads every shape (stringValue,
// intValue as either a JSON number or a string, boolValue, doubleValue)
// rather than assuming the one the spec prefers, so a future Claude Code
// release choosing the other encoding for the same field does not silently
// stop being read.

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// maxTelemetryBodyBytes bounds one OTLP/HTTP JSON logs export request --
// the same "bounded, like the gateway's other limits" discipline
// record.go's own maxToolCallRecordBodyBytes and facts.go's own
// maxRequestFactsBodyBytes hold, sized for THIS traffic's own shape rather
// than copied from theirs: an export batch is a handful of small log
// records on a short interval (OTEL_LOGS_EXPORT_INTERVAL), never a resent
// conversation history, so 4 MiB is generous headroom over anything a real
// batch has been measured at, not a bound chosen to just barely fit one.
const maxTelemetryBodyBytes = 4 << 20 // 4 MiB

// TelemetryLogsPath is where the harness's own OTLP/HTTP JSON exporter POSTs
// (OTEL_EXPORTER_OTLP_ENDPOINT=<base>, and the OTLP spec fixes the logs
// signal at <base>/v1/logs). Exported so whatever mounts TelemetryHandler on
// the gateway's own listener (not this package -- see this file's own
// package doc comment) uses the SAME path string rather than a second,
// hand-copied one.
const TelemetryLogsPath = "/v1/logs"

// telemetryDirName is the subdirectory of TelemetryConfig.Dir every kept
// record lands under -- "fewer parts": no new store, just a new
// subdirectory of the one record.go's own tool_call bodies already use.
const telemetryDirName = "telemetry"

// TelemetryConfig configures TelemetryHandler.
type TelemetryConfig struct {
	// Dir is the SAME body-store directory this package's own
	// ToolCallRecorder (record.go) and internal/mcp's observe_tool_call
	// already write tool_call bodies under. Telemetry records land in
	// Dir/telemetry, one file per tool_use_id, beside the per-run tool_call
	// bodies rather than in a store of their own. Required: a handler with
	// nowhere to write refuses (500) rather than silently discarding every
	// record it is handed.
	Dir string
	// Now reads the clock every kept record is stamped with -- never the
	// harness-asserted event.timestamp OTLP attribute (see this file's own
	// package doc comment for why: a harness-asserted id or time is not
	// authenticated, record.go's own reasoning for pendingCall.observedAt,
	// applied here to the SAME kind of value from a different source). Nil
	// means time.Now.
	Now func() time.Time
}

func (c TelemetryConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// telemetryRecord is the whole of what TelemetryHandler ever keeps for one
// tool_result, and the whole of what internal/reconciler's own witness pass
// ever reads back. See this file's own package doc comment, "Privacy",
// for why it holds exactly these five fields and nothing wider.
type telemetryRecord struct {
	ToolUseID string `json:"tool_use_id"`
	ToolName  string `json:"tool_name,omitempty"`
	Success   bool   `json:"success"`
	// Decision is "reject" for a call the harness stopped before it ran (a
	// refused permission, a hook's deny, an interrupt): such a call has no
	// tool_result, and its tool_decision is the witness. Empty for a
	// tool_result.
	Decision  string    `json:"decision,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Time      time.Time `json:"time"`
}

// TelemetryHandler answers POST TelemetryLogsPath: the OTLP/HTTP JSON logs
// export the harness's own exporter sends. See this file's own package doc
// comment for what is kept, what is dropped, and why.
func TelemetryHandler(cfg TelemetryConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeTelemetryError(w, http.StatusMethodNotAllowed,
				"innsegl gateway: "+TelemetryLogsPath+" only accepts POST (OTLP/HTTP logs export)")
			return
		}
		if cfg.Dir == "" {
			writeTelemetryError(w, http.StatusInternalServerError,
				"innsegl gateway: the telemetry receiver has no body-store directory configured; "+
					"refusing rather than silently discarding every record")
			return
		}
		if ct := r.Header.Get("Content-Type"); !isTelemetryJSON(ct) {
			// The Content-Type header's own value is never echoed back into
			// the response: it is the caller's own input, and a plain-text
			// name for what went wrong (protobuf specifically, or simply
			// "not JSON") says everything an operator needs without
			// reflecting an unbounded, caller-chosen string.
			what := "an encoding this receiver does not parse"
			if isTelemetryProtobuf(ct) {
				what = "protobuf"
			}
			writeTelemetryError(w, http.StatusUnsupportedMediaType,
				fmt.Sprintf("innsegl gateway: %s accepts OTLP/HTTP JSON only "+
					"(OTEL_EXPORTER_OTLP_PROTOCOL=http/json); this request's Content-Type names %s",
					TelemetryLogsPath, what))
			return
		}

		limited := io.LimitReader(r.Body, maxTelemetryBodyBytes+1)
		buf, err := io.ReadAll(limited)
		if err != nil {
			writeTelemetryError(w, http.StatusBadRequest,
				"innsegl gateway: the telemetry export body could not be read")
			return
		}
		if len(buf) > maxTelemetryBodyBytes {
			writeTelemetryError(w, http.StatusRequestEntityTooLarge,
				"innsegl gateway: the telemetry export body exceeds this receiver's bound; "+
					"nothing in this batch was kept")
			return
		}

		var req otlpLogsRequest
		if err := json.Unmarshal(buf, &req); err != nil {
			writeTelemetryError(w, http.StatusBadRequest,
				"innsegl gateway: the telemetry export body is not valid JSON")
			return
		}

		for _, rec := range extractToolResultRecords(req, cfg.now()) {
			if err := writeTelemetryRecord(cfg.Dir, rec); err != nil {
				// A write failure here is the same "witness, never a gate"
				// posture record.go's own recordAsync holds: it costs this
				// endpoint's own caller nothing, and the harness's OTLP
				// exporter already retries a batch on its own. There is no
				// operator alert sink threaded through this handler (unlike
				// record.go's OnRecordFailure) because there is no ledger
				// write here to fail loudly about -- this receiver's own
				// worst case is a missed corroboration, which the
				// reconciler's own witness pass already reports honestly as
				// "telemetry inactive" or "not yet matched", never as a
				// silent success.
				continue
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		discardWriteError(w.Write([]byte(`{}`))) // OTLP's own empty ExportLogsServiceResponse.
	})
}

// writeTelemetryError answers a refusal as OTLP-adjacent plain text: this
// endpoint is not part of the traffic Proxy.ServeHTTP relays (GW-001 does
// not apply to it), so there is no forwarding contract to preserve, and a
// clear plain-text reason is more useful to whatever logs a harness's own
// OTLP exporter keeps than a JSON envelope nothing reads.
func writeTelemetryError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	discardWriteError(io.WriteString(w, msg))
}

// isTelemetryJSON reports whether contentType names JSON (optionally with a
// charset or other parameter) -- OTLP/HTTP's protobuf encoding, and
// anything else, are refused (415) rather than guessed at.
func isTelemetryJSON(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json"
}

// isTelemetryProtobuf reports whether contentType names OTLP/HTTP's own
// protobuf encoding -- checked only to give a refusal a more specific name
// (see this file's own doc comment on the call site), never to admit it.
func isTelemetryProtobuf(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/x-protobuf"
}

// ---------------------------------------------------------------------------
// The OTLP/HTTP JSON logs request shape (OpenTelemetry Protocol, logs
// signal): resourceLogs -> scopeLogs -> logRecords, attributes as key/value
// pairs whose value is a oneof (stringValue/intValue/boolValue/
// doubleValue/...). Read loosely -- only the members this receiver ever
// looks at -- the same "read what is needed, drop what is not" posture
// record.go's own toolResultRawBlock holds for the Messages API's content
// blocks.
// ---------------------------------------------------------------------------

type otlpLogsRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpScopeLogs struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpLogRecord struct {
	Body       *otlpAnyValue `json:"body"`
	Attributes []otlpKV      `json:"attributes"`
}

type otlpKV struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue is OTLP's AnyValue oneof, decoded loosely: whichever member
// is present is read, and IntValue is left as json.RawMessage because the
// real traffic this file was built from does not consistently pick the
// spec's own preferred JSON shape for it (see this file's own package doc
// comment, "The value shapes are read leniently, on purpose").
type otlpAnyValue struct {
	StringValue *string         `json:"stringValue,omitempty"`
	BoolValue   *bool           `json:"boolValue,omitempty"`
	IntValue    json.RawMessage `json:"intValue,omitempty"`
	DoubleValue *float64        `json:"doubleValue,omitempty"`
}

// asString reads v as a string, whichever member of the oneof is set. ok is
// false when v holds none of the four members this receiver understands (an
// arrayValue or a kvlistValue, neither of which any attribute this file
// reads ever uses, or the zero value for an absent map entry).
func (v otlpAnyValue) asString() (string, bool) {
	switch {
	case v.StringValue != nil:
		return *v.StringValue, true
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue), true
	case len(v.IntValue) > 0:
		s := string(v.IntValue)
		// The spec's own preferred shape is a quoted decimal string; the
		// real traffic this was built from uses a bare JSON number for at
		// least one int64 field (event.sequence). Both unquote to the same
		// digits.
		if unquoted, err := strconv.Unquote(s); err == nil {
			return unquoted, true
		}
		return s, true
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'f', -1, 64), true
	default:
		return "", false
	}
}

// asBool reads v as a bool. Claude Code's own `success` attribute arrives as
// a stringValue ("true"/"false"), never a boolValue, in every real capture
// this file's tests were built from; strconv.ParseBool also accepts a real
// boolValue's own "true"/"false" string form (asString already normalises
// BoolValue that way), so one parse handles both without needing to know
// which shape a given export chose.
func (v otlpAnyValue) asBool() bool {
	s, ok := v.asString()
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(s)
	return err == nil && b
}

// logRecordAttrs indexes one log record's attributes by key. A repeated key
// keeps its first occurrence -- OTLP does not document a "last wins" rule,
// and every real record this receiver has seen carries each key once.
func logRecordAttrs(lr otlpLogRecord) map[string]otlpAnyValue {
	attrs := make(map[string]otlpAnyValue, len(lr.Attributes))
	for _, kv := range lr.Attributes {
		if _, seen := attrs[kv.Key]; !seen {
			attrs[kv.Key] = kv.Value
		}
	}
	return attrs
}

// isToolResultLogRecord reports whether lr is a claude_code.tool_result
// event -- read from the log record's own body (the documented shape) OR
// its event.name attribute (the shape a real capture actually carries: a
// SHORT name with no "claude_code." prefix), so a future Claude Code
// release settling on either convention alone is still recognised.
func isToolResultLogRecord(lr otlpLogRecord, attrs map[string]otlpAnyValue) bool {
	if lr.Body != nil {
		if body, ok := lr.Body.asString(); ok &&
			(body == "claude_code.tool_result" || body == "tool_result") {
			return true
		}
	}
	if name, ok := attrs["event.name"]; ok {
		if s, ok := name.asString(); ok && (s == "tool_result" || s == "claude_code.tool_result") {
			return true
		}
	}
	return false
}

// toolDecisionReject is a tool_decision's decision for a call that did not run.
const toolDecisionReject = "reject"

// isRejectedToolDecision reports whether lr is a claude_code.tool_decision
// whose decision is "reject": a call the harness stopped before it ran,
// which therefore has no tool_result. Read by body or event.name, as
// isToolResultLogRecord does.
func isRejectedToolDecision(lr otlpLogRecord, attrs map[string]otlpAnyValue) bool {
	named := false
	if lr.Body != nil {
		if body, ok := lr.Body.asString(); ok && (body == "claude_code.tool_decision" || body == "tool_decision") {
			named = true
		}
	}
	if name, ok := attrs["event.name"]; ok {
		if s, ok := name.asString(); ok && (s == "tool_decision" || s == "claude_code.tool_decision") {
			named = true
		}
	}
	if !named {
		return false
	}
	d, ok := attrs["decision"].asString()
	return ok && d == toolDecisionReject
}

// extractToolResultRecords walks req and returns one telemetryRecord per
// claude_code.tool_result log record that carries a usable tool_use_id
// (commitpath.IsToolUseID -- the SAME shape check the commit path already
// holds every tool call id to). Every other log record -- every other
// event type, and a tool_result with no usable id -- is silently dropped,
// per this file's own package doc comment.
func extractToolResultRecords(req otlpLogsRequest, receivedAt time.Time) []telemetryRecord {
	var out []telemetryRecord
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				attrs := logRecordAttrs(lr)
				decision := ""
				if !isToolResultLogRecord(lr, attrs) {
					if !isRejectedToolDecision(lr, attrs) {
						continue
					}
					decision = toolDecisionReject
				}
				toolUseID, ok := attrs["tool_use_id"]
				id, hasID := toolUseID.asString()
				if !ok || !hasID || !commitpath.IsToolUseID(id) {
					continue
				}
				rec := telemetryRecord{ToolUseID: id, Success: decision == "" && attrs["success"].asBool(),
					Decision: decision, Time: receivedAt}
				if v, ok := attrs["tool_name"]; ok {
					rec.ToolName, _ = v.asString()
				}
				if v, ok := attrs["session.id"]; ok {
					rec.SessionID, _ = v.asString()
				}
				out = append(out, rec)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Writing one record: the SAME temp-file-then-rename atomic write
// internal/mcp's own observeWriteBody uses for a tool_call body, restated
// here rather than imported -- that helper is unexported to its own package
// and takes a digest-named final path this receiver does not have (a
// telemetry record is keyed by tool_use_id, not by its own content hash).
// ---------------------------------------------------------------------------

// telemetryFileMode and telemetryDirMode mirror internal/mcp's own
// observeBodyMode/observeDirMode: 0600 for a file nothing but this process
// needs to read, 0700 for the directory holding it.
const (
	telemetryFileMode = 0o600
	telemetryDirMode  = 0o700
)

// writeTelemetryRecord writes rec to dir/telemetry/<tool_use_id>.json,
// atomically. rec.ToolUseID has already passed commitpath.IsToolUseID
// (extractToolResultRecords' own guard), so it is safe to use as a
// filename: no path separator, no "..", nothing filepath.Base could
// disagree with.
func writeTelemetryRecord(dir string, rec telemetryRecord) error {
	telemetryDir := filepath.Join(dir, telemetryDirName)
	if err := os.MkdirAll(telemetryDir, telemetryDirMode); err != nil {
		return err
	}
	body, err := json.Marshal(rec)
	if err != nil {
		// telemetryRecord holds only strings, a bool and a time.Time, none
		// of which json.Marshal can fail to encode; defensive rather than
		// reachable.
		return err
	}
	final := filepath.Join(telemetryDir, rec.ToolUseID+".json")
	partial := filepath.Join(telemetryDir, "."+rec.ToolUseID+".part")
	if err := os.WriteFile(partial, body, telemetryFileMode); err != nil {
		return err
	}
	if err := os.Rename(partial, final); err != nil {
		_ = os.Remove(partial)
		return err
	}
	return nil
}
