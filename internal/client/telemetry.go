// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
)

// Telemetry: the harness's OTLP log exports. Telemetry is the harness's own
// witness of each tool call (internal/gateway/witness.go); an export lost in
// an outage made every tool call in it a "no telemetry" drift alert, and
// Claude Code does not resend one. An export the core does not take is held
// in the outbox (outbox.go) and delivered once it answers.

// TelemetryLogsPath is where the harness exports its log records.
const TelemetryLogsPath = "/v1/logs"

// maxTelemetryExportBytes bounds one export.
const maxTelemetryExportBytes = 4 << 20

// serveTelemetry forwards an export to the core, and holds it when the core
// does not take it now, answering the harness as an OTLP success either way.
func (s *Server) serveTelemetry(w http.ResponseWriter, r *http.Request) {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		http.Error(w, "innsegl client: the telemetry receiver accepts OTLP/HTTP JSON only", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTelemetryExportBytes+1))
	if err != nil || len(body) > maxTelemetryExportBytes {
		http.Error(w, "innsegl client: the telemetry export could not be read", http.StatusBadRequest)
		return
	}
	body, err = scrubTelemetryExport(body)
	if err != nil {
		http.Error(w, "innsegl client: the telemetry export is not valid OTLP/HTTP JSON", http.StatusBadRequest)
		return
	}
	status, err := s.liveToCore(r, TelemetryLogsPath, body)
	switch {
	case err == nil && status/100 == 2:
		writeOTLPSuccess(w)
		return
	case err == nil && refusedForGood(status):
		s.log.Printf("the core refused a telemetry export (%d); it is not held", status)
		http.Error(w, fmt.Sprintf("innsegl client: the core refused the telemetry export (%d)", status), status)
		return
	}
	if herr := s.outbox.hold(KindTelemetry, body); herr != nil {
		s.log.Printf("the core did not take a telemetry export and it could not be held: %v", herr)
		http.Error(w, "innsegl client: the telemetry export could not be delivered or held", http.StatusServiceUnavailable)
		return
	}
	writeOTLPSuccess(w)
}

type telemetryExport struct {
	ResourceLogs []telemetryResourceLogs `json:"resourceLogs"`
}

type telemetryResourceLogs struct {
	ScopeLogs []telemetryScopeLogs `json:"scopeLogs"`
}

type telemetryScopeLogs struct {
	LogRecords []telemetryInputRecord `json:"logRecords"`
}

type telemetryInputRecord struct {
	Body       map[string]json.RawMessage `json:"body"`
	Attributes []telemetryInputAttribute  `json:"attributes"`
}

type telemetryInputAttribute struct {
	Key   string                     `json:"key"`
	Value map[string]json.RawMessage `json:"value"`
}

type telemetrySafeRecord struct {
	Body       map[string]string        `json:"body"`
	Attributes []telemetrySafeAttribute `json:"attributes"`
}

type telemetrySafeExport struct {
	ResourceLogs []telemetrySafeResourceLogs `json:"resourceLogs"`
}

type telemetrySafeResourceLogs struct {
	ScopeLogs []telemetrySafeScopeLogs `json:"scopeLogs"`
}

type telemetrySafeScopeLogs struct {
	LogRecords []telemetrySafeRecord `json:"logRecords"`
}

type telemetrySafeAttribute struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

func otlpStringValue(value map[string]json.RawMessage) (string, bool) {
	raw, ok := value["stringValue"]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func otlpNamedEvent(body map[string]json.RawMessage, attrs map[string]map[string]json.RawMessage) string {
	bodyName, _ := otlpStringValue(body)
	attrName, _ := otlpStringValue(attrs["event.name"])
	for _, candidate := range []string{bodyName, attrName} {
		switch candidate {
		case "codex.tool_result", "codex.tool_decision", "claude_code.tool_result", "tool_result", "claude_code.tool_decision", "tool_decision":
			return candidate
		}
	}
	return ""
}

// scrubTelemetryExport keeps only tool-call correlation fields that the
// reconciler can use. Codex includes command arguments, tool output, and
// account attributes in its OTLP export; those must not enter the durable
// outage outbox or be retained by the core.
func scrubTelemetryExport(body []byte) ([]byte, error) {
	var input telemetryExport
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, err
	}
	output := telemetrySafeExport{ResourceLogs: make([]telemetrySafeResourceLogs, 0, len(input.ResourceLogs))}
	for _, rl := range input.ResourceLogs {
		safeRL := telemetrySafeResourceLogs{ScopeLogs: make([]telemetrySafeScopeLogs, 0, len(rl.ScopeLogs))}
		for _, sl := range rl.ScopeLogs {
			safeSL := telemetrySafeScopeLogs{LogRecords: make([]telemetrySafeRecord, 0, len(sl.LogRecords))}
			for _, rec := range sl.LogRecords {
				attrs := make(map[string]map[string]json.RawMessage, len(rec.Attributes))
				for _, attr := range rec.Attributes {
					if _, exists := attrs[attr.Key]; !exists {
						attrs[attr.Key] = attr.Value
					}
				}
				eventName := otlpNamedEvent(rec.Body, attrs)
				codex := strings.HasPrefix(eventName, "codex.")
				resultEvent := eventName == "codex.tool_result" || eventName == "claude_code.tool_result" || eventName == "tool_result"
				decisionEvent := eventName == "codex.tool_decision" || eventName == "claude_code.tool_decision" || eventName == "tool_decision"
				if !resultEvent && !decisionEvent {
					continue
				}
				idKey, sessionKey, prefix := "tool_use_id", "session.id", "toolu_"
				if codex {
					idKey, sessionKey, prefix = "call_id", "conversation.id", "call_"
				}
				id, hasID := otlpStringValue(attrs[idKey])
				if !hasID || !strings.HasPrefix(id, prefix) || !commitpath.IsToolUseID(id) {
					continue
				}
				if decisionEvent {
					decision, ok := otlpStringValue(attrs["decision"])
					if !ok || (codex && decision != "denied" && decision != "abort") || (!codex && decision != "reject") {
						continue
					}
				}
				safe := telemetrySafeRecord{Body: map[string]string{"stringValue": eventName}, Attributes: make([]telemetrySafeAttribute, 0, 6)}
				add := func(key string) {
					if value, ok := attrs[key]; ok {
						if raw, err := json.Marshal(value); err == nil {
							safe.Attributes = append(safe.Attributes, telemetrySafeAttribute{Key: key, Value: raw})
						}
					}
				}
				// Canonical event name goes first, so later consumers need not
				// carry harness- or exporter-specific conventions forward.
				safe.Attributes = append(safe.Attributes, telemetrySafeAttribute{Key: "event.name", Value: json.RawMessage(`{"stringValue":` + strconv.Quote(eventName) + `}`)})
				add(idKey)
				add("tool_name")
				add("success")
				add("decision")
				add(sessionKey)
				safeSL.LogRecords = append(safeSL.LogRecords, safe)
			}
			if len(safeSL.LogRecords) > 0 {
				safeRL.ScopeLogs = append(safeRL.ScopeLogs, safeSL)
			}
		}
		if len(safeRL.ScopeLogs) > 0 {
			output.ResourceLogs = append(output.ResourceLogs, safeRL)
		}
	}
	return json.Marshal(output)
}

// liveToCore sends a live telemetry export or end to the core, unless the
// core is known to be down: a live request is never held up by a core that
// does not answer. When the core takes it, the delivery loop is woken.
func (s *Server) liveToCore(r *http.Request, path string, body []byte) (int, error) {
	if s.coreDown() {
		return 0, errors.New("the core did not answer a moment ago")
	}
	status, err := s.sendToCore(r.Context(), path, body, r.Header.Get("Content-Type"))
	if err == nil && status/100 == 2 {
		s.kickOutbox()
	}
	return status, err
}

func writeOTLPSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("{}")); err != nil {
		return
	}
}
