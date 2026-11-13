// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
	"time"
)

// OAI-004: a result without a wire success flag must not be shown as OK.
func TestOAI004UnknownWireOutcomeIsNotSuccess(t *testing.T) {
	var body gatewayBody
	if err := json.Unmarshal([]byte(`{"tool":"exec","result_observed":true,"result":"done","error_signal":"unknown"}`), &body); err != nil {
		t.Fatal(err)
	}
	if got := outcomeOf("exec", body); got.Kind != "unknown" || got.ExitCode != nil {
		t.Fatalf("outcome %+v", got)
	}
}

// OAI-019/025: the run record preserves why capture was incomplete without
// presenting an observation note as executable input or tool output.
func TestOAI025RunRecordKeepsMissingResponseContextReason(t *testing.T) {
	dir := t.TempDir()
	note := "the previous Responses context was not observed; recorded with input unknown"
	body, err := json.Marshal(map[string]any{"tool": "exec_command", "tool_use_id": "call_context_gap", "observation_incomplete": true, "result_observed": false, "note": note})
	if err != nil {
		t.Fatal(err)
	}
	digest := writeBodyFile(t, dir, "run-context-gap", body)
	row := recordEventRow{EventType: "tool_call", EventID: "event-context-gap", Body: map[string]any{"payload_digest": digest, "tool_name": "exec_command"}}
	steps, _, _, _ := (&recordServer{}).buildSteps(t.Context(), "run-context-gap", registeredFields{}, []recordEventRow{row}, nil, nil, nil, dir, time.Now())
	raw, err := json.Marshal(steps)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0]["observation_gap"] != note || result[0]["input"] != "" || result[0]["output"] != "" {
		t.Fatalf("missing context reason was lost or shown as tool data: %s", raw)
	}
}

func TestOAI025MissingHistoryKeepsCurrentCommandAndContextWarning(t *testing.T) {
	dir := t.TempDir()
	note := "the previous Responses context was not observed; the current call was observed"
	body := []byte(`{"tool":"exec_command","tool_use_id":"call_current_context","context_incomplete":true,"input":{"cmd":"echo current"},"result_observed":false,"note":"` + note + `"}`)
	digest := writeBodyFile(t, dir, "run-current-context", body)
	row := recordEventRow{EventType: "tool_call", EventID: "event-current-context", Body: map[string]any{"payload_digest": digest, "tool_name": "exec_command"}}
	steps, _, _, _ := (&recordServer{}).buildSteps(t.Context(), "run-current-context", registeredFields{}, []recordEventRow{row}, nil, nil, nil, dir, time.Now())
	if len(steps) != 1 || steps[0].ObservationIncomplete || steps[0].ObservationGap != note || steps[0].Input != `{"cmd":"echo current"}` {
		t.Fatalf("missing historical context erased or hid the current command: %+v", steps)
	}
}
