// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
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
