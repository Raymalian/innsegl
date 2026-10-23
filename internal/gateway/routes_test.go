// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestOAI006ResponsesCapabilitiesAdvertiseLinkedThreads(t *testing.T) {
	recorder := httptest.NewRecorder()
	ResponsesCapabilities(recorder, httptest.NewRequestWithContext(context.Background(), "GET", "/_gateway/capabilities", nil))
	var capabilities struct {
		Agents string `json:"agents"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.Agents != "linked-threads" {
		t.Fatalf("agents capability=%q, want linked-threads", capabilities.Agents)
	}
}
