// SPDX-License-Identifier: Apache-2.0

package clientjournal

import (
	"net/http"
	"testing"
)

// OAI-011: an account identifier or gateway token must never be persisted
// in an outage journal, while encoding and session facts survive replay.
func TestOAI011KeptHeadersRemoveOpenAIAccountAndGatewayCredentials(t *testing.T) {
	h := http.Header{
		"Authorization":      {"Bearer canary-provider"},
		"Chatgpt-Account-Id": {"canary-account"},
		"X-Gateway-Key":      {"canary-gateway"},
		"Content-Encoding":   {"zstd"},
		"Session-Id":         {"11111111-1111-4111-8111-111111111111"},
	}
	kept := KeptHeaders(h)
	for _, name := range []string{"Authorization", "ChatGPT-Account-ID", "X-Gateway-Key"} {
		if kept.Get(name) != "" {
			t.Errorf("retained sensitive header %s", name)
		}
	}
	if kept.Get("Content-Encoding") != "zstd" || kept.Get("Session-Id") != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("lost replay metadata")
	}
	if h.Get("ChatGPT-Account-ID") != "canary-account" {
		t.Fatal("changed forwarded headers")
	}
}
