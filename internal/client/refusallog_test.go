// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The core's refusal names no cause, on purpose. The client service passes it
// on unchanged and says in its own log what it knows: which session, and
// where to look. The core's own 503 is an outage (ADR-0068): the request
// goes to the provider, and the log names the core's answer.
func TestCoreRefusalPassesUnchangedAndIsExplainedInTheLog(t *testing.T) {
	core, paths := enrolled(t)
	const session = "11111111-1111-4111-8111-111111111111"
	cases := []struct {
		status     int
		body       string
		wantStatus int
		wantBody   string
		wantLogs   []string
	}{
		{http.StatusUnauthorized, `{"error":"innsegl core: request refused"}`,
			http.StatusUnauthorized, `{"error":"innsegl core: request refused"}`,
			[]string{session, "401", "certificate", "scope"}},
		{http.StatusServiceUnavailable, `{"error":"innsegl gateway: a dependency could not be reached (retrying)"}`,
			http.StatusOK, jrnSSE,
			[]string{session, "503", "a dependency could not be reached", "provider directly"}},
	}
	var next int
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		tc := cases[next]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tc.status)
		fmt.Fprint(w, tc.body)
	})
	_, front, logs := startJournalClient(t, paths, newProvider(t), ServerOptions{})
	for i, tc := range cases {
		next = i
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+"/v1/messages", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Claude-Code-Session-Id", session)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := string(readAll(t, resp.Body))
		_ = resp.Body.Close()
		if resp.StatusCode != tc.wantStatus || body != tc.wantBody {
			t.Fatalf("the harness got %d %q, want %d %q", resp.StatusCode, body, tc.wantStatus, tc.wantBody)
		}
		for _, want := range tc.wantLogs {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("the log %q does not say %q", logs.String(), want)
			}
		}
	}
}
