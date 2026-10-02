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
// where to look.
func TestCoreRefusalPassesUnchangedAndIsExplainedInTheLog(t *testing.T) {
	core, paths := enrolled(t)
	const session = "11111111-1111-4111-8111-111111111111"
	cases := []struct {
		status   int
		body     string
		wantLogs []string
	}{
		{http.StatusUnauthorized, `{"error":"innsegl core: request refused"}`,
			[]string{session, "401", "certificate", "scope"}},
		{http.StatusServiceUnavailable, `{"error":"innsegl gateway: a dependency could not be reached (retrying)"}`,
			[]string{session, "503", "a dependency could not be reached"}},
	}
	var next int
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		tc := cases[next]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tc.status)
		fmt.Fprint(w, tc.body)
	})
	_, front, logs := startClient(t, paths)
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
		if resp.StatusCode != tc.status || body != tc.body {
			t.Fatalf("the harness got %d %q, want the core's %d %q unchanged", resp.StatusCode, body, tc.status, tc.body)
		}
		for _, want := range tc.wantLogs {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("the log %q does not say %q", logs.String(), want)
			}
		}
	}
}
