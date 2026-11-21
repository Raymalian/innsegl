// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// OAI-011/024: exercise both route families through normal relays, refusals,
// malformed bodies and outage journals. These are synthetic canaries only.
func TestOAI011ResponsesCredentialOutageAndDiagnosticMatrix(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses"} {
		for _, mode := range []string{"not-recorded", "refusal", "outage", "malformed"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				core, paths := enrolled(t)
				core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, _ *http.Request) {
					if _, err := io.WriteString(w, `{"formats":["responses-http"]}`); err != nil {
						t.Error(err)
					}
				})
				core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
				stream := "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n"
				core.Mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
					if mode == "refusal" {
						http.Error(w, "scope refused", http.StatusForbidden)
						return
					}
					w.Header().Set(clientjournal.RecordedHeader, clientjournal.RecordedFalse)
					w.Header().Set("Content-Type", "text/event-stream")
					if _, err := io.WriteString(w, stream); err != nil {
						t.Error(err)
					}
				})
				seen := make(chan http.Header, 1)
				provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Clone()
					w.Header().Set("Content-Type", "text/event-stream")
					if _, err := io.WriteString(w, stream); err != nil {
						t.Error(err)
					}
				}))
				defer provider.Close()
				srv, front, logs := startJournalClient(t, paths, nil, ServerOptions{})
				target, err := url.Parse(provider.URL)
				if err != nil {
					t.Fatal(err)
				}
				srv.providerClient = &http.Client{Transport: responsesProviderRouteTransport{target: target, base: provider.Client().Transport}}
				if !srv.responsesAvailable(httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)) {
					t.Fatal("missing capability")
				}
				if status, _, _ := postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil); status != http.StatusNoContent {
					t.Fatalf("statement=%d", status)
				}
				if mode == "outage" {
					core.Close()
				}
				requestBody := `{"input":"hello"}`
				if mode == "malformed" {
					requestBody = "{"
				}
				status, headers, body := postJSON(t, front.URL+path, requestBody, map[string]string{"Session-Id": jrnRepoSession, "Authorization": "Bearer synthetic-provider-canary", "ChatGPT-Account-ID": "synthetic-account-canary", "X-Gateway-Key": "synthetic-gateway-canary"})
				wantStatus := http.StatusOK
				if mode == "refusal" {
					wantStatus = http.StatusForbidden
				}
				if status != wantStatus {
					t.Fatalf("response=%d, want %d", status, wantStatus)
				}
				if mode == "outage" {
					h := <-seen
					if h.Get("Authorization") != "Bearer synthetic-provider-canary" || h.Get("X-Gateway-Key") != "" {
						t.Fatal("outage changed provider auth or leaked gateway key")
					}
					wantAccount := ""
					if strings.HasPrefix(path, "/backend-api/codex/") {
						wantAccount = "synthetic-account-canary"
					}
					if h.Get("ChatGPT-Account-ID") != wantAccount {
						t.Fatal("outage sent account identifier to wrong provider")
					}
				}
				key := installationKey(t, paths)
				entries := readJournal(t, paths, &key.PublicKey)
				wantEntries := 1
				if mode == "refusal" {
					wantEntries = 0
				}
				if len(entries) != wantEntries {
					t.Fatalf("journal entries=%d, want %d", len(entries), wantEntries)
				}
				retained, err := json.Marshal(entries)
				if err != nil {
					t.Fatal(err)
				}
				replyHeaders, err := json.Marshal(headers)
				if err != nil {
					t.Fatal(err)
				}
				all := string(retained) + string(replyHeaders) + body + logs.String()
				for _, canary := range []string{"synthetic-provider-canary", "synthetic-account-canary", "synthetic-gateway-canary"} {
					if strings.Contains(all, canary) {
						t.Fatal("credential retained or reflected")
					}
				}
			})
		}
	}
}
