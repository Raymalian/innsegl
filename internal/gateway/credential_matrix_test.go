// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// OAI-011/024: authentication follows its selected route. The account
// identifier belongs to ChatGPT, not the API-key route; gateway keys stay local.
func TestOAI011CredentialRoutesAndDownstreamReplies(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/v1/models", "/backend-api/codex/responses", "/backend-api/codex/models"} {
		t.Run(path, func(t *testing.T) {
			seen := make(chan http.Header, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, `{"result":"ok"}`); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			provider, err := NewUpstream(upstream.URL, upstream.Client())
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(ResponsesRoutes(&Proxy{Guards: []Guard{}}, provider, provider))
			defer front.Close()
			method := http.MethodPost
			if strings.HasSuffix(path, "/models") {
				method = http.MethodGet
			}
			req, err := http.NewRequestWithContext(t.Context(), method, front.URL+path, strings.NewReader(`{"input":"hello"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer synthetic-provider-canary")
			req.Header.Set("ChatGPT-Account-ID", "synthetic-account-canary")
			req.Header.Set("X-Gateway-Key", "synthetic-gateway-canary")
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			header := <-seen
			if header.Get("Authorization") != "Bearer synthetic-provider-canary" || header.Get("X-Gateway-Key") != "" {
				t.Fatal("provider credential changed or gateway key escaped")
			}
			wantAccount := ""
			if strings.HasPrefix(path, "/backend-api/codex/") {
				wantAccount = "synthetic-account-canary"
			}
			if header.Get("ChatGPT-Account-ID") != wantAccount {
				t.Fatal("account identifier reached the wrong authentication route")
			}
			retained, err := json.Marshal(response.Header)
			if err != nil {
				t.Fatal(err)
			}
			for _, canary := range []string{"synthetic-provider-canary", "synthetic-account-canary", "synthetic-gateway-canary"} {
				if strings.Contains(string(retained)+string(body), canary) {
					t.Fatal("credential reflected downstream")
				}
			}
		})
	}
}

// OAI-011/018: even a signed journal with unexpected headers is sanitized
// again at import; replay never needs provider credentials or upstream traffic.
func TestOAI011JournalImportRechecksCredentialHeaders(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses"} {
		t.Run(path, func(t *testing.T) {
			calls := 0
			p := &Proxy{Guards: []Guard{guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
				calls++
				for _, name := range []string{"Authorization", "ChatGPT-Account-ID", "X-Gateway-Key"} {
					if r.Header.Get(name) != "" {
						t.Error("import retained credential header", name)
					}
				}
				return r, nil
			})}}
			importer := &JournalImporter{replayer: p}
			e := clientjournal.Entry{Method: http.MethodPost, Path: path, RequestBody: []byte(`{"input":"hello"}`), RequestHeaders: http.Header{"Authorization": {"Bearer synthetic-provider-canary"}, "Chatgpt-Account-Id": {"synthetic-account-canary"}, "X-Gateway-Key": {"synthetic-gateway-canary"}}, ResponseHeaders: http.Header{"Content-Type": {"text/event-stream"}}, ResponseBody: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")}
			outcome, err := importer.replay(t.Context(), "installation-test", "sha256:"+strings.Repeat("a", 64), e)
			if err != nil || outcome.Refusal != nil || calls != 1 {
				t.Fatalf("sanitized replay failed: %+v %v, guard calls=%d", outcome, err, calls)
			}
		})
	}
}
