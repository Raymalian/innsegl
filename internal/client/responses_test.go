// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OAI-023: a new client must not silently send new-format traffic to an
// old core as though it had been recorded.
func TestOAI023ResponsesRequiresCoreCapability(t *testing.T) {
	core, paths := enrolled(t)
	var forwarded bool
	core.Mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) { forwarded = true; w.WriteHeader(http.StatusOK) })
	_, front, _ := startClient(t, paths)
	status := scPost(t, front.URL+"/v1/responses", `{"input":"hello"}`, map[string]string{"Session-Id": scSession})
	if status != http.StatusNotImplemented || forwarded {
		t.Fatalf("status=%d forwarded=%v", status, forwarded)
	}
}

// OAI-009/023: route statements by the actual harness session, and preserve
// an explicit scope refusal rather than treating it as an outage.
func TestOAI009ResponsesCarriesStatementAndPreservesCoreRefusal(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{"formats": []string{"responses-http"}}); err != nil {
			return
		}
	})
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	var statement string
	core.Mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		statement = r.Header.Get(StatementHeader)
		w.WriteHeader(http.StatusForbidden)
	})
	_, front, _ := startClient(t, paths)
	scPost(t, front.URL+SessionStatementPath, `{"session_id":"`+scSession+`","cwd":"/w/app","repo":"github.com/acme/app","branch":"main","task":"t1"}`, nil)
	status := scPost(t, front.URL+"/v1/responses", `{"input":"hello"}`, map[string]string{"Session-Id": scSession})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d", status)
	}
	if got := decodeStatementHeader(t, statement); got["session_id"] != scSession {
		t.Fatalf("statement %v", got)
	}
}

// OAI-024: fallback chooses its fixed provider from the route, never from
// a header, and the original Claude fallback remains unchanged.
func TestOAI024ResponsesFallbackProviderSelection(t *testing.T) {
	core, paths := enrolled(t)
	_ = core
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer a.Close()
	srv, err := NewServerWith(paths, &syncWriter{}, ServerOptions{ProviderURL: a.URL, ProviderClient: a.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/v1/messages": a.URL, "/v1/responses": "https://api.openai.com", "/backend-api/codex/responses": "https://chatgpt.com"} {
		got := srv.providerForPath(path)
		if got.String() != want {
			t.Errorf("%s provider=%s want=%s", path, got, want)
		}
	}
}

// OAI-025: skipped/untrusted hooks must not silently turn a repository
// session into unrecorded traffic before its workspace is stated.
func TestOAI025ResponsesWithoutSessionHookDoesNotReachModel(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{"formats": []string{"responses-http"}}); err != nil {
			return
		}
	})
	var reached bool
	core.Mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) { reached = true; w.WriteHeader(http.StatusOK) })
	_, front, _ := startClient(t, paths)
	status := scPost(t, front.URL+"/v1/responses", `{"input":"hello"}`, map[string]string{"Session-Id": scSession})
	if status != http.StatusPreconditionRequired || reached {
		t.Fatalf("status=%d model reached=%v", status, reached)
	}
}

// OAI-023: a client advertises direct signing only when its enrolled core
// advertises it; an old capture-only core must not be treated as upgraded.
func TestOAI023SigningCapabilityComesFromCore(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "old", true: "new"}[supported], func(t *testing.T) {
			core, paths := enrolled(t)
			core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewEncoder(w).Encode(map[string]any{"formats": []string{"responses-http"}, "signing": supported, "signing_mode": "structured"}); err != nil {
					t.Error(err)
				}
			})
			_, front, _ := startClient(t, paths)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL+"/_client/capabilities", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var got struct {
				Signing bool `json:"signing"`
			}
			if err = json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Signing != supported {
				t.Fatalf("signing=%v want%v", got.Signing, supported)
			}
		})
	}
}

// OAI-006: child requests attach their own workspace statement using the
// measured shared session and distinct thread metadata.
func TestOAI006CodexMetadataSelectsChildStatement(t *testing.T) {
	const child = "22222222-2222-4222-8222-222222222222"
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"formats":["responses-http"]}`)); err != nil {
			t.Error(err)
		}
	})
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	var statement string
	core.Mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		statement = r.Header.Get(StatementHeader)
		w.WriteHeader(http.StatusNoContent)
	})
	_, front, _ := startClient(t, paths)
	scPost(t, front.URL+SessionStatementPath, `{"session_id":"`+scSession+`","cwd":"/w/root"}`, nil)
	scPost(t, front.URL+SessionStatementPath, `{"session_id":"`+scSession+`","agent_id":"`+child+`","cwd":"/w/child"}`, nil)
	status := scPost(t, front.URL+"/v1/responses", `{"input":"child"}`, map[string]string{"X-Codex-Turn-Metadata": `{"session_id":"` + scSession + `","thread_id":"` + child + `","agent_name":"/root/child"}`})
	if status != http.StatusNoContent {
		t.Fatalf("status=%d", status)
	}
	if got := decodeStatementHeader(t, statement); got["agent_id"] != child || got["cwd"] != "/w/child" {
		t.Fatalf("child lost statement: %v", got)
	}
}

func TestOAI006CodexMetadataAtCoreLimitStillSelectsChildStatement(t *testing.T) {
	const child = "22222222-2222-4222-8222-222222222222"
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"formats":["responses-http"]}`)); err != nil {
			t.Error(err)
		}
	})
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	var statement string
	core.Mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		statement = r.Header.Get(StatementHeader)
		w.WriteHeader(http.StatusNoContent)
	})
	_, front, _ := startClient(t, paths)
	scPost(t, front.URL+SessionStatementPath, `{"session_id":"`+scSession+`","agent_id":"`+child+`","cwd":"/w/child"}`, nil)
	metadata := `{"session_id":"` + scSession + `","thread_id":"` + child + `","agent_name":"/root/child","padding":"` + strings.Repeat("x", 9000) + `"}`
	status := scPost(t, front.URL+"/v1/responses", `{"input":"child"}`, map[string]string{"X-Codex-Turn-Metadata": metadata})
	if status != http.StatusNoContent {
		t.Fatalf("status=%d", status)
	}
	if got := decodeStatementHeader(t, statement); got["agent_id"] != child || got["cwd"] != "/w/child" {
		t.Fatalf("child statement lost at metadata size accepted by core: %v", got)
	}
}

// OAI-006/023: a new client never enables children against a root-only core.
func TestOAI006ChildCapabilityComesFromCore(t *testing.T) {
	for _, mode := range []string{"root-only", "linked-threads"} {
		t.Run(mode, func(t *testing.T) {
			core, paths := enrolled(t)
			core.Mux.HandleFunc("/_gateway/capabilities", func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewEncoder(w).Encode(map[string]any{"formats": []string{"responses-http"}, "agents": mode}); err != nil {
					t.Error(err)
				}
			})
			_, front, _ := startClient(t, paths)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+"/_client/capabilities", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var caps struct {
				Agents string `json:"agents"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
				t.Fatal(err)
			}
			if caps.Agents != mode {
				t.Fatalf("agents=%s want=%s", caps.Agents, mode)
			}
		})
	}
}
