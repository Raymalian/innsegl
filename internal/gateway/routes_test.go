// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OAI-010: Responses credentials must never go to the Messages upstream.
func TestOAI010ResponsesRoutesSelectOnlyConfiguredUpstream(t *testing.T) {
	var messages, responses int
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { messages++; discardWriteError(w.Write([]byte("wrong"))) }))
	defer a.Close()
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responses++
		if r.Header.Get("X-Gateway-Key") != "" {
			t.Error("gateway credential forwarded")
		}
		if r.Header.Get("Authorization") != "Bearer canary" {
			t.Error("lost provider authorization")
		}
		discardWriteError(w.Write([]byte("right")))
	}))
	defer b.Close()
	up, err := NewUpstream(a.URL, a.Client())
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewUpstream(b.URL, b.Client())
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Upstream: up, Guards: []Guard{}}
	// Configure through the production route constructor, not a body/header hint.
	h := ResponsesRoutes(p, api, api)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"hi"}`))
	r.Header.Set("Authorization", "Bearer canary")
	r.Header.Set("X-Gateway-Key", "gateway-canary")
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "right" || messages != 0 || responses != 1 {
		t.Fatalf("status=%d body=%q messages=%d responses=%d", w.Code, w.Body.String(), messages, responses)
	}
	for _, path := range []string{"/v1/responses/extra", "/backend-api/codex/other"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil))
		if w.Code < 400 {
			t.Fatalf("accepted %s", path)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/responses", nil))
	if w.Code < 400 {
		t.Fatal("accepted unsupported websocket/model GET")
	}
}
