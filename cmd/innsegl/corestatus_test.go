// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/accounts"
)

// #472: a machine asks the core, over its own certificate, what is up and
// what it may do. The core answers its version, its own readiness checks
// and the asking machine's installation.
func TestTheCoreAnswersItsStatusToAnEnrolledMachine(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := io.WriteString(w, `{"ready":false,"dependencies":[`+
			`{"dependency":"ledger","reachable":true},{"dependency":"sigstore","reachable":false}]}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(ready.Close)
	t.Setenv(envMCPHealthListen, strings.TrimPrefix(ready.URL, "http://"))

	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	_, cert := enrol(t, f, g, c)

	get := func(client *http.Client) (int, []byte) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+g.addr+coreStatusPath, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, b
	}

	if status, _ := get(g.client(t, nil)); status != http.StatusUnauthorized {
		t.Fatalf("status without a certificate: %d, want 401", status)
	}
	status, body := get(g.client(t, cert))
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	var got coreStatus
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("status body %s: %v", body, err)
	}
	if got.Version == "" {
		t.Error("no version")
	}
	want := map[string]bool{"ledger": true, "sigstore": false}
	if len(got.Components) != 2 {
		t.Fatalf("components = %+v", got.Components)
	}
	for _, comp := range got.Components {
		if up, ok := want[comp.Name]; !ok || up != comp.Up {
			t.Errorf("component %+v, want %v", comp, want)
		}
	}
	if got.Installation.ID != c.id || got.Installation.Status != accounts.StatusActive || got.Installation.Organisation == "" {
		t.Errorf("installation = %+v", got.Installation)
	}
}
