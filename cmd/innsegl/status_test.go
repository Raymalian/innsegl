// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client/clienttest"
)

// statusFixture is an enrolled machine whose core answers status with
// components, and whose local client service answers or not.
func statusFixture(t *testing.T, components string, serviceUp bool) statusDeps {
	t.Helper()
	f := newConnectFixture(t)
	f.core.Mux.HandleFunc(coreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"version":"v0.4.0","components":`+components+`,`+
			`"installation":{"id":"inst-1","name":"dev-laptop","kind":"workstation","status":"active",`+
			`"organisation":"example-org","repos":["*"]}}`); err != nil {
			t.Error(err)
		}
	})
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	local := "http://127.0.0.1:1" // nothing listens
	if serviceUp {
		svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, `{"core_reachable":true,"revoked":false,"certificate_expires_at":"2026-10-04T00:00:00Z"}`); err != nil {
				t.Error(err)
			}
		}))
		t.Cleanup(svc.Close)
		local = svc.URL
	}
	return statusDeps{home: f.home, localURL: local}
}

// #472: one command says what is up, what is down, the versions and the
// machine's scope.
func TestStatusSaysEverythingIsUp(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true},{"name":"sigstore","up":true}]`, true)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, errOut.String())
	}
	for _, want := range []string{"client service", "up", "core", "v0.4.0", "ledger", "sigstore",
		"dev-laptop", "workstation", "example-org", "all repositories"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}

// Anything down is named, and the exit is non-zero.
func TestStatusNamesWhatIsDown(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true},{"name":"sigstore","up":false}]`, false)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code == exitOK {
		t.Fatalf("exit 0 with sigstore and the client service down; stdout:\n%s", out.String())
	}
	if got := errOut.String(); !strings.Contains(got, "down: client service, sigstore") {
		t.Errorf("stderr does not name what is down:\n%s", got)
	}
}
