// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// RM-189 — the health response says whether the service is up, and nothing
// about which repositories it serves. Anyone who can reach a health probe
// could otherwise read the deployment's list of projects off it.
func TestRM189HealthResponseNamesNoRepository(t *testing.T) {
	srv, _ := testServer(t)

	a := get(t, srv.URL, "/api/v1/health")
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/health: %d", a.status)
	}
	if bytes.Contains(a.body, []byte(fixtureRepo)) {
		t.Errorf("the health response names the served repository %q:\n%s", fixtureRepo, a.body)
	}

	var fields map[string]json.RawMessage
	decodeBody(t, a, &fields)
	if _, ok := fields["repos"]; ok {
		t.Errorf("the health response carries a %q field:\n%s", "repos", a.body)
	}
}
