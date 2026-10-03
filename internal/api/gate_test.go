// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AUTH-001 (I): every read route and page with no session refuses; the
// allow-listed routes answer; a route registered without a decision is
// refused, proving deny-by-default rather than a list of routes somebody
// remembered to gate.

func TestAUTH001EveryReadRouteRefusesWithNoSession(t *testing.T) {
	srv, scenario := testServer(t)

	for _, path := range []string{
		"/api/v1/runs",
		"/api/v1/runs/run-000",
		"/api/v1/runs/run-000/log",
		"/api/v1/overview",
		"/api/v1/repos",
		"/api/v1/alerts",
		"/api/v1/attribution/" + scenario.commit + "?repo=" + fixtureRepo,
	} {
		a := get(t, srv.URL, path)
		if a.status != http.StatusUnauthorized {
			t.Errorf("GET %s with no session returned %d, want 401: %s", path, a.status, a.body)
		}
	}
}

func TestAUTH001AllowListedRoutesAnswerWithNoSession(t *testing.T) {
	srv, scenario := testServer(t)

	if a := get(t, srv.URL, "/api/v1/health"); a.status != http.StatusOK {
		t.Errorf("GET /api/v1/health with no session returned %d, want 200: %s", a.status, a.body)
	}
	if a := get(t, srv.URL, "/api/v1/proof/"+scenario.commit+"?repo="+fixtureRepo); a.status != http.StatusOK {
		t.Errorf("GET /api/v1/proof/... with no session returned %d, want 200: %s", a.status, a.body)
	}
}

// A route added to s.mux and left off authAllowedRoutes is refused, not
// silently admitted — the deny-by-default property itself, proved directly
// rather than inferred from the routes that happen to exist today.
func TestAUTH001ARouteRegisteredWithNoDecisionIsRefused(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	seed(t, owner, 3)
	store, _ := readStore(t, readerDSN)
	scenario := newProofScenario(t, proofOptions{})

	s, err := NewServer(ServerConfig{
		Store: store, Prover: scenario.prover(t),
		AuthStore: testAuthStore(t), WebAuthn: testWebAuthnConfig,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	reached := false
	s.mux.HandleFunc("GET /api/v1/__undecided_test_route", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/__undecided_test_route", nil)
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a route on the mux with no allow-list decision answered %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("the undecided route's own handler ran; deny-by-default must refuse " +
			"BEFORE the handler, not rely on the handler to refuse itself")
	}
}

func TestAUTH001ARouteOnTheMuxAndOnTheAllowListAnswersWithNoSession(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	seed(t, owner, 3)
	store, _ := readStore(t, readerDSN)
	scenario := newProofScenario(t, proofOptions{})

	s, err := NewServer(ServerConfig{
		Store: store, Prover: scenario.prover(t),
		AuthStore: testAuthStore(t), WebAuthn: testWebAuthnConfig,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.mux.HandleFunc("GET /api/v1/__decided_test_route", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	authAllowedRoutes["GET /api/v1/__decided_test_route"] = true
	t.Cleanup(func() { delete(authAllowedRoutes, "GET /api/v1/__decided_test_route") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/__decided_test_route", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("an explicitly allow-listed route answered %d with no session, want 200", rec.Code)
	}
}
