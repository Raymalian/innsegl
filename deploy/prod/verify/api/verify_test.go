// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// This file tests only what belongs to this thin wrapper: that a missing
// Fulcio/Rekor configuration is refused with a 500 rather than a panic or a
// silently-broken handler, and that a valid configuration is wired through
// to internal/edge (proven by a request internal/edge's own tests already
// cover the meaning of — a malformed sha, refused with 400). The verdict
// logic itself is internal/edge's, and its tests are edge_test.go's, not
// this file's to repeat.

func TestHandlerRefusesAMissingFulcioOrRekorConfiguration(t *testing.T) {
	for _, key := range []string{"INNSEGL_FULCIO_URL", "INNSEGL_REKOR_URL"} {
		t.Setenv(key, "")
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha=abc1234", nil)
	rec := httptest.NewRecorder()
	Handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestHandlerWiresAValidConfigurationThroughToEdge(t *testing.T) {
	fulcio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fulcio.Close()
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rekor.Close()

	t.Setenv("INNSEGL_FULCIO_URL", fulcio.URL)
	t.Setenv("INNSEGL_REKOR_URL", rekor.URL)
	// A malformed sha never reaches GitHub or Fulcio/Rekor at all; a 400
	// here proves this file's env wiring reached edge.New successfully
	// (New would have returned an error, and this would be a 500, if it had
	// not) and that ServeHTTP is the one answering.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha=not-hex!!", nil)
	rec := httptest.NewRecorder()
	Handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestMain(m *testing.M) {
	// Never let a developer's ambient GITHUB_TOKEN or INNSEGL_* leak into
	// these tests: each one sets exactly the environment it means to test.
	for _, key := range []string{
		"INNSEGL_FULCIO_URL", "INNSEGL_REKOR_URL", "INNSEGL_OIDC_ISSUER",
		"INNSEGL_VERIFY_REPO", "GITHUB_TOKEN",
	} {
		os.Unsetenv(key)
	}
	os.Exit(m.Run())
}
