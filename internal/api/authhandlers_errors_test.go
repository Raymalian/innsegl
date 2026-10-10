// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Coverage for the sign-in surface's own refusal and error paths — every
// malformed/oversized/wrong-method/missing-ceremony/bad-credential case
// serveAuth and its handlers answer, plus the handful of DB-error branches
// a closed AuthStore pool can provoke honestly (see authstore_errors_test.go
// for why a closed pool is the uniform choice here too).

// ---------------------------------------------------------------------------
// decodeAuthRequest — a direct, unexported-function test, since every POST
// handler shares this exact body-parsing logic and a bug here would fail
// all four the same way.
// ---------------------------------------------------------------------------

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom: the body could not be read") }

func TestDecodeAuthRequestRefusesABodyItCannotRead(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", errReader{})
	var into map[string]string
	if decodeAuthRequest(rec, req, &into) {
		t.Fatal("decodeAuthRequest accepted a body it could not read")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeAuthRequestRefusesAnOversizedBody(t *testing.T) {
	huge := strings.Repeat("a", maxAuthRequestBodyBytes+1)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", strings.NewReader(huge))
	var into map[string]string
	if decodeAuthRequest(rec, req, &into) {
		t.Fatal("decodeAuthRequest accepted a body over the bound")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestDecodeAuthRequestRefusesMalformedJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", strings.NewReader("{not json"))
	var into map[string]string
	if decodeAuthRequest(rec, req, &into) {
		t.Fatal("decodeAuthRequest accepted malformed JSON")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeAuthRequestAcceptsAnEmptyBodyAsAnEmptyObject(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", strings.NewReader(""))
	var into struct {
		Code string `json:"code"`
	}
	if !decodeAuthRequest(rec, req, &into) {
		t.Fatal("decodeAuthRequest refused an empty body, want it treated as {}")
	}
	if into.Code != "" {
		t.Errorf("Code = %q, want empty", into.Code)
	}
}

func TestDecodeAuthRequestAcceptsValidJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x",
		strings.NewReader(`{"code":"abc"}`))
	var into struct {
		Code string `json:"code"`
	}
	if !decodeAuthRequest(rec, req, &into) {
		t.Fatal("decodeAuthRequest refused valid JSON")
	}
	if into.Code != "abc" {
		t.Errorf("Code = %q, want %q", into.Code, "abc")
	}
}

// ---------------------------------------------------------------------------
// serveAuth — the method guard and the OPTIONS short-circuit, neither of
// which any ceremony test happens to exercise.
// ---------------------------------------------------------------------------

func TestServeAuthRefusesAMethodNoRouteAccepts(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodPut, srv.URL+"/api/v1/auth/session", "")
	if a.status != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /api/v1/auth/session = %d, want %d", a.status, http.StatusMethodNotAllowed)
	}
	if allow := a.header.Get("Allow"); !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
		t.Errorf("Allow = %q, want it to name GET and POST", allow)
	}
}

func TestServeAuthAnswersOPTIONSWithNoSessionAndNoBody(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodOptions, srv.URL+"/api/v1/auth/login/begin", "")
	if a.status != http.StatusNoContent {
		t.Fatalf("OPTIONS /api/v1/auth/login/begin = %d, want %d", a.status, http.StatusNoContent)
	}
	if allow := a.header.Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow = %q, want it to name POST", allow)
	}
	if len(a.body) != 0 {
		t.Errorf("OPTIONS carried a body: %q", a.body)
	}
}

// ---------------------------------------------------------------------------
// handleAuthSession — no session, either because there is no cookie or
// because the cookie names nothing live.
// ---------------------------------------------------------------------------

func TestHandleAuthSessionWithNoCookie(t *testing.T) {
	srv, _ := testServer(t)
	a := get(t, srv.URL, "/api/v1/auth/session")
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/session = %d, want %d", a.status, http.StatusOK)
	}
	var status SessionStatus
	decodeBody(t, a, &status)
	if status.Authenticated {
		t.Error("Authenticated = true with no cookie at all")
	}
}

func TestHandleAuthSessionWithAGarbageCookie(t *testing.T) {
	srv, _ := testServer(t)
	garbage := &http.Cookie{Name: sessionCookieName, Value: "not-a-real-session-token"}
	a := get(t, srv.URL, "/api/v1/auth/session", garbage)
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/session = %d, want %d", a.status, http.StatusOK)
	}
	var status SessionStatus
	decodeBody(t, a, &status)
	if status.Authenticated {
		t.Error("Authenticated = true with a cookie naming no live session")
	}
}

// ---------------------------------------------------------------------------
// handleEnrolBegin
// ---------------------------------------------------------------------------

func TestHandleEnrolBeginRefusesAnEmptyDisplayName(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), authCeremonyTTL)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "", code))
	if a.status != http.StatusBadRequest {
		t.Fatalf("enrol/begin with an empty display_name returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandleEnrolBeginReportsAnEnrolmentOpenDatabaseError(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	authStore.Close()

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", "any-code"))
	if a.status != http.StatusInternalServerError {
		t.Fatalf("enrol/begin against a closed store returned %d, want %d: %s",
			a.status, http.StatusInternalServerError, a.body)
	}
}

// ---------------------------------------------------------------------------
// handleEnrolFinish
// ---------------------------------------------------------------------------

func TestHandleEnrolFinishRefusesAnUnknownCeremony(t *testing.T) {
	srv, _, _ := testServerConfigured(t)
	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": "no-such-ceremony",
		"credential":  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/finish", string(finishBody))
	if a.status != http.StatusUnauthorized {
		t.Fatalf("enrol/finish with an unknown ceremony returned %d, want %d: %s",
			a.status, http.StatusUnauthorized, a.body)
	}
}

func TestHandleEnrolFinishRefusesAMalformedCredential(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), authCeremonyTTL)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}
	begin := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", code))
	if begin.status != http.StatusOK {
		t.Fatalf("enrol/begin: %d: %s", begin.status, begin.body)
	}
	var creation ceremonyResponse
	if jerr := json.Unmarshal(begin.body, &creation); jerr != nil {
		t.Fatalf("decoding enrol/begin: %v", jerr)
	}

	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": creation.CeremonyID,
		"credential":  json.RawMessage(`{"this is":"not a webauthn credential"}`),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	finish := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/finish", string(finishBody))
	if finish.status != http.StatusUnauthorized {
		t.Fatalf("enrol/finish with a malformed credential returned %d, want %d: %s",
			finish.status, http.StatusUnauthorized, finish.body)
	}
}

// ---------------------------------------------------------------------------
// handleLoginBegin
// ---------------------------------------------------------------------------

func TestHandleLoginBeginReportsASaveCeremonyDatabaseError(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	authStore.Close()

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/begin", "{}")
	if a.status != http.StatusInternalServerError {
		t.Fatalf("login/begin against a closed store returned %d, want %d: %s",
			a.status, http.StatusInternalServerError, a.body)
	}
}

// ---------------------------------------------------------------------------
// handleLogout
// ---------------------------------------------------------------------------

func TestHandleLogoutWithNoCookieIsStillOK(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/logout", "")
	if a.status != http.StatusOK {
		t.Fatalf("logout with no cookie returned %d, want %d: %s", a.status, http.StatusOK, a.body)
	}
}

func TestHandleLogoutWithAGarbageCookieIsStillOK(t *testing.T) {
	srv, _ := testServer(t)
	garbage := &http.Cookie{Name: sessionCookieName, Value: "not-a-real-session-token"}
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/logout", "", garbage)
	if a.status != http.StatusOK {
		t.Fatalf("logout with a garbage cookie returned %d, want %d: %s", a.status, http.StatusOK, a.body)
	}
}

func TestHandleLogoutReportsARevokeSessionDatabaseError(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	authStore.Close()

	nonEmpty := &http.Cookie{Name: sessionCookieName, Value: "whatever-nonempty-token"}
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/logout", "", nonEmpty)
	if a.status != http.StatusInternalServerError {
		t.Fatalf("logout against a closed store returned %d, want %d: %s",
			a.status, http.StatusInternalServerError, a.body)
	}
}
