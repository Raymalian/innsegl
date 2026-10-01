// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Coverage for the account surface's own refusal and error paths — the same
// "every malformed/wrong-method/missing-ceremony case" discipline
// authhandlers_errors_test.go holds the sign-in surface to (#445).

// ---------------------------------------------------------------------------
// serveAccount — the method guard and the OPTIONS short-circuit.
// ---------------------------------------------------------------------------

func TestServeAccountRefusesAMethodNoRouteAccepts(t *testing.T) {
	srv, _, cookie := testServerWithSession(t)
	a := do(t, "PROPFIND", srv.URL+"/api/v1/account", "", cookie)
	if a.status != http.StatusMethodNotAllowed {
		t.Fatalf("PROPFIND /api/v1/account = %d, want %d", a.status, http.StatusMethodNotAllowed)
	}
	if allow := a.header.Get("Allow"); !strings.Contains(allow, "GET") || !strings.Contains(allow, "PATCH") {
		t.Errorf("Allow = %q, want it to name GET and PATCH", allow)
	}
}

func TestServeAccountAnswersOPTIONSWithNoSessionAndNoBody(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodOptions, srv.URL+"/api/v1/account", "")
	if a.status != http.StatusNoContent {
		t.Fatalf("OPTIONS /api/v1/account = %d, want %d", a.status, http.StatusNoContent)
	}
	if allow := a.header.Get("Allow"); !strings.Contains(allow, "DELETE") {
		t.Errorf("Allow = %q, want it to name DELETE", allow)
	}
	if len(a.body) != 0 {
		t.Errorf("OPTIONS carried a body: %q", a.body)
	}
}

// A garbage cookie is the same as no session at all.
func TestAccountRoutesRefuseAGarbageCookie(t *testing.T) {
	srv, _ := testServer(t)
	garbage := &http.Cookie{Name: sessionCookieName, Value: "not-a-real-session-token"}
	a := get(t, srv.URL, "/api/v1/account", garbage)
	if a.status != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/account with a garbage cookie returned %d, want 401", a.status)
	}
}

// ---------------------------------------------------------------------------
// handleAuthSetup
// ---------------------------------------------------------------------------

func TestHandleAuthSetupReportsADatabaseError(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	authStore.Close()

	a := get(t, srv.URL, "/api/v1/auth/setup")
	if a.status != http.StatusInternalServerError {
		t.Fatalf("GET /api/v1/auth/setup against a closed store returned %d, want %d: %s",
			a.status, http.StatusInternalServerError, a.body)
	}
}

// ---------------------------------------------------------------------------
// handleRecover
// ---------------------------------------------------------------------------

func TestHandleRecoverRefusesMalformedJSON(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", "{not json")
	if a.status != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/auth/recover with malformed JSON returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

// ---------------------------------------------------------------------------
// handlePatchAccount / handlePasskeyBegin / handlePasskeyRename — each
// shares decodeAuthRequest, but each handler's OWN early-return on it is a
// distinct line this file exercises once per handler.
// ---------------------------------------------------------------------------

func TestHandlePatchAccountRefusesMalformedJSON(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account", "{not json", cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("PATCH /api/v1/account with malformed JSON returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandlePasskeyBeginRefusesMalformedJSON(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/account/passkeys/begin", "{not json", cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/account/passkeys/begin with malformed JSON returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandlePasskeyBeginRefusesAnEmptyName(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/account/passkeys/begin",
		mustJSON(t, PasskeyBeginRequest{Name: "   "}), cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/account/passkeys/begin with a blank name returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandlePasskeyFinishRefusesMalformedJSON(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/account/passkeys/finish", "{not json", cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/account/passkeys/finish with malformed JSON returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandlePasskeyFinishRefusesAnUnknownCeremony(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/account/passkeys/finish",
		mustJSON(t, map[string]any{"ceremony_id": "no-such-ceremony", "credential": map[string]any{}}), cookie)
	if a.status != http.StatusUnauthorized {
		t.Fatalf("account/passkeys/finish with an unknown ceremony returned %d, want %d: %s",
			a.status, http.StatusUnauthorized, a.body)
	}
}

// A 'register' (first-enrolment) ceremony id is a DIFFERENT kind and must
// not be redeemable by the add-a-passkey finish route.
func TestHandlePasskeyFinishRefusesALoginKindCeremony(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	begin := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/begin", "{}")
	if begin.status != http.StatusOK {
		t.Fatalf("login/begin: %d: %s", begin.status, begin.body)
	}
	var assertion loginCeremonyResponse
	decodeBody(t, begin, &assertion)

	a := do(t, http.MethodPost, srv.URL+"/api/v1/account/passkeys/finish",
		mustJSON(t, map[string]any{"ceremony_id": assertion.CeremonyID, "credential": map[string]any{}}), cookie)
	if a.status != http.StatusUnauthorized {
		t.Fatalf("account/passkeys/finish with a login-kind ceremony id returned %d, want %d: %s",
			a.status, http.StatusUnauthorized, a.body)
	}
}

func TestHandlePasskeyRenameRefusesMalformedJSON(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	acc := getAccount(t, srv.URL, cookie)
	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account/passkeys/"+acc.Passkeys[0].ID, "{not json", cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("PATCH .../passkeys/{id} with malformed JSON returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

// ---------------------------------------------------------------------------
// The store-call-failed branches each handler answers 500 for — reached by
// calling the handler directly (same technique as authmisc_errors_test.go's
// TestIssueSessionReportsACreateSessionDatabaseError), with an already-closed
// AuthStore and a session put straight on the request's context the way
// serveAccount itself would have, since serveAccount's own session check
// would otherwise fail on the same closed pool before any handler ran.
// ---------------------------------------------------------------------------

func accountTestRequest(ctx context.Context, method, path, body string) *http.Request {
	return httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
}

func TestAccountHandlersReportDatabaseErrorsFromAClosedStore(t *testing.T) {
	store := testAuthStore(t)
	store.Close()
	s := &Server{authStore: store, webAuthnConfig: testWebAuthnConfig, sessionLifetime: time.Hour}
	ctx := context.WithValue(context.Background(), accountSessionContextKey{},
		accountSession{userID: "u-closed", passkeyID: "pk-closed"})

	cases := []struct {
		name string
		run  func(w http.ResponseWriter, r *http.Request)
		req  *http.Request
	}{
		{"GET /api/v1/account", s.handleGetAccount,
			accountTestRequest(ctx, http.MethodGet, "/api/v1/account", "")},
		{"PATCH /api/v1/account", s.handlePatchAccount,
			accountTestRequest(ctx, http.MethodPatch, "/api/v1/account", mustJSON(t, AccountUpdate{DisplayName: "ok"}))},
		{"POST /api/v1/account/passkeys/begin", s.handlePasskeyBegin,
			accountTestRequest(ctx, http.MethodPost, "/api/v1/account/passkeys/begin",
				mustJSON(t, PasskeyBeginRequest{Name: "ok"}))},
		{"PATCH /api/v1/account/passkeys/{id}", s.handlePasskeyRename,
			accountTestRequest(ctx, http.MethodPatch, "/api/v1/account/passkeys/x", mustJSON(t, PasskeyRename{Name: "ok"}))},
		{"DELETE /api/v1/account/passkeys/{id}", s.handlePasskeyDelete,
			accountTestRequest(ctx, http.MethodDelete, "/api/v1/account/passkeys/x", "")},
		{"POST /api/v1/account/recovery-codes", s.handleRecoveryCodesRegenerate,
			accountTestRequest(ctx, http.MethodPost, "/api/v1/account/recovery-codes", "")},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		c.run(rec, c.req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s against a closed store returned %d, want %d: %s",
				c.name, rec.Code, http.StatusInternalServerError, rec.Body.String())
		}
	}
}

func TestHandlePasskeyRenameRefusesAnEmptyName(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	acc := getAccount(t, srv.URL, cookie)
	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account/passkeys/"+acc.Passkeys[0].ID,
		mustJSON(t, PasskeyRename{Name: ""}), cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("PATCH .../passkeys/{id} with a blank name returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}
