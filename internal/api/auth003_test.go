// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// AUTH-003 (I): registration and sign-in with a virtual authenticator /
// the library's test helpers, userVerification required; cookie flags;
// sign-out revokes; attestation format recorded.

// Registration itself, including a full round trip to a gated route, is
// already exercised end to end by signInTestUser (http_test.go) — every
// case here checks one specific property of that same ceremony rather than
// re-running it from scratch.

func TestAUTH003RegistrationOptionsRequireUserVerification(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", code))
	if a.status != http.StatusOK {
		t.Fatalf("enrol/begin: %d: %s", a.status, a.body)
	}
	var creation ceremonyResponse
	if err := json.Unmarshal(a.body, &creation); err != nil {
		t.Fatalf("decoding enrol/begin: %v", err)
	}
	if creation.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Errorf("AuthenticatorSelection.UserVerification = %q, want %q",
			creation.Response.AuthenticatorSelection.UserVerification,
			protocol.VerificationRequired)
	}
	if creation.Response.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("AuthenticatorSelection.ResidentKey = %q, want required — a "+
			"one-button, usernameless sign-in page needs a discoverable credential",
			creation.Response.AuthenticatorSelection.ResidentKey)
	}
}

func TestAUTH003LoginOptionsRequireUserVerification(t *testing.T) {
	srv, _, _ := testServerWithSession(t)

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/begin", "{}")
	if a.status != http.StatusOK {
		t.Fatalf("login/begin: %d: %s", a.status, a.body)
	}
	var assertion loginCeremonyResponse
	if err := json.Unmarshal(a.body, &assertion); err != nil {
		t.Fatalf("decoding login/begin: %v", err)
	}
	if assertion.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("assertion UserVerification = %q, want %q",
			assertion.Response.UserVerification, protocol.VerificationRequired)
	}
}

func TestAUTH003SessionCookieFlags(t *testing.T) {
	srv, _, cookie := testServerWithSession(t)
	_ = srv

	if !cookie.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	// testWebAuthnConfig's origin is http://, matching the reference
	// deployment's documented http://localhost:8082 — Secure is correctly
	// false here (ADR-0062: "Secure where the origin is https"), and a case
	// with an https:// origin proves the other half below.
	if cookie.Secure {
		t.Error("Secure is set on an http:// origin's cookie")
	}
	if cookie.MaxAge <= 0 {
		t.Error("the session cookie carries no bounded lifetime")
	}
}

// TestAUTH003SessionCookieIsSecureOnAnHTTPSOrigin proves the other half of
// "Secure where the origin is https": setSessionCookie is asserted directly
// rather than through a second full ceremony, since every case above already
// proves the ceremony's own mechanics and this one exists only to prove the
// ONE thing that differs when the configured origin is https.
func TestAUTH003SessionCookieIsSecureOnAnHTTPSOrigin(t *testing.T) {
	s := &Server{webAuthnConfig: WebAuthnConfig{RPOrigin: "https://localhost:8443"}}

	rec := httptest.NewRecorder()
	s.setSessionCookie(rec, "test-token", time.Now().Add(time.Hour))

	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			found = true
			if !c.Secure {
				t.Error("Secure is not set on an https:// origin's cookie")
			}
		}
	}
	if !found {
		t.Fatal("setSessionCookie set no cookie")
	}
}

func TestAUTH003SignOutRevokesTheSession(t *testing.T) {
	srv, _, cookie := testServerWithSession(t)

	before := get(t, srv.URL, "/api/v1/overview", cookie)
	if before.status != http.StatusOK {
		t.Fatalf("GET /api/v1/overview before sign-out: %d: %s", before.status, before.body)
	}

	out := do(t, http.MethodPost, srv.URL+"/api/v1/auth/logout", "", cookie)
	if out.status != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/logout: %d: %s", out.status, out.body)
	}

	after := get(t, srv.URL, "/api/v1/overview", cookie)
	if after.status != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/overview with the SAME cookie after sign-out returned %d, "+
			"want 401 — the server-side row must be revoked, not merely the browser told "+
			"to forget it (ADR-0062)", after.status)
	}
}

func TestAUTH003AttestationFormatIsRecorded(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the session this test just created does not verify")
	}
	creds, err := authStore.PasskeysByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("PasskeysByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("%d passkeys for the enrolled user, want 1", len(creds))
	}
	// The software authenticator answers "none" (webauthntest_test.go);
	// ADR-0062 records whatever comes back, unenforced, and "none" is the
	// ordinary case for a real platform passkey too.
	if creds[0].AttestationFormat == "" {
		t.Error("AttestationFormat was not recorded on the stored passkey")
	}
	if !strings.Contains(creds[0].AttestationFormat, "none") {
		t.Errorf("AttestationFormat = %q, want %q", creds[0].AttestationFormat, "none")
	}
}

// verifySessionToken is VerifySession, called directly for a test that
// already holds the raw cookie value rather than another HTTP round trip.
func verifySessionToken(t *testing.T, store *AuthStore, token string) (userID, passkeyID string, ok bool) {
	t.Helper()
	userID, passkeyID, ok, err := store.VerifySession(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	return userID, passkeyID, ok
}
