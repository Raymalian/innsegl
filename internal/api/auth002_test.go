// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// AUTH-002: enrolment is gated by a one-time code alone — only a valid,
// unused, unexpired code completes; a missing, unknown, used or expired code
// refuses.

func enrolBeginBody(t *testing.T, displayName, code string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"display_name": displayName, "code": code})
	if err != nil {
		t.Fatalf("encoding enrol/begin body: %v", err)
	}
	return string(body)
}

func TestAUTH002EnrolmentWithAValidCodeCompletes(t *testing.T) {
	// signInTestUser runs the whole begin/finish ceremony, exactly what this
	// case measures; a separate implementation here would just be a second
	// copy of it.
	srv, _, cookie := testServerWithSession(t)

	a := get(t, srv.URL, "/api/v1/auth/session", cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/session: %d: %s", a.status, a.body)
	}
	var status SessionStatus
	decodeBody(t, a, &status)
	if !status.Authenticated {
		t.Fatal("a completed enrolment did not leave a valid session behind")
	}
}

func TestAUTH002AUsedCodeIsRefused(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}

	first := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Op One", code))
	if first.status != http.StatusOK {
		t.Fatalf("first enrol/begin with a fresh code returned %d, want 200: %s", first.status, first.body)
	}

	second := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Op Two", code))
	if second.status != http.StatusForbidden {
		t.Fatalf("a second enrol/begin with the SAME code returned %d, want 403 "+
			"(AUTH-004: a reused code is refused)", second.status)
	}
}

func TestAUTH002AnExpiredCodeIsRefused(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	// A negative TTL is already expired the instant it is minted.
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), -time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", code))
	if a.status != http.StatusForbidden {
		t.Fatalf("enrol/begin with an expired code returned %d, want 403: %s", a.status, a.body)
	}
}

func TestAUTH002AnUnknownCodeIsRefused(t *testing.T) {
	srv, _, _ := testServerConfigured(t)

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin",
		enrolBeginBody(t, "Operator", "not-a-code-anyone-minted"))
	if a.status != http.StatusForbidden {
		t.Fatalf("enrol/begin with an unknown code returned %d, want 403: %s", a.status, a.body)
	}
}

// Once a user with a passkey exists, enrol/begin refuses even with a fresh
// code: ADR-0062 builds only the first user.
func TestAUTH002EnrolmentClosedOnceAUserExists(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	_ = signInTestUser(t, srv.URL, authStore)

	code, _, err := authStore.CreateEnrolmentCode(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Second Op", code))
	if a.status != http.StatusForbidden {
		t.Fatalf("enrol/begin after a user already exists returned %d, want 403: %s", a.status, a.body)
	}
}
