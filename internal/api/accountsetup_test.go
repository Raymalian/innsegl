// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// #445 (RM-279), ADR-0062's 2026-10-01 amendment: "accounts a person can
// manage" — the setup link's own status endpoint, and the ten recovery
// codes first enrolment mints.

// GET /api/v1/auth/setup answers whether an account still needs creating,
// with no session, both before and after the first enrolment.
func TestAccountSetupStatusBeforeAndAfterEnrolment(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)

	before := get(t, srv.URL, "/api/v1/auth/setup")
	if before.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/setup (before): %d: %s", before.status, before.body)
	}
	var beforeStatus SetupStatus
	decodeBody(t, before, &beforeStatus)
	if !beforeStatus.Needed {
		t.Fatal("Needed = false before any passkey exists")
	}

	_ = signInTestUser(t, srv.URL, authStore)

	after := get(t, srv.URL, "/api/v1/auth/setup")
	if after.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/setup (after): %d: %s", after.status, after.body)
	}
	var afterStatus SetupStatus
	decodeBody(t, after, &afterStatus)
	if afterStatus.Needed {
		t.Fatal("Needed = true after the first passkey was enrolled")
	}
}

// GET /api/v1/auth/setup needs no session — it is on the public, no-cookie
// surface alongside every other route under authRoutePrefix.
func TestAccountSetupStatusNeedsNoSession(t *testing.T) {
	srv, _ := testServer(t)
	a := get(t, srv.URL, "/api/v1/auth/setup")
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/setup with no cookie at all: %d: %s", a.status, a.body)
	}
}

// First enrolment mints ten recovery codes, shown once in EnrolFinished, and
// each one is usable as a sign-in exactly once.
func TestFirstEnrolmentMintsTenRecoveryCodesEachUsableOnce(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	code, _, err := authStore.CreateEnrolmentCode(t.Context(), authCeremonyTTL)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}

	begin := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", code))
	if begin.status != http.StatusOK {
		t.Fatalf("enrol/begin: %d: %s", begin.status, begin.body)
	}
	var creation ceremonyResponse
	decodeBody(t, begin, &creation)

	auth := newSoftAuthenticator(t)
	credentialBody, rerr := auth.Register(creation.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}
	finishBody := mustJSON(t, map[string]any{
		"ceremony_id": creation.CeremonyID,
		"credential":  json.RawMessage(credentialBody),
	})
	finish := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/finish", finishBody)
	if finish.status != http.StatusOK {
		t.Fatalf("enrol/finish: %d: %s", finish.status, finish.body)
	}
	var finished EnrolFinished
	decodeBody(t, finish, &finished)
	if !finished.Authenticated {
		t.Fatal("EnrolFinished.Authenticated = false")
	}
	if len(finished.RecoveryCodes) != 10 {
		t.Fatalf("got %d recovery codes, want 10", len(finished.RecoveryCodes))
	}
	seen := map[string]bool{}
	for _, c := range finished.RecoveryCodes {
		if seen[c] {
			t.Fatalf("recovery code %q was minted twice", c)
		}
		seen[c] = true
		if !strings.Contains(c, "-") {
			t.Errorf("recovery code %q carries no separator", c)
		}
	}

	// Each code signs in exactly once.
	for i, c := range finished.RecoveryCodes {
		first := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: c}))
		if first.status != http.StatusOK {
			t.Fatalf("code %d: first use of %q returned %d, want 200: %s", i, c, first.status, first.body)
		}
		var result RecoverResult
		decodeBody(t, first, &result)
		if !result.Authenticated {
			t.Fatalf("code %d: RecoverResult.Authenticated = false", i)
		}
		if result.Remaining != len(finished.RecoveryCodes)-1-i {
			t.Errorf("code %d: Remaining = %d, want %d", i, result.Remaining, len(finished.RecoveryCodes)-1-i)
		}

		second := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: c}))
		if second.status != http.StatusUnauthorized {
			t.Fatalf("code %d: reusing %q returned %d, want 401", i, c, second.status)
		}
	}
}

// A recovery code nobody ever minted is refused, and recorded.
func TestRecoverWithAWrongCodeIsRefused(t *testing.T) {
	srv, _ := testServer(t)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: "not-a-real-code"}))
	if a.status != http.StatusUnauthorized {
		t.Fatalf("a wrong recovery code returned %d, want 401: %s", a.status, a.body)
	}
}

// A code that canonicalises to nothing at all (empty, or only dashes and
// whitespace) is refused the same way — ConsumeRecoveryCode's own guard
// against hashing and matching an empty canonical string.
func TestRecoverWithAnEmptyCodeIsRefused(t *testing.T) {
	srv, _ := testServer(t)
	for _, code := range []string{"", "  ", "---"} {
		a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: code}))
		if a.status != http.StatusUnauthorized {
			t.Errorf("recovery code %q returned %d, want 401: %s", code, a.status, a.body)
		}
	}
}

// A recovery code is accepted case-insensitively and with or without its
// dash.
func TestRecoverAcceptsACodeWithOrWithoutItsDashAndCase(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	regen := do(t, http.MethodPost, srv.URL+"/api/v1/account/recovery-codes", "", cookie)
	if regen.status != http.StatusOK {
		t.Fatalf("POST /api/v1/account/recovery-codes: %d: %s", regen.status, regen.body)
	}
	var codes RecoveryCodes
	decodeBody(t, regen, &codes)
	if len(codes.Codes) == 0 {
		t.Fatal("no codes minted")
	}
	raw := codes.Codes[0]
	variant := strings.ToLower(strings.ReplaceAll(raw, "-", ""))

	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: variant}))
	if a.status != http.StatusOK {
		t.Fatalf("a lower-cased, dash-stripped code returned %d, want 200: %s", a.status, a.body)
	}
}

// Regenerating recovery codes voids every earlier one.
func TestRegeneratingRecoveryCodesVoidsTheOldOnes(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	first := do(t, http.MethodPost, srv.URL+"/api/v1/account/recovery-codes", "", cookie)
	if first.status != http.StatusOK {
		t.Fatalf("first POST /api/v1/account/recovery-codes: %d: %s", first.status, first.body)
	}
	var firstCodes RecoveryCodes
	decodeBody(t, first, &firstCodes)

	second := do(t, http.MethodPost, srv.URL+"/api/v1/account/recovery-codes", "", cookie)
	if second.status != http.StatusOK {
		t.Fatalf("second POST /api/v1/account/recovery-codes: %d: %s", second.status, second.body)
	}
	var secondCodes RecoveryCodes
	decodeBody(t, second, &secondCodes)
	if len(secondCodes.Codes) != 10 {
		t.Fatalf("got %d codes on regeneration, want 10", len(secondCodes.Codes))
	}

	// An old code is now refused...
	stale := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: firstCodes.Codes[0]}))
	if stale.status != http.StatusUnauthorized {
		t.Fatalf("a voided code returned %d, want 401: %s", stale.status, stale.body)
	}
	// ...and a fresh one still works.
	fresh := do(t, http.MethodPost, srv.URL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: secondCodes.Codes[0]}))
	if fresh.status != http.StatusOK {
		t.Fatalf("a freshly minted code returned %d, want 200: %s", fresh.status, fresh.body)
	}
}
