// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// AUTH-004 (C): forged/replayed assertion, reused code, cross-origin request
// → refused. The reused-code case is auth002_test.go's
// TestAUTH002AUsedCodeIsRefused, named here rather than duplicated.

// A login assertion whose signature does not verify against the enrolled
// public key — the software authenticator signs with a SECOND, unrelated
// key — is refused rather than silently accepted.
func TestAUTH004AForgedAssertionIsRefused(t *testing.T) {
	srv, _, cookie := testServerWithSession(t)
	whoAmI := get(t, srv.URL, "/api/v1/auth/session", cookie)
	var status sessionStatus
	decodeBody(t, whoAmI, &status)
	if !status.Authenticated {
		t.Fatal("no signed-in session to attack")
	}

	beginResp := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/begin", "{}")
	if beginResp.status != http.StatusOK {
		t.Fatalf("login/begin: %d: %s", beginResp.status, beginResp.body)
	}
	var assertion loginCeremonyResponse
	if err := json.Unmarshal(beginResp.body, &assertion); err != nil {
		t.Fatalf("decoding login/begin: %v", err)
	}

	// A different authenticator — a different private key, and no
	// credential this deployment ever registered — answers the same
	// challenge. Its assertion's signature cannot verify against any
	// enrolled public key, forged or not.
	forger := newSoftAuthenticator(t)
	credentialBody, aerr := forger.Assert(assertion.CredentialAssertion, testWebAuthnConfig.RPOrigin,
		"not-a-real-user-handle")
	if aerr != nil {
		t.Fatalf("Assert: %v", aerr)
	}

	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": assertion.CeremonyID,
		"credential":  json.RawMessage(credentialBody),
	})
	if err != nil {
		t.Fatalf("encoding login/finish: %v", err)
	}
	finish := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/finish", string(finishBody))
	if finish.status != http.StatusUnauthorized {
		t.Fatalf("a forged assertion returned %d, want 401: %s", finish.status, finish.body)
	}
}

// The SAME finished ceremony, replayed a second time with the identical
// request body, finds nothing: LoadAndConsumeCeremony deletes on read. The
// first attempt, from the actually-enrolled authenticator, succeeds — so the
// second's refusal is provably about replay, not about an assertion that
// was never going to verify in the first place.
func TestAUTH004AReplayedCeremonyIsRefused(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	auth, cookie := enrolTestUser(t, srv.URL, authStore)
	userID, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the session enrolTestUser just created does not verify")
	}

	beginResp := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/begin", "{}")
	if beginResp.status != http.StatusOK {
		t.Fatalf("login/begin: %d: %s", beginResp.status, beginResp.body)
	}
	var assertion loginCeremonyResponse
	if err := json.Unmarshal(beginResp.body, &assertion); err != nil {
		t.Fatalf("decoding login/begin: %v", err)
	}

	credentialBody, aerr := auth.Assert(assertion.CredentialAssertion, testWebAuthnConfig.RPOrigin, userID)
	if aerr != nil {
		t.Fatalf("Assert: %v", aerr)
	}
	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": assertion.CeremonyID,
		"credential":  json.RawMessage(credentialBody),
	})
	if err != nil {
		t.Fatalf("encoding login/finish: %v", err)
	}

	first := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/finish", string(finishBody))
	if first.status != http.StatusOK {
		t.Fatalf("the enrolled authenticator's own sign-in was refused: %d: %s", first.status, first.body)
	}

	second := do(t, http.MethodPost, srv.URL+"/api/v1/auth/login/finish", string(finishBody))
	if second.status != http.StatusUnauthorized {
		t.Fatalf("replaying the same, already-consumed ceremony returned %d, want 401", second.status)
	}
}

// A POST to the sign-in surface whose Origin header names a different
// origin than this deployment's own is refused before any ceremony logic
// runs.
func TestAUTH004ACrossOriginRequestIsRefused(t *testing.T) {
	srv, _, _ := testServerConfigured(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/api/v1/auth/login/begin", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Origin", "https://attacker.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST login/begin with a foreign Origin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-origin POST returned %d, want 403", resp.StatusCode)
	}
}

// The matching origin is, correctly, not refused by the origin check (it may
// still be refused for other reasons, which is not what this case is about).
func TestAUTH004ASameOriginRequestIsNotRefusedByTheOriginCheck(t *testing.T) {
	srv, _, _ := testServerConfigured(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/api/v1/auth/login/begin", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Origin", testWebAuthnConfig.RPOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST login/begin with the matching Origin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("a same-origin request was refused by the origin check")
	}
}
