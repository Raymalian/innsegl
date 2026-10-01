// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// #445 (RM-279), ADR-0062's 2026-10-01 amendment — the account page itself:
// GET/PATCH /api/v1/account, adding/renaming/removing a passkey, and the
// session gate and Origin check every account route shares with the
// sign-in surface.

func getAccount(t *testing.T, baseURL string, cookie *http.Cookie) Account {
	t.Helper()
	a := get(t, baseURL, "/api/v1/account", cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/account: %d: %s", a.status, a.body)
	}
	var acc Account
	decodeBody(t, a, &acc)
	return acc
}

func TestGetAccountReportsTheFirstPasskeyAndTenRecoveryCodes(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	acc := getAccount(t, srv.URL, cookie)
	if acc.DisplayName != "Test Operator" {
		t.Errorf("DisplayName = %q, want %q", acc.DisplayName, "Test Operator")
	}
	if len(acc.Passkeys) != 1 {
		t.Fatalf("got %d passkeys, want 1", len(acc.Passkeys))
	}
	if !acc.Passkeys[0].Current {
		t.Error("the passkey this session just signed in with is not marked Current")
	}
	if acc.RecoveryCodesRemaining != 10 {
		t.Errorf("RecoveryCodesRemaining = %d, want 10", acc.RecoveryCodesRemaining)
	}
}

func TestPatchAccountUpdatesTheDisplayName(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account",
		mustJSON(t, AccountUpdate{DisplayName: "  New Name  "}), cookie)
	if a.status != http.StatusOK {
		t.Fatalf("PATCH /api/v1/account: %d: %s", a.status, a.body)
	}
	var acc Account
	decodeBody(t, a, &acc)
	if acc.DisplayName != "New Name" {
		t.Errorf("DisplayName = %q, want trimmed %q", acc.DisplayName, "New Name")
	}

	again := getAccount(t, srv.URL, cookie)
	if again.DisplayName != "New Name" {
		t.Errorf("a later GET reports DisplayName = %q, want %q", again.DisplayName, "New Name")
	}
}

func TestPatchAccountRefusesAnEmptyDisplayName(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account",
		mustJSON(t, AccountUpdate{DisplayName: "   "}), cookie)
	if a.status != http.StatusBadRequest {
		t.Fatalf("PATCH /api/v1/account with a blank name returned %d, want 400: %s", a.status, a.body)
	}
}

// A second passkey can be added while signed in, and used to sign in on its
// own — and the account page then marks IT current, not the first one.
func TestAddASecondPasskeyAndSignInWithIt(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the enrolling session does not verify")
	}

	secondAuth, secondPasskey := addPasskeyViaAPI(t, srv.URL, "laptop", cookie)
	if secondPasskey.Name != "laptop" {
		t.Errorf("Name = %q, want %q", secondPasskey.Name, "laptop")
	}
	if secondPasskey.Current {
		t.Error("a just-added passkey is marked Current, but this session did not sign in with it")
	}

	acc := getAccount(t, srv.URL, cookie)
	if len(acc.Passkeys) != 2 {
		t.Fatalf("got %d passkeys after adding a second, want 2", len(acc.Passkeys))
	}

	login := loginWithAuthenticator(t, srv.URL, secondAuth, userID)
	if login.status != http.StatusOK {
		t.Fatalf("signing in with the second passkey returned %d, want 200: %s", login.status, login.body)
	}
	secondCookie := sessionCookieFrom(t, login)

	acc2 := getAccount(t, srv.URL, secondCookie)
	var found bool
	for _, pk := range acc2.Passkeys {
		if pk.ID == secondPasskey.ID {
			found = true
			if !pk.Current {
				t.Error("the passkey THIS session signed in with is not marked Current")
			}
		} else if pk.Current {
			t.Errorf("passkey %q (%s) is marked Current, but this session signed in with %s",
				pk.Name, pk.ID, secondPasskey.ID)
		}
	}
	if !found {
		t.Fatal("the second passkey is missing from the account's own listing")
	}
}

// Signing in stamps the passkey's own last_used_at.
func TestSignInStampsThePasskeysLastUsedAt(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	auth, cookie := enrolTestUser(t, srv.URL, authStore)
	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the enrolling session does not verify")
	}

	before := getAccount(t, srv.URL, cookie)
	if before.Passkeys[0].LastUsedAt != nil {
		t.Fatal("a never-signed-in-again passkey already carries a last_used_at")
	}

	login := loginWithAuthenticator(t, srv.URL, auth, userID)
	if login.status != http.StatusOK {
		t.Fatalf("signing in again returned %d, want 200: %s", login.status, login.body)
	}
	after := getAccount(t, srv.URL, sessionCookieFrom(t, login))
	if after.Passkeys[0].LastUsedAt == nil {
		t.Error("signing in did not stamp the passkey's last_used_at")
	}
}

func TestRenameAPasskey(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	acc := getAccount(t, srv.URL, cookie)
	id := acc.Passkeys[0].ID

	a := do(t, http.MethodPatch, srv.URL+"/api/v1/account/passkeys/"+id,
		mustJSON(t, PasskeyRename{Name: "renamed"}), cookie)
	if a.status != http.StatusOK {
		t.Fatalf("PATCH /api/v1/account/passkeys/%s: %d: %s", id, a.status, a.body)
	}

	after := getAccount(t, srv.URL, cookie)
	if after.Passkeys[0].Name != "renamed" {
		t.Errorf("Name = %q after rename, want %q", after.Passkeys[0].Name, "renamed")
	}
}

// Deleting a passkey that is not the last one succeeds; deleting the last
// one is refused (409), and deleting it ends the session it signed in.
func TestDeletePasskeyNonLastOKLastConflict(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)
	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the enrolling session does not verify")
	}
	secondAuth, secondPasskey := addPasskeyViaAPI(t, srv.URL, "second", cookie)

	login := loginWithAuthenticator(t, srv.URL, secondAuth, userID)
	if login.status != http.StatusOK {
		t.Fatalf("signing in with the second passkey: %d: %s", login.status, login.body)
	}
	secondCookie := sessionCookieFrom(t, login)

	del := do(t, http.MethodDelete, srv.URL+"/api/v1/account/passkeys/"+secondPasskey.ID, "", cookie)
	if del.status != http.StatusOK {
		t.Fatalf("DELETE a non-last passkey returned %d, want 200: %s", del.status, del.body)
	}

	// The deleted passkey's own session is ended.
	after := get(t, srv.URL, "/api/v1/overview", secondCookie)
	if after.status != http.StatusUnauthorized {
		t.Fatalf("the deleted passkey's session still answers (%d), want 401", after.status)
	}

	acc := getAccount(t, srv.URL, cookie)
	if len(acc.Passkeys) != 1 {
		t.Fatalf("got %d passkeys after removing the second, want 1", len(acc.Passkeys))
	}

	lastID := acc.Passkeys[0].ID
	last := do(t, http.MethodDelete, srv.URL+"/api/v1/account/passkeys/"+lastID, "", cookie)
	if last.status != http.StatusConflict {
		t.Fatalf("DELETE the only remaining passkey returned %d, want 409: %s", last.status, last.body)
	}
}

// A passkey id that belongs to a DIFFERENT user is 404, not 403 or 409 — it
// must not distinguish "not yours" from "does not exist".
func TestPasskeyOfAnotherUserIs404(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	// A second, independent account, reached directly on the store rather
	// than through HTTP enrolment (closed once a user exists) — this
	// deployment only ever has one in practice; this proves the ownership
	// scope holds even so.
	otherCred := webauthn.Credential{ID: []byte("other-users-credential"), AttestationFormat: "none"}
	if err := authStore.CreateUser(t.Context(), "other-user", "Someone Else"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := authStore.AddPasskey(t.Context(), "other-user", "theirs", otherCred); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	otherID := credentialIDString(otherCred.ID)

	rename := do(t, http.MethodPatch, srv.URL+"/api/v1/account/passkeys/"+otherID,
		mustJSON(t, PasskeyRename{Name: "stolen"}), cookie)
	if rename.status != http.StatusNotFound {
		t.Fatalf("renaming another user's passkey returned %d, want 404: %s", rename.status, rename.body)
	}

	del := do(t, http.MethodDelete, srv.URL+"/api/v1/account/passkeys/"+otherID, "", cookie)
	if del.status != http.StatusNotFound {
		t.Fatalf("deleting another user's passkey returned %d, want 404: %s", del.status, del.body)
	}
}

// Every account route answers 401 without a session.
func TestAccountRoutesRequireASession(t *testing.T) {
	srv, _ := testServer(t)

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/account"},
		{http.MethodPatch, "/api/v1/account"},
		{http.MethodPost, "/api/v1/account/passkeys/begin"},
		{http.MethodPost, "/api/v1/account/passkeys/finish"},
		{http.MethodPatch, "/api/v1/account/passkeys/anything"},
		{http.MethodDelete, "/api/v1/account/passkeys/anything"},
		{http.MethodPost, "/api/v1/account/recovery-codes"},
	}
	for _, c := range cases {
		a := do(t, c.method, srv.URL+c.path, "{}")
		if a.status != http.StatusUnauthorized {
			t.Errorf("%s %s with no session returned %d, want 401: %s", c.method, c.path, a.status, a.body)
		}
	}
}

// Every mutating account route checks Origin, the same as the sign-in
// surface's own mutating routes.
func TestAccountMutatingRoutesCheckOrigin(t *testing.T) {
	srv, _, authStore := testServerConfigured(t)
	cookie := signInTestUser(t, srv.URL, authStore)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPatch,
		srv.URL+"/api/v1/account", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Origin", "https://attacker.example")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH /api/v1/account with a foreign Origin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-origin PATCH to /api/v1/account returned %d, want 403", resp.StatusCode)
	}
}
