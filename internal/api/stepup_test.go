// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/webauthntest"
)

// #602 (RM-354): a stolen dashboard session cannot change how the account
// signs in. Adding or removing a passkey, regenerating recovery codes and
// linking or unlinking an organisation's sign-in each take a fresh passkey
// assertion, with user verification (AUTH-019); and a session ends after 30
// minutes without a request (AUTH-020).
//
// AUTH-019 and AUTH-020 are PROPOSED for doc 07's TC-AUTH: the next free
// numbers there and in the code on 2026-10-12.

// stepUpVia drives one begin/finish pair confirmed by auth's passkey, as
// the dashboard does: begin with body, assert the challenge, finish.
func stepUpVia(t *testing.T, baseURL, route string, body any, auth *webauthntest.Authenticator,
	userID string, cookie *http.Cookie,
) answer {
	t.Helper()
	begin := unlockDo(t, http.MethodPost, baseURL+route+"/begin", mustJSON(t, body), testWebAuthnConfig.RPOrigin, cookie)
	if begin.status != http.StatusOK {
		return begin
	}
	var challenge loginCeremonyResponse
	decodeBody(t, begin, &challenge)
	credential, err := auth.Assert(challenge.CredentialAssertion, testWebAuthnConfig.RPOrigin, userID)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return unlockDo(t, http.MethodPost, baseURL+route+"/finish", mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(credential),
	}), testWebAuthnConfig.RPOrigin, cookie)
}

// stepUpUser is an enrolled person on a fresh server: their passkey, their
// session, and their id.
type stepUpUser struct {
	srvURL    string
	authStore *AuthStore
	auth      *webauthntest.Authenticator
	cookie    *http.Cookie
	userID    string
}

func newStepUpUser(t *testing.T) stepUpUser {
	t.Helper()
	srv, _, authStore := testServerConfigured(t)
	return newStepUpUserOn(t, srv.URL, authStore)
}

// newStepUpUserOn enrols the first person on a server already running.
func newStepUpUserOn(t *testing.T, srvURL string, authStore *AuthStore) stepUpUser {
	t.Helper()
	auth, cookie := enrolTestUser(t, srvURL, authStore)
	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the enrolling session does not verify")
	}
	return stepUpUser{srvURL: srvURL, authStore: authStore, auth: auth, cookie: cookie, userID: userID}
}

// regenerate mints new recovery codes, confirmed by the person's passkey.
func (u stepUpUser) regenerate(t *testing.T) answer {
	t.Helper()
	return stepUpVia(t, u.srvURL, "/api/v1/account/recovery-codes", struct{}{}, u.auth, u.userID, u.cookie)
}

func (u stepUpUser) passkeyCount(t *testing.T) int {
	t.Helper()
	return len(getAccount(t, u.srvURL, u.cookie).Passkeys)
}

// AUTH-019 — the session alone no longer changes how the account signs in.
func TestAUTH019SessionAloneCannotChangeSignIn(t *testing.T) {
	u := newStepUpUser(t)

	// The routes that took the session alone are gone.
	acc := getAccount(t, u.srvURL, u.cookie)
	if a := do(t, http.MethodDelete, u.srvURL+"/api/v1/account/passkeys/"+acc.Passkeys[0].ID, "", u.cookie); a.status == http.StatusOK {
		t.Fatalf("DELETE a passkey with the session alone answered 200: %s", a.body)
	}
	if a := do(t, http.MethodPost, u.srvURL+"/api/v1/account/recovery-codes", "{}", u.cookie); a.status == http.StatusOK {
		t.Fatalf("regenerating recovery codes with the session alone answered 200: %s", a.body)
	}

	// Adding a passkey: begin asks for a confirmation; a finish that
	// carries none, or one from a passkey not on this account, adds nothing.
	begin := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/begin",
		mustJSON(t, PasskeyBeginRequest{Name: "thief"}), testWebAuthnConfig.RPOrigin, u.cookie)
	if begin.status != http.StatusOK {
		t.Fatalf("passkeys/begin: %d %s", begin.status, begin.body)
	}
	var challenge passkeyAddChallenge
	decodeBody(t, begin, &challenge)
	if challenge.Confirm == nil {
		t.Fatal("passkeys/begin asked for no confirmation from a passkey session")
	}
	thief := newSoftAuthenticator(t)
	created, err := thief.Register(challenge.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if err != nil {
		t.Fatal(err)
	}
	noConfirm := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/finish", mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(created),
	}), testWebAuthnConfig.RPOrigin, u.cookie)
	if noConfirm.status != http.StatusUnauthorized {
		t.Fatalf("passkeys/finish without a confirmation: %d, want 401: %s", noConfirm.status, noConfirm.body)
	}
	if n := u.passkeyCount(t); n != 1 {
		t.Fatalf("%d passkeys after a refused add, want 1", n)
	}

	// The same refusal for a confirmation signed by the new key itself.
	begin = unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/begin",
		mustJSON(t, PasskeyBeginRequest{Name: "thief"}), testWebAuthnConfig.RPOrigin, u.cookie)
	decodeBody(t, begin, &challenge)
	created, err = thief.Register(challenge.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := thief.Assert(challenge.Confirm, testWebAuthnConfig.RPOrigin, u.userID)
	if err != nil {
		t.Fatal(err)
	}
	wrong := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/finish", mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(created), "confirmation": json.RawMessage(forged),
	}), testWebAuthnConfig.RPOrigin, u.cookie)
	if wrong.status != http.StatusUnauthorized {
		t.Fatalf("passkeys/finish confirmed by a passkey not on the account: %d, want 401: %s", wrong.status, wrong.body)
	}
	if n := u.passkeyCount(t); n != 1 {
		t.Fatalf("%d passkeys after a forged confirmation, want 1", n)
	}

	// Remove and regenerate: a finish whose assertion is not the account's
	// changes nothing.
	for _, route := range []string{"/api/v1/account/passkeys/remove", "/api/v1/account/recovery-codes"} {
		a := stepUpVia(t, u.srvURL, route, PasskeyRemove{ID: acc.Passkeys[0].ID}, thief, u.userID, u.cookie)
		if a.status == http.StatusOK {
			t.Fatalf("%s confirmed by a passkey not on the account answered 200: %s", route, a.body)
		}
	}
}

// AUTH-019 — with a fresh passkey assertion each change goes through.
func TestAUTH019FreshPasskeyConfirmsEachChange(t *testing.T) {
	u := newStepUpUser(t)

	second, pk := addPasskeyViaAPI(t, u.srvURL, "laptop", u.cookie, u.auth, u.userID)
	if n := u.passkeyCount(t); n != 2 {
		t.Fatalf("%d passkeys after a confirmed add, want 2", n)
	}

	codes := stepUpVia(t, u.srvURL, "/api/v1/account/recovery-codes", struct{}{}, second, u.userID, u.cookie)
	if codes.status != http.StatusOK {
		t.Fatalf("recovery-codes confirmed: %d %s", codes.status, codes.body)
	}
	var minted RecoveryCodes
	decodeBody(t, codes, &minted)
	if len(minted.Codes) != recoveryCodeCount {
		t.Fatalf("%d codes, want %d", len(minted.Codes), recoveryCodeCount)
	}

	// A ceremony begun for one change cannot finish another.
	begin := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/recovery-codes/begin", "{}",
		testWebAuthnConfig.RPOrigin, u.cookie)
	var challenge loginCeremonyResponse
	decodeBody(t, begin, &challenge)
	credential, err := u.auth.Assert(challenge.CredentialAssertion, testWebAuthnConfig.RPOrigin, u.userID)
	if err != nil {
		t.Fatal(err)
	}
	cross := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/remove/finish", mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(credential),
	}), testWebAuthnConfig.RPOrigin, u.cookie)
	if cross.status != http.StatusUnauthorized {
		t.Fatalf("a recovery-codes ceremony finished a passkey removal: %d %s", cross.status, cross.body)
	}

	if a := stepUpVia(t, u.srvURL, "/api/v1/account/passkeys/remove", PasskeyRemove{ID: "no-such"}, u.auth,
		u.userID, u.cookie); a.status != http.StatusNotFound {
		t.Fatalf("removing an unknown passkey: %d, want 404", a.status)
	}
	removed := stepUpVia(t, u.srvURL, "/api/v1/account/passkeys/remove", PasskeyRemove{ID: pk.ID}, u.auth, u.userID, u.cookie)
	if removed.status != http.StatusOK {
		t.Fatalf("passkeys/remove confirmed: %d %s", removed.status, removed.body)
	}
	if n := u.passkeyCount(t); n != 1 {
		t.Fatalf("%d passkeys after a confirmed removal, want 1", n)
	}
	last := getAccount(t, u.srvURL, u.cookie).Passkeys[0].ID
	if a := stepUpVia(t, u.srvURL, "/api/v1/account/passkeys/remove", PasskeyRemove{ID: last}, u.auth,
		u.userID, u.cookie); a.status != http.StatusConflict {
		t.Fatalf("removing the last passkey: %d, want 409", a.status)
	}

	events := authEventTypes(t, u)
	for _, want := range []string{AuthEventPasskeyAdded, AuthEventRecoveryCodesRegenerated, AuthEventPasskeyRemoved} {
		if !strings.Contains(events, want) {
			t.Errorf("no %s auth event in %s", want, events)
		}
	}
}

func authEventTypes(t *testing.T, u stepUpUser) string {
	t.Helper()
	rows, err := u.authStore.pool.Query(t.Context(), `SELECT event_type FROM innsegl_auth.auth_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return strings.Join(out, ",")
}

// AUTH-019 — a recovery-code sign-in is the one way back in with no
// passkey at hand, so for a short while after it the code itself is the
// fresh factor for adding one; after that, a passkey confirms it.
func TestAUTH019RecoverySignInMayAddAPasskeyOnlyWhileFresh(t *testing.T) {
	u := newStepUpUser(t)
	codes, err := u.authStore.MintRecoveryCodes(t.Context(), u.userID)
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, http.MethodPost, u.srvURL+"/api/v1/auth/recover", mustJSON(t, RecoverRequest{Code: codes[0]}))
	if rec.status != http.StatusOK {
		t.Fatalf("recover: %d %s", rec.status, rec.body)
	}
	recovery := sessionCookieFrom(t, rec)

	if _, pk := addPasskeyViaAPI(t, u.srvURL, "replacement", recovery, nil, u.userID); pk.Name != "replacement" {
		t.Fatalf("added %+v", pk)
	}

	// The window is measured from the sign-in.
	if _, err = u.authStore.pool.Exec(t.Context(), `UPDATE innsegl_auth.sessions
		SET created_at = created_at - interval '11 minutes' WHERE session_id_hash = $1`, hashToken(recovery.Value)); err != nil {
		t.Fatal(err)
	}
	begin := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/begin",
		mustJSON(t, PasskeyBeginRequest{Name: "late"}), testWebAuthnConfig.RPOrigin, recovery)
	var challenge passkeyAddChallenge
	decodeBody(t, begin, &challenge)
	if challenge.Confirm == nil {
		t.Fatal("an old recovery session was let add a passkey without a confirmation")
	}
	late := newSoftAuthenticator(t)
	created, err := late.Register(challenge.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if err != nil {
		t.Fatal(err)
	}
	a := unlockDo(t, http.MethodPost, u.srvURL+"/api/v1/account/passkeys/finish", mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(created),
	}), testWebAuthnConfig.RPOrigin, recovery)
	if a.status != http.StatusUnauthorized {
		t.Fatalf("an old recovery session added a passkey: %d %s", a.status, a.body)
	}
}

// ---------------------------------------------------------------------------
// AUTH-020 — idle sessions end
// ---------------------------------------------------------------------------

func backdateLastSeen(t *testing.T, u stepUpUser, cookie *http.Cookie, by time.Duration) {
	t.Helper()
	if _, err := u.authStore.pool.Exec(t.Context(), `UPDATE innsegl_auth.sessions
		SET last_seen_at = clock_timestamp() - make_interval(secs => $2) WHERE session_id_hash = $1`,
		hashToken(cookie.Value), by.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func lastSeen(t *testing.T, u stepUpUser, cookie *http.Cookie) time.Time {
	t.Helper()
	var at time.Time
	if err := u.authStore.pool.QueryRow(t.Context(), `SELECT last_seen_at FROM innsegl_auth.sessions
		WHERE session_id_hash = $1`, hashToken(cookie.Value)).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// AUTH-020 — 30 minutes without a request ends a session, on every surface,
// and the session check says why.
func TestAUTH020IdleSessionEnds(t *testing.T) {
	u := newStepUpUser(t)

	// 29 idle minutes: still live, and the request slides the clock.
	backdateLastSeen(t, u, u.cookie, 29*time.Minute)
	if a := get(t, u.srvURL, "/api/v1/overview", u.cookie); a.status != http.StatusOK {
		t.Fatalf("a session idle 29 minutes: %d, want 200", a.status)
	}
	if since := time.Since(lastSeen(t, u, u.cookie)); since > time.Minute {
		t.Fatalf("a request did not move last_seen_at (it is %s old)", since)
	}

	// 31: over, on the read API, the account surface and the session check.
	backdateLastSeen(t, u, u.cookie, 31*time.Minute)
	a := get(t, u.srvURL, "/api/v1/overview", u.cookie)
	if a.status != http.StatusUnauthorized || !strings.Contains(string(a.body), "30 minutes") {
		t.Fatalf("a session idle 31 minutes: %d %s", a.status, a.body)
	}
	if a := get(t, u.srvURL, "/api/v1/account", u.cookie); a.status != http.StatusUnauthorized {
		t.Fatalf("the account surface answered an idle session: %d", a.status)
	}
	session := get(t, u.srvURL, "/api/v1/auth/session", u.cookie)
	var status SessionStatus
	decodeBody(t, session, &status)
	if status.Authenticated || status.Ended != sessionEndedIdle {
		t.Fatalf("auth/session for an idle session = %+v", status)
	}

	// It stays ended: a request does not revive it.
	backdateLastSeen(t, u, u.cookie, 0)
	if a := get(t, u.srvURL, "/api/v1/overview", u.cookie); a.status != http.StatusUnauthorized {
		t.Fatalf("an idle-ended session came back: %d", a.status)
	}
	// A fresh sign-in is not ended.
	login := loginWithAuthenticator(t, u.srvURL, u.auth, u.userID)
	if a := get(t, u.srvURL, "/api/v1/overview", sessionCookieFrom(t, login)); a.status != http.StatusOK {
		t.Fatalf("a new sign-in after an idle end: %d", a.status)
	}
	if got := sessionIdleTimeout; got != 30*time.Minute {
		t.Fatalf("sessionIdleTimeout = %s, want 30m", got)
	}
}

// AUTH-020 — a session the store cannot slide or end is no session: the
// check fails closed.
func TestAUTH020SessionStoreFailuresFailClosed(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `REVOKE UPDATE ON innsegl_auth.sessions FROM `+AuthWriterRole)
	if a := get(t, h.srv.URL, "/api/v1/overview", h.cookie); a.status != http.StatusUnauthorized {
		t.Fatalf("a session the store cannot slide: %d, want 401", a.status)
	}
	h.ownerExec(t, `UPDATE innsegl_auth.sessions SET last_seen_at = clock_timestamp() - interval '1 hour'`)
	if a := get(t, h.srv.URL, "/api/v1/overview", h.cookie); a.status != http.StatusUnauthorized {
		t.Fatalf("an idle session the store cannot end: %d, want 401", a.status)
	}
}
