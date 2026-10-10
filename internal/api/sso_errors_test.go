// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The organisation sign-in's own failure paths (#485): every refusal and
// every store failure the routes answer, read back through the server. A
// store failure is made with the migration owner's credential (never a role
// the API holds) or through fakeOrgs' error knobs.

var errSpineDown = errors.New("the spine is down")

func (h ssoHarness) post(t *testing.T, path, body string, cookies ...*http.Cookie) answer {
	t.Helper()
	return do(t, http.MethodPost, h.srv.URL+path, body, cookies...)
}

// AUTH-008: each refusal of a change to the connection, as the spine
// answers it, is its own status.
func TestAUTH008TheSpinesRefusalsOfAChangeAreDistinct(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrOrgForbidden, http.StatusForbidden},
		{ErrSSONameTaken, http.StatusConflict},
		{ErrOrgInvalid, http.StatusBadRequest},
		{ErrSSONotConfigured, http.StatusNotFound},
		{errSpineDown, http.StatusInternalServerError},
	} {
		h.orgs.mu.Lock()
		h.orgs.sso().setErr = tc.err
		h.orgs.mu.Unlock()
		a := h.confirm(t, "sso/configure", SSOConfigureRequest{OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{
			SignInName: "example-org", Issuer: h.idp.Issuer(), ClientID: ssoTestClient}}, h.auth)
		if a.status != tc.want {
			t.Errorf("configure refused with %v: %d %s, want %d", tc.err, a.status, a.body, tc.want)
		}
	}
	h.orgs.mu.Lock()
	h.orgs.sso().setErr = nil
	h.orgs.mu.Unlock()
	h.configure(t)
	h.orgs.mu.Lock()
	h.orgs.sso().removedErr = errSpineDown
	h.orgs.mu.Unlock()
	if a := h.confirm(t, "sso/remove", MemberRequest{OrganisationID: orgA}, h.auth); a.status != http.StatusInternalServerError {
		t.Errorf("remove with the spine down: %d %s", a.status, a.body)
	}
	h.orgs.mu.Lock()
	h.orgs.sso().removedErr = nil
	h.orgs.mu.Unlock()
	if a := h.confirm(t, "sso/remove", MemberRequest{OrganisationID: orgA}, h.auth); a.status != http.StatusOK {
		t.Fatalf("remove: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/sso/remove/begin", mustJSON(t, MemberRequest{OrganisationID: orgA}), h.cookie); a.status != http.StatusNotFound {
		t.Errorf("removing what is not there: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/sso/remove/begin", "{", h.cookie); a.status != http.StatusBadRequest {
		t.Errorf("remove with a bad body: %d", a.status)
	}
	if a := h.post(t, "/api/v1/account/sso/remove/finish", `{"ceremony_id":"nope"}`, h.cookie); a.status != http.StatusUnauthorized {
		t.Errorf("remove finish with no ceremony: %d", a.status)
	}
	if a := h.post(t, "/api/v1/account/sso/configure/finish", `{"ceremony_id":"nope"}`, h.cookie); a.status != http.StatusUnauthorized {
		t.Errorf("configure finish with no ceremony: %d", a.status)
	}
}

// AUTH-008: configure/begin refuses a body it cannot use before any
// passkey prompt, and someone else's organisation.
func TestAUTH008ConfigureBeginRefusesWhatItCannotUse(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"not JSON":           {"{", http.StatusBadRequest},
		"no client id":       {mustJSON(t, SSOConfigureRequest{OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{SignInName: "x-org", Issuer: h.idp.Issuer()}}), http.StatusBadRequest},
		"an http issuer":     {mustJSON(t, SSOConfigureRequest{OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{SignInName: "x-org", Issuer: "http://idp.example.test", ClientID: "c"}}), http.StatusBadRequest},
		"someone else's org": {mustJSON(t, SSOConfigureRequest{OrganisationID: orgC, SSOConnectionParams: SSOConnectionParams{SignInName: "x-org", Issuer: h.idp.Issuer(), ClientID: "c"}}), http.StatusForbidden},
	} {
		if a := h.post(t, "/api/v1/account/sso/configure/begin", tc.body, h.cookie); a.status != tc.want {
			t.Errorf("%s: %d %s, want %d", name, a.status, a.body, tc.want)
		}
	}
}

// AUTH-009: the read and the begin routes report a spine they cannot read,
// a provider they cannot reach and a sign-in they cannot save.
func TestAUTH009BeginAndReadReportWhatTheyCannotDo(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)

	if a := h.post(t, "/api/v1/auth/sso/begin", "{"); a.status != http.StatusBadRequest {
		t.Errorf("begin with a bad body: %d", a.status)
	}
	if a := h.post(t, "/api/v1/account/sso/link", "{", h.cookie); a.status != http.StatusBadRequest {
		t.Errorf("link with a bad body: %d", a.status)
	}

	h.orgs.mu.Lock()
	h.orgs.sso().lookupErr = errSpineDown
	h.orgs.mu.Unlock()
	if a := h.post(t, "/api/v1/auth/sso/begin", mustJSON(t, SSOSignInRequest{SignInName: "example-org"})); a.status != http.StatusInternalServerError {
		t.Errorf("begin with the spine down: %d", a.status)
	}
	if a := get(t, h.srv.URL, "/api/v1/account/sso?organisation_id="+orgA, h.cookie); a.status != http.StatusInternalServerError {
		t.Errorf("read with the spine down: %d", a.status)
	}
	h.orgs.mu.Lock()
	h.orgs.sso().lookupErr = nil
	h.orgs.mu.Unlock()

	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.webauthn_ceremonies FROM `+AuthWriterRole)
	if a := h.post(t, "/api/v1/auth/sso/begin", mustJSON(t, SSOSignInRequest{SignInName: "example-org"})); a.status != http.StatusInternalServerError {
		t.Errorf("begin that cannot save its state: %d %s", a.status, a.body)
	}
	h.ownerExec(t, `GRANT INSERT ON innsegl_auth.webauthn_ceremonies TO `+AuthWriterRole)

	h.idp.Close()
	if a := h.post(t, "/api/v1/auth/sso/begin", mustJSON(t, SSOSignInRequest{SignInName: "example-org"})); a.status != http.StatusBadGateway {
		t.Errorf("begin with the provider gone: %d %s", a.status, a.body)
	}
}

// AUTH-009: no spine at all answers 503 on the public route and refuses at
// the callback.
func TestAUTH009NoSpineNoOrganisationSignIn(t *testing.T) {
	h := newOrgHarness(t, roleOwner, false)
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/sso/begin", `{"sign_in_name":"x"}`); a.status != http.StatusServiceUnavailable {
		t.Errorf("begin with no spine: %d", a.status)
	}
	a := noFollow(t, http.DefaultClient, http.MethodGet, h.srv.URL+ssoCallbackPath+"?state=s&code=c", "")
	if a.status != http.StatusSeeOther || a.header.Get("Location") != "/?sso=internal" {
		t.Errorf("callback with no spine: %d %s", a.status, a.header.Get("Location"))
	}
}

// AUTH-010: the callback turns every failure after the state into a
// refusal that signs no one in: a corrupt flight, the provider gone, a
// store that cannot read identities or open the session, and a spine that
// fails the join.
func TestAUTH010TheCallbackRefusesEveryFailureAfterTheState(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	h.linked(t)

	f := h.beginSignIn(t, "example-org")
	h.ownerExec(t, `UPDATE innsegl_auth.webauthn_ceremonies SET session_data = '[1]' WHERE ceremony_id = $1`, f.state)
	if where, s := h.land(t, f, f.binding); where != "/?sso=internal" || s != nil {
		t.Errorf("a corrupt flight: %q %v", where, s)
	}

	f = h.beginSignIn(t, "example-org")
	h.ownerExec(t, `ALTER TABLE innsegl_auth.oidc_identities RENAME TO oidc_identities_gone`)
	if where, s := h.land(t, f, f.binding); where != "/?sso=internal" || s != nil {
		t.Errorf("identities unreadable: %q %v", where, s)
	}
	h.ownerExec(t, `ALTER TABLE innsegl_auth.oidc_identities_gone RENAME TO oidc_identities`)

	h.orgs.mu.Lock()
	h.orgs.sso().joinErr = errSpineDown
	h.orgs.mu.Unlock()
	f = h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, f.binding); where != "/?sso=internal" || s != nil {
		t.Errorf("the join failed: %q %v", where, s)
	}
	h.orgs.mu.Lock()
	h.orgs.sso().joinErr = nil
	h.orgs.mu.Unlock()

	f = h.beginSignIn(t, "example-org")
	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.sessions FROM `+AuthWriterRole)
	if where, s := h.land(t, f, f.binding); where != "/?sso=internal" || s != nil {
		t.Errorf("no session could be opened: %q %v", where, s)
	}
	h.ownerExec(t, `GRANT INSERT ON innsegl_auth.sessions TO `+AuthWriterRole)

	// The provider refuses the code (another client's secret now): no token.
	f = h.beginSignIn(t, "example-org")
	h.orgs.mu.Lock()
	c := h.orgs.sso().conns[orgA]
	c.ClientSecret = "wrong"
	h.orgs.sso().conns[orgA] = c
	h.orgs.mu.Unlock()
	if where, s := h.land(t, f, f.binding); where != "/?sso=provider" || s != nil {
		t.Errorf("the provider refused the code: %q %v", where, s)
	}

	f = h.beginSignIn(t, "example-org")
	h.idp.Close()
	if where, s := h.land(t, f, f.binding); where != "/?sso=provider" || s != nil {
		t.Errorf("the provider gone mid-flight: %q %v", where, s)
	}
}

// AUTH-011: connecting is refused, and leaves no link behind, when the
// organisation removed the person or the join fails; a store that cannot
// write the link refuses too.
func TestAUTH011AConnectTheOrganisationRefusesLeavesNoLink(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	for _, tc := range []struct {
		err    error
		reason string
	}{{ErrRemovedMember, "removed"}, {errSpineDown, "internal"}} {
		h.orgs.mu.Lock()
		h.orgs.sso().joinErr = tc.err
		h.orgs.mu.Unlock()
		f := h.beginLink(t)
		if where, _ := h.land(t, f, f.binding); where != "/account?sso="+tc.reason {
			t.Errorf("join refused with %v: %q", tc.err, where)
		}
		if n := h.count(t, `SELECT count(*) FROM innsegl_auth.oidc_identities`); n != 0 {
			t.Errorf("a refused join left %d links", n)
		}
	}
	h.orgs.mu.Lock()
	h.orgs.sso().joinErr = nil
	h.orgs.mu.Unlock()

	f := h.beginLink(t)
	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.oidc_identities FROM `+AuthWriterRole)
	if where, _ := h.land(t, f, f.binding); where != "/account?sso=internal" {
		t.Errorf("a link that cannot be written: %q", where)
	}
	h.ownerExec(t, `GRANT INSERT ON innsegl_auth.oidc_identities TO `+AuthWriterRole)

	if a := do(t, http.MethodDelete, h.srv.URL+"/api/v1/account/sign-ins/not-a-number", "", h.cookie); a.status != http.StatusNotFound {
		t.Errorf("unlink a malformed id: %d", a.status)
	}
	h.ownerExec(t, `ALTER TABLE innsegl_auth.oidc_identities RENAME TO oidc_identities_gone`)
	if a := do(t, http.MethodDelete, h.srv.URL+"/api/v1/account/sign-ins/1", "", h.cookie); a.status != http.StatusInternalServerError {
		t.Errorf("unlink with the table gone: %d", a.status)
	}
	if a := get(t, h.srv.URL, "/api/v1/account", h.cookie); a.status != http.StatusInternalServerError ||
		strings.Contains(string(a.body), "oidc") {
		t.Errorf("the account with its sign-ins unreadable: %d %s", a.status, a.body)
	}
}

// The identity store's methods report a pool they cannot use, never a
// "not found" that would read as an unknown identity.
func TestSSOStoreMethodsAfterThePoolIsClosed(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	ctx := context.Background()
	if _, _, err := store.CreateSSOSession(ctx, "u", strings.Repeat("a", 32), time.Hour); err == nil {
		t.Error("CreateSSOSession on a closed pool returned nil")
	}
	if err := store.LinkOIDCIdentity(ctx, "https://i", "s", "u", ""); err == nil || errors.Is(err, ErrIdentityLinkedElsewhere) {
		t.Errorf("LinkOIDCIdentity on a closed pool: %v", err)
	}
	if _, err := store.UserByOIDCIdentity(ctx, "https://i", "s"); err == nil || errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("UserByOIDCIdentity on a closed pool: %v", err)
	}
	if _, err := store.OIDCIdentities(ctx, "u"); err == nil {
		t.Error("OIDCIdentities on a closed pool returned nil")
	}
	if err := store.UnlinkOIDCIdentity(ctx, "u", 1); err == nil || errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("UnlinkOIDCIdentity on a closed pool: %v", err)
	}
	if err := store.unlinkOIDCIdentityBySubject(ctx, "u", "https://i", "s"); err == nil {
		t.Error("unlinkOIDCIdentityBySubject on a closed pool returned nil")
	}
}
