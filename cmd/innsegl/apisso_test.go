// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/oidctest"
)

// AUTH-011 end to end (#485): the real `innsegl api`, the real accounts
// spine and a real provider (internal/oidctest: TLS, signed tokens, PKCE,
// exact redirect URIs). The owner's organisation signs in through its
// provider; a second person links their identity there and so joins it;
// they sign in through it; the owner removes them, which ends that session
// and refuses the next sign-in; the owner's passkey session is untouched.
// Nothing the provider said reaches an auth event, the audit trail or the
// command's log.
func TestAUTH011TheOrganisationSignInEndToEndThroughTheCommand(t *testing.T) {
	ownerDSN, readerDSN, authDSN := freshLedgerDB(t)
	repoDir, _ := newProofRepo(t)
	fulcio, rekor := closedAddress(t), closedAddress(t)

	idp, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	const (
		client  = "innsegl-e2e"
		secret  = "e2e-secret-auth011"
		subject = "e2e-subject-auth011"
		email   = "member-auth011@example.test"
	)
	idp.Register(oidctest.Client{ID: client, Secret: secret,
		RedirectURIs: []string{apiIntegrationOrigin + "/api/v1/auth/sso/callback"}})
	idp.SignInAs(subject, email, "Member Person")

	addr, stderr := startAPICommandWith(t, apiDeps{ssoClient: idp.HTTPClient()},
		apiArgsFor(t, readerDSN, authDSN, "github.com/innsegl/demo", repoDir, fulcio, rekor)...)
	base := "http://" + addr
	ownerCookie := enrolAndSignIn(t, base, authDSN)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	spine, err := accounts.Open(ctx, authDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spine.Close)
	authStore, err := api.OpenAuthStore(ctx, authDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authStore.Close)

	var ownerID string
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if err = conn.QueryRow(ctx, `SELECT user_id FROM innsegl_auth.users`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	ms, err := spine.Memberships(ctx, ownerID)
	if err != nil || len(ms) != 1 || ms[0].Role != accounts.RoleOwner {
		t.Fatalf("the owner's organisations: %+v %v", ms, err)
	}
	org := ms[0]
	if _, err = spine.SetSSOConnection(ctx, org.AccountID, api.SSOConnectionParams{SignInName: "e2e-org",
		Issuer: idp.Issuer(), ClientID: client, ClientSecret: secret}, ownerID); err != nil {
		t.Fatal(err)
	}

	// A second person, signed in some other way, with no membership.
	memberID, err := api.NewUserID()
	if err != nil {
		t.Fatal(err)
	}
	if err = authStore.CreateUser(ctx, memberID, "Member Person"); err != nil {
		t.Fatal(err)
	}
	token, _, err := authStore.CreateSession(ctx, memberID, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	memberCookie := &http.Cookie{Name: "innsegl_session", Value: token}

	// They link the organisation's sign-in: they are now its member.
	where, _ := ssoFlightThrough(t, idp, base, "/api/v1/account/sso/link",
		`{"organisation_id":"`+org.AccountID+`"}`, memberCookie)
	if where != "/account?notice=sso-linked" {
		t.Fatalf("link landed on %s", where)
	}
	if got := sessionOrgs(t, base, memberCookie); !strings.Contains(got, org.AccountID+":member") {
		t.Fatalf("after linking, the member's organisations = %s", got)
	}

	// They sign in through it: the same session cookie a passkey opens.
	where, ssoCookie := ssoFlightThrough(t, idp, base, "/api/v1/auth/sso/begin", `{"sign_in_name":"e2e-org"}`)
	if where != "/" || ssoCookie == nil {
		t.Fatalf("sign-in landed on %s with %v", where, ssoCookie)
	}
	if got := sessionOrgs(t, base, ssoCookie); !strings.Contains(got, org.AccountID+":member") {
		t.Fatalf("the SSO session's organisations = %s", got)
	}

	// The owner removes them: the SSO session ends, and the organisation's
	// sign-in does not bring them back.
	removal, err := spine.RemoveMember(ctx, org.AccountID, memberID, ownerID)
	if err != nil || removal.SessionsRevoked < 2 {
		t.Fatalf("removal: %+v %v, want both their sessions revoked", removal, err)
	}
	if got := sessionOrgs(t, base, ssoCookie); got != "signed out" {
		t.Fatalf("after removal the SSO session answers %s", got)
	}
	if where, again := ssoFlightThrough(t, idp, base, "/api/v1/auth/sso/begin", `{"sign_in_name":"e2e-org"}`); where != "/?sso=removed" || again != nil {
		t.Fatalf("a removed member signed back in: %s %v", where, again)
	}

	// The owner's passkey session never noticed.
	if status, body := getJSON(t, base+"/api/v1/account", ownerCookie); status != http.StatusOK {
		t.Fatalf("the owner's passkey session: %d %s", status, body)
	}

	var trail string
	if err = conn.QueryRow(ctx, `SELECT
		(SELECT coalesce(string_agg(row_to_json(e)::text, ''), '') FROM innsegl_auth.auth_events e) ||
		(SELECT coalesce(string_agg(row_to_json(a)::text, ''), '') FROM innsegl_auth.audit a)`).Scan(&trail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trail, "organisation sign-in") {
		t.Fatalf("no auth event recorded the organisation sign-in: %s", trail)
	}
	for what, surface := range map[string]string{"the auth events and audit trail": trail, "the command's log": stderr.String()} {
		for _, leak := range []string{subject, email, idp.Issuer(), client, secret} {
			if strings.Contains(surface, leak) {
				t.Errorf("%s holds %q", what, leak)
			}
		}
	}
}

// ssoFlightThrough begins at path, walks the provider and lands at the
// callback as one browser would, answering where it was sent and the
// session cookie it was given.
func ssoFlightThrough(t *testing.T, idp *oidctest.Provider, base, path, body string, cookies ...*http.Cookie) (string, *http.Cookie) {
	t.Helper()
	status, header, raw := postJSON(t, base+path, body, cookies...)
	if status != http.StatusOK {
		t.Fatalf("POST %s: %d %s", path, status, raw)
	}
	var begin struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatal(err)
	}
	binding := cookieFrom(header, "innsegl_sso")
	if binding == nil {
		t.Fatal("no binding cookie")
	}
	status, header = oneHop(t, idp.HTTPClient(), begin.RedirectURL, nil)
	back, err := url.Parse(header.Get("Location"))
	if err != nil || status != http.StatusFound {
		t.Fatalf("the provider answered %d (%v)", status, err)
	}
	status, header = oneHop(t, http.DefaultClient, base+back.Path+"?"+back.RawQuery, binding)
	if status != http.StatusSeeOther {
		t.Fatalf("callback: %d", status)
	}
	return header.Get("Location"), cookieFrom(header, "innsegl_session")
}

func cookieFrom(h http.Header, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// oneHop GETs target without following a redirect.
func oneHop(t *testing.T, client *http.Client, target string, cookie *http.Cookie) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header
}

// sessionOrgs answers a session's organisations as "id:role" pairs, or
// "signed out".
func sessionOrgs(t *testing.T, base string, cookie *http.Cookie) string {
	t.Helper()
	status, body := getJSON(t, base+"/api/v1/auth/session", cookie)
	if status != http.StatusOK {
		t.Fatalf("session: %d %s", status, body)
	}
	var s api.SessionStatus
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	if !s.Authenticated {
		return "signed out"
	}
	var out []string
	for _, o := range s.Organisations {
		out = append(out, o.ID+":"+o.Role)
	}
	return strings.Join(out, ",")
}
