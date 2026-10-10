// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"strconv"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/oidctest"
)

// Signing in with an organisation's identity provider, through the server
// (#485, E30). The provider is real (internal/oidctest: TLS, signed tokens,
// PKCE, exact redirect URIs); the server, sessions, passkeys, ceremonies and
// identities are real rows; the spine is fakeOrgs, whose sign-in half also
// writes the connection row a session references. internal/accounts runs the
// real spine (AUTH-008, AUTH-011) and cmd/innsegl the whole of it end to end.

const ssoTestEmail = "person@example.test"

type ssoHarness struct {
	orgHarness
	idp *oidctest.Provider
}

func newSSOHarness(t *testing.T, role string) ssoHarness {
	t.Helper()
	idp, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	idp.Register(oidctest.Client{ID: ssoTestClient, Secret: ssoTestSecret,
		RedirectURIs: []string{testWebAuthnConfig.RPOrigin + ssoCallbackPath}})
	idp.SignInAs(ssoTestSubject, ssoTestEmail, "A Person")
	h := newOrgHarness(t, role, true, func(c *ServerConfig) { c.SSOHTTPClient = idp.HTTPClient() })
	return ssoHarness{orgHarness: h, idp: idp}
}

// configure sets organisation A's sign-in through the owner's passkey.
func (h ssoHarness) configure(t *testing.T) AccountSSO {
	t.Helper()
	a := h.confirm(t, "sso/configure", SSOConfigureRequest{OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{
		SignInName: "example-org", Issuer: h.idp.Issuer(), ClientID: ssoTestClient, ClientSecret: ssoTestSecret,
	}}, h.auth)
	if a.status != http.StatusOK {
		t.Fatalf("configure: %d %s", a.status, a.body)
	}
	var out AccountSSO
	decodeBody(t, a, &out)
	return out
}

// noFollow issues one request and never follows a redirect.
func noFollow(t *testing.T, client *http.Client, method, target, payload string, cookies ...*http.Cookie) answer {
	t.Helper()
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var body io.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range cookies {
		if ck != nil {
			req.AddCookie(ck)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { discardError(resp.Body.Close()) }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

func cookieNamed(a answer, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: a.header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// flight is one sign-in in progress: where the provider sent the browser
// back, and the browser's binding cookie.
type flight struct {
	callback string // the server's callback URL, with code and state
	binding  *http.Cookie
	state    string
}

// start begins a sign-in (begin) or a link (link, with a session) and walks
// the provider's authorization endpoint.
func (h ssoHarness) start(t *testing.T, begin answer) flight {
	t.Helper()
	if begin.status != http.StatusOK {
		t.Fatalf("begin: %d %s", begin.status, begin.body)
	}
	var b SSOBegin
	decodeBody(t, begin, &b)
	binding := cookieNamed(begin, ssoCookieName)
	if binding == nil || !binding.HttpOnly || binding.SameSite != http.SameSiteLaxMode || binding.Path != ssoCallbackPath {
		t.Fatalf("binding cookie = %+v", binding)
	}
	authz := noFollow(t, h.idp.HTTPClient(), http.MethodGet, b.RedirectURL, "")
	if authz.status != http.StatusFound {
		t.Fatalf("the provider answered %d: %s", authz.status, authz.body)
	}
	back, err := url.Parse(authz.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Scheme + "://" + back.Host + back.Path; got != testWebAuthnConfig.RPOrigin+ssoCallbackPath {
		t.Fatalf("the provider sent the browser to %s", got)
	}
	return flight{callback: h.srv.URL + ssoCallbackPath + "?" + back.RawQuery, binding: binding,
		state: back.Query().Get("state")}
}

func (h ssoHarness) beginSignIn(t *testing.T, name string) flight {
	t.Helper()
	return h.start(t, do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/sso/begin", mustJSON(t, SSOSignInRequest{SignInName: name})))
}

func (h ssoHarness) beginLink(t *testing.T) flight {
	t.Helper()
	return h.start(t, do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/link",
		mustJSON(t, MemberRequest{OrganisationID: orgA}), h.cookie))
}

// land finishes at the callback and answers where the server sent the
// browser and the session cookie it set, if any.
func (h ssoHarness) land(t *testing.T, f flight, cookies ...*http.Cookie) (string, *http.Cookie) {
	t.Helper()
	a := noFollow(t, http.DefaultClient, http.MethodGet, f.callback, "", cookies...)
	if a.status != http.StatusSeeOther {
		t.Fatalf("callback: %d %s", a.status, a.body)
	}
	return a.header.Get("Location"), cookieNamed(a, sessionCookieName)
}

func (h ssoHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var n int
	if err := c.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// linked links the provider's identity to the harness user and answers the
// account page's view of it.
func (h ssoHarness) linked(t *testing.T) {
	t.Helper()
	f := h.beginLink(t)
	where, _ := h.land(t, f, f.binding)
	if where != "/account?notice=sso-linked" {
		t.Fatalf("link landed on %s", where)
	}
}

// AUTH-008: only the owner sets the organisation's sign-in, after a fresh
// passkey of its own kind; the secret never comes back; a member sees that
// it exists and its name, nothing about the provider.
func TestAUTH008OnlyTheOwnerConfiguresTheSignInAfterAFreshPasskey(t *testing.T) {
	for _, role := range []string{roleAdmin, roleMember} {
		h := newSSOHarness(t, role)
		a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/configure/begin", mustJSON(t, SSOConfigureRequest{
			OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{SignInName: "example-org",
				Issuer: h.idp.Issuer(), ClientID: ssoTestClient}}), h.cookie)
		if a.status != http.StatusForbidden {
			t.Fatalf("%s began configuring: %d %s", role, a.status, a.body)
		}
		if a = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/remove/begin",
			mustJSON(t, MemberRequest{OrganisationID: orgA}), h.cookie); a.status != http.StatusForbidden {
			t.Fatalf("%s began removing: %d %s", role, a.status, a.body)
		}
	}

	h := newSSOHarness(t, roleOwner)
	// A provider that cannot be reached is refused before any passkey prompt.
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/configure/begin", mustJSON(t, SSOConfigureRequest{
		OrganisationID: orgA, SSOConnectionParams: SSOConnectionParams{SignInName: "example-org",
			Issuer: "https://idp.invalid", ClientID: ssoTestClient}}), h.cookie)
	if a.status != http.StatusBadGateway {
		t.Fatalf("an unreachable provider: %d %s", a.status, a.body)
	}
	// A confirmation begun for removing cannot finish configuring.
	h.configure(t)
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/remove/begin",
		mustJSON(t, MemberRequest{OrganisationID: orgA}), h.cookie)
	if begin.status != http.StatusOK {
		t.Fatalf("remove/begin: %d %s", begin.status, begin.body)
	}
	if a = h.finish(t, "sso/configure", h.assertion(t, begin, h.auth)); a.status != http.StatusUnauthorized {
		t.Fatalf("a removal's confirmation finished a configuration: %d %s", a.status, a.body)
	}

	got := get(t, h.srv.URL, "/api/v1/account/sso?organisation_id="+orgA, h.cookie)
	var view AccountSSO
	decodeBody(t, got, &view)
	if !view.Configured || view.SignInName != "example-org" || view.Issuer != h.idp.Issuer() ||
		view.ClientID != ssoTestClient || !view.HasClientSecret || !view.CanManage ||
		view.RedirectURI != testWebAuthnConfig.RPOrigin+ssoCallbackPath {
		t.Fatalf("the owner's view = %+v", view)
	}
	if strings.Contains(string(got.body), ssoTestSecret) {
		t.Fatal("the client secret came back")
	}

	// A member of organisation B (the harness user is one) sees only that
	// B has no sign-in; a member of A who is not its owner sees the name.
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID][0].Role = roleMember
	h.orgs.mu.Unlock()
	got = get(t, h.srv.URL, "/api/v1/account/sso?organisation_id="+orgA, h.cookie)
	view = AccountSSO{}
	decodeBody(t, got, &view)
	if !view.Configured || view.SignInName != "example-org" || view.Issuer != "" || view.ClientID != "" ||
		view.CanManage || strings.Contains(string(got.body), h.idp.Issuer()) {
		t.Fatalf("a member's view = %s", got.body)
	}
	if a = get(t, h.srv.URL, "/api/v1/account/sso?organisation_id="+orgC, h.cookie); a.status != http.StatusForbidden {
		t.Fatalf("someone else's organisation: %d", a.status)
	}
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID][0].Role = roleOwner
	h.orgs.mu.Unlock()

	if a = h.confirm(t, "sso/remove", MemberRequest{OrganisationID: orgA}, h.auth); a.status != http.StatusOK {
		t.Fatalf("remove: %d %s", a.status, a.body)
	}
	if strings.Join(h.orgs.sso().removed, ",") != orgA+"|"+h.userID {
		t.Fatalf("removed = %v", h.orgs.sso().removed)
	}
}

// AUTH-009: a person links the organisation's sign-in to their account, then
// signs in with it: authorization code with PKCE, the same session cookie a
// passkey gets, and the organisation joined. Only the issuer and subject are
// kept: never the email, never a name.
func TestAUTH009AnExistingPersonSignsInThroughTheOrganisation(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	h.linked(t)

	if n := h.count(t, `SELECT count(*) FROM innsegl_auth.oidc_identities WHERE user_id = $1 AND issuer = $2 AND subject = $3`,
		h.userID, h.idp.Issuer(), ssoTestSubject); n != 1 {
		t.Fatalf("identities linked = %d", n)
	}
	acct := get(t, h.srv.URL, "/api/v1/account", h.cookie)
	var account Account
	decodeBody(t, acct, &account)
	if len(account.SignIns) != 1 || account.SignIns[0].Organisation != "example-org" ||
		account.SignIns[0].SignInName != "example-org" {
		t.Fatalf("account sign-ins = %+v", account.SignIns)
	}

	users := h.count(t, `SELECT count(*) FROM innsegl_auth.users`)
	f := h.beginSignIn(t, "Example-Org ")
	where, session := h.land(t, f, f.binding)
	if where != "/" || session == nil {
		t.Fatalf("sign-in landed on %q with session %v", where, session)
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.MaxAge <= 0 {
		t.Fatalf("the session cookie = %+v", session)
	}
	st := sessionOrganisations(t, h.srv.URL, session)
	if !st.Authenticated || st.DisplayName != "Test Operator" {
		t.Fatalf("the SSO session = %+v", st)
	}
	if n := h.count(t, `SELECT count(*) FROM innsegl_auth.sessions WHERE sso_connection_id IS NOT NULL AND user_id = $1`, h.userID); n != 1 {
		t.Fatalf("sessions opened through the connection = %d", n)
	}
	if after := h.count(t, `SELECT count(*) FROM innsegl_auth.users`); after != users {
		t.Fatalf("signing in made %d users", after-users)
	}
	if got := strings.Join(h.orgs.sso().joins, ","); !strings.Contains(got, "|"+h.userID) {
		t.Fatalf("joins asked = %s", got)
	}

	// Nothing the provider said beyond issuer and subject is anywhere in
	// the auth schema.
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var dump string
	if err := c.QueryRow(ctx, `SELECT string_agg(t, '') FROM (
		SELECT row_to_json(x)::text t FROM innsegl_auth.users x UNION ALL
		SELECT row_to_json(x)::text FROM innsegl_auth.oidc_identities x UNION ALL
		SELECT row_to_json(x)::text FROM innsegl_auth.sessions x UNION ALL
		SELECT row_to_json(x)::text FROM innsegl_auth.auth_events x UNION ALL
		SELECT row_to_json(x)::text FROM innsegl_auth.webauthn_ceremonies x) u`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{ssoTestEmail, "A Person"} {
		if strings.Contains(dump, leak) {
			t.Errorf("the auth schema holds %q", leak)
		}
	}
}

// AUTH-009: an identity no one has linked signs no one in, and makes no
// person: joining is for an existing one.
func TestAUTH009AnUnknownIdentityIsRefusedAndMakesNoUser(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	users := h.count(t, `SELECT count(*) FROM innsegl_auth.users`)
	f := h.beginSignIn(t, "example-org")
	where, session := h.land(t, f, f.binding)
	if where != "/?sso=unknown" || session != nil {
		t.Fatalf("an unknown identity landed on %q with %v", where, session)
	}
	if after := h.count(t, `SELECT count(*) FROM innsegl_auth.users`); after != users {
		t.Fatal("an unknown identity made a user")
	}
	if n := h.count(t, `SELECT count(*) FROM innsegl_auth.oidc_identities`); n != 0 {
		t.Fatal("an unknown identity was stored")
	}
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/sso/begin",
		mustJSON(t, SSOSignInRequest{SignInName: "nobody"})); a.status != http.StatusNotFound {
		t.Fatalf("an unknown sign-in name: %d %s", a.status, a.body)
	}
}

// AUTH-010: the state is single-use and bound to the browser that began
// the sign-in; a provider's refusal, a wrong token or a connection changed
// mid-flight signs no one in.
func TestAUTH010TheCallbackRefusesAReplayAnotherBrowserAndAWrongToken(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	h.linked(t)

	f := h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f); where != "/?sso=browser" || s != nil {
		t.Fatalf("no binding cookie: %q %v", where, s)
	}
	if where, s := h.land(t, f, f.binding); where != "/?sso=expired" || s != nil {
		t.Fatalf("the state replayed after a refusal: %q %v", where, s)
	}

	f = h.beginSignIn(t, "example-org")
	other := h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, other.binding); where != "/?sso=browser" || s != nil {
		t.Fatalf("another browser's binding: %q %v", where, s)
	}

	f = h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, f.binding); where != "/" || s == nil {
		t.Fatalf("a good sign-in: %q %v", where, s)
	}
	if where, s := h.land(t, f, f.binding); where != "/?sso=expired" || s != nil {
		t.Fatalf("a spent state replayed: %q %v", where, s)
	}

	f = h.beginSignIn(t, "example-org")
	denied := strings.Replace(f.callback, "code=", "error=access_denied&code=", 1)
	if where, s := h.land(t, flight{callback: denied}, f.binding); where != "/?sso=denied" || s != nil {
		t.Fatalf("the provider's refusal: %q %v", where, s)
	}

	h.idp.Tamper(func(c *oidctest.Claims, _ *oidctest.Signing) { c.Nonce = "someone-elses" })
	f = h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, f.binding); where != "/?sso=refused" || s != nil {
		t.Fatalf("a token with another nonce: %q %v", where, s)
	}
	h.idp.Tamper(nil)

	f = h.beginSignIn(t, "example-org")
	h.orgs.mu.Lock()
	c := h.orgs.sso().conns[orgA]
	c.ClientID = "changed"
	h.orgs.sso().conns[orgA] = c
	h.orgs.mu.Unlock()
	if where, s := h.land(t, f, f.binding); where != "/?sso=changed" || s != nil {
		t.Fatalf("a connection changed mid-flight: %q %v", where, s)
	}

	events := h.authEventDetails(t)
	for _, leak := range []string{ssoTestSubject, ssoTestEmail, h.idp.Issuer(), "127.0.0.1"} {
		if strings.Contains(events, leak) {
			t.Errorf("an auth event holds %q: %s", leak, events)
		}
	}
	if !strings.Contains(events, "organisation sign-in") {
		t.Errorf("no auth event names the organisation sign-in: %s", events)
	}
}

// AUTH-011: passkeys keep working beside the organisation's sign-in; a
// person the organisation removed is not signed back in through it; an
// identity linked to someone else is not taken; unlinking ends it.
func TestAUTH011PasskeysKeepWorkingAndARemovedMemberIsRefused(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	h.linked(t)

	if a := loginWithAuthenticator(t, h.srv.URL, h.auth, h.userID); a.status != http.StatusOK {
		t.Fatalf("passkey sign-in beside SSO: %d %s", a.status, a.body)
	}

	h.orgs.mu.Lock()
	h.orgs.sso().joinErr = ErrRemovedMember
	h.orgs.mu.Unlock()
	f := h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, f.binding); where != "/?sso=removed" || s != nil {
		t.Fatalf("a removed member: %q %v", where, s)
	}
	h.orgs.mu.Lock()
	h.orgs.sso().joinErr = nil
	h.orgs.mu.Unlock()

	// A second person links the same provider identity: refused.
	_, cookie2 := enrolSecondUser(t, h)
	f = h.start(t, do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sso/link",
		mustJSON(t, MemberRequest{OrganisationID: orgA}), cookie2))
	if where, _ := h.land(t, f, f.binding); where != "/account?sso=taken" {
		t.Fatalf("a second person took a linked identity: %q", where)
	}

	acct := get(t, h.srv.URL, "/api/v1/account", h.cookie)
	var account Account
	decodeBody(t, acct, &account)
	if len(account.SignIns) != 1 {
		t.Fatalf("sign-ins = %+v", account.SignIns)
	}
	path := "/api/v1/account/sign-ins/" + strconv.FormatInt(account.SignIns[0].ID, 10)
	if a := do(t, http.MethodDelete, h.srv.URL+path, "", cookie2); a.status != http.StatusNotFound {
		t.Fatalf("someone else unlinked it: %d", a.status)
	}
	if a := do(t, http.MethodDelete, h.srv.URL+path, "", h.cookie); a.status != http.StatusOK {
		t.Fatalf("unlink: %d %s", a.status, a.body)
	}
	f = h.beginSignIn(t, "example-org")
	if where, s := h.land(t, f, f.binding); where != "/?sso=unknown" || s != nil {
		t.Fatalf("an unlinked identity signed in: %q %v", where, s)
	}
}

// AUTH-010: a sign-in that is never finished expires on its own clock.
func TestAUTH010AStateOutlivingItsBoundIsRefused(t *testing.T) {
	h := newSSOHarness(t, roleOwner)
	h.configure(t)
	f := h.beginSignIn(t, "example-org")
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	if _, err := c.Exec(ctx, `UPDATE innsegl_auth.webauthn_ceremonies SET expires_at = now() - interval '1 second'
		WHERE ceremony_id = $1 AND kind = 'sso'`, f.state); err != nil {
		t.Fatal(err)
	}
	if where, s := h.land(t, f, f.binding); where != "/?sso=expired" || s != nil {
		t.Fatalf("an expired state: %q %v", where, s)
	}
	if ssoFlightTTL > 15*time.Minute || ssoFlightTTL < time.Minute {
		t.Fatalf("a sign-in may stay in flight for %s", ssoFlightTTL)
	}
}

// enrolSecondUser makes a second person with a session (and no passkey: a
// link needs only a session) who is a member of organisation A.
func enrolSecondUser(t *testing.T, h ssoHarness) (string, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	id, err := NewUserID()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.authStore.CreateUser(ctx, id, "Second Person"); err != nil {
		t.Fatal(err)
	}
	token, _, err := h.authStore.CreateSession(ctx, id, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h.orgs.mu.Lock()
	h.orgs.memberships[id] = []OrgMembership{{AccountID: orgA, Name: "example-org", Role: roleMember}}
	h.orgs.mu.Unlock()
	return id, &http.Cookie{Name: sessionCookieName, Value: token}
}

