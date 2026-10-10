// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"innsegl.dev/innsegl/internal/oidctest"
)

// The relying party's half of an organisation's sign-in (E30, #485), against
// a real provider (internal/oidctest) that signs real ID tokens and checks
// its own side: client, exact redirect URI, PKCE and single-use codes. No
// database: these are the protocol's checks alone.

const (
	ssoTestClient   = "innsegl-dashboard"
	ssoTestSecret   = "s3cret-for-tests"
	ssoTestRedirect = "https://dashboard.example.test/api/v1/auth/sso/callback"
	ssoTestSubject  = "idp-subject-7f3a"
)

type ssoRun struct {
	idp  *oidctest.Provider
	hc   *http.Client
	meta oidcProviderMeta
}

func newSSORun(t *testing.T) ssoRun {
	t.Helper()
	idp, err := oidctest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	idp.Register(oidctest.Client{ID: ssoTestClient, Secret: ssoTestSecret, RedirectURIs: []string{ssoTestRedirect}})
	idp.SignInAs(ssoTestSubject, "person@example.test", "A Person")
	hc := idp.HTTPClient()
	meta, err := discoverOIDC(context.Background(), hc, idp.Issuer())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	return ssoRun{idp: idp, hc: hc, meta: meta}
}

// code walks the authorization endpoint as a browser would and answers the
// code it redirects back with.
func (r ssoRun) code(t *testing.T, state, nonce, challenge, redirect string) string {
	t.Helper()
	u := r.meta.authorizationURL(ssoTestClient, redirect, state, nonce, challenge)
	noFollow := *r.hc
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { discardError(resp.Body.Close()) }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize answered %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != state {
		t.Fatalf("the provider returned state %q", loc.Query().Get("state"))
	}
	return loc.Query().Get("code")
}

// signIn is the whole relying-party exchange: PKCE, the code, the token,
// the verified identity.
func (r ssoRun) signIn(t *testing.T) (oidcIdentity, error) {
	t.Helper()
	verifier, challenge, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	code := r.code(t, "state-1", "nonce-1", challenge, ssoTestRedirect)
	raw, err := exchangeCode(context.Background(), r.hc, r.meta, ssoTestClient, ssoTestSecret, code, verifier, ssoTestRedirect)
	if err != nil {
		return oidcIdentity{}, err
	}
	return verifyIDToken(context.Background(), r.hc, r.meta, raw, ssoTestClient, "nonce-1", time.Now())
}

// AUTH-010: a token the provider signed for this client, this nonce and
// this moment is accepted, and yields the issuer and subject only.
func TestAUTH010AValidIDTokenYieldsTheIssuerAndSubject(t *testing.T) {
	r := newSSORun(t)
	id, err := r.signIn(t)
	if err != nil {
		t.Fatalf("a valid sign-in was refused: %v", err)
	}
	if id.Issuer != r.idp.Issuer() || id.Subject != ssoTestSubject {
		t.Fatalf("identity = %+v", id)
	}
	if r.idp.TokensIssued() != 1 {
		t.Fatalf("tokens issued = %d", r.idp.TokensIssued())
	}
}

// AUTH-010: every way an ID token can be wrong is refused, and the refusal
// names the reason without echoing what the token claimed.
func TestAUTH010AnIDTokenThatIsWrongInAnyWayIsRefused(t *testing.T) {
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		tamper func(*oidctest.Claims, *oidctest.Signing)
	}{
		{"another issuer", func(c *oidctest.Claims, _ *oidctest.Signing) { c.Issuer = "https://evil.example.test" }},
		{"another audience", func(c *oidctest.Claims, _ *oidctest.Signing) { c.Audience = []string{"someone-else"} }},
		{"several audiences and no azp", func(c *oidctest.Claims, _ *oidctest.Signing) {
			c.Audience = []string{ssoTestClient, "someone-else"}
		}},
		{"several audiences, azp another client", func(c *oidctest.Claims, _ *oidctest.Signing) {
			c.Audience, c.AZP = []string{ssoTestClient, "someone-else"}, "someone-else"
		}},
		{"another nonce", func(c *oidctest.Claims, _ *oidctest.Signing) { c.Nonce = "nonce-2" }},
		{"no nonce", func(c *oidctest.Claims, _ *oidctest.Signing) { c.Nonce = "" }},
		{"expired", func(c *oidctest.Claims, _ *oidctest.Signing) {
			c.Expiry = time.Now().Add(-10 * time.Minute).Unix()
		}},
		{"issued in the future", func(c *oidctest.Claims, _ *oidctest.Signing) {
			c.IssuedAt = time.Now().Add(time.Hour).Unix()
		}},
		{"no subject", func(c *oidctest.Claims, _ *oidctest.Signing) { c.Subject = "" }},
		{"signed by a key the provider does not publish", func(_ *oidctest.Claims, s *oidctest.Signing) { s.Key = otherRSA }},
		{"a key id the provider does not publish", func(_ *oidctest.Claims, s *oidctest.Signing) {
			s.Key, s.KeyID = otherRSA, "unknown-kid"
		}},
		{"alg none", func(_ *oidctest.Claims, s *oidctest.Signing) { s.Algorithm = "none" }},
		{"HS256 keyed with the public key", func(_ *oidctest.Claims, s *oidctest.Signing) {
			pub, merr := x509.MarshalPKIXPublicKey(&otherRSA.PublicKey)
			if merr != nil {
				panic(merr)
			}
			s.Algorithm, s.Key = jose.HS256, pub
		}},
		{"ES256 by a key the provider does not publish", func(_ *oidctest.Claims, s *oidctest.Signing) {
			s.Algorithm, s.Key = jose.ES256, otherEC
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSSORun(t)
			r.idp.Tamper(tc.tamper)
			id, err := r.signIn(t)
			if err == nil {
				t.Fatalf("accepted: %+v", id)
			}
			if !errors.Is(err, errIDTokenRefused) {
				t.Fatalf("refused, but not as an ID token: %v", err)
			}
			for _, leak := range []string{ssoTestSubject, "person@example.test", "evil.example.test"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the refusal echoes %q: %v", leak, err)
				}
			}
		})
	}
}

// AUTH-010: the PKCE verifier and the redirect URI are the ones the
// authorization request named, or the provider gives no token at all.
func TestAUTH010TheProviderRefusesAnotherVerifierOrRedirectURI(t *testing.T) {
	r := newSSORun(t)
	_, challenge, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	otherVerifier, _, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	code := r.code(t, "s", "n", challenge, ssoTestRedirect)
	if _, err := exchangeCode(context.Background(), r.hc, r.meta, ssoTestClient, ssoTestSecret, code,
		otherVerifier, ssoTestRedirect); err == nil {
		t.Fatal("a code was exchanged with another PKCE verifier")
	}

	verifier, challenge, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	code = r.code(t, "s", "n", challenge, ssoTestRedirect)
	if _, err := exchangeCode(context.Background(), r.hc, r.meta, ssoTestClient, ssoTestSecret, code,
		verifier, ssoTestRedirect+"/"); err == nil {
		t.Fatal("a code was exchanged with a redirect URI that differs by one character")
	}
	// A refused exchange spends nothing; a code exchanged once is spent for
	// good.
	raw, err := exchangeCode(context.Background(), r.hc, r.meta, ssoTestClient, ssoTestSecret, code, verifier, ssoTestRedirect)
	if err != nil {
		t.Fatalf("the right exchange was refused: %v", err)
	}
	if raw == "" {
		t.Fatal("no ID token")
	}
	if _, err := exchangeCode(context.Background(), r.hc, r.meta, ssoTestClient, ssoTestSecret, code,
		verifier, ssoTestRedirect); err == nil {
		t.Fatal("a code was exchanged twice")
	}
	if verifier == otherVerifier || len(verifier) < 43 {
		t.Fatalf("verifiers are not fresh, long random strings: %q", verifier)
	}
}

// AUTH-010: discovery is believed only when it names the issuer it was
// fetched from, over https, with https endpoints.
func TestAUTH010DiscoveryMustNameItsOwnIssuerOverHTTPS(t *testing.T) {
	r := newSSORun(t)
	if _, err := discoverOIDC(context.Background(), r.hc, r.idp.Issuer()+"/"); err == nil {
		t.Error("discovery fetched for issuer X/ was believed when it names X")
	}
	if _, err := discoverOIDC(context.Background(), r.hc, "http://idp.example.test"); err == nil {
		t.Error("an http issuer was accepted")
	}
	if _, err := discoverOIDC(context.Background(), r.hc, "https://user@idp.example.test"); err == nil {
		t.Error("an issuer with user information was accepted")
	}
	if _, err := discoverOIDC(context.Background(), r.hc, "https://idp.example.test?x=1"); err == nil {
		t.Error("an issuer with a query was accepted")
	}

	q, err := url.Parse(r.meta.authorizationURL(ssoTestClient, ssoTestRedirect, "st", "no", "ch"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"response_type": "code", "client_id": ssoTestClient, "redirect_uri": ssoTestRedirect,
		"state": "st", "nonce": "no", "code_challenge": "ch", "code_challenge_method": "S256", "scope": "openid"}
	for k, v := range want {
		if got := q.Query().Get(k); got != v {
			t.Errorf("authorization URL %s = %q, want %q", k, got, v)
		}
	}
}

// The guarded client refuses a provider at a loopback, link-local or
// unspecified address: an owner's issuer URL is not a way to reach the
// core's own host or a cloud metadata service.
func TestSSOClientRefusesLoopbackAndLinkLocalAddresses(t *testing.T) {
	hc := newSSOHTTPClient()
	for _, u := range []string{"https://127.0.0.1:1/.well-known/openid-configuration",
		"https://[::1]:1/x", "https://169.254.169.254/latest", "https://0.0.0.0:1/x"} {
		resp, err := hc.Get(u)
		if err == nil {
			discardError(resp.Body.Close())
			t.Errorf("%s was reached", u)
			continue
		}
		if !strings.Contains(err.Error(), "refused to connect") {
			t.Errorf("%s: %v", u, err)
		}
	}
}
