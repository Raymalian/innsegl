// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The relying party's refusals of a provider that answers badly (#485,
// AUTH-010): each is a provider error, never a crash and never a token.

func tlsProvider(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

// AUTH-010: a document that is not 200, not JSON, too large, or names
// endpoints that are not https is refused as a provider error.
func TestAUTH010ABadlyAnsweringProviderIsRefused(t *testing.T) {
	var body string
	status := http.StatusOK
	srv, hc := tlsProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body)) //nolint:errcheck // a test server's write
	})
	ctx := context.Background()
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"500":       {http.StatusInternalServerError, "{}"},
		"not JSON":  {http.StatusOK, "<html>"},
		"too large": {http.StatusOK, `{"x":"` + strings.Repeat("a", maxSSOResponseBytes) + `"}`},
		"http token endpoint": {http.StatusOK, `{"issuer":"` + srv.URL + `","authorization_endpoint":"https://a.example/a",` +
			`"token_endpoint":"http://a.example/t","jwks_uri":"https://a.example/j"}`},
	} {
		status, body = tc.status, tc.body
		if _, err := discoverOIDC(ctx, hc, srv.URL); !errors.Is(err, errSSOProvider) {
			t.Errorf("%s: %v, want a provider error", name, err)
		}
	}
	if _, err := discoverOIDC(ctx, hc, "https://127.0.0.1:1"); !errors.Is(err, errSSOProvider) {
		t.Errorf("an unreachable provider: %v", err)
	}
	if err := ssoGetJSON(ctx, hc, "://bad", &struct{}{}); !errors.Is(err, errSSOProvider) {
		t.Errorf("an unparsable URL: %v", err)
	}
}

// AUTH-010: the token endpoint's refusals and malformed answers yield no
// token; a provider that lists only client_secret_post gets the secret in
// the form, a public client sends none.
func TestAUTH010TheTokenEndpointsAnswersAreCheckedAndTheSecretGoesWhereTheProviderSays(t *testing.T) {
	var answer string
	var seen []string
	srv, hc := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		_, _, basic := r.BasicAuth()
		seen = append(seen, map[bool]string{true: "basic", false: "form:" + r.PostForm.Get("client_secret")}[basic])
		if strings.Contains(answer, "error") {
			w.WriteHeader(http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(answer)) //nolint:errcheck // a test server's write
	})
	ctx := context.Background()
	post := oidcProviderMeta{TokenEndpoint: srv.URL + "/token", TokenAuthMethods: []string{"client_secret_post"}}
	basic := oidcProviderMeta{TokenEndpoint: srv.URL + "/token"}

	answer = `{"id_token":"tok"}`
	if raw, err := exchangeCode(ctx, hc, post, "c", "s3", "code", "v", "https://r"); err != nil || raw != "tok" {
		t.Fatalf("post: %q %v", raw, err)
	}
	if _, err := exchangeCode(ctx, hc, basic, "c", "s3", "code", "v", "https://r"); err != nil {
		t.Fatal(err)
	}
	if _, err := exchangeCode(ctx, hc, basic, "c", "", "code", "v", "https://r"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "form:s3,basic,form:" {
		t.Errorf("client authentication = %v", seen)
	}

	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"an OAuth error":             {`{"error":"invalid_grant"}`, errSSOProvider},
		"an unregistered error code": {`{"error":"Bad Thing!"}`, errSSOProvider},
		"a too-long error code":      {`{"error":"` + strings.Repeat("a", 65) + `"}`, errSSOProvider},
		"not JSON":                   {`<html>`, errSSOProvider},
		"no ID token":                {`{"access_token":"a"}`, errIDTokenRefused},
	} {
		answer = tc.body
		if _, err := exchangeCode(ctx, hc, basic, "c", "", "code", "v", "https://r"); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := exchangeCode(ctx, hc, oidcProviderMeta{TokenEndpoint: "https://127.0.0.1:1/t"}, "c", "", "x", "v", "https://r"); !errors.Is(err, errSSOProvider) {
		t.Errorf("an unreachable token endpoint: %v", err)
	}
	if _, err := exchangeCode(ctx, hc, oidcProviderMeta{TokenEndpoint: "://bad"}, "c", "", "x", "v", "https://r"); !errors.Is(err, errSSOProvider) {
		t.Errorf("an unparsable token endpoint: %v", err)
	}
	if got := safeOAuthError(""); got != "no error code" {
		t.Errorf("safeOAuthError(\"\") = %q", got)
	}
}

// AUTH-010: an ID token whose keys cannot be fetched, whose claims are not
// JSON, or whose audience or times are malformed is refused.
func TestAUTH010AnIDTokenWithMalformedClaimsOrNoKeysIsRefused(t *testing.T) {
	r := newSSORun(t)
	ctx := context.Background()
	if _, err := verifyIDToken(ctx, r.hc, oidcProviderMeta{JWKSURI: "https://127.0.0.1:1/jwks"}, "a.b.c", "c", "n", time.Now()); err == nil {
		t.Error("a token that does not parse was accepted")
	}
	good := r.idp.PrivateKey()
	sign := func(payload string) string {
		t.Helper()
		raw, err := signRaw(payload, good, r.idp.KeyID())
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	now := time.Now().Unix()
	base := func(aud, exp, iat string) string {
		return `{"iss":"` + r.idp.Issuer() + `","sub":"s","nonce":"n","aud":` + aud + `,"exp":` + exp + `,"iat":` + iat + `}`
	}
	future := itoa(int(now + 300))
	for name, payload := range map[string]string{
		"claims not JSON":     "not json",
		"audience a number":   base("7", future, itoa(int(now))),
		"no expiry":           `{"iss":"` + r.idp.Issuer() + `","sub":"s","nonce":"n","aud":"c","iat":` + itoa(int(now)) + `}`,
		"expiry not a number": base(`"c"`, `"soon"`, itoa(int(now))),
		"no issue time":       `{"iss":"` + r.idp.Issuer() + `","sub":"s","nonce":"n","aud":"c","exp":` + future + `}`,
	} {
		if _, err := verifyIDToken(ctx, r.hc, r.meta, sign(payload), "c", "n", time.Now()); !errors.Is(err, errIDTokenRefused) {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	if _, err := verifyIDToken(ctx, r.hc, oidcProviderMeta{JWKSURI: "https://127.0.0.1:1/jwks", Issuer: r.idp.Issuer()},
		sign(base(`"c"`, future, itoa(int(now)))), "c", "n", time.Now()); !errors.Is(err, errSSOProvider) {
		t.Errorf("keys that cannot be fetched: %v", err)
	}
	// A token with no key id is checked against every published key.
	noKid, err := signRaw(base(`"c"`, future, itoa(int(now))), good, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyIDToken(ctx, r.hc, r.meta, noKid, "c", "n", time.Now()); err != nil {
		t.Errorf("a token with no kid, signed by the published key: %v", err)
	}
}

// The guarded client refuses to follow a redirect.
func TestSSOClientFollowsNoRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.RedirectHandler("https://example.test/", http.StatusFound))
	t.Cleanup(srv.Close)
	hc := newSSOHTTPClient()
	hc.Transport = srv.Client().Transport
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		discardError(resp.Body.Close())
		t.Fatal("a redirect was followed")
	}
	if !strings.Contains(err.Error(), "redirects are not followed") {
		t.Errorf("redirect: %v", err)
	}
}

// signRaw signs payload exactly as given, RS256, with kid when not empty.
func signRaw(payload string, key *rsa.PrivateKey, kid string) (string, error) {
	opts := &jose.SignerOptions{}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign([]byte(payload))
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
