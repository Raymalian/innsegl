// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The relying party's half of signing in with an organisation's identity
// provider (E30, #485): OpenID Connect's authorization code flow with PKCE.
//
// What this file checks, and nothing here can be configured away:
//
//   - discovery is believed only when it names the exact issuer it was
//     fetched from, over https, with https endpoints;
//   - the ID token's signature verifies under a key the issuer publishes, with
//     an algorithm from idTokenAlgorithms (never "none", never a shared-secret
//     HMAC);
//   - iss is the issuer, aud holds the client id (and azp names it when aud
//     holds more than one), the nonce is the one this sign-in sent, the token
//     has not expired and was not issued in the future;
//   - sub is present.
//
// The identity a sign-in yields is the issuer and subject, and nothing else:
// no email, no name. A refusal says why without echoing what the token
// claimed.

// errIDTokenRefused is every ID token refusal, wrapped with the reason.
var errIDTokenRefused = errors.New("api: the identity provider's ID token was refused")

// errSSOProvider is every failure to talk to the identity provider.
var errSSOProvider = errors.New("api: the identity provider could not be used")

// idTokenAlgorithms is the allow-list: asymmetric signatures only.
var idTokenAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

// ssoClockSkew is the slack allowed between this host's clock and the
// provider's, for exp and iat.
const ssoClockSkew = time.Minute

// maxSSOResponseBytes bounds every document read from a provider.
const maxSSOResponseBytes = 1 << 20

// ssoHTTPTimeout bounds every request to a provider.
const ssoHTTPTimeout = 10 * time.Second

// oidcProviderMeta is the part of a provider's discovery document this
// relying party uses.
type oidcProviderMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// oidcIdentity is what a verified sign-in yields.
type oidcIdentity struct {
	Issuer  string
	Subject string
}

// newSSOHTTPClient is the client every provider request goes through. It
// refuses to connect to a loopback, link-local, multicast or unspecified
// address, checked on the address actually dialled, so a name that resolves
// there is refused too. It follows no redirects.
func newSSOHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: ssoHTTPTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("api: refused to connect to %s: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
				return fmt.Errorf("api: refused to connect to %s: an identity provider is never at "+
					"a loopback, link-local or unspecified address", address)
			}
			return nil
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	transport.Proxy = nil
	return &http.Client{
		Timeout:   ssoHTTPTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("api: an identity provider's endpoint redirected; redirects are not followed")
		},
	}
}

// validIssuerURL refuses an issuer that is not a plain https URL.
func validIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("%w: the issuer must be an https URL with no user, query or fragment", errSSOProvider)
	}
	return nil
}

// getJSON fetches url into v, bounded.
func ssoGetJSON(ctx context.Context, hc *http.Client, target string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errSSOProvider, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errSSOProvider, err)
	}
	defer func() { discardError(resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSSOResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: reading %s: %w", errSSOProvider, target, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", errSSOProvider, target, resp.StatusCode)
	}
	if len(body) > maxSSOResponseBytes {
		return fmt.Errorf("%w: %s answered more than %d bytes", errSSOProvider, target, maxSSOResponseBytes)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: %s is not JSON: %w", errSSOProvider, target, err)
	}
	return nil
}

// discoverOIDC reads issuer's discovery document and believes it only when
// it names that exact issuer and https endpoints.
func discoverOIDC(ctx context.Context, hc *http.Client, issuer string) (oidcProviderMeta, error) {
	if err := validIssuerURL(issuer); err != nil {
		return oidcProviderMeta{}, err
	}
	var m oidcProviderMeta
	if err := ssoGetJSON(ctx, hc, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &m); err != nil {
		return oidcProviderMeta{}, err
	}
	if m.Issuer != issuer {
		return oidcProviderMeta{}, fmt.Errorf("%w: the discovery document names another issuer than the "+
			"one configured (they must match exactly, trailing slash included)", errSSOProvider)
	}
	for name, endpoint := range map[string]string{"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint": m.TokenEndpoint, "jwks_uri": m.JWKSURI} {
		if u, err := url.Parse(endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
			return oidcProviderMeta{}, fmt.Errorf("%w: the discovery document's %s is not an https URL",
				errSSOProvider, name)
		}
	}
	return m, nil
}

// authorizationURL is where a browser is sent to sign in.
func (m oidcProviderMeta) authorizationURL(clientID, redirectURI, state, nonce, challenge string) string {
	u, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil {
		return m.AuthorizationEndpoint
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// newPKCE mints a PKCE verifier (32 random bytes, base64url: 43 characters)
// and its S256 challenge.
func newPKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("api: no randomness available: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// exchangeCode trades an authorization code for the provider's ID token,
// sending the PKCE verifier and the exact redirect URI. A client with a
// secret authenticates with HTTP Basic unless the provider lists only
// client_secret_post.
func exchangeCode(ctx context.Context, hc *http.Client, m oidcProviderMeta, clientID, secret, code, verifier, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	basic := secret != "" && (len(m.TokenAuthMethods) == 0 || slices.Contains(m.TokenAuthMethods, "client_secret_basic"))
	if secret != "" && !basic {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSSOProvider, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSSOProvider, err)
	}
	defer func() { discardError(resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSSOResponseBytes))
	if err != nil {
		return "", fmt.Errorf("%w: reading the token response: %w", errSSOProvider, err)
	}
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if jerr := json.Unmarshal(body, &tok); jerr != nil {
		return "", fmt.Errorf("%w: the token endpoint answered %d with no JSON", errSSOProvider, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || tok.Error != "" {
		return "", fmt.Errorf("%w: the token endpoint refused the code (%d, %s)", errSSOProvider,
			resp.StatusCode, safeOAuthError(tok.Error))
	}
	if tok.IDToken == "" {
		return "", fmt.Errorf("%w: the token response holds no ID token", errIDTokenRefused)
	}
	return tok.IDToken, nil
}

// safeOAuthError keeps an OAuth error code to its registered alphabet, so a
// provider's text never reaches a log as anything but a short token.
func safeOAuthError(code string) string {
	if code == "" || len(code) > 64 {
		return "no error code"
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return "an unregistered error code"
		}
	}
	return code
}

// idTokenClaims is the part of an ID token this relying party reads.
type idTokenClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	AZP      string          `json:"azp"`
	Nonce    string          `json:"nonce"`
	Expiry   *json.Number    `json:"exp"`
	IssuedAt *json.Number    `json:"iat"`
}

func refuse(reason string) error { return fmt.Errorf("%w: %s", errIDTokenRefused, reason) }

// verifyIDToken checks raw's signature under the provider's published keys
// and its claims against this sign-in, and answers the issuer and subject.
func verifyIDToken(ctx context.Context, hc *http.Client, m oidcProviderMeta, raw, clientID, nonce string, now time.Time) (oidcIdentity, error) {
	jws, err := jose.ParseSigned(raw, idTokenAlgorithms)
	if err != nil {
		return oidcIdentity{}, refuse("it is not a signed token with an allowed algorithm")
	}
	if len(jws.Signatures) != 1 {
		return oidcIdentity{}, refuse("it carries other than one signature")
	}
	header := jws.Signatures[0].Header

	var set jose.JSONWebKeySet
	if err := ssoGetJSON(ctx, hc, m.JWKSURI, &set); err != nil {
		return oidcIdentity{}, err
	}
	var candidates []jose.JSONWebKey
	if header.KeyID != "" {
		candidates = set.Key(header.KeyID)
	} else {
		candidates = set.Keys
	}
	var payload []byte
	for _, k := range candidates {
		if k.Use == "enc" || !k.IsPublic() || (k.Algorithm != "" && k.Algorithm != header.Algorithm) {
			continue
		}
		if p, verr := jws.Verify(k.Key); verr == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return oidcIdentity{}, refuse("its signature does not verify under any key the issuer publishes")
	}

	var c idTokenClaims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return oidcIdentity{}, refuse("its claims are not JSON")
	}
	if c.Issuer != m.Issuer {
		return oidcIdentity{}, refuse("it was issued by another issuer")
	}
	aud, err := audiences(c.Audience)
	if err != nil || !slices.Contains(aud, clientID) {
		return oidcIdentity{}, refuse("it was issued to another client")
	}
	if len(aud) > 1 && c.AZP != clientID {
		return oidcIdentity{}, refuse("it names several audiences and is not authorised for this client")
	}
	if c.AZP != "" && c.AZP != clientID {
		return oidcIdentity{}, refuse("it was authorised for another client")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return oidcIdentity{}, refuse("its nonce is not this sign-in's")
	}
	exp, ok := unixTime(c.Expiry)
	if !ok || !now.Before(exp.Add(ssoClockSkew)) {
		return oidcIdentity{}, refuse("it has expired, or names no expiry")
	}
	if iat, ok := unixTime(c.IssuedAt); !ok || iat.After(now.Add(ssoClockSkew)) {
		return oidcIdentity{}, refuse("it was issued in the future, or names no issue time")
	}
	if c.Subject == "" || len(c.Subject) > 255 {
		return oidcIdentity{}, refuse("its subject is missing or longer than 255 bytes")
	}
	return oidcIdentity{Issuer: c.Issuer, Subject: c.Subject}, nil
}

// audiences reads aud, which is a string or an array of strings.
func audiences(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// unixTime reads a NumericDate.
func unixTime(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}
