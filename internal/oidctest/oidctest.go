// SPDX-License-Identifier: Apache-2.0

// Package oidctest is a small OpenID Connect provider for this project's own
// tests (E30, #485): discovery, a JSON Web Key Set, an authorization endpoint
// and a token endpoint that issues ID tokens signed with a real RSA key.
//
// It is not a mock that skips checks. The relying party it serves fetches its
// discovery document and its keys over TLS, sends it a real authorization
// code with a PKCE verifier, and verifies the signature of what comes back.
// The provider checks its side too: the client's id and secret, the exact
// redirect URI, the PKCE verifier against the challenge, and that a code is
// spent once.
//
// A test can make it misbehave on purpose (Tamper) to prove the relying party
// refuses a token with the wrong issuer, audience, nonce, expiry, signature
// or algorithm.
//
// It is a package under internal/, not a _test.go file, so internal/api,
// internal/accounts and cmd/innsegl can share one provider. Nothing outside a
// test imports it.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims is what one ID token says. Tamper may change any of it.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	AZP       string   `json:"azp,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	Expiry    int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email,omitempty"`
	Name      string   `json:"name,omitempty"`
	ExtraJSON string   `json:"-"`
}

// Signing is how one ID token is signed. Tamper may change it.
type Signing struct {
	// Algorithm is the JWS alg. RS256 by default; "none" and HS256 are
	// signed the way an attacker would sign them.
	Algorithm jose.SignatureAlgorithm
	// Key signs. The provider's own key by default; a different key makes a
	// signature no published key verifies.
	Key any
	// KeyID is the kid header. The provider's own by default.
	KeyID string
}

// Client is one registered relying party.
type Client struct {
	ID           string
	Secret       string // empty: a public client
	RedirectURIs []string
}

// Provider is the running test provider.
type Provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	mu       sync.Mutex
	clients  map[string]Client
	codes    map[string]pendingCode
	subject  string
	email    string
	name     string
	tamper   func(*Claims, *Signing)
	tokens   int
	issuer   string
	authBase string
}

type pendingCode struct {
	clientID      string
	redirectURI   string
	challenge     string
	nonce         string
	subject       string
	issuedAt      time.Time
	spent         bool
	challengeMeth string
}

// Option configures New.
type Option func(*Provider)

// WithIssuer serves discovery naming issuer instead of the server's own URL:
// a provider whose address inside a container network differs from the one
// the test reaches. The token and key endpoints are published under it.
func WithIssuer(issuer string) Option { return func(p *Provider) { p.issuer = issuer } }

// WithAuthorizationBase publishes the authorization endpoint under base: the
// address a browser reaches, when it differs from the issuer's.
func WithAuthorizationBase(base string) Option { return func(p *Provider) { p.authBase = base } }

// New starts a provider on a TLS listener. Close it when done.
func New(opts ...Option) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidctest: generating the signing key: %w", err)
	}
	kid := make([]byte, 8)
	if _, err := rand.Read(kid); err != nil {
		return nil, err
	}
	p := &Provider{
		key: key, keyID: hex.EncodeToString(kid),
		clients: map[string]Client{}, codes: map[string]pendingCode{},
	}
	for _, o := range opts {
		o(p)
	}
	p.server = httptest.NewUnstartedServer(p.handler())
	p.server.StartTLS()
	if p.issuer == "" {
		p.issuer = p.server.URL
	}
	if p.authBase == "" {
		p.authBase = p.issuer
	}
	return p, nil
}

// NewServer is New on a listener the caller started, for a provider served
// from a container: handler() wrapped by the caller's own TLS server.
func NewServer(issuer, authBase string) (*Provider, http.Handler, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	kid := make([]byte, 8)
	if _, err := rand.Read(kid); err != nil {
		return nil, nil, err
	}
	p := &Provider{
		key: key, keyID: hex.EncodeToString(kid),
		clients: map[string]Client{}, codes: map[string]pendingCode{},
		issuer: issuer, authBase: authBase,
	}
	return p, p.handler(), nil
}

// Close stops the provider.
func (p *Provider) Close() {
	if p.server != nil {
		p.server.Close()
	}
}

// Issuer is the issuer URL a relying party is configured with.
func (p *Provider) Issuer() string { return p.issuer }

// HTTPClient trusts the provider's certificate and nothing else.
func (p *Provider) HTTPClient() *http.Client { return p.server.Client() }

// TLSConfig is the provider's server TLS config, for a test that wants its
// certificate pool.
func (p *Provider) TLSConfig() *tls.Config { return p.server.TLS }

// PrivateKey is the provider's signing key, for a test that signs a token by
// hand.
func (p *Provider) PrivateKey() *rsa.PrivateKey { return p.key }

// KeyID is the kid of the provider's published key.
func (p *Provider) KeyID() string { return p.keyID }

// Register adds a relying party.
func (p *Provider) Register(c Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[c.ID] = c
}

// SignInAs makes the authorization endpoint approve at once, as subject,
// with the email and name claims set. An empty subject shows the approval
// form instead (a browser picks the subject).
func (p *Provider) SignInAs(subject, email, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subject, p.email, p.name = subject, email, name
}

// Tamper changes every token issued from now on. nil stops it.
func (p *Provider) Tamper(f func(*Claims, *Signing)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tamper = f
}

// TokensIssued counts the ID tokens the token endpoint has answered.
func (p *Provider) TokensIssued() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokens
}

func (p *Provider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /authorize", p.approve)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.authBase + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: p.keyID, Algorithm: string(jose.RS256), Use: "sig",
	}}})
}

// authorize checks the request the way a provider must, then either
// approves at once (SignInAs) or shows a one-field form.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if msg := p.checkAuthorize(q); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	subject := p.subject
	p.mu.Unlock()
	if subject != "" {
		p.redirectWithCode(w, r, q, subject)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var hidden strings.Builder
	for k, vs := range q {
		for _, v := range vs {
			fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v))
		}
	}
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Test identity provider</title>
<style>body{font-family:sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}
label,input,button{display:block;font-size:1rem;margin:.5rem 0}input{padding:.4rem;width:100%%}
button{padding:.5rem 1rem}</style></head><body>
<h1>Test identity provider</h1><p>Sign in to continue to the application.</p>
<form method="post" action="/authorize">%s
<label for="sub">User</label><input id="sub" name="login_subject" value="test-user" required>
<label for="email">Email</label><input id="email" name="login_email" value="test-user@example.test">
<button type="submit">Sign in</button></form></body></html>`, hidden.String())
}

func (p *Provider) approve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	q := url.Values{}
	for k, vs := range r.PostForm {
		if k == "login_subject" || k == "login_email" {
			continue
		}
		q[k] = vs
	}
	if msg := p.checkAuthorize(q); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(r.PostForm.Get("login_subject"))
	if subject == "" {
		http.Error(w, "no user", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.email = r.PostForm.Get("login_email")
	p.mu.Unlock()
	p.redirectWithCode(w, r, q, subject)
}

func (p *Provider) checkAuthorize(q url.Values) string {
	p.mu.Lock()
	c, ok := p.clients[q.Get("client_id")]
	p.mu.Unlock()
	switch {
	case !ok:
		return "unknown client_id"
	case !contains(c.RedirectURIs, q.Get("redirect_uri")):
		return "redirect_uri is not registered for this client (exact match)"
	case q.Get("response_type") != "code":
		return "response_type must be code"
	case !contains(strings.Fields(q.Get("scope")), "openid"):
		return "scope must include openid"
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		return "PKCE with S256 is required"
	case q.Get("state") == "":
		return "state is required"
	}
	return ""
}

func (p *Provider) redirectWithCode(w http.ResponseWriter, r *http.Request, q url.Values, subject string) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "no randomness", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(raw)
	p.mu.Lock()
	p.codes[code] = pendingCode{
		clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"),
		challenge: q.Get("code_challenge"), challengeMeth: q.Get("code_challenge_method"),
		nonce: q.Get("nonce"), subject: subject, issuedAt: time.Now(),
	}
	p.mu.Unlock()
	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := target.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	target.RawQuery = v.Encode()
	//nolint:gosec // G710: the target is a redirect URI registered for this client, checked exactly by checkAuthorize.
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// token answers the authorization-code grant, checking the client, the
// exact redirect URI, the PKCE verifier and that the code is unspent.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID, secret = f.Get("client_id"), f.Get("client_secret")
	} else {
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			tokenError(w, "invalid_client", "bad basic auth")
			return
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			tokenError(w, "invalid_client", "bad basic auth")
			return
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.clients[clientID]
	if !ok || subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		tokenError(w, "invalid_client", "client authentication failed")
		return
	}
	if f.Get("grant_type") != "authorization_code" {
		tokenError(w, "unsupported_grant_type", "authorization_code only")
		return
	}
	pc, ok := p.codes[f.Get("code")]
	switch {
	case !ok || pc.spent:
		tokenError(w, "invalid_grant", "unknown or spent code")
		return
	case pc.clientID != clientID:
		tokenError(w, "invalid_grant", "code was issued to another client")
		return
	case pc.redirectURI != f.Get("redirect_uri"):
		tokenError(w, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	case time.Since(pc.issuedAt) > time.Minute:
		tokenError(w, "invalid_grant", "code expired")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
		tokenError(w, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}
	pc.spent = true
	p.codes[f.Get("code")] = pc

	now := time.Now()
	claims := Claims{
		Issuer: p.issuer, Subject: pc.subject, Audience: []string{clientID}, Nonce: pc.nonce,
		Expiry: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), Email: p.email, Name: p.name,
	}
	sign := Signing{Algorithm: jose.RS256, Key: p.key, KeyID: p.keyID}
	if p.tamper != nil {
		p.tamper(&claims, &sign)
	}
	idToken, err := SignToken(claims, sign)
	if err != nil {
		tokenError(w, "server_error", err.Error())
		return
	}
	p.tokens++
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-" + hex.EncodeToString(sum[:8]), "token_type": "Bearer",
		"expires_in": 300, "id_token": idToken,
	})
}

// SignToken signs claims as s says. Algorithm "none" yields an unsigned
// token, the classic downgrade a relying party must refuse.
func SignToken(claims Claims, s Signing) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if claims.ExtraJSON != "" {
		payload = []byte(strings.TrimSuffix(string(payload), "}") + "," + claims.ExtraJSON + "}")
	}
	if s.Algorithm == "none" {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if s.KeyID != "" {
		opts = opts.WithHeader("kid", s.KeyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.Algorithm, Key: s.Key}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func tokenError(w http.ResponseWriter, code, desc string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // a test provider's write to a closed client is not an error worth reporting
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
