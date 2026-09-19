// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TC-MCP admin-credential contract tests (MCP-087..MCP-093).
//
// # WHY THESE IDS AND NOT THE ONES THE ISSUE NAMES
//
// #264 names MCP-078, MCP-079, MCP-081, MCP-082 and MCP-084, which is what the
// plan behind it allocated in 2026-09-18. Every one of those was taken between
// then and now by RM-151..RM-157, and doc 07 carries them: MCP-078 is the
// abandonment horizon, MCP-079 and MCP-080 the parent-session edge, MCP-081
// and MCP-082 the parent-run edge, MCP-083..MCP-085 the descendant cascade,
// MCP-086 the retire CLI. Claiming them again would be the fifth collision in
// this project. The measured next free id is MCP-087, and the block below runs
// from there; the mapping is recorded in doc 07 beside the new rows.
//
// # WHAT IS UNDER TEST
//
// Nothing authenticates a caller on the identity-lifecycle listener (doc 04
// AB-13, AB-15, AB-23). These assert the check that closes it: a
// repository-scoped credential, verified offline from a file, in front of the
// six admin tools.

// ---------------------------------------------------------------------------
// Minting, on the test's side of the boundary.
//
// internal/mcp VERIFIES and never signs (E8): the private half lives with the
// mint command in cmd/innsegl and nothing here holds one at run time. A test
// is a caller, so it mints the way that command does — through this package's
// own exported format, so the two cannot drift into signing different bytes.
// ---------------------------------------------------------------------------

// testIssuer is one minting key and the key set that admits it.
type testIssuer struct {
	key *ecdsa.PrivateKey
	kid string
	jwk AdminCredentialJWK
}

func newTestIssuer(t *testing.T) testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a P-256 key: %v", err)
	}
	jwk, err := AdminCredentialJWKOf(&key.PublicKey)
	if err != nil {
		t.Fatalf("AdminCredentialJWKOf: %v", err)
	}
	return testIssuer{key: key, kid: jwk.KID, jwk: jwk}
}

// mint signs claims under this issuer's key.
func (i testIssuer) mint(t *testing.T, claims AdminCredentialClaims) string {
	t.Helper()
	return i.mintAs(t, i.kid, claims)
}

// mintAs signs under a stated kid, so an unknown one can be presented.
func (i testIssuer) mintAs(t *testing.T, kid string, claims AdminCredentialClaims) string {
	t.Helper()
	input, err := AdminCredentialSigningInput(kid, claims)
	if err != nil {
		t.Fatalf("AdminCredentialSigningInput: %v", err)
	}
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksFile writes a key set holding every issuer given, and returns its path.
func jwksFile(t *testing.T, issuers ...testIssuer) string {
	t.Helper()
	set := AdminCredentialJWKSet{}
	for _, i := range issuers {
		set.Keys = append(set.Keys, i.jwk)
	}
	body, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		t.Fatalf("marshalling the key set: %v", err)
	}
	path := filepath.Join(t.TempDir(), "admin-jwks.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// goodClaims is a credential for repo that is valid at the instant it is made.
func goodClaims(repo string) AdminCredentialClaims {
	now := time.Now().UTC()
	return AdminCredentialClaims{
		Issuer:    AdminCredentialIssuer,
		Audience:  AdminCredentialAudience,
		Repo:      repo,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expiry:    now.Add(10 * time.Minute).Unix(),
		TokenID:   "0123456789abcdef",
	}
}

// verifierFor builds the shipped verifier over a key set on disk.
func verifierFor(t *testing.T, path string) *AdminCredentialVerifier {
	t.Helper()
	v, err := NewAdminCredentialVerifier(AdminCredentialConfig{KeySetFile: path})
	if err != nil {
		t.Fatalf("NewAdminCredentialVerifier(%s): %v", path, err)
	}
	return v
}

// ---------------------------------------------------------------------------
// MCP-087 — one byte-identical refusal for every credential failure.
// ---------------------------------------------------------------------------

// TestMCP087EveryCredentialFailureIsOneByteIdenticalRefusal.
//
// A distinguishable "wrong audience" is an oracle over which audiences exist,
// and a distinguishable "expired" tells a caller its token was otherwise
// admissible. Every failure is the same bytes, produced before the tool layer:
// no handler runs, so nothing is appended, no identity is claimed and SPIRE is
// never reached.
func TestMCP087EveryCredentialFailureIsOneByteIdenticalRefusal(t *testing.T) {
	issuer := newTestIssuer(t)
	other := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))

	// EXPIRED, AND EXPIRED FOR THAT REASON. exp - iat stays inside the TTL
	// bound: a window of two hours would be refused by the bound check first,
	// and the case would pass without the expiry branch ever running.
	expired := goodClaims("github.com/acme/widgets")
	expired.IssuedAt = time.Now().Add(-20 * time.Minute).Unix()
	expired.NotBefore = expired.IssuedAt
	expired.Expiry = time.Now().Add(-10 * time.Minute).Unix()

	future := goodClaims("github.com/acme/widgets")
	future.NotBefore = time.Now().Add(time.Hour).Unix()

	wrongAudience := goodClaims("github.com/acme/widgets")
	wrongAudience.Audience = "innsegl-read"

	wrongIssuer := goodClaims("github.com/acme/widgets")
	wrongIssuer.Issuer = "someone-else"

	overlong := goodClaims("github.com/acme/widgets")
	overlong.Expiry = overlong.IssuedAt + int64((AdminCredentialMaxTTL + time.Minute).Seconds())

	badRepo := goodClaims("not a repository")

	tampered := issuer.mint(t, goodClaims("github.com/acme/widgets"))
	tampered = tampered[:len(tampered)-2] + "AA"

	cases := []struct {
		name  string
		token string
		// present says whether the Authorization header is sent at all.
		present bool
	}{
		{name: "absent", present: false},
		{name: "empty", token: "", present: true},
		{name: "malformed", token: "not-a-token", present: true},
		{name: "two segments", token: "aaa.bbb", present: true},
		{name: "not base64", token: "!!!.???.***", present: true},
		{name: "expired", token: issuer.mint(t, expired), present: true},
		{name: "not yet valid", token: issuer.mint(t, future), present: true},
		{name: "wrong audience", token: issuer.mint(t, wrongAudience), present: true},
		{name: "wrong issuer", token: issuer.mint(t, wrongIssuer), present: true},
		{name: "ttl beyond the bound", token: issuer.mint(t, overlong), present: true},
		{name: "repo outside doc 02 §5", token: issuer.mint(t, badRepo), present: true},
		{name: "unknown key id", token: issuer.mintAs(t, "not-a-known-kid", goodClaims("github.com/acme/widgets")), present: true},
		{name: "another issuer's signature", token: other.mint(t, goodClaims("github.com/acme/widgets")), present: true},
		{name: "tampered signature", token: tampered, present: true},
	}

	var reached int
	guarded := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))

	var first []byte
	var firstStatus int
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("{}"))
			if tc.present {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			body, err := io.ReadAll(rec.Result().Body)
			if err != nil {
				t.Fatalf("reading the refusal: %v", err)
			}
			if first == nil {
				first, firstStatus = body, rec.Code
				return
			}
			if rec.Code != firstStatus || string(body) != string(first) {
				t.Errorf("refusal differs from the first one:\n got %d %q\nwant %d %q\n"+
					"every credential failure must be one byte-identical refusal, or the "+
					"difference is an oracle", rec.Code, body, firstStatus, first)
			}
		})
	}
	if reached != 0 {
		t.Errorf("the guarded handler ran %d times; every credential failure must be "+
			"refused BEFORE the tool layer", reached)
	}
}

// TestMCP087AValidCredentialReachesTheHandlerAndTheTokenDoesNot.
//
// The admitted request carries the repository onward and no longer carries the
// credential: nothing downstream can log what it cannot see.
func TestMCP087AValidCredentialReachesTheHandlerAndTheTokenDoesNot(t *testing.T) {
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	token := issuer.mint(t, goodClaims("github.com/acme/widgets"))

	var sawRepo, sawAuthorization string
	guarded := v.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawRepo = r.Header.Get(adminScopeHeader)
		sawAuthorization = r.Header.Get("Authorization")
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	// A caller that tries to name its own repository is overwritten, not
	// trusted: the scope header is an internal one and the middleware is the
	// only writer of it.
	req.Header.Set(adminScopeHeader, "github.com/acme/other")
	guarded.ServeHTTP(httptest.NewRecorder(), req)

	if sawRepo != "github.com/acme/widgets" {
		t.Errorf("the handler saw repository %q, want the credential's own", sawRepo)
	}
	if sawAuthorization != "" {
		t.Errorf("the credential reached the handler as %q; it must be stripped once verified",
			sawAuthorization)
	}
}

// ---------------------------------------------------------------------------
// MCP-090 — key identity and rotation, and the start-up refusal.
// ---------------------------------------------------------------------------

// TestMCP090RotationWithOverlapAdmitsBothKeys. Two keys in one file is how a
// rotation happens without a window in which live credentials stop working.
func TestMCP090RotationWithOverlapAdmitsBothKeys(t *testing.T) {
	outgoing := newTestIssuer(t)
	incoming := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, outgoing, incoming))

	for name, issuer := range map[string]testIssuer{"outgoing": outgoing, "incoming": incoming} {
		scope, ok := v.Verify(issuer.mint(t, goodClaims("github.com/acme/widgets")))
		if !ok {
			t.Errorf("the %s key's credential was refused during an overlap", name)
			continue
		}
		if scope.Repo != "github.com/acme/widgets" {
			t.Errorf("the %s key's credential carried repository %q", name, scope.Repo)
		}
	}
}

// TestMCP090AKeySetThatCannotBeUsedIsRefusedAtConstruction. A deployment that
// believes it is authenticated and is not is worse than one that knows it is
// open, so every one of these fails the process rather than the first call.
func TestMCP090AKeySetThatCannotBeUsedIsRefusedAtConstruction(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return path
	}
	issuer := newTestIssuer(t)
	dup := AdminCredentialJWKSet{Keys: []AdminCredentialJWK{issuer.jwk, issuer.jwk}}
	dupBody, err := json.Marshal(dup)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	cases := []struct {
		name string
		path string
	}{
		{"no file at all", filepath.Join(dir, "absent.json")},
		{"not JSON", write("garbage.json", "this is not a key set")},
		{"no keys", write("empty.json", `{"keys":[]}`)},
		{"wrong key type", write("rsa.json",
			`{"keys":[{"kty":"RSA","crv":"P-256","kid":"a","alg":"ES256","x":"AA","y":"AA"}]}`)},
		{"wrong algorithm", write("es384.json",
			`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","alg":"ES384","x":"AA","y":"AA"}]}`)},
		{"no key set named at all", ""},
		{"wrong curve", write("p384.json",
			`{"keys":[{"kty":"EC","crv":"P-384","kid":"a","alg":"ES256","x":"AA","y":"AA"}]}`)},
		{"coordinates off the curve", write("offcurve.json",
			`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","alg":"ES256",`+
				`"x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",`+
				`"y":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`)},
		{"no key id", write("nokid.json",
			`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","x":"AA","y":"AA"}]}`)},
		{"two keys with one id", write("dup.json", string(dupBody))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAdminCredentialVerifier(AdminCredentialConfig{KeySetFile: tc.path}); err == nil {
				t.Fatalf("NewAdminCredentialVerifier(%s) succeeded; verification material that "+
					"cannot admit anything must fail the process, not the first call", tc.path)
			}
		})
	}
}

// TestMCP090VerificationIsOfflineOnce. The key set is read at construction and
// never again: this system must gain no dependency on whatever issues the
// credential, so an issuer that is gone — or a file that is deleted after
// start-up — changes nothing about a credential already minted.
func TestMCP090VerificationIsOfflineOnce(t *testing.T) {
	issuer := newTestIssuer(t)
	path := jwksFile(t, issuer)
	v := verifierFor(t, path)

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the key set: %v", err)
	}
	if _, ok := v.Verify(issuer.mint(t, goodClaims("github.com/acme/widgets"))); !ok {
		t.Errorf("a credential was refused after the key set file was removed; verification " +
			"must not depend on anything outside this process once it has started")
	}
}

// ---------------------------------------------------------------------------
// The claim set, and what is deliberately absent from it.
// ---------------------------------------------------------------------------

// TestTheCredentialCarriesARepositoryAndNothingThatIdentifiesAnAccount.
//
// The closed claim set is ENFORCED rather than documented: a token carrying
// `sub`, an account id, an email or a display name is refused, so the rule
// cannot be broken by whatever mints one next.
func TestTheCredentialCarriesARepositoryAndNothingThatIdentifiesAnAccount(t *testing.T) {
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))

	for _, extra := range []string{"sub", "account_id", "principal_id", "email", "name", "org", "role"} {
		t.Run(extra, func(t *testing.T) {
			var claims map[string]any
			body, err := json.Marshal(goodClaims("github.com/acme/widgets"))
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if decodeErr := json.Unmarshal(body, &claims); decodeErr != nil {
				t.Fatalf("unmarshalling: %v", decodeErr)
			}
			claims[extra] = "whoever"
			payload, payloadErr := json.Marshal(claims)
			if payloadErr != nil {
				t.Fatalf("marshalling: %v", payloadErr)
			}
			header, err := json.Marshal(map[string]string{
				"alg": "ES256", "typ": "JWT", "kid": issuer.kid,
			})
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			input := base64.RawURLEncoding.EncodeToString(header) + "." +
				base64.RawURLEncoding.EncodeToString(payload)
			sum := sha256.Sum256([]byte(input))
			r, s, err := ecdsa.Sign(rand.Reader, issuer.key, sum[:])
			if err != nil {
				t.Fatalf("signing: %v", err)
			}
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			token := input + "." + base64.RawURLEncoding.EncodeToString(sig)

			if _, ok := v.Verify(token); ok {
				t.Errorf("a credential carrying %q was admitted; the claim set is closed so "+
					"that nothing identifying an account can ride in it", extra)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MCP-092 — the agent listener, and single-listener mode.
// ---------------------------------------------------------------------------

// TestMCP092TheAgentListenerIsUnchanged. No credential is configured on it and
// none is required: a repository-scoped credential there would become
// credential-fetch authority over every run in that repository, which is wider
// than the gap it would close.
func TestMCP092TheAgentListenerIsUnchanged(t *testing.T) {
	_, url := serveProbeSet(t, AgentTools())
	session := connect(t, url)
	for _, tool := range AgentTools() {
		res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
			Name: string(tool), Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatalf("%s over the agent listener: %v", tool, err)
		}
		if res.IsError {
			t.Errorf("%s was refused on the agent listener with no credential presented", tool)
		}
	}
}

// TestMCP092SingleListenerModeRequiresNothing. With -admin-listen unset all
// eight tools serve on one listener, exactly as before, and no credential is
// configured or asked for.
func TestMCP092SingleListenerModeRequiresNothing(t *testing.T) {
	_, url := serveProbeSet(t, nil)
	session := connect(t, url)
	for _, tool := range ToolNames() {
		res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
			Name: string(tool), Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatalf("%s on the single listener: %v", tool, err)
		}
		if res.IsError {
			t.Errorf("%s was refused on the single listener; single-listener mode is unchanged", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// The scope, as the tools read it.
// ---------------------------------------------------------------------------

// TestAnUnscopedContextAdmitsEveryRepository. That is single-listener mode and
// every deployment before this: the tools are unchanged when nothing put a
// scope in front of them.
func TestAnUnscopedContextAdmitsEveryRepository(t *testing.T) {
	if !adminScopeAdmits(t.Context(), "github.com/acme/widgets") {
		t.Error("an unscoped context refused a repository; with no credential configured " +
			"every tool serves exactly as it did before")
	}
	if !adminScopeAdmits(t.Context(), "") {
		t.Error("an unscoped context refused a run with no recorded repository")
	}
}

// TestAScopedContextAdmitsOnlyItsOwnRepository, including the empty repository
// a pre-ADR-0045 run carries: a run whose repository was never recorded cannot
// be shown to be this credential's, so it is not.
func TestAScopedContextAdmitsOnlyItsOwnRepository(t *testing.T) {
	ctx := withAdminScope(t.Context(), AdminScope{Repo: "github.com/acme/widgets"})
	for repo, want := range map[string]bool{
		"github.com/acme/widgets":  true,
		"github.com/acme/other":    false,
		"github.com/other/widgets": false,
		"":                         false,
	} {
		if got := adminScopeAdmits(ctx, repo); got != want {
			t.Errorf("adminScopeAdmits(%q) = %v, want %v", repo, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Every refusal branch, named.
//
// IP §2 puts SIGNATURE VERIFICATION on the 100%-branch floor, and the served
// refusal is deliberately indistinguishable — so the only place the individual
// branches can be held open is here, against Explain, which is what `innsegl
// admin-credential verify` renders for an operator.
// ---------------------------------------------------------------------------

// explainClaims mints claims under issuer and returns Explain's reason.
func explainClaims(t *testing.T, v *AdminCredentialVerifier, i testIssuer, mutate func(*AdminCredentialClaims)) error {
	t.Helper()
	claims := goodClaims("github.com/acme/widgets")
	mutate(&claims)
	_, err := v.Explain(i.mint(t, claims))
	return err
}

func TestEveryAdminCredentialRefusalBranchIsNamed(t *testing.T) {
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	good := issuer.mint(t, goodClaims("github.com/acme/widgets"))
	parts := strings.Split(good, ".")

	t.Run("claims", func(t *testing.T) {
		for name, mutate := range map[string]func(*AdminCredentialClaims){
			"no jti":         func(c *AdminCredentialClaims) { c.TokenID = "" },
			"oversized jti":  func(c *AdminCredentialClaims) { c.TokenID = strings.Repeat("a", 65) },
			"no iat":         func(c *AdminCredentialClaims) { c.IssuedAt = 0 },
			"no nbf":         func(c *AdminCredentialClaims) { c.NotBefore = 0 },
			"no exp":         func(c *AdminCredentialClaims) { c.Expiry = 0 },
			"exp before iat": func(c *AdminCredentialClaims) { c.Expiry = c.IssuedAt - 1 },
			"iat in the future": func(c *AdminCredentialClaims) {
				c.IssuedAt = time.Now().Add(time.Hour).Unix()
				c.Expiry = c.IssuedAt + 60
			},
		} {
			if err := explainClaims(t, v, issuer, mutate); err == nil {
				t.Errorf("%s was admitted", name)
			}
		}
	})

	t.Run("token shape", func(t *testing.T) {
		for name, token := range map[string]string{
			"oversized":              strings.Repeat("a", adminCredentialMaxBytes+1),
			"header not base64":      "!!!." + parts[1] + "." + parts[2],
			"header not JSON":        base64url(t, "not json") + "." + parts[1] + "." + parts[2],
			"claims not base64":      parts[0] + ".!!!." + parts[2],
			"signature not base64":   parts[0] + "." + parts[1] + ".!!!",
			"signature wrong length": parts[0] + "." + parts[1] + "." + base64url(t, "short"),
			"trailing JSON":          base64url(t, `{"alg":"ES256","typ":"JWT","kid":"x"}{}`) + "." + parts[1] + "." + parts[2],
		} {
			if _, err := v.Explain(token); err == nil {
				t.Errorf("%s was admitted", name)
			}
		}
	})

	t.Run("header", func(t *testing.T) {
		for name, header := range map[string]map[string]string{
			"wrong alg": {"alg": "HS256", "typ": "JWT", "kid": issuer.kid},
			"wrong typ": {"alg": "ES256", "typ": "JWS", "kid": issuer.kid},
			"no kid":    {"alg": "ES256", "typ": "JWT"},
		} {
			rendered, err := json.Marshal(header)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			token := base64.RawURLEncoding.EncodeToString(rendered) + "." + parts[1] + "." + parts[2]
			if _, err := v.Explain(token); err == nil {
				t.Errorf("%s was admitted", name)
			}
		}
	})

	t.Run("claims not base64", func(t *testing.T) {
		// Signed over a payload segment that is not base64url, so the
		// signature check passes and the DECODE of the segment is what
		// refuses. Splicing an unsigned segment in would be caught one step
		// earlier and this branch would never run.
		if _, err := v.Explain(signRaw(t, issuer, parts[0], "!!!")); err == nil {
			t.Error("a signed non-base64 claims segment was admitted")
		}
	})

	t.Run("claims not JSON", func(t *testing.T) {
		// Signed, so the signature check passes and the DECODE is what refuses.
		// Reached only by minting over bytes that are not a claim set, which is
		// what the raw signing path below does.
		token := signRaw(t, issuer, parts[0], base64url(t, "not json"))
		if _, err := v.Explain(token); err == nil {
			t.Error("a signed non-object claim segment was admitted")
		}
	})

	t.Run("key set members", func(t *testing.T) {
		for name, jwk := range map[string]AdminCredentialJWK{
			"wrong use":    {KeyType: "EC", Curve: "P-256", KID: "a", Use: "enc", X: issuer.jwk.X, Y: issuer.jwk.Y},
			"x not base64": {KeyType: "EC", Curve: "P-256", KID: "a", X: "!!!", Y: issuer.jwk.Y},
			"y not base64": {KeyType: "EC", Curve: "P-256", KID: "a", X: issuer.jwk.X, Y: "!!!"},
		} {
			if _, err := adminCredentialPublicKey(jwk); err == nil {
				t.Errorf("%s was accepted as a verification key", name)
			}
		}
	})

	t.Run("the format's own refusals", func(t *testing.T) {
		if _, err := AdminCredentialSigningInput("", goodClaims("github.com/acme/widgets")); err == nil {
			t.Error("a credential with no key id was rendered; a verifier could not choose a key")
		}
		if _, err := AdminCredentialJWKOf(nil); err == nil {
			t.Error("a nil key was rendered as a JWK")
		}
		// Names the curve and holds no point. (*ecdsa.PublicKey).Bytes PANICS
		// on one, so this is a refusal and not a crash only because the guard
		// checks for the point before asking for its encoding.
		if _, err := AdminCredentialJWKOf(&ecdsa.PublicKey{Curve: elliptic.P256()}); err == nil {
			t.Error("a key with no point was rendered as a JWK")
		}
		notP256, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a P-384 key: %v", err)
		}
		if _, err := AdminCredentialJWKOf(&notP256.PublicKey); err == nil {
			t.Error("a P-384 key was rendered as a JWK; one curve means one code path")
		}
	})

	t.Run("the operator-facing report", func(t *testing.T) {
		if got := v.KeySetFile(); got == "" {
			t.Error("KeySetFile names nothing; a start-up log has no key set to name")
		}
		if got := v.KeyIDs(); len(got) != 1 || got[0] != issuer.kid {
			t.Errorf("KeyIDs() = %v, want the one key in the set", got)
		}
	})
}

// base64url renders s the way every segment of a credential is rendered.
func base64url(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// signRaw signs two already-rendered segments, so a case can present claims
// that are correctly signed and still not a claim set.
func signRaw(t *testing.T, i testIssuer, header, payload string) string {
	t.Helper()
	input := header + "." + payload
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
