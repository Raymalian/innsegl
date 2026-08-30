// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Unit cases for the gitsign wrapper.
//
// These run without Docker and without a real gitsign, because what they are
// about is the wrapper's own decisions: what it refuses, what it puts in a
// child's environment, and where its boundaries sit. The cases that need a
// real Fulcio, a real Rekor and a real signature are in
// gitsignintegration_test.go and skip loudly when the stack is absent — IP §2,
// "a mocked Fulcio proves nothing about I5", cuts both ways: a mock proves
// nothing about Sigstore, and a container proves nothing about a branch that
// only fires when a URL is malformed.

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

// fakeBinary writes an executable shell script and returns its path. It stands
// in for `git` or `gitsign` in cases where the wrapper's decision happens
// before either would be invoked, or where what matters is the environment
// they are handed rather than what they do with it.
func fakeBinary(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// testCA is a throwaway CA used to mint certificates with windows the case
// chooses. It exists only so the validity-window boundary can be tested on
// both sides (IP §6.8) without waiting ten minutes for a real one to expire.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "innsegl test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		key:  key,
		cert: cert,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// leaf mints a certificate with a SPIFFE URI SAN, a Fulcio issuer extension
// and the given validity window.
func (ca *testCA) leaf(t *testing.T, spiffeID, issuer string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	issuerDER, err := asn1.Marshal(issuer)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{
			{Id: oidFulcioIssuerV2, Value: issuerDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// fakeSigstore serves Fulcio's and Rekor's read endpoints. It is not a Fulcio:
// it issues nothing and signs nothing. What it stands in for is the two
// documents the wrapper fetches and the log it reads back.
type fakeSigstore struct {
	t      *testing.T
	server *httptest.Server

	fulcioRoot   []byte
	fulcioStatus int
	rekorKey     []byte
	rekorStatus  int

	indexBody   any
	indexStatus int
	entries     map[string]map[string]any
	entryStatus int
}

func newFakeSigstore(t *testing.T, ca *testCA) *fakeSigstore {
	t.Helper()
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSigstore{
		t:          t,
		fulcioRoot: ca.pem,
		rekorKey:   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		entries:    map[string]map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc(fulcioRootPath, func(w http.ResponseWriter, _ *http.Request) {
		if f.fulcioStatus != 0 {
			w.WriteHeader(f.fulcioStatus)
			return
		}
		f.write(w, f.fulcioRoot)
	})
	mux.HandleFunc(rekorPubKeyPath, func(w http.ResponseWriter, _ *http.Request) {
		if f.rekorStatus != 0 {
			w.WriteHeader(f.rekorStatus)
			return
		}
		f.write(w, f.rekorKey)
	})
	mux.HandleFunc(rekorIndexPath, func(w http.ResponseWriter, _ *http.Request) {
		if f.indexStatus != 0 {
			w.WriteHeader(f.indexStatus)
			return
		}
		f.writeJSON(w, f.indexBody)
	})
	mux.HandleFunc(rekorEntriesPath+"/", func(w http.ResponseWriter, r *http.Request) {
		if f.entryStatus != 0 {
			w.WriteHeader(f.entryStatus)
			return
		}
		uuid := strings.TrimPrefix(r.URL.Path, rekorEntriesPath+"/")
		entry, ok := f.entries[uuid]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.writeJSON(w, map[string]any{uuid: entry})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// write and writeJSON keep the handlers' error returns checked: a fake that
// silently fails to answer would make the case under test fail for a reason
// that has nothing to do with the wrapper.
func (f *fakeSigstore) write(w http.ResponseWriter, body []byte) {
	if _, err := w.Write(body); err != nil {
		f.t.Errorf("writing a response: %v", err)
	}
}

func (f *fakeSigstore) writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("encoding a response: %v", err)
	}
}

func (f *fakeSigstore) marshal(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		f.t.Fatalf("marshalling a fixture: %v", err)
	}
	return raw
}

// addEntry records a hashedrekord the way Rekor stores one.
func (f *fakeSigstore) addEntry(uuid, artifactHash string, cert *x509.Certificate, index int64) {
	body := f.marshal(map[string]any{
		"kind":       rekorHashedRekord,
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": rekorSHA256, "value": artifactHash},
			},
			"signature": map[string]any{
				"content": "c2ln",
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(certPEM(cert)),
				},
			},
		},
	})
	f.entries[uuid] = map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"logIndex":       index,
		"logID":          "test-log",
		"integratedTime": time.Now().Unix(),
	}
}

// unitSigner builds a Signer whose Fulcio and Rekor are the fake, and whose
// binaries are scripts. src may be nil for a source that is never called.
func unitSigner(t *testing.T, f *fakeSigstore, mutate func(*Config)) *Signer {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		FulcioURL:   f.server.URL,
		RekorURL:    f.server.URL,
		Issuer:      "http://spire-oidc:8080",
		GitsignPath: fakeBinary(t, dir, "gitsign", "exit 0"),
		GitPath:     fakeBinary(t, dir, "git", "exit 0"),
		Author:      AuthorPolicy{AllowUnlinked: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	signer, err := NewSigner(cfg, staticSource{})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	return signer
}

type staticSource struct {
	cred Credential
	err  error
}

func (s staticSource) Credential(context.Context) (Credential, error) { return s.cred, s.err }

const unitIdentity = "spiffe://innsegl.dev/agent/demo/rm-032/run-unit"

func unitClaim() Claim {
	return Claim{Identity: unitIdentity, Run: "run-unit", Task: "rm-032"}
}

func liveCredential() Credential {
	return Credential{
		Token:     "a.b.c",
		SPIFFEID:  unitIdentity,
		Audience:  AudienceSigstore,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

// ---------------------------------------------------------------------------
// E8 — the MCP never holds, caches or proxies agent private keys.
// ---------------------------------------------------------------------------

// TestE8TheWrapperHoldsNoKeyMaterial is the exemption made checkable.
//
// E8 is an absence, and an absence is easy to claim and easy to lose. Two
// things are asserted, both structural:
//
//  1. No type this package hands a caller, and no field the Signer keeps, can
//     hold a private key. A crypto.Signer or an *ecdsa.PrivateKey appearing
//     anywhere in Signer, Result or Credential is the beginning of custody.
//
//  2. GITSIGN_CREDENTIAL_CACHE never reaches the child, even when it is set in
//     this process's own environment. That variable points gitsign at a daemon
//     that keeps the ephemeral private key and certificate alive between
//     signatures, which is exactly the custody E8 forbids — and an operator
//     who exports it for their own interactive use would otherwise turn it on
//     for the MCP without knowing.
func TestE8TheWrapperHoldsNoKeyMaterial(t *testing.T) {
	forbidden := []string{"PrivateKey", "crypto.Signer", "ecdsa", "rsa.", "ed25519"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(Signer{}), reflect.TypeOf(Result{}),
		reflect.TypeOf(Credential{}), reflect.TypeOf(Certificate{}),
	} {
		for i := range typ.NumField() {
			name := typ.Field(i).Type.String()
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s is a %s: this package must hold no key material (E8)",
						typ.Name(), typ.Field(i).Name, name)
				}
			}
		}
	}

	t.Setenv("GITSIGN_CREDENTIAL_CACHE", "/tmp/should-never-be-passed-through.sock")
	t.Setenv("SIGSTORE_ID_TOKEN", "a-token-from-somebody-elses-session")
	t.Setenv("GITSIGN_FULCIO_URL", "https://fulcio.sigstore.dev")

	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	signer := unitSigner(t, f, nil)
	trust, err := signer.trustMaterial(t.Context())
	if err != nil {
		t.Fatalf("trustMaterial: %v", err)
	}
	env := signer.signEnv(trust, liveCredential(), Request{
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
	})

	seen := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := seen[k]; dup {
			t.Errorf("%s appears twice in the child environment", k)
		}
		seen[k] = v
	}
	if _, ok := seen["GITSIGN_CREDENTIAL_CACHE"]; ok {
		t.Error("GITSIGN_CREDENTIAL_CACHE reached the child: gitsign's credential " +
			"cache daemon holds the ephemeral private key between signatures (E8)")
	}
	if got := seen["SIGSTORE_ID_TOKEN"]; got != "a.b.c" {
		t.Errorf("SIGSTORE_ID_TOKEN = %q; the child must get THIS run's credential, "+
			"not whatever the parent process had", got)
	}
	if got := seen["GITSIGN_FULCIO_URL"]; got != f.server.URL {
		t.Errorf("GITSIGN_FULCIO_URL = %q, want %q: the parent's environment must "+
			"not be able to redirect the CA", got, f.server.URL)
	}
	if got := seen["GITSIGN_TOKEN_PROVIDER"]; got != "envvar" {
		t.Errorf("GITSIGN_TOKEN_PROVIDER = %q, want envvar: provider auto-detection "+
			"would let a CI token or a workload socket sign as somebody else", got)
	}
	for _, want := range []string{
		"GITSIGN_FULCIO_ROOT", "SIGSTORE_REKOR_PUBLIC_KEY",
		"SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
	} {
		if _, ok := seen[want]; !ok {
			t.Errorf("%s is missing from the child environment", want)
		}
	}
	// The placeholder CT key must be a key, and must not be either of the two
	// real ones: see placeholderCTLogKey.
	ct, err := os.ReadFile(seen["SIGSTORE_CT_LOG_PUBLIC_KEY_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ct)
	if block == nil {
		t.Fatal("the placeholder CT log key is not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Errorf("the placeholder CT log key does not parse: %v", err)
	}
	if string(ct) == string(f.rekorKey) || strings.Contains(string(ct), "CERTIFICATE") {
		t.Error("the placeholder CT log key is one of the deployment's real keys; " +
			"it must be a key nobody holds")
	}
}

// TestPlaceholderCTLogKeyIsDifferentEveryTime pins the property that makes the
// placeholder safe: nothing retains the private half, so no two calls can
// produce a key anybody could have signed an SCT with.
func TestPlaceholderCTLogKeyIsDifferentEveryTime(t *testing.T) {
	a, err := placeholderCTLogKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := placeholderCTLogKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("two placeholder CT log keys are identical, so one is stored somewhere")
	}
}

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------

func TestNewSignerRefusesAConfigurationItCannotSignWith(t *testing.T) {
	dir := t.TempDir()
	gitsign := fakeBinary(t, dir, "gitsign", "exit 0")
	git := fakeBinary(t, dir, "git", "exit 0")
	good := Config{
		FulcioURL: "http://127.0.0.1:5555", RekorURL: "http://127.0.0.1:3000",
		Issuer: "http://spire-oidc:8080", GitsignPath: gitsign, GitPath: git,
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		src    CredentialSource
	}{
		{"no credential source", nil, nil},
		{"no Fulcio", func(c *Config) { c.FulcioURL = "" }, staticSource{}},
		{"no Rekor", func(c *Config) { c.RekorURL = "" }, staticSource{}},
		{"Fulcio is not a URL", func(c *Config) { c.FulcioURL = "://x" }, staticSource{}},
		{"Fulcio has no host", func(c *Config) { c.FulcioURL = "fulcio:5555" }, staticSource{}},
		{"Rekor has no host", func(c *Config) { c.RekorURL = "rekor" }, staticSource{}},
		{"no issuer", func(c *Config) { c.Issuer = "" }, staticSource{}},
		{"no gitsign", func(c *Config) { c.GitsignPath = filepath.Join(dir, "absent") }, staticSource{}},
		{"no git", func(c *Config) { c.GitPath = filepath.Join(dir, "absent") }, staticSource{}},
		{"work directory is a file", func(c *Config) {
			c.WorkDir = fakeBinary(t, dir, "not-a-directory", "exit 0")
		}, staticSource{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			s, err := NewSigner(cfg, tc.src)
			if err == nil {
				_ = s.Close()
				t.Fatal("NewSigner accepted a configuration it cannot sign with")
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("error = %v, want it to wrap ErrConfig", err)
			}
		})
	}
}

func TestNewSignerFillsInTheDocumentedDefaults(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, func(c *Config) {
		c.Audience, c.Timeout, c.Skew, c.MinValidity = "", 0, 0, 0
	})
	if s.cfg.Audience != AudienceSigstore {
		t.Errorf("Audience = %q, want %q", s.cfg.Audience, AudienceSigstore)
	}
	if s.cfg.Timeout != DefaultTimeout || s.cfg.Skew != DefaultSkew ||
		s.cfg.MinValidity != DefaultMinValidity {
		t.Errorf("bounds = %v/%v/%v, want %v/%v/%v",
			s.cfg.Timeout, s.cfg.Skew, s.cfg.MinValidity,
			DefaultTimeout, DefaultSkew, DefaultMinValidity)
	}
	if s.cfg.Now == nil || s.cfg.HTTPClient == nil {
		t.Error("Now and HTTPClient must be defaulted")
	}
	// A caller-supplied work directory is the caller's to remove.
	dir := t.TempDir()
	own := unitSigner(t, f, func(c *Config) { c.WorkDir = dir })
	if err := own.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Close removed a work directory it did not create: %v", err)
	}
	// One it made is one it removes.
	made := unitSigner(t, f, nil)
	path := made.workDir
	if err := made.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Close left %s behind: %v", path, err)
	}
}

// TestSignRefusesADefaultLookupWhenNothingIsOnPath covers the PATH-resolved
// default, which is what a deployment that names no binary gets.
func TestNewSignerResolvesBinariesOnPath(t *testing.T) {
	dir := t.TempDir()
	fakeBinary(t, dir, "gitsign", "exit 0")
	fakeBinary(t, dir, "git", "exit 0")
	t.Setenv("PATH", dir)
	s, err := NewSigner(Config{
		FulcioURL: "http://127.0.0.1:5555", RekorURL: "http://127.0.0.1:3000",
		Issuer: "http://spire-oidc:8080",
	}, staticSource{})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.cfg.GitsignPath != filepath.Join(dir, "gitsign") {
		t.Errorf("GitsignPath = %q, want the PATH lookup %q",
			s.cfg.GitsignPath, filepath.Join(dir, "gitsign"))
	}
}

// ---------------------------------------------------------------------------
// Credentials — IP §6.2.
// ---------------------------------------------------------------------------

// TestCredentialUsableAtTheBoundary walks both sides of the refusal threshold.
// The property that matters is one-sidedness: nothing widens the window.
func TestCredentialUsableAtTheBoundary(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	base := Credential{Token: "a.b.c", SPIFFEID: unitIdentity, Audience: AudienceSigstore}
	cases := []struct {
		name    string
		expires time.Time
		min     time.Duration
		want    bool
	}{
		{"comfortably live", now.Add(10 * time.Minute), 30 * time.Second, true},
		{"one second past the margin", now.Add(31 * time.Second), 30 * time.Second, true},
		{"exactly on the margin", now.Add(30 * time.Second), 30 * time.Second, false},
		{"one second inside the margin", now.Add(29 * time.Second), 30 * time.Second, false},
		{"expires exactly now", now, 0, false},
		{"expired a second ago", now.Add(-time.Second), 0, false},
		{"expired an hour ago", now.Add(-time.Hour), 30 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.ExpiresAt = tc.expires
			err := c.usableAt(now, tc.min)
			if (err == nil) != tc.want {
				t.Fatalf("usableAt = %v, want usable=%v", err, tc.want)
			}
		})
	}
	t.Run("no token", func(t *testing.T) {
		c := Credential{ExpiresAt: now.Add(time.Hour)}
		if err := c.usableAt(now, 0); err == nil {
			t.Error("a credential with no token was accepted")
		}
	})
	t.Run("no expiry", func(t *testing.T) {
		c := Credential{Token: "a.b.c"}
		if err := c.usableAt(now, 0); err == nil {
			t.Error("a credential with no expiry was accepted: an unbounded " +
				"credential is one nothing can ever call expired")
		}
	})
}

func TestCredentialIsRefusedForTheWrongRunOrAudience(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	now := time.Now()
	cases := []struct {
		name string
		cred Credential
	}{
		{"another run's credential", Credential{
			Token: "a.b.c", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-032/run-other",
			Audience: AudienceSigstore, ExpiresAt: now.Add(time.Hour)}},
		{"another relying party's audience", Credential{
			Token: "a.b.c", SPIFFEID: unitIdentity,
			Audience: "not-sigstore", ExpiresAt: now.Add(time.Hour)}},
		{"expired", Credential{
			Token: "a.b.c", SPIFFEID: unitIdentity,
			Audience: AudienceSigstore, ExpiresAt: now.Add(-time.Hour)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := unitSigner(t, f, nil)
			s.src = staticSource{cred: tc.cred}
			_, err := s.credential(t.Context(), unitClaim())
			if err == nil {
				t.Fatal("the credential was accepted")
			}
			if !errors.Is(err, ErrCredentialUnavailable) {
				t.Errorf("error = %v, want it to wrap ErrCredentialUnavailable", err)
			}
		})
	}
}

// TestCredentialCacheIsDroppedBeforeTheRefetch is the ordering IP §6.2 turns
// on: "if re-fetch fails, signing blocks". A cache that survived a failed
// re-fetch would make that sentence false.
func TestCredentialCacheIsDroppedBeforeTheRefetch(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	clock := time.Now()
	s := unitSigner(t, f, func(c *Config) { c.Now = func() time.Time { return clock } })

	live := Credential{Token: "a.b.c", SPIFFEID: unitIdentity,
		Audience: AudienceSigstore, ExpiresAt: clock.Add(time.Hour)}
	s.src = staticSource{cred: live}
	if _, err := s.credential(t.Context(), unitClaim()); err != nil {
		t.Fatalf("the first fetch: %v", err)
	}
	if s.cred.Token != live.Token {
		t.Fatal("the credential was not cached, so nothing below tests reuse")
	}

	// Reused while live, with a source that would fail if consulted.
	s.src = staticSource{err: errors.New("must not be called")}
	if got, err := s.credential(t.Context(), unitClaim()); err != nil || got.Token != live.Token {
		t.Fatalf("a live credential was not reused: %v %v", got, err)
	}

	// Expired, and the re-fetch is blocked.
	clock = live.ExpiresAt.Add(time.Second)
	blocked := errors.New("get_credential is unreachable")
	s.src = staticSource{err: blocked}
	_, err := s.credential(t.Context(), unitClaim())
	if !errors.Is(err, ErrCredentialUnavailable) || !errors.Is(err, blocked) {
		t.Fatalf("error = %v, want ErrCredentialUnavailable wrapping the source's own", err)
	}
	if s.cred.Token != "" {
		t.Error("the expired credential survived a failed re-fetch: signing could " +
			"reach for it again (IP §6.2)")
	}
}

// TestSignBlocksWhenTheAuthorPolicyIsUnconfigured is ADR-0028 decision 6 wired
// through: the zero-value policy admits nothing, so a deployment that forgets
// to configure it fails at its first signature instead of signing unguarded.
func TestSignBlocksWhenTheAuthorPolicyIsUnconfigured(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	called := false
	s := unitSigner(t, f, func(c *Config) { c.Author = AuthorPolicy{} })
	s.src = funcSource(func() (Credential, error) {
		called = true
		return liveCredential(), nil
	})
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "an unguarded commit",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Fatalf("Sign error = %v, want ErrAuthorNotAdmitted", err)
	}
	if called {
		t.Error("a credential was spent on a commit the author gate refuses")
	}
}

type funcSource func() (Credential, error)

func (f funcSource) Credential(context.Context) (Credential, error) { return f() }

func TestSignRefusesAMalformedRequestBeforeSpendingAnything(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	cases := []struct {
		name string
		req  Request
		want error
	}{
		{"no repository", Request{Message: "x", AuthorEmail: "operator@innsegl.invalid",
			Claim: unitClaim()}, ErrConfig},
		{"empty message", Request{Repo: t.TempDir(), Message: "",
			AuthorEmail: "operator@innsegl.invalid", Claim: unitClaim()}, ErrMessage},
		{"a claim that disagrees with itself", Request{Repo: t.TempDir(), Message: "x",
			AuthorEmail: "operator@innsegl.invalid",
			Claim:       Claim{Identity: unitIdentity, Run: "run-other", Task: "rm-032"}}, ErrClaim},
		{"a co-authorship trailer", Request{Repo: t.TempDir(),
			Message:     "x\n\nCo-authored-by: Somebody <s@example.com>",
			AuthorEmail: "operator@innsegl.invalid", Claim: unitClaim()}, ErrCoAuthorship},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := unitSigner(t, f, nil)
			s.src = staticSource{cred: liveCredential()}
			if _, err := s.Sign(t.Context(), tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("Sign error = %v, want %v", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Trust material — ADR-0024's definition of reachable, and the two error
// classes IP §6.3 distinguishes.
// ---------------------------------------------------------------------------

func TestTrustMaterialTellsFulcioDownFromRekorDown(t *testing.T) {
	ca := newTestCA(t)
	leafOnly := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Minute))

	cases := []struct {
		name   string
		mutate func(*fakeSigstore)
		want   error
	}{
		{"Fulcio answers 500", func(f *fakeSigstore) { f.fulcioStatus = 500 }, ErrSigningUnavailable},
		{"Fulcio serves prose", func(f *fakeSigstore) { f.fulcioRoot = []byte("not a certificate") },
			ErrSigningUnavailable},
		{"Fulcio serves a PEM that is not a certificate", func(f *fakeSigstore) {
			f.fulcioRoot = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
		}, ErrSigningUnavailable},
		{"Fulcio serves a leaf, not a CA", func(f *fakeSigstore) {
			f.fulcioRoot = certPEM(leafOnly)
		}, ErrSigningUnavailable},
		{"Rekor answers 500", func(f *fakeSigstore) { f.rekorStatus = 500 }, ErrTransparencyUnavailable},
		{"Rekor serves prose", func(f *fakeSigstore) { f.rekorKey = []byte("not a key") },
			ErrTransparencyUnavailable},
		{"Rekor serves a PEM that is not a key", func(f *fakeSigstore) {
			f.rekorKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})
		}, ErrTransparencyUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSigstore(t, ca)
			tc.mutate(f)
			s := unitSigner(t, f, nil)
			_, err := s.trustMaterial(t.Context())
			if !errors.Is(err, tc.want) {
				t.Fatalf("trustMaterial error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTrustMaterialIsFetchedOnceAndReused(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	first, err := s.trustMaterial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.fulcioStatus = 500 // a second fetch would now fail
	second, err := s.trustMaterial(t.Context())
	if err != nil || second != first {
		t.Fatalf("trustMaterial refetched: %v %v", second, err)
	}
}

func TestTrustMaterialFailsWhenSigstoreIsNotListening(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	f.server.Close()
	if _, err := s.trustMaterial(t.Context()); !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("trustMaterial error = %v, want ErrSigningUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// Reading a signature back off a commit.
// ---------------------------------------------------------------------------

// TestCertificatesFromARealSignature parses a CMS blob produced by the real
// gitsign against the real compose stack, captured into testdata. A synthetic
// blob would only prove that our parser agrees with our encoder.
func TestCertificatesFromARealSignature(t *testing.T) {
	armored, err := os.ReadFile(filepath.Join("testdata", "signed-commit.sig.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certificatesFromSignature(armored)
	if err != nil {
		t.Fatalf("certificatesFromSignature: %v", err)
	}
	leaf, err := leafOf(certs)
	if err != nil {
		t.Fatalf("leafOf: %v", err)
	}
	got := describeCertificate(leaf)
	if !strings.HasPrefix(got.SPIFFEID, "spiffe://innsegl.dev/agent/") {
		t.Errorf("URI SAN = %q, want this deployment's SPIFFE ID grammar", got.SPIFFEID)
	}
	if got.Issuer != "http://spire-oidc:8080" {
		t.Errorf("issuer = %q, want the compose stack's", got.Issuer)
	}
	if got.NotAfter.Sub(got.NotBefore) != 10*time.Minute {
		t.Errorf("validity window is %s; Fulcio issues ten-minute certificates",
			got.NotAfter.Sub(got.NotBefore))
	}
	if len(got.Fingerprint) != 64 {
		t.Errorf("fingerprint %q is not a sha256 hex digest", got.Fingerprint)
	}
	fromPEM, err := fingerprintOfCertPEM(certPEM(leaf))
	if err != nil || fromPEM != got.Fingerprint {
		t.Errorf("fingerprintOfCertPEM = %q/%v, want %q", fromPEM, err, got.Fingerprint)
	}
}

func TestCertificatesFromSignatureRefusesWhatItCannotRead(t *testing.T) {
	valid, err := os.ReadFile(filepath.Join("testdata", "signed-commit.sig.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(valid)
	cases := []struct {
		name    string
		armored []byte
	}{
		{"not PEM at all", []byte("gpgsig")},
		{"a PGP signature", pem.EncodeToMemory(&pem.Block{Type: "PGP SIGNATURE", Bytes: []byte{1}})},
		{"PEM that is not ASN.1", pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte("junk")})},
		{"a ContentInfo whose content is not SignedData", pem.EncodeToMemory(&pem.Block{
			Type: "SIGNED MESSAGE", Bytes: mustMarshalContentInfo(t, []byte{0x05, 0x00})})},
		{"truncated", pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: block.Bytes[:40]})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := certificatesFromSignature(tc.armored); !errors.Is(err, ErrSignature) {
				t.Fatalf("error = %v, want ErrSignature", err)
			}
		})
	}
	t.Run("no certificate in the set", func(t *testing.T) {
		empty := cmsSignedData{Version: 1}
		der, merr := asn1.Marshal(empty)
		if merr != nil {
			t.Fatal(merr)
		}
		armored := pem.EncodeToMemory(&pem.Block{
			Type: "SIGNED MESSAGE", Bytes: mustMarshalContentInfo(t, der)})
		if _, err := certificatesFromSignature(armored); !errors.Is(err, ErrSignature) {
			t.Fatalf("error = %v, want ErrSignature", err)
		}
	})
	t.Run("a set with no leaf", func(t *testing.T) {
		ca := newTestCA(t)
		if _, err := leafOf([]*x509.Certificate{ca.cert}); !errors.Is(err, ErrSignature) {
			t.Fatalf("error = %v, want ErrSignature: a CA is not a signing identity", err)
		}
	})
	t.Run("fingerprintOfCertPEM on rubbish", func(t *testing.T) {
		if _, err := fingerprintOfCertPEM([]byte("nope")); !errors.Is(err, ErrSignature) {
			t.Errorf("error = %v, want ErrSignature", err)
		}
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
		if _, err := fingerprintOfCertPEM(bad); !errors.Is(err, ErrSignature) {
			t.Errorf("error = %v, want ErrSignature", err)
		}
	})
}

// mustMarshalContentInfo wraps arbitrary DER in a CMS ContentInfo.
func mustMarshalContentInfo(t *testing.T, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(cmsContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{FullBytes: content},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestGpgsigOfReadsTheHeaderGitWrote(t *testing.T) {
	object := "tree abc\n" +
		"parent def\n" +
		"gpgsig -----BEGIN SIGNED MESSAGE-----\n" +
		" AAAA\n" +
		" -----END SIGNED MESSAGE-----\n" +
		"author o <o@innsegl.invalid> 1 +0000\n" +
		"\n" +
		"a message\n"
	got, err := gpgsigOf(object)
	if err != nil {
		t.Fatal(err)
	}
	want := "-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n"
	if string(got) != want {
		t.Errorf("gpgsigOf = %q, want %q", got, want)
	}
	if _, err := gpgsigOf("tree abc\n\nunsigned\n"); !errors.Is(err, ErrSignature) {
		t.Errorf("an unsigned commit gave %v, want ErrSignature", err)
	}
}

// TestCheckCertificateWalksBothSidesOfTheSkewBound is IP §6.8's requirement
// spelled out: "document the bound and test the boundary on both sides".
func TestCheckCertificateWalksBothSidesOfTheSkewBound(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	const issuer = "http://spire-oidc:8080"
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	cred := Credential{Token: "a.b.c", SPIFFEID: unitIdentity,
		Audience: AudienceSigstore, ExpiresAt: now.Add(time.Hour)}

	cases := []struct {
		name                string
		spiffeID, certIssue string
		notBefore, notAfter time.Time
		wantErr             bool
	}{
		{"live", unitIdentity, issuer, now.Add(-time.Minute), now.Add(9 * time.Minute), false},
		{"expired one second inside the skew bound", unitIdentity, issuer,
			now.Add(-10 * time.Minute), now.Add(-DefaultSkew + time.Second), false},
		{"expired exactly at the skew bound", unitIdentity, issuer,
			now.Add(-10 * time.Minute), now.Add(-DefaultSkew), false},
		{"expired one second past the skew bound", unitIdentity, issuer,
			now.Add(-10 * time.Minute), now.Add(-DefaultSkew - time.Second), true},
		{"not yet valid, one second inside the bound", unitIdentity, issuer,
			now.Add(DefaultSkew - time.Second), now.Add(time.Hour), false},
		{"not yet valid, one second past the bound", unitIdentity, issuer,
			now.Add(DefaultSkew + time.Second), now.Add(time.Hour), true},
		{"another run's SAN", "spiffe://innsegl.dev/agent/demo/rm-032/run-other", issuer,
			now.Add(-time.Minute), now.Add(time.Hour), true},
		{"another issuer", unitIdentity, "https://accounts.google.com",
			now.Add(-time.Minute), now.Add(time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := unitSigner(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
			cert := ca.leaf(t, tc.spiffeID, tc.certIssue, tc.notBefore, tc.notAfter)
			err := s.checkCertificate(cert, unitClaim(), cred)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkCertificate = %v, want error=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrIdentityMismatch) {
				t.Errorf("error = %v, want ErrIdentityMismatch", err)
			}
		})
	}
	t.Run("the certificate is for the claim but not for the credential", func(t *testing.T) {
		s := unitSigner(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
		other := cred
		other.SPIFFEID = "spiffe://innsegl.dev/agent/demo/rm-032/run-other"
		cert := ca.leaf(t, unitIdentity, issuer, now.Add(-time.Minute), now.Add(time.Hour))
		if err := s.checkCertificate(cert, unitClaim(), other); !errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("error = %v, want ErrIdentityMismatch", err)
		}
	})
}

// TestFulcioIssuerFallsBackToTheDeprecatedExtension keeps an older Fulcio from
// being reported as having no issuer at all.
func TestFulcioIssuerFallsBackToTheDeprecatedExtension(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: oidFulcioIssuerV1, Value: []byte("http://spire-oidc:8080")},
	}}
	if got := fulcioIssuerOf(cert); got != "http://spire-oidc:8080" {
		t.Errorf("issuer = %q, want the deprecated .1 extension to be read", got)
	}
	// A .8 that is not a UTF8String falls through to .1 rather than being
	// reported as an issuer nobody named.
	cert = &x509.Certificate{Extensions: []pkix.Extension{
		{Id: oidFulcioIssuerV2, Value: []byte{0xff}},
		{Id: oidFulcioIssuerV1, Value: []byte("http://spire-oidc:8080")},
	}}
	if got := fulcioIssuerOf(cert); got != "http://spire-oidc:8080" {
		t.Errorf("issuer = %q, want the fallback", got)
	}
	if got := fulcioIssuerOf(&x509.Certificate{}); got != "" {
		t.Errorf("issuer = %q, want empty for a certificate with no extension", got)
	}
	if got := describeCertificate(&x509.Certificate{SerialNumber: big.NewInt(1)}); got.SPIFFEID != "" {
		t.Errorf("SPIFFEID = %q, want empty for a certificate with no URI SAN", got.SPIFFEID)
	}
}

// ---------------------------------------------------------------------------
// Finding the Rekor entry.
// ---------------------------------------------------------------------------

func TestFindRekorEntryReturnsTheEntryForThisCommit(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	const commitSHA = "39a05acbd29763e07b5ce9eb3718526a47a290f3"

	// Two candidates under the same artifact hash: one logged under somebody
	// else's certificate, and this commit's. Picking the first would be the
	// vacuous answer.
	other := ca.leaf(t, "spiffe://innsegl.dev/agent/demo/rm-032/run-other",
		"http://spire-oidc:8080", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	f.addEntry(strings.Repeat("a", 64), sha256HexOf(commitSHA), other, 7)
	f.addEntry(strings.Repeat("b", 64), sha256HexOf(commitSHA), leaf, 9)
	f.indexBody = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}

	got, err := findRekorEntry(t.Context(), f.server.Client(), f.server.URL, commitSHA, leaf)
	if err != nil {
		t.Fatalf("findRekorEntry: %v", err)
	}
	if got.UUID != strings.Repeat("b", 64) || got.LogIndex != 9 {
		t.Errorf("entry = %+v, want the one logged under this commit's certificate", got)
	}
	if got.IntegratedAt.IsZero() {
		t.Error("the entry has no integration time")
	}
}

func TestFindRekorEntryRefusesWhatIsNotThisCommits(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	other := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	const commitSHA = "39a05acbd29763e07b5ce9eb3718526a47a290f3"
	uuid := strings.Repeat("c", 64)

	cases := []struct {
		name   string
		mutate func(*fakeSigstore)
	}{
		{"the search index is empty", func(f *fakeSigstore) { f.indexBody = []string{} }},
		{"the search index answers 500", func(f *fakeSigstore) { f.indexStatus = 500 }},
		{"the search index answers with an object", func(f *fakeSigstore) {
			f.indexBody = map[string]string{"not": "a list"}
		}},
		{"the entry endpoint answers 500", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			f.entryStatus = 500
		}},
		{"the log has no such entry", func(f *fakeSigstore) { f.indexBody = []string{uuid} }},
		{"the entry body is not base64", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			f.entries[uuid] = map[string]any{"body": "!!!", "logIndex": 1}
		}},
		{"the entry body is not JSON", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			f.entries[uuid] = map[string]any{
				"body":     base64.StdEncoding.EncodeToString([]byte("not json")),
				"logIndex": 1}
		}},
		{"the entry is a different kind", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			body := f.marshal(map[string]any{"kind": "rekord"})
			f.entries[uuid] = map[string]any{
				"body": base64.StdEncoding.EncodeToString(body), "logIndex": 1}
		}},
		{"the entry is for a different artifact", func(f *fakeSigstore) {
			f.addEntry(uuid, sha256HexOf("some other commit"), leaf, 1)
			f.indexBody = []string{uuid}
		}},
		{"the entry is under a different certificate", func(f *fakeSigstore) {
			f.addEntry(uuid, sha256HexOf(commitSHA), other, 1)
			f.indexBody = []string{uuid}
		}},
		{"the entry's public key is not base64", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			body := f.marshal(map[string]any{
				"kind": rekorHashedRekord,
				"spec": map[string]any{
					"data": map[string]any{"hash": map[string]any{
						"algorithm": rekorSHA256, "value": sha256HexOf(commitSHA)}},
					"signature": map[string]any{
						"publicKey": map[string]any{"content": "!!!"}},
				}})
			f.entries[uuid] = map[string]any{
				"body": base64.StdEncoding.EncodeToString(body), "logIndex": 1}
		}},
		{"the entry's public key is not a certificate", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			body := f.marshal(map[string]any{
				"kind": rekorHashedRekord,
				"spec": map[string]any{
					"data": map[string]any{"hash": map[string]any{
						"algorithm": rekorSHA256, "value": sha256HexOf(commitSHA)}},
					"signature": map[string]any{"publicKey": map[string]any{
						"content": base64.StdEncoding.EncodeToString(
							pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))}},
				}})
			f.entries[uuid] = map[string]any{
				"body": base64.StdEncoding.EncodeToString(body), "logIndex": 1}
		}},
		{"the entry's public key is not PEM", func(f *fakeSigstore) {
			f.indexBody = []string{uuid}
			body := f.marshal(map[string]any{
				"kind": rekorHashedRekord,
				"spec": map[string]any{
					"data": map[string]any{"hash": map[string]any{
						"algorithm": rekorSHA256, "value": sha256HexOf(commitSHA)}},
					"signature": map[string]any{"publicKey": map[string]any{
						"content": base64.StdEncoding.EncodeToString([]byte("not pem"))}},
				}})
			f.entries[uuid] = map[string]any{
				"body": base64.StdEncoding.EncodeToString(body), "logIndex": 1}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSigstore(t, ca)
			f.indexBody = []string{}
			tc.mutate(f)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err := findRekorEntry(ctx, f.server.Client(), f.server.URL, commitSHA, leaf)
			if err == nil {
				t.Fatal("findRekorEntry accepted an entry that is not this commit's")
			}
			if !errors.Is(err, ErrTransparencyUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("error = %v, want ErrTransparencyUnavailable", err)
			}
		})
	}
}

func TestFindRekorEntryRefusesAMalformedRekorURL(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if _, err := findRekorEntry(t.Context(), http.DefaultClient, "://x", "sha", leaf); !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

func sha256HexOf(s string) string {
	return sha256Hex(s)
}

// ---------------------------------------------------------------------------
// Verify.
// ---------------------------------------------------------------------------

func TestVerifyRefusesToRunWithoutAnIdentity(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	cases := []struct{ repo, rev, id string }{
		{"", "HEAD", unitIdentity},
		{t.TempDir(), "", unitIdentity},
		{t.TempDir(), "HEAD", ""},
	}
	for _, tc := range cases {
		if _, err := s.Verify(t.Context(), tc.repo, tc.rev, tc.id); !errors.Is(err, ErrConfig) {
			t.Errorf("Verify(%q,%q,%q) = %v, want ErrConfig", tc.repo, tc.rev, tc.id, err)
		}
	}
}

func TestVerifyReportsWhichClaimFailed(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	// A gitsign that exits 0 but reports a failed claim. Trusting the exit
	// status alone would call this commit verified.
	fake := fakeBinary(t, dir, "gitsign-lax", `
echo "tlog index: 12"
echo "Validated Git signature: true"
echo "Validated Rekor entry: false"
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	v, err := s.Verify(t.Context(), t.TempDir(), "HEAD", unitIdentity)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify error = %v, want ErrVerification", err)
	}
	if v.LogIndex != 12 {
		t.Errorf("LogIndex = %d, want 12", v.LogIndex)
	}
	if v.Claims["Validated Rekor entry"] {
		t.Error("the failing claim was not reported")
	}
}

func TestVerifyPassesWhenGitsignAgrees(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-ok", `
echo "tlog index: 3"
echo "Validated Git signature: true"
echo "Validated Rekor entry: true"
echo "Validated Certificate claims: true"
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	v, err := s.Verify(t.Context(), t.TempDir(), "HEAD", unitIdentity)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(v.Claims) != 3 || v.LogIndex != 3 {
		t.Errorf("Verification = %+v, want three claims and index 3", v)
	}
}

func TestVerifyReportsANonZeroExit(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-no", `echo "Error: no matching CertificateIdentity found" >&2; exit 1`)
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	_, err := s.Verify(t.Context(), t.TempDir(), "HEAD", unitIdentity)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify error = %v, want ErrVerification", err)
	}
	if !strings.Contains(err.Error(), "no matching CertificateIdentity") {
		t.Errorf("error = %v, want gitsign's own words quoted", err)
	}
}

func TestVerifyFailsWhenSigstoreIsUnreachable(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	f.server.Close()
	if _, err := s.Verify(t.Context(), t.TempDir(), "HEAD", unitIdentity); !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("Verify error = %v, want ErrSigningUnavailable", err)
	}
}

func TestParseVerificationIgnoresPoseOutput(t *testing.T) {
	v := parseVerification("hello\ntlog index: not-a-number\nSomething: true\n")
	if v.LogIndex != -1 {
		t.Errorf("LogIndex = %d, want -1 when gitsign printed no usable index", v.LogIndex)
	}
	if len(v.Claims) != 0 {
		t.Errorf("Claims = %v, want only lines gitsign spells as claims", v.Claims)
	}
}

// ---------------------------------------------------------------------------
// The git invocation.
// ---------------------------------------------------------------------------

// TestSignReportsWhatGitsignSaid keeps the CA's and the log's own words in the
// error, which is what makes a signing failure diagnosable at all.
func TestSignReportsWhatGitsignSaid(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "git-refuses", `
echo "error: gpg failed to sign the data:" >&2
echo "There was an error processing the identity token" >&2
exit 128`)
	s := unitSigner(t, f, func(c *Config) { c.GitPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit that will not be signed",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSigning) {
		t.Fatalf("Sign error = %v, want ErrSigning", err)
	}
	if !strings.Contains(err.Error(), "error processing the identity token") {
		t.Errorf("error = %v, want the child's output attached", err)
	}
}

// TestSignReportsAnUnsignedCommit is the case where git succeeds and yet the
// object carries no signature. It must never be reported as a signed commit.
func TestSignReportsAnUnsignedCommit(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "git-unsigned", `
case "$*" in
  *rev-parse*) echo 0000000000000000000000000000000000000000 ;;
  *cat-file*)  printf 'tree abc\n\na message\n' ;;
esac
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit with no signature",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Sign error = %v, want ErrSignature", err)
	}
}

// TestSignFailsWhenTheRevisionCannotBeResolved covers the read-back path where
// git itself refuses after the commit was made.
func TestSignFailsWhenTheRevisionCannotBeResolved(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "git-halfway", `
case "$*" in
  *rev-parse*) echo "fatal: ambiguous argument 'HEAD'" >&2; exit 128 ;;
esac
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit whose HEAD cannot be read",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Sign error = %v, want ErrSignature", err)
	}
}

// TestSignFailsWhenTheCertificateIsNotThisRuns is the wrapper refusing to
// report a success it cannot stand behind (IP §6.9, from our own side).
func TestSignFailsWhenTheCertificateIsNotThisRuns(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	armored, err := os.ReadFile(filepath.Join("testdata", "signed-commit.sig.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(string(armored), "\n"), "\n") {
		indented.WriteString(" " + line + "\n")
	}
	object := "tree abc\ngpgsig" + strings.TrimPrefix(indented.String(), "") + "\nnot this run\n"
	dir := t.TempDir()
	script := filepath.Join(dir, "commit-object")
	if werr := os.WriteFile(script, []byte(object), 0o600); werr != nil {
		t.Fatal(werr)
	}
	fake := fakeBinary(t, dir, "git-otherrun", `
case "$*" in
  *rev-parse*) echo 39a05acbd29763e07b5ce9eb3718526a47a290f3 ;;
  *cat-file*)  cat `+script+` ;;
esac
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err = s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit signed by another run",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Sign error = %v, want ErrIdentityMismatch", err)
	}
}

func TestJoinURLRefusesWhatIsNotAnEndpoint(t *testing.T) {
	for _, base := range []string{"://x", "fulcio:5555", "", "/api"} {
		if _, err := joinURL(base, fulcioRootPath); !errors.Is(err, ErrConfig) {
			t.Errorf("joinURL(%q) = %v, want ErrConfig", base, err)
		}
	}
	got, err := joinURL("http://127.0.0.1:5555/", fulcioRootPath)
	if err != nil || got != "http://127.0.0.1:5555"+fulcioRootPath {
		t.Errorf("joinURL = %q/%v", got, err)
	}
}

func TestTruncateKeepsErrorsReadable(t *testing.T) {
	if got := truncate([]byte("short")); got != "short" {
		t.Errorf("truncate = %q", got)
	}
	got := truncate([]byte(strings.Repeat("x", 600)))
	if n := len([]rune(got)); n != 513 || !strings.HasSuffix(got, "\u2026") {
		t.Errorf("truncate produced %d runes (%q…), want 512 plus an ellipsis", n, got[:8])
	}
}

// ---------------------------------------------------------------------------
// The remaining error returns. Each of these is a path a deployment can reach
// and none of them is reachable from a container, which is why they are here
// and not in the integration suite.
// ---------------------------------------------------------------------------

// derTLV builds one ASN.1 element. It exists so a malformed CMS can be
// constructed byte by byte: encoding/asn1 refuses to marshal the shapes these
// cases need, which is the point of the cases.
func derTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

// cmsAround wraps a SignedData body in a CMS ContentInfo and armours it the way
// a commit's gpgsig header carries it.
func cmsAround(signedData []byte) []byte {
	// OID 1.2.840.113549.1.7.2, id-signedData.
	oid := derTLV(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02})
	inner := derTLV(0xa0, signedData)
	return pem.EncodeToMemory(&pem.Block{
		Type: "SIGNED MESSAGE", Bytes: derTLV(0x30, append(oid, inner...))})
}

func TestCertificatesFromSignatureWalksAMalformedSignedData(t *testing.T) {
	version := derTLV(0x02, []byte{0x01})
	digestAlgs := derTLV(0x31, nil)
	encap := derTLV(0x30, nil)

	cases := []struct {
		name string
		pem  []byte
	}{
		{"the content is not a SignedData", cmsAround(derTLV(0x02, []byte{0x01}))},
		{"a SignedData with no certificates", cmsAround(derTLV(0x30,
			concat(version, digestAlgs, encap)))},
		{"a SignedData whose certificate set is empty", cmsAround(derTLV(0x30,
			concat(version, digestAlgs, encap, derTLV(0xa0, nil))))},
		{"a SignedData whose certificate set is not certificates", cmsAround(derTLV(0x30,
			concat(version, digestAlgs, encap, derTLV(0xa0, []byte{0x30, 0x01, 0x00}))))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := certificatesFromSignature(tc.pem); !errors.Is(err, ErrSignature) {
				t.Fatalf("error = %v, want ErrSignature", err)
			}
		})
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestHTTPHelpersRefuseAnUnrequestableEndpoint(t *testing.T) {
	const bad = "http://127.0.0.1:1/\x7f"
	if _, err := httpGet(t.Context(), http.DefaultClient, bad); err == nil {
		t.Error("httpGet accepted an endpoint it cannot build a request for")
	}
	if _, err := httpPostJSON(t.Context(), http.DefaultClient, bad, nil); err == nil {
		t.Error("httpPostJSON accepted an endpoint it cannot build a request for")
	}
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()
	if _, err := httpPostJSON(t.Context(), http.DefaultClient, url, nil); err == nil {
		t.Error("httpPostJSON succeeded against a closed server")
	}
}

func TestMatchRekorEntryRefusesAnUnreadableResponse(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	uuid := strings.Repeat("d", 64)

	t.Run("the log answers with something that is not an entry map", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte("not json")); err != nil {
				t.Errorf("writing a response: %v", err)
			}
		}))
		defer srv.Close()
		if _, err := matchRekorEntry(t.Context(), srv.Client(), srv.URL,
			[]string{uuid}, "hash", leaf); err == nil {
			t.Error("matchRekorEntry accepted a response that is not JSON")
		}
	})
	t.Run("the log answers with somebody else's entry", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(`{"another-uuid":{"logIndex":1}}`)); err != nil {
				t.Errorf("writing a response: %v", err)
			}
		}))
		defer srv.Close()
		if _, err := matchRekorEntry(t.Context(), srv.Client(), srv.URL,
			[]string{uuid}, "hash", leaf); err == nil {
			t.Error("matchRekorEntry accepted an entry the log did not key by our uuid")
		}
	})
	t.Run("no candidates", func(t *testing.T) {
		if _, err := matchRekorEntry(t.Context(), http.DefaultClient, "http://127.0.0.1:1",
			nil, "hash", leaf); err == nil {
			t.Error("matchRekorEntry returned a nil error for an empty candidate list")
		}
	})
	t.Run("a uuid that cannot be put in a URL", func(t *testing.T) {
		if _, err := matchRekorEntry(t.Context(), http.DefaultClient, "://x",
			[]string{uuid}, "hash", leaf); !errors.Is(err, ErrConfig) {
			t.Errorf("error = %v, want ErrConfig", err)
		}
	})
}

// TestFindRekorEntryGivesUpAfterItsAttempts covers the bounded poll: an entry
// that never appears is TRANSPARENCY_UNAVAILABLE, not an endless wait
// (IP §6.3, "no indefinite hangs").
func TestFindRekorEntryGivesUpAfterItsAttempts(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	f.indexBody = []string{}
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err := findRekorEntry(ctx, f.server.Client(), f.server.URL, "deadbeef", leaf)
	if !errors.Is(err, ErrTransparencyUnavailable) {
		t.Fatalf("error = %v, want ErrTransparencyUnavailable", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("the lookup took %s; it must be bounded", time.Since(start))
	}
}

func TestNewSignerReportsAWorkDirectoryItCannotMake(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(dir, "does-not-exist"))
	_, err := NewSigner(Config{
		FulcioURL: "http://127.0.0.1:5555", RekorURL: "http://127.0.0.1:3000",
		Issuer:      "http://spire-oidc:8080",
		GitsignPath: fakeBinary(t, dir, "gitsign", "exit 0"),
		GitPath:     fakeBinary(t, dir, "git", "exit 0"),
	}, staticSource{})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

func TestTrustMaterialReportsADirectoryItCannotWriteTo(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	s := unitSigner(t, f, func(c *Config) { c.WorkDir = dir })
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restoring %s: %v", dir, err)
		}
	})
	if _, err := s.trustMaterial(t.Context()); !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

func TestSignReportsAMessageItCannotWrite(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	s := unitSigner(t, f, func(c *Config) { c.WorkDir = dir })
	s.src = staticSource{cred: liveCredential()}
	if _, err := s.trustMaterial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restoring %s: %v", dir, err)
		}
	})
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit whose message cannot be written",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

func TestSignBlocksWhenTheCredentialSourceIsUnreachable(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	s.src = staticSource{err: errors.New("get_credential is unreachable")}
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit with no credential",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("error = %v, want ErrCredentialUnavailable", err)
	}
}

func TestSignBlocksWhenSigstoreIsUnreachable(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	s.src = staticSource{cred: liveCredential()}
	f.server.Close()
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit with no CA",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("error = %v, want ErrSigningUnavailable", err)
	}
}

func TestSignFailsWhenTheCommitCannotBeRead(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "git-nocatfile", `
case "$*" in
  *rev-parse*) echo 39a05acbd29763e07b5ce9eb3718526a47a290f3 ;;
  *cat-file*)  echo "fatal: bad object" >&2; exit 128 ;;
esac
exit 0`)
	s := unitSigner(t, f, func(c *Config) { c.GitPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.Sign(t.Context(), Request{
		Repo: t.TempDir(), Message: "a commit that cannot be read back",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("error = %v, want ErrSignature", err)
	}
}

// TestSignFailsWhenTheLogHasNoEntryForTheCommit is IP §6.3's rule read the
// other way round: a signature with no transparency entry is not
// non-repudiable, so a Sign that cannot find one must not report success. The
// commit here is signed under the real captured certificate, so everything up
// to the log lookup passes.
func TestSignFailsWhenTheLogHasNoEntryForTheCommit(t *testing.T) {
	armored, err := os.ReadFile(filepath.Join("testdata", "signed-commit.sig.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certificatesFromSignature(armored)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := leafOf(certs)
	if err != nil {
		t.Fatal(err)
	}
	desc := describeCertificate(leaf)

	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	f.indexBody = []string{}

	dir := t.TempDir()
	object := filepath.Join(dir, "commit-object")
	var b strings.Builder
	b.WriteString("tree abc\ngpgsig ")
	for i, line := range strings.Split(strings.TrimRight(string(armored), "\n"), "\n") {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\na real signature\n")
	if err := os.WriteFile(object, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := fakeBinary(t, dir, "git-real-sig", `
case "$*" in
  *rev-parse*) echo 39a05acbd29763e07b5ce9eb3718526a47a290f3 ;;
  *cat-file*)  cat `+object+` ;;
esac
exit 0`)

	// Inside the captured certificate's ten-minute window, so the validity
	// check passes and the case is about the log rather than the clock.
	inside := desc.NotBefore.Add(time.Minute)
	s := unitSigner(t, f, func(c *Config) {
		c.GitPath = fake
		c.Now = func() time.Time { return inside }
	})
	claim := Claim{Identity: desc.SPIFFEID, Run: "run-manual-1", Task: "rm-032"}
	s.src = staticSource{cred: Credential{
		Token: "a.b.c", SPIFFEID: desc.SPIFFEID,
		Audience: AudienceSigstore, ExpiresAt: inside.Add(time.Hour)}}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := s.Sign(ctx, Request{
		Repo: t.TempDir(), Message: "a signature with no transparency entry",
		AuthorName: "Innsegl Operator", AuthorEmail: "operator@innsegl.invalid",
		Claim: claim,
	}); !errors.Is(err, ErrTransparencyUnavailable) {
		t.Fatalf("error = %v, want ErrTransparencyUnavailable", err)
	}
}
