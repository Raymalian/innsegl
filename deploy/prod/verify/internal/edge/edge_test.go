// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// VER-010 — RM-061 (verify.innsegl.dev, #69).
//
// This is the public proof surface's own layer: turning an HTTP request for
// a repo+SHA into a call against internal/verify.VerifyCommit, and turning
// that Report into an HTTP response. It does not re-implement any of the
// three checks — every fixture below fakes only the two things a serverless
// function cannot have (a GitHub API and, standing in for it, Fulcio/Rekor),
// exactly as internal/verify's own fixtures_test.go fakes the servers and
// nothing else.
//
// What is asserted here: request validation (a malformed sha or repo never
// reaches GitHub), the fetch-to-VerifyCommit wiring (the pieces GitHub hands
// back are the pieces the report was computed from), and the verdict-to-
// status mapping this issue's report has to argue for.

// ---------------------------------------------------------------------------
// A minimal, real Fulcio-shaped CA and a real CMS signature, so VerifyCommit
// is exercised for real rather than stubbed. Deliberately smaller than
// internal/verify's fixtures: this package proves the WIRING, not the three
// checks themselves — those are internal/verify's tests to own.
// ---------------------------------------------------------------------------

const fixtureIdentity = "spiffe://innsegl.dev/agent/demo/rm-061/run-1"

type fixtureContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type fixtureSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

func cmsPEM(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	encap, err := asn1.Marshal(struct{ ContentType asn1.ObjectIdentifier }{
		asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
	})
	if err != nil {
		t.Fatalf("marshalling encapContentInfo: %v", err)
	}
	sd, err := asn1.Marshal(fixtureSignedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		EncapContentInfo: asn1.RawValue{FullBytes: encap},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der},
	})
	if err != nil {
		t.Fatalf("marshalling SignedData: %v", err)
	}
	ci, err := asn1.Marshal(fixtureContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd},
	})
	if err != nil {
		t.Fatalf("marshalling ContentInfo: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: ci})
}

// fixtureFulcio is a CA plus one leaf certificate carrying a URI SAN, shaped
// like the certificates Fulcio issues — no CT log, code-signing EKU is not
// needed for this package's purpose (chain + presence, not usage bits).
type fixtureFulcio struct {
	rootPEM []byte
	leafPEM []byte
	leaf    *x509.Certificate
	server  *httptest.Server
}

func newFixtureFulcio(t *testing.T, spiffeID string, notBefore, notAfter time.Time) *fixtureFulcio {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edge test fulcio"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rootCert", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck // test fixture write to an in-process httptest server
		w.Write(caPEM)
	})
	f := &fixtureFulcio{rootPEM: caPEM, leafPEM: leafPEM, leaf: leafCert}
	f.server = httptest.NewServer(mux)
	return f
}

// A fake Rekor that always reports "no entry", which is enough for this
// package's purpose: proving the wiring reaches VerifyCommit and that a
// FAILED verdict (which check 2 always is here) maps to the status this
// issue's report argues for. internal/verify's own fixtures already prove
// the VERIFIED path end to end; duplicating that machinery here would be
// testing internal/verify a second time rather than testing edge.
func newFakeRekor(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test fixture write to an in-process httptest server
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/v1/log/publicKey", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// A fake GitHub commits API.
// ---------------------------------------------------------------------------

type fakeGitHub struct {
	server *httptest.Server
	// commits maps "owner/repo@sha" to the JSON body GitHub would return.
	commits map[string]ghFixture
}

type ghFixture struct {
	status int
	body   string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{commits: map[string]ghFixture{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		for k, f := range g.commits {
			repo, sha, ok := strings.Cut(k, "@")
			if !ok {
				continue
			}
			if "/repos/"+repo+"/commits/"+sha == key {
				w.WriteHeader(f.status)
				//nolint:errcheck // test fixture write to an in-process httptest server
				w.Write([]byte(f.body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		//nolint:errcheck // test fixture write to an in-process httptest server
		w.Write([]byte(`{"message":"Not Found"}`))
	})
	g.server = httptest.NewServer(mux)
	return g
}

func ghCommitJSON(sha, tree, message, signature string) string {
	//nolint:errcheck // json.Marshal of a literal map[string]any cannot fail
	body, _ := json.Marshal(map[string]any{
		"sha": sha,
		"commit": map[string]any{
			"tree":    map[string]any{"sha": tree},
			"message": message,
			"verification": map[string]any{
				"verified":  false,
				"reason":    "unknown_signature_type",
				"signature": signature,
				"payload":   "",
			},
		},
	})
	return string(body)
}

// ---------------------------------------------------------------------------
// Assembling one handler under test.
// ---------------------------------------------------------------------------

type testEnv struct {
	handler *Handler
	gh      *fakeGitHub
	fulcio  *fixtureFulcio
	rekor   *httptest.Server
}

func newTestEnv(t *testing.T, identity string, notBefore, notAfter time.Time) *testEnv {
	t.Helper()
	gh := newFakeGitHub(t)
	fulcio := newFixtureFulcio(t, identity, notBefore, notAfter)
	rekor := newFakeRekor(t)
	t.Cleanup(func() {
		gh.server.Close()
		fulcio.server.Close()
		rekor.Close()
	})

	h, err := New(Config{
		Repo:          DefaultRepo,
		FulcioURL:     fulcio.server.URL,
		RekorURL:      rekor.URL,
		GitHubAPIBase: gh.server.URL,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		Now:           func() time.Time { return notAfter.Add(365 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &testEnv{handler: h, gh: gh, fulcio: fulcio, rekor: rekor}
}

// ---------------------------------------------------------------------------
// Request validation — malformed input never reaches GitHub.
// ---------------------------------------------------------------------------

func TestVER008RejectsAMalformedSHAWithoutCallingGitHub(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha=not-hex!!&repo=Raymalian/innsegl", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestVER008RejectsAMalformedRepo(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha=abc1234&repo=not-a-repo", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestVER008RejectsAnythingButGET(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/verify?sha=abc1234", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// The fetch-to-VerifyCommit wire, and the verdict/status mapping.
// ---------------------------------------------------------------------------

// A commit GitHub has never heard of is a 404 — the same status a stranger
// gets from GitHub itself, not a 500 that would suggest OUR service is
// broken.
func TestVER008AnUnknownCommitIsNotFound(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))

	sha := "0000000000000000000000000000000000000f"
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/verify?sha="+sha+"&repo="+DefaultRepo, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// A commit GitHub serves, whose signature does not chain to this
// deployment's Fulcio root, comes back as a 200 with verdict FAILED — doc
// 06's "never collapse" rule extends to the transport: a refused
// verification is a successful answer, not a server error.
func TestVER008AFailedVerdictIsStillHTTP200(t *testing.T) {
	notBefore, notAfter := time.Now().Add(-time.Minute), time.Now().Add(9*time.Minute)
	env := newTestEnv(t, fixtureIdentity, notBefore, notAfter)

	sig := cmsPEM(t, env.fulcio.leaf)
	sha := "1111111111111111111111111111111111111e"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{
		status: http.StatusOK,
		body: ghCommitJSON(sha, "treesha0000000000000000000000000000000",
			"RM-061: fixture\n\nAgent-Identity: "+fixtureIdentity+"\n", string(sig)),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha="+sha, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var rep verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decoding the report: %v\nbody: %s", err, rec.Body.String())
	}
	if rep.Verdict != verify.VerdictFailed {
		t.Fatalf("verdict = %s, want %s (Rekor holds no entry): %+v", rep.Verdict, verify.VerdictFailed, rep)
	}
	if rep.CommitSHA != sha {
		t.Errorf("report commit sha = %q, want %q", rep.CommitSHA, sha)
	}
	if rep.Repo != "https://github.com/"+DefaultRepo {
		t.Errorf("report repo label = %q, want the github URL", rep.Repo)
	}
}

// An unsigned, untrailered commit is UNATTRIBUTED, and that is also a 200 —
// it is a completed answer about a commit that makes no claim, not an error.
func TestVER008AnUnattributedCommitIsHTTP200(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	sha := "2222222222222222222222222222222222222d"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{
		status: http.StatusOK,
		body:   ghCommitJSON(sha, "treesha0000000000000000000000000000000", "an ordinary commit\n", ""),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha="+sha, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var rep verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	if rep.Verdict != verify.VerdictUnattributed {
		t.Fatalf("verdict = %s, want %s", rep.Verdict, verify.VerdictUnattributed)
	}
}

// GitHub itself failing (rate-limited, an outage — anything but 404) is a
// 502: the fault is upstream of us, not the commit and not our own logic.
func TestVER008AGitHubFailureIsABadGateway(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	sha := "3333333333333333333333333333333333333c"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{
		status: http.StatusForbidden,
		body:   `{"message":"API rate limit exceeded"}`,
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha="+sha, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

// Fulcio itself being unreachable makes check 1 UNAVAILABLE, which rolls up
// to an unavailable verdict — mapped to 503, distinct from both the 200s
// above and from the request-shaped 4xxs: the commit was never judged, our
// dependency was down.
func TestVER008AnUnavailableVerdictIsHTTP503(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	// Both Fulcio and Rekor are down: check 1 and check 2 both come back
	// UNAVAILABLE rather than FAILED (a reachable Rekor with no entry is a
	// FAILED check, which doc 06's rollup outranks — this fixture needs
	// neither dependency reachable to reach a genuine UNAVAILABLE rollup).
	env.fulcio.server.Close()
	env.rekor.Close()

	sig := cmsPEM(t, env.fulcio.leaf)
	sha := "4444444444444444444444444444444444444b"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{
		status: http.StatusOK,
		body: ghCommitJSON(sha, "treesha0000000000000000000000000000000",
			"RM-061: fixture\n\nAgent-Identity: "+fixtureIdentity+"\n", string(sig)),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha="+sha, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	var rep verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	if rep.Verdict != verify.VerdictUnavailable {
		t.Fatalf("verdict = %s, want %s", rep.Verdict, verify.VerdictUnavailable)
	}
}

// A repo query parameter, when supplied, overrides the default — proving
// the handler does not silently ignore it.
func TestVER008ARepoParameterOverridesTheDefault(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	const otherRepo = "example/other"
	sha := "5555555555555555555555555555555555555a"
	env.gh.commits[otherRepo+"@"+sha] = ghFixture{
		status: http.StatusOK,
		body:   ghCommitJSON(sha, "treesha0000000000000000000000000000000", "an ordinary commit\n", ""),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verify?sha="+sha+"&repo="+otherRepo, nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Error-return paths not reachable through a full request — every one of
// them is still a branch this project's TDD mandate (IP §2) requires a test
// to have observed, the same discipline internal/verify's own
// errorpaths_test.go applies to itself.
// ---------------------------------------------------------------------------

func TestNewFillsInEveryDefault(t *testing.T) {
	h, err := New(Config{FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:2"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h.cfg.Repo != DefaultRepo {
		t.Errorf("Repo = %q, want %q", h.cfg.Repo, DefaultRepo)
	}
	if h.cfg.GitHubAPIBase != defaultGitHubAPIBase {
		t.Errorf("GitHubAPIBase = %q, want %q", h.cfg.GitHubAPIBase, defaultGitHubAPIBase)
	}
	if h.cfg.HTTPClient == nil {
		t.Error("HTTPClient left nil")
	}
	if h.cfg.RequestTimeout != defaultRequestTimeout {
		t.Errorf("RequestTimeout = %v, want %v", h.cfg.RequestTimeout, defaultRequestTimeout)
	}
}

func TestNewRefusesWhatVerifyNewWouldRefuse(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted a configuration with no Fulcio or Rekor URL")
	}
}

func TestStatusForAnUnknownVerdictIs500RatherThanASilentDefault(t *testing.T) {
	if got := statusFor(verify.Verdict("not-a-real-verdict")); got != http.StatusInternalServerError {
		t.Errorf("statusFor(unknown) = %d, want %d", got, http.StatusInternalServerError)
	}
}

func TestServeHTTPAnswersOPTIONSForCORSPreflight(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/api/verify", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("no Access-Control-Allow-Methods header on the preflight response")
	}
}

func TestFetchCommitRefusesAnUnbuildableRequest(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	// A raw control character makes url.Parse (and so
	// http.NewRequestWithContext) refuse the URL outright — this is what
	// "the GitHub request could not be built" looks like in practice.
	env.handler.cfg.GitHubAPIBase = "http://example.invalid/\x7f"

	if _, err := env.handler.fetchCommit(t.Context(), DefaultRepo, "abc1234"); err == nil {
		t.Fatal("fetchCommit accepted an unbuildable request")
	}
}

func TestFetchCommitRejectsAResponseThatDoesNotParse(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	sha := "6666666666666666666666666666666666666f"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{status: http.StatusOK, body: "not json"}

	if _, err := env.handler.fetchCommit(t.Context(), DefaultRepo, sha); err == nil {
		t.Fatal("fetchCommit accepted a response body that is not JSON")
	}
}

func TestFetchCommitRejectsAResponseCarryingNoSHA(t *testing.T) {
	env := newTestEnv(t, fixtureIdentity, time.Now(), time.Now().Add(time.Hour))
	sha := "7777777777777777777777777777777777777e"
	env.gh.commits[DefaultRepo+"@"+sha] = ghFixture{
		status: http.StatusOK,
		body:   `{"commit":{"message":"no sha field above"}}`,
	}

	if _, err := env.handler.fetchCommit(t.Context(), DefaultRepo, sha); err == nil {
		t.Fatal("fetchCommit accepted a response with no sha")
	}
}

// failWriter fails every Write, so writeJSON's own write-failure branch (a
// client that hung up mid-response, in production) is reachable from a test.
type failWriter struct {
	*httptest.ResponseRecorder
}

func (f failWriter) Write([]byte) (int, error) {
	return 0, errors.New("the client hung up")
}

func TestWriteJSONLogsRatherThanPanicsWhenTheWriteItselfFails(t *testing.T) {
	// The only assertion possible here is that this does not panic: a write
	// failure after headers are already sent has nothing left to report to
	// but the log, exactly like net/http's own handlers.
	writeJSON(failWriter{httptest.NewRecorder()}, http.StatusOK, errorBody{Error: "x"})
}

// writeJSON's encoder failure path, mirroring internal/verify's own
// TestRenderJSONReportsAnEncoderFailureRatherThanReturningNothing: a
// verify.Report and an errorBody are both encoder-safe by construction, so
// this branch is unreachable in production and reachable only from here.
func TestWriteJSONReturns500OnAnEncodingFailureRatherThanAPartialBody(t *testing.T) {
	old := marshalIndent
	marshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("the encoder refused")
	}
	t.Cleanup(func() { marshalIndent = old })

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, errorBody{Error: "irrelevant"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty: a failed encode must not leak a partial body", rec.Body.String())
	}
}
