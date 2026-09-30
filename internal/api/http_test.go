// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/verify"
	"innsegl.dev/innsegl/internal/webauthntest"
)

// newSoftAuthenticator wraps webauthntest.New for a *testing.T caller — the
// software authenticator itself lives in internal/webauthntest so
// cmd/innsegl's own integration tests (a different package, driving the
// compiled binary over real HTTP) can share it rather than duplicate it.
func newSoftAuthenticator(t *testing.T) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New()
	if err != nil {
		t.Fatalf("webauthntest.New: %v", err)
	}
	return a
}

// TC-API — the HTTP surface.
//
// FD P6: "Read-only means read-only. No mutating action exists anywhere in the
// UI." The UI is not where that is enforced. A read-only API whose transport
// accepts a POST is one handler away from having one, so the refusal is at the
// front door and applies to every path, including paths that do not exist.

// testWebAuthnConfig is fixed rather than derived from the httptest server's
// own (randomly ported, 127.0.0.1) address: nothing in this package drives a
// real browser, so nothing ever collects a clientDataJSON naming the
// httptest listener's own origin. What matters is that every test speaks the
// SAME origin this config names — the software authenticator in
// webauthntest_test.go asserts it, and a case that wants AUTH-004's refusal
// deliberately asserts a different one.
var testWebAuthnConfig = WebAuthnConfig{
	RPID:          "localhost",
	RPOrigin:      "http://localhost:8082",
	RPDisplayName: "Innsegl (test)",
}

// testAuthStore opens an AuthStore on migratedWithAuth's auth-writer DSN —
// TC-API's own "ask the server, never the Go source" discipline, applied to
// the sign-in surface's credential the same way it already is to the
// read-only one.
func testAuthStore(t *testing.T) *AuthStore {
	t.Helper()
	_, _, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func testServer(t *testing.T) (*httptest.Server, *proofScenario) {
	t.Helper()
	listening, scenario, _ := testServerConfigured(t,
		filepath.Join(t.TempDir(), "absent-managed-settings.json"))
	return listening, scenario
}

// testServerConfigured is testServer with the managed-settings path under
// the caller's control — testServerWithSession uses a DENYING fixture so its
// enrolment ceremony can complete; every other case uses an absent one (via
// testServer), matching the default posture AUTH-002 measures separately.
func testServerConfigured(t *testing.T, managedSettingsPath string) (*httptest.Server, *proofScenario, *AuthStore) {
	t.Helper()
	owner, _, readerDSN := migrated(t)
	seed(t, owner, 3)
	store, _ := readStore(t, readerDSN)
	authStore := testAuthStore(t)

	s := newProofScenario(t, proofOptions{})
	srv, err := NewServer(ServerConfig{
		Store: store, Prover: s.prover(t),
		AuthStore: authStore, WebAuthn: testWebAuthnConfig,
		ManagedSettingsPath: managedSettingsPath,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)
	return listening, s, authStore
}

// denyingManagedSettingsJSON is a managed-settings.json CheckSocketDenial
// reads as Denied — the fixture every test that needs a real, completed
// enrolment ceremony uses, so the socket-denial gate (AUTH-002, tested on
// its own in socketdenial_test.go) does not also gate every OTHER case that
// merely needs a signed-in session to exercise ADR-0062's route gate.
const denyingManagedSettingsJSON = `{
	"sandbox": {
		"enabled": true,
		"allowUnsandboxedCommands": false,
		"network": {"allowLocalBinding": true}
	}
}`

// testServerWithSession is testServer plus a signed-in session, returned as
// the *http.Cookie every gated request in a case needs to attach.
func testServerWithSession(t *testing.T) (*httptest.Server, *proofScenario, *http.Cookie) {
	t.Helper()
	path := writeManagedSettings(t, denyingManagedSettingsJSON)
	listening, scenario, authStore := testServerConfigured(t, path)
	cookie := signInTestUser(t, listening.URL, authStore)
	return listening, scenario, cookie
}

// signInTestUser runs a full enrolment ceremony over real HTTP against a
// running server, using the software authenticator (webauthntest_test.go),
// and returns the session cookie the server set. It mints its own one-time
// code directly on authStore — the same AuthStore the running server holds —
// rather than through the CLI, which cmd/innsegl's own tests cover.
func signInTestUser(t *testing.T, baseURL string, authStore *AuthStore) *http.Cookie {
	t.Helper()
	_, cookie := enrolTestUser(t, baseURL, authStore)
	return cookie
}

// enrolTestUser is signInTestUser, also returning the software authenticator
// it enrolled — for a case (AUTH-004's replay) that needs to drive the SAME
// enrolled authenticator through a second ceremony afterwards.
func enrolTestUser(t *testing.T, baseURL string, authStore *AuthStore) (*webauthntest.Authenticator, *http.Cookie) {
	t.Helper()
	code, _, err := authStore.CreateEnrolmentCode(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrolmentCode: %v", err)
	}

	beginBody, err := json.Marshal(map[string]string{"display_name": "Test Operator", "code": code})
	if err != nil {
		t.Fatalf("encoding enrol/begin request: %v", err)
	}
	beginResp := do(t, http.MethodPost, baseURL+"/api/v1/auth/enrol/begin", string(beginBody))
	if beginResp.status != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/enrol/begin: %d: %s", beginResp.status, beginResp.body)
	}
	var creation ceremonyResponse
	if jerr := json.Unmarshal(beginResp.body, &creation); jerr != nil {
		t.Fatalf("decoding enrol/begin response: %v: %s", jerr, beginResp.body)
	}

	auth := newSoftAuthenticator(t)
	credentialBody, rerr := auth.Register(creation.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}
	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": creation.CeremonyID,
		"credential":  json.RawMessage(credentialBody),
	})
	if err != nil {
		t.Fatalf("encoding enrol/finish request: %v", err)
	}
	finishResp := do(t, http.MethodPost, baseURL+"/api/v1/auth/enrol/finish", string(finishBody))
	if finishResp.status != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/enrol/finish: %d: %s", finishResp.status, finishResp.body)
	}

	for _, c := range finishResp.header["Set-Cookie"] {
		parsed := (&http.Response{Header: http.Header{"Set-Cookie": {c}}}).Cookies()
		for _, pc := range parsed {
			if pc.Name == sessionCookieName {
				return auth, pc
			}
		}
	}
	t.Fatal("enrol/finish set no session cookie")
	return nil, nil
}

// answer is one HTTP response, already read and closed. The body is read here
// rather than handed back open so that no case can leak a connection.
type answer struct {
	status int
	header http.Header
	body   []byte
}

// do issues one request. A trailing *http.Cookie — ADR-0062's session —
// attaches to it; every case that predates #410 passes none, which is why
// this is variadic rather than a new required parameter touching every
// existing call site in this package.
func do(t *testing.T, method, target, payload string, cookies ...*http.Cookie) answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var reader io.Reader
	if payload != "" {
		reader = strings.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, target, err)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("closing the body of %s %s: %v", method, target, cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body of %s %s: %v", method, target, err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: body}
}

func get(t *testing.T, base, path string, cookies ...*http.Cookie) answer {
	t.Helper()
	return do(t, http.MethodGet, base+path, "", cookies...)
}

func decodeBody(t *testing.T, a answer, into any) {
	t.Helper()
	if err := json.Unmarshal(a.body, into); err != nil {
		t.Fatalf("the response is not JSON: %v: %s", err, a.body)
	}
}

// API-007 — every mutating method is refused, on every path.
func TestAPI007EveryMutatingMethodIsRefusedOnEveryPath(t *testing.T) {
	srv, _ := testServer(t)

	paths := []string{"/api/v1/runs", "/api/v1/runs/run-000", "/api/v1/overview",
		"/api/v1/proof/deadbeef", "/api/v1/health", "/", "/nothing/here"}
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, "PROPFIND"}

	for _, path := range paths {
		for _, method := range methods {
			a := do(t, method, srv.URL+path, `{"anything":true}`)
			if a.status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s returned %d, want 405: FD P6 makes this API read-only "+
					"at the transport, not by the absence of a handler. body: %s",
					method, path, a.status, a.body)
			}
			if allow := a.header.Get("Allow"); !strings.Contains(allow, http.MethodGet) {
				t.Errorf("%s %s refused with Allow: %q; a refusal that does not say "+
					"what IS allowed is not actionable", method, path, allow)
			}
		}
	}
}

// The read surface: every view answers, in JSON, uncacheable.
func TestTheReadRoutesAnswerInJSONAndAreNeverCached(t *testing.T) {
	srv, scenario, cookie := testServerWithSession(t)

	t.Run("runs", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs?limit=2", cookie)
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/runs: %d", a.status)
		}
		if ct := a.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type %q", ct)
		}
		// FD anti-pattern 1 is "a verified state rendered from cache while the
		// live check errored". Nothing this API serves is cacheable.
		if cc := a.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("Cache-Control %q; a cached proof surface is FD anti-pattern 1 "+
				"waiting to happen", cc)
		}
		var page RunPage
		decodeBody(t, a, &page)
		if len(page.Runs) != 2 || page.Limit != 2 {
			t.Fatalf("limit=2 produced %d runs with Limit=%d", len(page.Runs), page.Limit)
		}
		if page.NextCursor == "" {
			t.Error("three runs were seeded and a page of two carries no next cursor")
		}
		if page.DataAsOf.IsZero() {
			t.Error("the page carries no data-as-of marker (FD §4.4)")
		}
	})

	t.Run("filters ride in the URL", func(t *testing.T) {
		// FD §7: "every view's state (filters, selected run, verification
		// input) lives in the URL".
		a := get(t, srv.URL, "/api/v1/runs?agent_type=release-bot&limit=50", cookie)
		var page RunPage
		decodeBody(t, a, &page)
		for _, r := range page.Runs {
			if r.AgentType != "release-bot" {
				t.Errorf("agent_type=release-bot returned a %s run", r.AgentType)
			}
		}
		if len(page.Runs) == 0 {
			t.Error("the filter matched nothing; the case would pass vacuously")
		}
	})

	t.Run("a malformed query is a bad request, not an empty page", func(t *testing.T) {
		for _, q := range []string{"?status=retiredish", "?cursor=not-a-cursor", "?limit=zero"} {
			a := get(t, srv.URL, "/api/v1/runs"+q, cookie)
			if a.status != http.StatusBadRequest {
				t.Errorf("GET /api/v1/runs%s returned %d, want 400", q, a.status)
			}
		}
	})

	t.Run("run detail", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs/run-000", cookie)
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/runs/run-000: %d", a.status)
		}
		var detail RunDetail
		decodeBody(t, a, &detail)
		if detail.RunID != "run-000" || len(detail.Timeline) == 0 {
			t.Fatalf("run detail: %+v", detail)
		}
	})

	t.Run("an unknown run is 404", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs/run-nope", cookie)
		if a.status != http.StatusNotFound {
			t.Fatalf("GET an unknown run returned %d, want 404", a.status)
		}
		var e errorEnvelope
		decodeBody(t, a, &e)
		if e.Error.Message == "" {
			t.Error("a 404 with no message; FD §4.6 wants an explicit error state")
		}
	})

	t.Run("overview", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/overview", cookie)
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/overview: %d", a.status)
		}
		var o Overview
		decodeBody(t, a, &o)
		if o.DataAsOf.IsZero() {
			t.Error("the overview carries no data-as-of marker")
		}
	})

	t.Run("health reports the read-only evidence", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/health")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/health: %d", a.status)
		}
		var h Health
		decodeBody(t, a, &h)
		if len(h.Database.Probes) == 0 {
			t.Fatal("health carries no write probes; \"read-only\" is a measured fact " +
				"or it is a claim in a README")
		}
		if h.Database.Writable() {
			t.Error("health reports a writable credential on a store that opened")
		}
	})

	t.Run("proof", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/proof/"+scenario.commit+
			"?repo="+url.QueryEscape(fixtureRepo))
		if a.status != http.StatusOK {
			t.Fatalf("GET the proof: %d: %s", a.status, a.body)
		}
		var p Proof
		decodeBody(t, a, &p)
		if p.Verdict != string(verify.VerdictVerified) {
			t.Fatalf("verdict %q over the wire: %+v", p.Verdict, p.Checks)
		}
		// The material survives the JSON round trip, which is the only form in
		// which a client ever sees it.
		if bad := Contradictions(Rederive(p)); len(bad) != 0 {
			t.Fatalf("the proof as served over HTTP convicts itself: %+v", bad)
		}
		if p.Material.CommitObject == "" || p.Material.CertificatePEM == "" {
			t.Error("the served proof lost its material in transit")
		}
	})

	t.Run("a commit no served repository holds is 404", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/proof/"+strings.Repeat("a", 40))
		if a.status != http.StatusNotFound {
			t.Fatalf("GET a proof for an unknown commit returned %d, want 404", a.status)
		}
	})
}
