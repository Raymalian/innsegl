// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

const (
	cgTrustDomain = "innsegl.dev"
	cgInstA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cgInstB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// cgCA is a stand-in for the deployment's identity authority: it issues
// certificates of the client shape (one URI SAN, client-auth EKU), so the
// guard's verification is spire.VerifyClientCertificate run for real.
type cgCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newCGCA(t *testing.T) *cgCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &cgCA{cert: cert, key: key}
}

func (ca *cgCA) issue(t *testing.T, spiffeID string) []*x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert}
}

type cgBundle struct {
	roots []*x509.Certificate
	err   error
	calls atomic.Int32
}

func (b *cgBundle) X509Bundle(context.Context) ([]*x509.Certificate, error) {
	b.calls.Add(1)
	return b.roots, b.err
}

type cgInstallations struct {
	mu     sync.Mutex
	active map[string]bool
	scope  map[string]bool // installation + " " + repo
	err    error
}

func (c *cgInstallations) InstallationActive(_ context.Context, id string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active[id], c.err
}

func (c *cgInstallations) InScope(_ context.Context, id, repo string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scope[id+" "+repo], c.err
}

type cgFixture struct {
	ca     *cgCA
	bundle *cgBundle
	inst   *cgInstallations
	guard  *ClientGuard
}

func newCGFixture(t *testing.T, burst int) *cgFixture {
	t.Helper()
	ca := newCGCA(t)
	f := &cgFixture{
		ca:     ca,
		bundle: &cgBundle{roots: []*x509.Certificate{ca.cert}},
		inst:   &cgInstallations{active: map[string]bool{cgInstA: true, cgInstB: true}, scope: map[string]bool{}},
	}
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 1, Burst: burst})
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewClientGuard(ClientGuardConfig{
		TrustDomain:   cgTrustDomain,
		Bundle:        f.bundle,
		Installations: f.inst,
		RateLimit:     lim,
	})
	if err != nil {
		t.Fatalf("NewClientGuard: %v", err)
	}
	f.guard = g
	return f
}

func cgRequest(chain []*x509.Certificate) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader("{}"))
	if chain != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: chain}
	}
	return r
}

// serve runs r through the guard in front of a handler that records what it
// saw, and answers the response and whether the handler ran.
func (f *cgFixture) serve(r *http.Request) (*httptest.ResponseRecorder, string, bool) {
	var seen string
	var ran bool
	h := f.guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		seen, _ = InstallationFromContext(r.Context())
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, seen, ran
}

func clientID(id string) string { return "spiffe://" + cgTrustDomain + "/client/" + id }

// GW-018: with a certificate for an active installation, the request goes on
// and carries the installation; KEY-002: every certificate or installation
// problem is the one identical 401, and nothing behind the guard runs.
func TestGW018ClientGuardAdmitsOnlyAValidCertificateOfAnActiveInstallation(t *testing.T) {
	f := newCGFixture(t, 100)

	rec, seen, ran := f.serve(cgRequest(f.ca.issue(t, clientID(cgInstA))))
	if !ran || seen != cgInstA || rec.Code != http.StatusTeapot {
		t.Fatalf("valid certificate: ran=%v installation=%q status=%d", ran, seen, rec.Code)
	}

	other := newCGCA(t)
	f.inst.active[cgInstB] = false
	cases := map[string]*http.Request{
		"no certificate":           cgRequest(nil),
		"another authority":        cgRequest(other.issue(t, clientID(cgInstA))),
		"an agent run's identity":  cgRequest(f.ca.issue(t, "spiffe://"+cgTrustDomain+"/agent/a/b/run-1")),
		"another trust domain":     cgRequest(f.ca.issue(t, "spiffe://example.org/client/"+cgInstA)),
		"a revoked installation":   cgRequest(f.ca.issue(t, clientID(cgInstB))),
		"an unknown installation":  cgRequest(f.ca.issue(t, clientID(strings.Repeat("c", 32)))),
		"TLS without certificates": {Method: http.MethodPost, URL: &url.URL{Path: "/"}, TLS: &tls.ConnectionState{}, Header: http.Header{}},
	}
	var first string
	for name, r := range cases {
		rec, _, ran := f.serve(r)
		if ran {
			t.Errorf("%s: the handler behind the guard ran", name)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		body, err := io.ReadAll(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = string(body)
		}
		if string(body) != first {
			t.Errorf("%s: body %q differs from %q: one refusal shape", name, body, first)
		}
	}
	if want := `{"error":"` + ClientRefusalMessage + `"}`; first != want {
		t.Errorf("refusal body = %q, want %q", first, want)
	}
}

// A dependency outage is not a certificate problem: 503 with Retry-After, and
// still nothing behind the guard runs.
func TestClientGuardAnswersAnOutageWithARetry(t *testing.T) {
	f := newCGFixture(t, 100)
	chain := f.ca.issue(t, clientID(cgInstA))

	f.inst.err = errors.New("database down")
	rec, _, ran := f.serve(cgRequest(chain))
	if ran || rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("installation read failing: ran=%v status=%d retry=%q", ran, rec.Code, rec.Header().Get("Retry-After"))
	}

	f2 := newCGFixture(t, 100)
	f2.bundle.err = errors.New("authority down")
	rec, _, ran = f2.serve(cgRequest(f2.ca.issue(t, clientID(cgInstA))))
	if ran || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("bundle read failing: ran=%v status=%d", ran, rec.Code)
	}
}

// The bundle is read once and cached, not once per request.
func TestClientGuardCachesTheBundle(t *testing.T) {
	f := newCGFixture(t, 100)
	chain := f.ca.issue(t, clientID(cgInstA))
	for i := 0; i < 5; i++ {
		if _, _, ran := f.serve(cgRequest(chain)); !ran {
			t.Fatalf("request %d refused", i)
		}
	}
	if n := f.bundle.calls.Load(); n != 1 {
		t.Fatalf("bundle read %d times for five requests, want 1", n)
	}
	if pool := f.guard.ClientCAs(t.Context()); pool == nil {
		t.Fatal("ClientCAs answered no pool with a bundle cached")
	}
}

// KEY-006: the rate limit is per installation. One installation over its
// budget is refused 429; another is not affected.
func TestKEY006RateLimitIsPerInstallation(t *testing.T) {
	f := newCGFixture(t, 2)
	a := f.ca.issue(t, clientID(cgInstA))
	b := f.ca.issue(t, clientID(cgInstB))
	for i := 0; i < 2; i++ {
		if _, _, ran := f.serve(cgRequest(a)); !ran {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	rec, _, ran := f.serve(cgRequest(a))
	if ran || rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the burst: ran=%v status=%d retry=%q", ran, rec.Code, rec.Header().Get("Retry-After"))
	}
	if _, _, ran := f.serve(cgRequest(b)); !ran {
		t.Fatal("another installation was refused by the first one's limit")
	}
}

func TestNewClientGuardRefusesAnIncompleteConfiguration(t *testing.T) {
	f := newCGFixture(t, 1)
	lim, err := NewSessionRateLimiter(SessionRateLimit{Rate: 1, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]ClientGuardConfig{
		"no trust domain":  {Bundle: f.bundle, Installations: f.inst, RateLimit: lim},
		"no bundle":        {TrustDomain: cgTrustDomain, Installations: f.inst, RateLimit: lim},
		"no installations": {TrustDomain: cgTrustDomain, Bundle: f.bundle, RateLimit: lim},
		"no rate limit":    {TrustDomain: cgTrustDomain, Bundle: f.bundle, Installations: f.inst},
	} {
		if _, err := NewClientGuard(cfg); err == nil {
			t.Errorf("%s: NewClientGuard accepted it", name)
		}
	}
}

// GW-018, pinning: a session belongs to the first installation that used it.
func TestGW018SessionPinsToTheFirstInstallation(t *testing.T) {
	p := NewSessionPins(2)
	if !p.Pin("s1", cgInstA) {
		t.Fatal("the first installation was refused a fresh session")
	}
	if !p.Pin("s1", cgInstA) {
		t.Fatal("the first installation was refused its own session")
	}
	if p.Pin("s1", cgInstB) {
		t.Fatal("a second installation took a pinned session")
	}
	if p.Pin("", cgInstA) || p.Pin("s2", "") {
		t.Fatal("an empty session or installation was pinned")
	}
	if !p.Pin("s2", cgInstB) || !p.Pin("s3", cgInstB) {
		t.Fatal("fresh sessions refused")
	}
	// Bounded: the oldest pin is forgotten, never the newest.
	if !p.Pin("s3", cgInstB) || p.Pin("s3", cgInstA) {
		t.Fatal("the newest pin was not kept")
	}
}

// The identity guard, in hosted mode, refuses a session pinned to another
// installation, refuses to register a run outside the installation's scope,
// and registers one inside it -- with 401, the client refusal, for both
// refusals, and nothing registered.
func TestGW018IdentityGuardEnforcesPinAndScope(t *testing.T) {
	f := newIdentityFixture(t)
	inst := &cgInstallations{active: map[string]bool{cgInstA: true}, scope: map[string]bool{cgInstA + " github.com/acme/app": true}}
	pins := NewSessionPins(0)
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: f.mappings, Tree: f.tree, Policy: NewPolicy(), Registrar: f.registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
		Pins: pins, Scope: inst,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.sessionWorkspaces.RecordStated("s9", "", StatedWorkspace{Cwd: "/w", Repo: "github.com/acme/app", Branch: "main", Task: "t1"})
	f.sessionWorkspaces.RecordStated("s8", "", StatedWorkspace{Cwd: "/w", Repo: "github.com/acme/other", Branch: "main", Task: "t1"})

	withInst := func(r *http.Request, inst string) *http.Request {
		return r.WithContext(WithInstallation(r.Context(), inst))
	}
	main9 := Identification{SessionID: "s9", AgentID: mainAgentID}

	// No installation on the request in hosted mode: refused.
	if _, ref := g.Check(identityRequest(t, main9, "hi", "")); ref == nil || ref.Status != http.StatusUnauthorized {
		t.Fatalf("no installation: refusal %+v, want 401", ref)
	}
	// In scope: registered.
	if _, ref := g.Check(withInst(identityRequest(t, main9, "hi", ""), cgInstA)); ref != nil {
		t.Fatalf("in scope: refused %+v", ref)
	}
	registered := len(f.registrar.calls)
	// Another installation using the same session: refused.
	if _, ref := g.Check(withInst(identityRequest(t, main9, "hi", ""), cgInstB)); ref == nil ||
		ref.Status != http.StatusUnauthorized || ref.Reason != ClientRefusalMessage {
		t.Fatalf("second installation: refusal %+v, want the 401 client refusal", ref)
	}
	// Out of scope: refused and nothing registered.
	main8 := Identification{SessionID: "s8", AgentID: mainAgentID}
	if _, ref := g.Check(withInst(identityRequest(t, main8, "hi", ""), cgInstA)); ref == nil ||
		ref.Status != http.StatusUnauthorized || ref.Reason != ClientRefusalMessage {
		t.Fatalf("out of scope: refusal %+v, want the 401 client refusal", ref)
	}
	if len(f.registrar.calls) != registered {
		t.Fatalf("registrar calls %v after refusals, want %d", f.registrar.calls, registered)
	}
	// A directory-only statement is not enough in hosted mode: the core never
	// reads a client's files.
	f.sessionWorkspaces.Record("s7", "", "/w")
	main7 := Identification{SessionID: "s7", AgentID: mainAgentID}
	if _, ref := g.Check(withInst(identityRequest(t, main7, "hi", ""), cgInstA)); ref == nil || ref.Status != http.StatusUnauthorized {
		t.Fatalf("directory-only statement in hosted mode: refusal %+v, want 401", ref)
	}
}

// RM-308 (#488): the pin outlives a core restart. The run mapping records the
// installation each run was made under; a fresh core (empty in-memory pins)
// refuses another installation for that session -- for the main agent and
// for a new subagent alike -- and the installation that owns it is not
// locked out by the attempt.
func TestGW018APinSurvivesARestartThroughTheRunMapping(t *testing.T) {
	f := newIdentityFixture(t)
	inst := &cgInstallations{
		active: map[string]bool{cgInstA: true, cgInstB: true},
		scope:  map[string]bool{cgInstA + " github.com/acme/app": true, cgInstB + " github.com/acme/app": true},
	}
	// What a previous core process left: session s9's main run, made under A.
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-a", SessionID: "s9", AgentID: mainAgentID, Fingerprint: "fp-1", ClientID: cgInstA,
	}); err != nil {
		t.Fatal(err)
	}
	f.runStates.set("run-a", ledger.RunActive)
	f.sessionWorkspaces.RecordStated("s9", "", StatedWorkspace{Cwd: "/w", Repo: "github.com/acme/app", Branch: "main", Task: "t1"})

	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: f.mappings, Tree: f.tree, Policy: NewPolicy(), Registrar: f.registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
		Pins: NewSessionPins(0), Scope: inst, // a fresh process: no pins in memory
	})
	if err != nil {
		t.Fatal(err)
	}
	as := func(id Identification, installation string) *Refusal {
		r := identityRequest(t, id, "hello", "hi")
		_, ref := g.Check(r.WithContext(WithInstallation(r.Context(), installation)))
		return ref
	}
	main9 := Identification{SessionID: "s9", AgentID: mainAgentID}
	sub9 := Identification{SessionID: "s9", AgentID: "a0123456789abcdef"}

	if ref := as(main9, cgInstB); ref == nil || ref.Status != http.StatusUnauthorized {
		t.Fatalf("B on A's session after a restart: refusal %+v, want 401", ref)
	}
	if ref := as(sub9, cgInstB); ref == nil || ref.Status != http.StatusUnauthorized {
		t.Fatalf("B's subagent on A's session after a restart: refusal %+v, want 401", ref)
	}
	if ref := as(main9, cgInstA); ref != nil {
		t.Fatalf("A on its own session after B's attempts: refused %+v", ref)
	}
}
