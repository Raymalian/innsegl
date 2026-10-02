// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/mirror"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-284 (#460): enrolment, renewal and the client-certificate guard, driven
// through the real openGateway in hosted mode against a real Postgres.
//
// The identity authority here is a test CA issuing certificates of the
// client shape from the CSR's own key and SAN: what MintClientX509SVID's
// contract promises. The real SPIRE mint and its policy are SPI-020..023 in
// internal/spire, against a real SPIRE server; this file proves what the
// gateway does with the answer.

const (
	enTrustDomain = gwIdentityTrustDomain
	enRepo        = "github.com/acme/app"
	enOtherRepo   = "github.com/acme/elsewhere"
	enRefusal     = `{"error":"innsegl core: enrolment refused"}`
)

var enGuardRefusal = `{"error":"` + gateway.ClientRefusalMessage + `"}`

// ---------------------------------------------------------------------------
// The test identity authority.
// ---------------------------------------------------------------------------

type enAuthority struct {
	cert  *x509.Certificate
	key   crypto.Signer
	mints atomic.Int32
	mu    sync.Mutex
	fail  error
}

func newEnAuthority(t *testing.T) *enAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test identity authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &enAuthority{cert: cert, key: key}
}

func (a *enAuthority) TrustDomain() string { return enTrustDomain }

func (a *enAuthority) X509Bundle(context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{a.cert}, nil
}

func (a *enAuthority) MintClientX509SVID(_ context.Context, csrDER []byte, ttl time.Duration) ([]*x509.Certificate, []*x509.Certificate, error) {
	a.mints.Add(1)
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail != nil {
		return nil, nil, fail
	}
	if _, err := spire.CheckClientCSR(csrDER, enTrustDomain); err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	leaf := a.sign(csr.PublicKey, csr.URIs, ttl)
	return []*x509.Certificate{leaf}, []*x509.Certificate{a.cert}, nil
}

func (a *enAuthority) setFail(err error) {
	a.mu.Lock()
	a.fail = err
	a.mu.Unlock()
}

func (a *enAuthority) sign(pub crypto.PublicKey, uris []*url.URL, ttl time.Duration) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ttl),
		URIs: uris, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, pub, a.key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

// ---------------------------------------------------------------------------
// The fixture: a ledger database, register_agent wired, an account with a
// grant, and the authority published the way serve publishes the MCP's own.
// ---------------------------------------------------------------------------

type enFixture struct {
	ownerDSN, authDSN string
	writer            *accounts.Store
	account           string
	ids               *gwIdentityFakeSPIRE
	authority         *enAuthority
}

func newEnFixture(t *testing.T) *enFixture {
	t.Helper()
	ownerDSN, _, authDSN := freshLedgerDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)
	idem := mcp.NewIdempotencyStore(gwIdentityPool(t, ownerDSN))
	ids := newGWIdentityFakeSPIRE()
	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatal(err)
	}
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatal(err)
	}
	restoreReg, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities: ids, Runs: dir, Ledger: store, Idempotency: idem,
		ParentID: gwIdentityParentID, Pseudonyms: literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreReg)
	restoreRet, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{Runs: dir, Entries: ids, Ledger: store})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRet)

	pool := gwIdentityPool(t, ownerDSN)
	if _, serr := pool.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-1', 'Owner')`); serr != nil {
		t.Fatalf("seed user: %v", serr)
	}
	writer, err := accounts.Open(ctx, authDSN)
	if err != nil {
		t.Fatalf("accounts.Open: %v", err)
	}
	t.Cleanup(writer.Close)
	acct, err := writer.CreateAccount(ctx, accounts.CreateAccountParams{Name: "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AddMember(ctx, acct.ID, "u-1", accounts.RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	if err := writer.GrantRepo(ctx, acct.ID, enRepo, "u-1"); err != nil {
		t.Fatal(err)
	}

	auth := newEnAuthority(t)
	t.Cleanup(publishClientAuthority(auth))
	return &enFixture{ownerDSN: ownerDSN, authDSN: authDSN, writer: writer, account: acct.ID, ids: ids, authority: auth}
}

func (f *enFixture) token(t *testing.T, repos ...string) string {
	t.Helper()
	if len(repos) == 0 {
		repos = []string{enRepo}
	}
	tok, _, err := f.writer.CreateEnrolmentToken(t.Context(), accounts.TokenParams{
		AccountID: f.account, CreatedBy: "u-1", Repos: repos})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *enFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := gwIdentityPool(t, f.ownerDSN).QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// enGateway is a hosted-mode gateway and what a test needs to reach it.
type enGateway struct {
	addr     string
	certDir  string
	upstream *atomic.Int32
}

func startHostedGateway(t *testing.T, f *enFixture) *enGateway {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)

	keyDir, certDir := gatewayTestCADirs(t)
	if os.Getenv(mirror.EnvDir) == "" {
		t.Setenv(mirror.EnvDir, filepath.Join(t.TempDir(), "mirror"))
	}
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstream.URL, "-dsn", f.ownerDSN,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
		"-client-auth", clientAuthSPIFFE, "-accounts-dsn", f.authDSN,
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- runGateway(ctx, args, io.Discard, &stderr, deps) }()
	var addr string
	select {
	case addr = <-addrCh:
	case code := <-done:
		t.Fatalf("the hosted gateway did not start: exit %d: %s", code, stderr.String())
	case <-time.After(15 * time.Second):
		t.Fatal("the hosted gateway never announced a bound address")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the hosted gateway did not stop")
		}
	})
	return &enGateway{addr: addr, certDir: certDir, upstream: &hits}
}

// client answers an HTTPS client trusting the gateway, presenting cert when
// it is non-nil.
func (g *enGateway) client(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(g.certDir, gateway.CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (g *enGateway) post(t *testing.T, c *http.Client, path, body string, header map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+g.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// ---------------------------------------------------------------------------
// The client half: a key, a CSR naming the id the client chose.
// ---------------------------------------------------------------------------

type enClient struct {
	id  string
	key *ecdsa.PrivateKey
}

func newEnClient(t *testing.T) *enClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return &enClient{id: hex.EncodeToString(b), key: key}
}

func (c *enClient) csr(t *testing.T, spiffeID string) string {
	t.Helper()
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func (c *enClient) ownCSR(t *testing.T) string {
	return c.csr(t, "spiffe://"+enTrustDomain+"/client/"+c.id)
}

func enrolBody(t *testing.T, token, csr, name string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"token": token, "csr": csr, "name": name})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// enIssued is a 200 answer from enrol or renew, parsed.
type enIssued struct {
	InstallationID string `json:"installation_id"`
	Certificate    string `json:"certificate"`
	Bundle         string `json:"bundle"`
	ExpiresAt      string `json:"expires_at"`
	chain, bundle  []*x509.Certificate
}

func parseIssued(t *testing.T, body string) enIssued {
	t.Helper()
	var out enIssued
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	out.chain = parsePEMCerts(t, out.Certificate)
	out.bundle = parsePEMCerts(t, out.Bundle)
	return out
}

func parsePEMCerts(t *testing.T, s string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatalf("no certificate in %q", s)
	}
	return out
}

func (c *enClient) tlsCert(issued enIssued) *tls.Certificate {
	cert := &tls.Certificate{PrivateKey: c.key, Leaf: issued.chain[0]}
	for _, x := range issued.chain {
		cert.Certificate = append(cert.Certificate, x.Raw)
	}
	return cert
}

// enrol enrols c with a fresh token and answers its client certificate.
func enrol(t *testing.T, f *enFixture, g *enGateway, c *enClient, repos ...string) (enIssued, *tls.Certificate) {
	t.Helper()
	status, body := g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, f.token(t, repos...), c.ownCSR(t), "laptop"), nil)
	if status != http.StatusOK {
		t.Fatalf("enrol: %d %s", status, body)
	}
	issued := parseIssued(t, body)
	return issued, c.tlsCert(issued)
}

// ---------------------------------------------------------------------------
// GW-016: enrolment.
// ---------------------------------------------------------------------------

func TestGW016EnrolIssuesACertificateTheGuardAccepts(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	tok := f.token(t)

	status, body := g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, tok, c.ownCSR(t), "laptop"), nil)
	if status != http.StatusOK {
		t.Fatalf("enrol: %d %s", status, body)
	}
	issued := parseIssued(t, body)
	if issued.InstallationID != c.id {
		t.Fatalf("installation_id = %q, want the id the CSR named, %q", issued.InstallationID, c.id)
	}
	id, err := spire.VerifyClientCertificate(issued.chain, issued.bundle, enTrustDomain, time.Now())
	if err != nil || id != c.id {
		t.Fatalf("VerifyClientCertificate = %q, %v", id, err)
	}
	if pub, ok := issued.chain[0].PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(c.key.Public()) {
		t.Fatal("the certificate does not carry the CSR's key")
	}
	exp, err := time.Parse(time.RFC3339, issued.ExpiresAt)
	if err != nil || time.Until(exp) > spire.ClientCertTTL+time.Minute || exp.Before(time.Now()) {
		t.Fatalf("expires_at = %q (%v)", issued.ExpiresAt, err)
	}
	inst, err := f.writer.GetInstallation(t.Context(), c.id)
	if err != nil || inst.AccountID != f.account || inst.Status != accounts.StatusActive || inst.Name != "laptop" ||
		len(inst.Repos) != 1 || inst.Repos[0] != enRepo {
		t.Fatalf("installation = %+v, %v", inst, err)
	}

	// KEY-001: the token is single use.
	status, body = g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, tok, newEnClient(t).ownCSR(t), "again"), nil)
	if status != http.StatusUnauthorized || body != enRefusal {
		t.Fatalf("second use: %d %s, want 401 %s", status, body, enRefusal)
	}

	// The certificate opens the guarded routes.
	if status, body := g.post(t, g.client(t, c.tlsCert(issued)), gatewaySessionWorkspacePath,
		statement(t, "11111111-1111-4111-8111-111111111111", enRepo), nil); status != http.StatusNoContent {
		t.Fatalf("session-workspace with the enrolled certificate: %d %s", status, body)
	}
}

// KEY-002: every token problem is the one identical 401, and refuses
// before anything is created or minted. A CSR naming anything but a client
// identity is a 400 before the token is touched.
func TestGW016EnrolRefusals(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	cl := g.client(t, nil)

	expired := f.token(t)
	parts := strings.Split(expired, "_")
	if _, err := gwIdentityPool(t, f.ownerDSN).Exec(t.Context(),
		`UPDATE innsegl_auth.enrolment_tokens SET expires_at = now() - interval '1 second' WHERE token_id = $1`, parts[1]); err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "_" + parts[1] + "_" + strings.Repeat("0", len(parts[2]))
	for name, tok := range map[string]string{
		"expired": expired, "forged": forged, "malformed": "nonsense", "empty": "",
		"unknown": "ie_0000000000000000_" + strings.Repeat("a", 64),
	} {
		status, body := g.post(t, cl, coreEnrolPath, enrolBody(t, tok, c.ownCSR(t), "x"), nil)
		if status != http.StatusUnauthorized || body != enRefusal {
			t.Errorf("%s token: %d %s, want 401 %s", name, status, body, enRefusal)
		}
	}

	good := f.token(t)
	for name, csr := range map[string]string{
		"an agent path":        c.csr(t, "spiffe://"+enTrustDomain+"/agent/a/b/run-1"),
		"another trust domain": c.csr(t, "spiffe://example.org/client/"+c.id),
		"not base64":           "%%%",
		"not a CSR":            base64.StdEncoding.EncodeToString([]byte("nope")),
	} {
		status, body := g.post(t, cl, coreEnrolPath, enrolBody(t, good, csr, "x"), nil)
		if status != http.StatusBadRequest {
			t.Errorf("CSR naming %s: %d %s, want 400", name, status, body)
		}
	}
	if status, _ := g.post(t, cl, coreEnrolPath, `{"token":`, nil); status != http.StatusBadRequest {
		t.Errorf("malformed JSON: %d, want 400", status)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.installations`); n != 0 {
		t.Fatalf("installations after refusals = %d, want 0", n)
	}
	if n := f.authority.mints.Load(); n != 0 {
		t.Fatalf("the authority minted %d times for refused enrolments", n)
	}
	// None of that spent the good token.
	if status, body := g.post(t, cl, coreEnrolPath, enrolBody(t, good, c.ownCSR(t), "x"), nil); status != http.StatusOK {
		t.Fatalf("the good token after refused CSRs: %d %s, want 200", status, body)
	}

	// The trust domain a client needs to write its CSR is readable without
	// a certificate.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+g.addr+coreEnrolPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var td struct {
		TrustDomain string `json:"trust_domain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil || td.TrustDomain != enTrustDomain {
		t.Fatalf("GET %s = %+v, %v", coreEnrolPath, td, err)
	}
}

// KEY-003: a failed mint leaves the token unspent and nothing created.
func TestKEY003AFailedMintBurnsNothing(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	tok := f.token(t)

	f.authority.setFail(errors.New("authority down"))
	status, body := g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, tok, c.ownCSR(t), "laptop"), nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("enrol with the authority down: %d %s, want 503", status, body)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.installations`); n != 0 {
		t.Fatalf("installations after a failed mint = %d, want 0", n)
	}
	f.authority.setFail(nil)
	status, body = g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, tok, c.ownCSR(t), "laptop"), nil)
	if status != http.StatusOK {
		t.Fatalf("the same token after the authority recovered: %d %s, want 200", status, body)
	}
}

// ---------------------------------------------------------------------------
// GW-017: renewal.
// ---------------------------------------------------------------------------

func TestGW017RenewOverTheCurrentCertificate(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	first, cert := enrol(t, f, g, c)

	renewBody := func(csr string) string {
		b, err := json.Marshal(map[string]string{"csr": csr})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	status, body := g.post(t, g.client(t, cert), coreRenewPath, renewBody(c.ownCSR(t)), nil)
	if status != http.StatusOK {
		t.Fatalf("renew: %d %s", status, body)
	}
	renewed := parseIssued(t, body)
	if renewed.InstallationID != c.id || renewed.chain[0].SerialNumber.Cmp(first.chain[0].SerialNumber) == 0 {
		t.Fatalf("renewed %s serial %v, first serial %v", renewed.InstallationID, renewed.chain[0].SerialNumber, first.chain[0].SerialNumber)
	}
	if inst, err := f.writer.GetInstallation(t.Context(), c.id); err != nil || inst.LastRenewedAt == nil {
		t.Fatalf("last_renewed_at not stamped: %+v, %v", inst, err)
	}

	// No certificate: the one refusal.
	if status, body := g.post(t, g.client(t, nil), coreRenewPath, renewBody(c.ownCSR(t)), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("renew without a certificate: %d %s", status, body)
	}
	// A CSR naming another installation.
	other := newEnClient(t)
	if status, body := g.post(t, g.client(t, cert), coreRenewPath, renewBody(other.ownCSR(t)), nil); status != http.StatusUnauthorized {
		t.Fatalf("renew naming another installation: %d %s, want 401", status, body)
	}
	// KEY-005: revoked.
	if err := f.writer.SetInstallationStatus(t.Context(), c.id, accounts.StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
	}
	mints := f.authority.mints.Load()
	if status, body := g.post(t, g.client(t, c.tlsCert(renewed)), coreRenewPath, renewBody(c.ownCSR(t)), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("renew a revoked installation: %d %s", status, body)
	}
	if f.authority.mints.Load() != mints {
		t.Fatal("the authority minted for a revoked installation")
	}
}

// ---------------------------------------------------------------------------
// GW-018 / GW-019: the guard on every client-facing route.
// ---------------------------------------------------------------------------

func statement(t *testing.T, session, repo string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"session_id": session, "cwd": "/client/repo", "repo": repo, "branch": "main", "task": "task-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func messageHeaders(session string) map[string]string {
	return map[string]string{"X-Claude-Code-Session-Id": session, "Content-Type": "application/json"}
}

const enMessage = `{"messages":[{"role":"user","content":"hello"}]}`

func TestGW018HostedGuardOnEveryRoute(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	a := newEnClient(t)
	_, certA := enrol(t, f, g, a)
	b := newEnClient(t)
	_, certB := enrol(t, f, g, b)
	anon := g.client(t, nil)
	clA, clB := g.client(t, certA), g.client(t, certB)
	const session = "22222222-2222-4222-8222-222222222222"

	// No certificate: every route is the one 401, and nothing is forwarded
	// or recorded (KEY-004).
	for _, path := range []string{"/v1/messages", gatewaySessionWorkspacePath, gatewaySessionEndPath, "/v1/logs", coreRenewPath} {
		status, body := g.post(t, anon, path, enMessage, messageHeaders(session))
		if status != http.StatusUnauthorized || body != enGuardRefusal {
			t.Errorf("%s without a certificate: %d %s", path, status, body)
		}
	}
	if g.upstream.Load() != 0 {
		t.Fatalf("the upstream saw %d requests from unauthenticated callers", g.upstream.Load())
	}

	// Out of scope (A's explicit repos list leaves it out): the statement is
	// refused and no run is registered.
	if status, body := g.post(t, clA, gatewaySessionWorkspacePath, statement(t, session, enOtherRepo), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("out-of-scope statement: %d %s", status, body)
	}
	// A repository-less statement is a session outside any repository: it
	// is accepted, and its model requests pass through unrecorded
	// (ADR-0063, amended 2026-10-02).
	const homeSession = "44444444-4444-4444-8444-444444444444"
	before := f.ids.entryCount()
	if status, body := g.post(t, clA, gatewaySessionWorkspacePath,
		`{"session_id":"`+homeSession+`","cwd":"/client/home"}`, nil); status != http.StatusNoContent {
		t.Fatalf("directory-only statement: %d %s, want 204", status, body)
	}
	if status, body := g.post(t, clA, "/v1/messages", enMessage, messageHeaders(homeSession)); status != http.StatusOK {
		t.Fatalf("message outside any repository: %d %s, want it forwarded", status, body)
	}
	if g.upstream.Load() != 1 {
		t.Fatalf("upstream saw %d requests, want the pass-through one", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, homeSession); n != 0 ||
		f.ids.entryCount() != before {
		t.Fatalf("a session outside any repository was recorded: %d mapping rows", n)
	}
	g.upstream.Store(0)

	// RM-313: nothing the core cannot record is a 503 loop. A session whose
	// statement was refused for scope, and one never stated at all, are
	// forwarded unrecorded.
	const outSession, unstatedSession = "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"
	if status, body := g.post(t, clA, gatewaySessionWorkspacePath, statement(t, outSession, enOtherRepo), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("out-of-scope statement: %d %s, want the refusal the hook surfaces", status, body)
	}
	for _, s := range []string{outSession, unstatedSession} {
		if status, body := g.post(t, clA, "/v1/messages", enMessage, messageHeaders(s)); status != http.StatusOK {
			t.Fatalf("session %s: %d %s, want it forwarded unrecorded", s, status, body)
		}
	}
	// The statement on the request, as the client service attaches it: a
	// core whose registry is empty (a restart) records the run from it, and
	// a header naming a repository out of scope is forwarded unrecorded.
	const headerSession, headerOutSession = "88888888-8888-4888-8888-888888888888", "99999999-9999-4999-8999-999999999999"
	for s, repo := range map[string]string{headerSession: enRepo, headerOutSession: enOtherRepo} {
		h := messageHeaders(s)
		h[gateway.StatementHeader] = base64.RawURLEncoding.EncodeToString([]byte(statement(t, s, repo)))
		if status, body := g.post(t, clA, "/v1/messages", enMessage, h); status != http.StatusOK {
			t.Fatalf("session %s with a header statement for %s: %d %s, want it forwarded", s, repo, status, body)
		}
	}
	if g.upstream.Load() != 4 {
		t.Fatalf("upstream saw %d requests, want 4", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND client_id = $2`, headerSession, a.id); n != 1 {
		t.Fatalf("mapping rows for the header-stated session = %d, want 1", n)
	}
	for _, s := range []string{outSession, unstatedSession, headerOutSession} {
		if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, s); n != 0 {
			t.Fatalf("session %s has %d mapping rows, want none", s, n)
		}
	}
	g.upstream.Store(0)

	// In scope: stated, then forwarded, and the mapping row names A (GW-019).
	if status, body := g.post(t, clA, gatewaySessionWorkspacePath, statement(t, session, enRepo), nil); status != http.StatusNoContent {
		t.Fatalf("in-scope statement: %d %s", status, body)
	}
	if status, body := g.post(t, clA, "/v1/messages", enMessage, messageHeaders(session)); status != http.StatusOK {
		t.Fatalf("message with a valid certificate: %d %s", status, body)
	}
	if g.upstream.Load() != 1 {
		t.Fatalf("upstream saw %d requests, want 1", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND client_id = $2`, session, a.id); n != 1 {
		t.Fatalf("mapping rows naming installation A = %d, want 1 (GW-019)", n)
	}

	// Pinned: B may neither state nor use A's session.
	if status, body := g.post(t, clB, gatewaySessionWorkspacePath, statement(t, session, enRepo), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("B stating A's session: %d %s", status, body)
	}
	if status, body := g.post(t, clB, "/v1/messages", enMessage, messageHeaders(session)); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("B using A's session: %d %s", status, body)
	}
	if status, _ := g.post(t, clB, gatewaySessionEndPath, `{"session_id":"`+session+`"}`, nil); status != http.StatusUnauthorized {
		t.Fatalf("B ending A's session: %d, want 401", status)
	}
	if g.upstream.Load() != 1 {
		t.Fatalf("upstream saw %d requests after refusals, want 1", g.upstream.Load())
	}

	// Revoked: A's certificate stops working at once.
	entries := f.ids.entryCount()
	if err := f.writer.SetInstallationStatus(t.Context(), a.id, accounts.StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
	}
	if status, body := g.post(t, clA, "/v1/messages", enMessage, messageHeaders(session)); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("revoked installation: %d %s", status, body)
	}
	// ...outside a repository too: pass-through is not a way around it.
	if status, body := g.post(t, clA, gatewaySessionWorkspacePath,
		`{"session_id":"`+homeSession+`","cwd":"/client/home"}`, nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("revoked installation, directory-only statement: %d %s", status, body)
	}
	if status, body := g.post(t, clA, "/v1/messages", enMessage, messageHeaders(homeSession)); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("revoked installation outside any repository: %d %s", status, body)
	}
	if g.upstream.Load() != 1 || f.ids.entryCount() != entries {
		t.Fatal("a revoked installation's request reached the upstream or registered a run")
	}
}

// ---------------------------------------------------------------------------
// Configuration, and MCP-096.
// ---------------------------------------------------------------------------

func TestHostedModeConfiguration(t *testing.T) {
	base := []string{"-ca-key-dir", "/k", "-ca-cert-dir", "/c"}
	for name, extra := range map[string][]string{
		"an unknown mode":    {"-client-auth", "mtls", "-dsn", "postgres://x", "-accounts-dsn", "postgres://y"},
		"no accounts writer": {"-client-auth", clientAuthSPIFFE, "-dsn", "postgres://x"},
		"no ledger database": {"-client-auth", clientAuthSPIFFE, "-accounts-dsn", "postgres://y"},
	} {
		t.Setenv(mirror.EnvDir, "/mirror")
		t.Setenv(envLedgerDSN, "")
		t.Setenv(envGatewayAccountsDSN, "")
		t.Setenv(envGatewayClientAuth, "")
		var stderr bytes.Buffer
		if _, code, ok := parseGatewayFlags(append(append([]string{}, base...), extra...), &stderr); ok || code != exitUsage {
			t.Errorf("%s: parsed ok=%v code=%d, want a usage error", name, ok, code)
		}
	}
	t.Setenv(envGatewayClientAuth, clientAuthSPIFFE)
	t.Setenv(envLedgerDSN, "postgres://x")
	t.Setenv(envGatewayAccountsDSN, "postgres://y")
	t.Setenv(mirror.EnvDir, "/mirror")
	o, _, ok := parseGatewayFlags(base, io.Discard)
	if !ok || o.clientAuth != clientAuthSPIFFE || o.accountsDSN != "postgres://y" {
		t.Fatalf("hosted mode from the environment: %+v ok=%v", o, ok)
	}
	// The mirror is where a hosted client's commits are read from before they
	// are signed, and it is evidence (ADR-0065): hosted mode needs it.
	t.Setenv(mirror.EnvDir, "")
	if _, code, ok := parseGatewayFlags(base, io.Discard); ok || code != exitUsage {
		t.Errorf("hosted mode with no mirror: ok=%v code=%d, want a usage error", ok, code)
	}
}

// MCP-096: the gateway mints only through the MCP's own admin client,
// published by serve; it opens no admin identity of its own, and hosted mode
// refuses to start without one.
func TestMCP096TheMCPsAdminIdentityIsTheOnlyMinter(t *testing.T) {
	t.Cleanup(publishClientAuthority(nil))
	keyDir, certDir := gatewayTestCADirs(t)
	o := gatewayOptions{
		listen: "127.0.0.1:0", upstream: "https://example.invalid", rateLimitRate: 1, rateLimitBurst: 1,
		backstopInterval: time.Minute, caKeyDir: keyDir, caCertDir: certDir, agentMessageKeyID: defaultAgentMessageKeyID,
		clientAuth: clientAuthSPIFFE, dsn: "postgres://unused", accountsDSN: "postgres://unused",
	}
	if srv, err := openGateway(t.Context(), o, newServeLog(io.Discard)); err == nil {
		srv.Close()
		t.Fatal("hosted mode started with no published authority")
	} else if !strings.Contains(err.Error(), "admin") {
		t.Fatalf("refusal %q does not say the MCP's admin client is missing", err)
	}

	for _, file := range []string{"gateway.go", "enrol.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"spire.Dial(", "dialSPIREAdmin(", "workloadapi."} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("%s calls %s: the gateway must not open an admin identity of its own", file, forbidden)
			}
		}
	}
	src, err := os.ReadFile("servewiring.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "publishClientAuthority(admin)") {
		t.Error("servewiring.go does not publish the MCP's own admin client to the gateway")
	}
}
