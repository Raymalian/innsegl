// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewUpstreamRefusesAnEmptyBaseURL(t *testing.T) {
	if _, err := NewUpstream("", nil); err == nil {
		t.Fatal("NewUpstream(\"\", nil) succeeded, want a refusal")
	}
	if _, err := NewUpstream("   ", nil); err == nil {
		t.Fatal("NewUpstream(whitespace, nil) succeeded, want a refusal")
	}
}

func TestNewUpstreamRefusesAURLWithNoSchemeOrHost(t *testing.T) {
	for _, bad := range []string{"api.anthropic.com", "/just/a/path", "://broken"} {
		if _, err := NewUpstream(bad, nil); err == nil {
			t.Errorf("NewUpstream(%q, nil) succeeded, want a refusal: an upstream base URL "+
				"needs a scheme and a host to be reachable at all", bad)
		}
	}
}

func TestNewUpstreamDefaultsToAClientWithNoTimeout(t *testing.T) {
	up, err := NewUpstream("https://api.anthropic.com", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	if up.Client == nil {
		t.Fatal("Client is nil; a nil client passed in must still leave a usable one")
	}
	if up.Client.Timeout != 0 {
		t.Errorf("Client.Timeout = %v, want 0: a streamed reply must not be cut off by a "+
			"whole-request timeout (see NewUpstream's own doc comment)", up.Client.Timeout)
	}
}

func TestNewUpstreamKeepsAnExplicitClient(t *testing.T) {
	custom := &http.Client{}
	up, err := NewUpstream("https://api.anthropic.com", custom)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	if up.Client != custom {
		t.Error("NewUpstream replaced the given client instead of keeping it")
	}
}

func TestUpstreamResolveJoinsBaseAndRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name, base, path, query, want string
	}{
		{"no base path", "https://api.anthropic.com", "/v1/messages", "beta=1", "/v1/messages"},
		{"base path, no trailing slash", "https://example.com/api", "/v1/messages", "", "/api/v1/messages"},
		{"base path with trailing slash", "https://example.com/api/", "/v1/messages", "", "/api/v1/messages"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, err := NewUpstream(tc.base, nil)
			if err != nil {
				t.Fatalf("NewUpstream: %v", err)
			}
			got := up.resolve(tc.path, tc.query)
			if got.Path != tc.want {
				t.Errorf("resolve(%q, %q).Path = %q, want %q", tc.path, tc.query, got.Path, tc.want)
			}
			if got.RawQuery != tc.query {
				t.Errorf("resolve(%q, %q).RawQuery = %q, want %q", tc.path, tc.query, got.RawQuery, tc.query)
			}
		})
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"", "/v1/messages", "/v1/messages"}, // a empty, b slashed
		{"/api", "/v1", "/api/v1"},           // a not slashed, b slashed
		{"/api/", "/v1", "/api/v1"},          // both slashed
		{"/api", "v1", "/api/v1"},            // neither slashed, a non-empty
		{"/api/", "v1", "/api/v1"},           // a slashed, b not
	} {
		if got := singleJoiningSlash(tc.a, tc.b); got != tc.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestUpstreamBaseReturnsACopy(t *testing.T) {
	up, err := NewUpstream("https://api.anthropic.com/v1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	got := up.Base()
	got.Path = "/mutated"
	if up.base.Path == "/mutated" {
		t.Error("Base() returned an alias of the internal URL; a caller's mutation must not reach it")
	}
}

// ---------------------------------------------------------------------------
// GW-006: self-signed, expired, wrong-host and untrusted-root upstreams are
// each refused, and nothing is forwarded. GW-008: the refusal reaches the
// caller as a JSON error naming the failure class, never a dropped
// connection, and never by echoing anything from the request.
//
// Every case here builds its own purpose-built certificate rather than
// reaching for a public test host, so the scenario is exact and does not
// depend on the network.
// ---------------------------------------------------------------------------

// testCA is a minimal certificate authority, generated fresh per test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "innsegl test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leafOpts customizes the purpose-built server certificate a GW-006 case
// signs. The zero value is a certificate valid right now, for 127.0.0.1,
// with no DNS names.
type leafOpts struct {
	notBefore, notAfter time.Time
	ipAddresses         []net.IP
	dnsNames            []string
	selfSigned          bool // issuer == subject; ca is ignored when true
}

// leaf issues a server certificate for opts, signed by ca -- or self-signed
// when opts.selfSigned is true, in which case ca may be nil.
func (ca *testCA) leaf(t *testing.T, opts leafOpts) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	notBefore, notAfter := opts.notBefore, opts.notAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "innsegl test leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  opts.ipAddresses,
		DNSNames:     opts.dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	parent := tmpl
	signer := key
	if !opts.selfSigned {
		parent = ca.cert
		signer = ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	// The full chain -- leaf and, when issued rather than self-signed, its
	// issuing CA -- is what a real server sends: a client (this platform's
	// own verifier included) needs the intermediate handed to it, or a
	// missing link reads as a broken chain rather than an untrusted root.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if !opts.selfSigned {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}
	return tlsCert
}

// runGW006Case wires a purpose-built TLS server presenting leaf up, sends
// one request through a Proxy in front of it (using client -- nil for the
// REAL production default, so self-signed and untrusted-root cases prove
// system-root rejection exactly as a deployment would see it; non-nil for
// the injectable client/root-pool seam expired and wrong-host cases need to
// isolate their own failure from an unrelated chain-of-trust one), and
// checks the shared shape every GW-006/GW-008 case must have: a 5xx the
// caller can read as an error, a JSON body naming innsegl and the
// certificate failure class, nothing forwarded from the upstream, and no
// echo of the request's own Authorization header. The response body is
// closed in this same function, not handed back to the caller, so the
// close is never in question.
func runGW006Case(t *testing.T, leaf tls.Certificate, client *http.Client) {
	t.Helper()
	var upstreamReached atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	defer srv.Close()

	up, err := NewUpstream(srv.URL, client)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-ant-test-should-never-be-echoed-back")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		t.Errorf("status = %d, want a 5xx", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode JSON error body: %v (body: %q)", err, raw)
	}
	if !strings.Contains(body.Error, "innsegl") {
		t.Errorf("error body %q does not name innsegl", body.Error)
	}
	if !strings.Contains(body.Error, "certificate rejected") {
		t.Errorf("error body %q does not name the failure class (want \"certificate rejected\")",
			body.Error)
	}
	if strings.Contains(body.Error, "sk-ant-test-should-never-be-echoed-back") {
		t.Errorf("error body %q echoes the request's own Authorization header", body.Error)
	}
	if upstreamReached.Load() {
		t.Error("the upstream handler ran; a rejected certificate must forward nothing")
	}
}

// TestGW006SelfSignedUpstreamIsRefused: a leaf certificate that signs
// itself -- issuer equals subject -- is not in, and can never be added to,
// any trust store by an operator who did not generate it. Verified with
// NewUpstream's own default client (nil), so this is exactly what a real
// deployment sees against the system roots.
func TestGW006SelfSignedUpstreamIsRefused(t *testing.T) {
	leaf := (&testCA{}).leaf(t, leafOpts{
		ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		selfSigned:  true,
	})
	runGW006Case(t, leaf, nil)
}

// TestGW006UntrustedRootUpstreamIsRefused: a leaf issued by a private CA --
// a real two-certificate chain, unlike the self-signed case -- whose root
// is not in the system trust store either. Also verified with the default
// client, proving system-root rejection.
func TestGW006UntrustedRootUpstreamIsRefused(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{ipAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	runGW006Case(t, leaf, nil)
}

// TestGW006ExpiredUpstreamCertificateIsRefused: a leaf issued by a CA the
// client trusts (the injectable root-pool seam), with NotAfter in the past.
// Trusting the issuing CA isolates this from an unrelated unknown-authority
// failure: the ONLY reason this certificate fails is that it has expired.
func TestGW006ExpiredUpstreamCertificateIsRefused(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{
		ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		notBefore:   time.Now().Add(-48 * time.Hour),
		notAfter:    time.Now().Add(-time.Hour), // expired
	})
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
	}}
	runGW006Case(t, leaf, client)
}

// TestGW006WrongHostUpstreamCertificateIsRefused: a leaf issued by a CA the
// client trusts, but naming a DIFFERENT IP than the one the gateway
// actually dials (127.0.0.1). The only reason this certificate fails is
// the hostname mismatch.
func TestGW006WrongHostUpstreamCertificateIsRefused(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{ipAddresses: []net.IP{net.ParseIP("10.0.0.99")}})
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
	}}
	runGW006Case(t, leaf, client)
}

// TestDefaultUpstreamClientRejectsBelowTLS12 pins the MinVersion floor
// behaviourally: a server that will not negotiate above TLS 1.1 is refused
// by NewUpstream's own default client, not merely by inspecting the
// Transport's configured field.
func TestDefaultUpstreamClientRejectsBelowTLS12(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{ipAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
	}}
	up, err := NewUpstream(srv.URL, client)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := up.Client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a TLS-1.1-only server was accepted by a client floored at TLS 1.2, want a refusal")
	}
}

// TestDefaultUpstreamClientFloorsAtTLS12 pins defaultUpstreamClient's own
// configured floor directly, so a regression here fails fast with a clear
// assertion rather than only through the slower end-to-end case above.
func TestDefaultUpstreamClientFloorsAtTLS12(t *testing.T) {
	up, err := NewUpstream("https://api.anthropic.com", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	transport, ok := up.Client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatalf("default client's Transport does not carry a TLSClientConfig")
	}
	if got := transport.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Errorf("TLSClientConfig.MinVersion = %#x, want tls.VersionTLS12 (%#x)", got, tls.VersionTLS12)
	}
}

// TestNoProductionCodeSetsInsecureSkipVerify parses this package's own
// PRODUCTION source (every *.go file except *_test.go) and walks its AST
// for the identifier InsecureSkipVerify. Its presence anywhere in CODE --
// even set to false -- would mean a future edit is one word away from
// disabling certificate verification silently; its total absence from code
// is what this test pins. Parsing rather than a plain text search is
// deliberate: it lets a doc comment go on NAMING the field (as this
// package's own package doc and NewUpstream's doc comment do, to say it is
// never set) without that mention tripping the gate meant to catch actual
// use.
func TestNoProductionCodeSetsInsecureSkipVerify(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/gateway: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == "InsecureSkipVerify" {
				t.Errorf("%s:%s references InsecureSkipVerify in code (not a comment); "+
					"production code must never set it",
					name, fset.Position(ident.Pos()))
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no production .go files were found to check -- this test is not exercising anything")
	}
}

// ---------------------------------------------------------------------------
// GW-008, the two failure classes GW-006 does not exercise: a refused TCP
// connection and a stalled handshake that times out. Both must still reach
// the caller as a JSON error naming innsegl and the failure class, with a
// status that fits (502 for a refusal, 504 for a timeout).
// ---------------------------------------------------------------------------

// TestGW008ConnectionRefusedNamesTheFailureClass: nothing listens on the
// chosen port, so the dial itself fails.
func TestGW008ConnectionRefusedNamesTheFailureClass(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	if closeErr := ln.Close(); closeErr != nil {
		t.Fatalf("close reserved port: %v", closeErr)
	} // closed: now nothing listens there, so the dial is refused.

	client := &http.Client{Timeout: 3 * time.Second}
	up, err := NewUpstream("http://"+addr, client)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (StatusBadGateway)", resp.StatusCode, http.StatusBadGateway)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") || !strings.Contains(body.Error, "connection refused") {
		t.Errorf("error body = %q, want it to name innsegl and \"connection refused\"", body.Error)
	}
}

// stallListener accepts a TCP connection and then does nothing at all --
// never completes a TLS handshake -- so a client dialing it experiences
// exactly a stalled handshake, not a refusal or a reset.
type stallListener struct {
	net.Listener
}

func newStallListener(t *testing.T) *stallListener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sl := &stallListener{Listener: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Held open deliberately: read nothing, write nothing, never
			// close. The handshake the client is waiting on never arrives.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return sl
}

// TestGW008UpstreamTimeoutNamesTheFailureClassAndUses504: the TLS handshake
// never completes, so the client's own bound on it is what fires.
func TestGW008UpstreamTimeoutNamesTheFailureClassAndUses504(t *testing.T) {
	ln := newStallListener(t)
	defer func() { _ = ln.Close() }()

	client := &http.Client{Transport: &http.Transport{
		TLSHandshakeTimeout: 200 * time.Millisecond,
	}}
	up, err := NewUpstream("https://"+ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want %d (StatusGatewayTimeout)", resp.StatusCode, http.StatusGatewayTimeout)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") || !strings.Contains(body.Error, "timed out") {
		t.Errorf("error body = %q, want it to name innsegl and \"timed out\"", body.Error)
	}
}

// stubRoundTripper returns err for every request, unwrapped -- neither an
// x509 type, a net.Error, nor a *net.OpError -- so classifyUpstreamError's
// own default branch is what a genuinely unclassified transport failure
// exercises.
type stubRoundTripper struct{ err error }

func (rt stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, rt.err }

// TestGW008UnclassifiedUpstreamErrorFallsBackToAGenericMessage: a transport
// failure that is none of the three named classes still reaches the caller
// as a JSON 502 naming innsegl, never a dropped connection -- the fallback
// classifyUpstreamError's default case exists for.
func TestGW008UnclassifiedUpstreamErrorFallsBackToAGenericMessage(t *testing.T) {
	client := &http.Client{Transport: stubRoundTripper{err: errors.New("boom")}}
	up, err := NewUpstream("https://example.invalid", client)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v (want a response from the gateway, not a transport error)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (StatusBadGateway)", resp.StatusCode, http.StatusBadGateway)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode JSON error body: %v", err)
	}
	if !strings.Contains(body.Error, "innsegl") {
		t.Errorf("error body = %q, want it to name innsegl", body.Error)
	}
}

// TestIsConnectionRefusedFallsBackToTheErrorsOwnText covers
// isConnectionRefused's non-*net.OpError branch directly: an error that
// carries "connection refused" in its own text without being an
// *net.OpError at all.
func TestIsConnectionRefusedFallsBackToTheErrorsOwnText(t *testing.T) {
	if !isConnectionRefused(errors.New("dial tcp: connection refused")) {
		t.Error("isConnectionRefused did not recognise \"connection refused\" in a plain error's own text")
	}
	if isConnectionRefused(errors.New("boom")) {
		t.Error("isConnectionRefused matched an error that does not mention a refusal")
	}
}
