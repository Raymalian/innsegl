// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A client identity, as RM-300 (#476) defines it:
//
//	spiffe://{trust-domain}/client/{32 lowercase hex}
//
// It names an enrolled installation, never an agent run, and it must never be
// able to obtain a signing token. These tests hold both halves: what may be
// minted, and what a client identity may never become.

const testClientHex = "0123456789abcdef0123456789abcdef"

func testClientID() string { return "spiffe://" + testTrustDomain + "/client/" + testClientHex }

// newTestCSR builds a CSR carrying exactly the SANs given, signed by a fresh key.
func newTestCSR(t *testing.T, uris []string, dns []string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{DNSNames: dns}
	for _, u := range uris {
		parsed, perr := url.Parse(u)
		if perr != nil {
			t.Fatalf("url.Parse(%q): %v", u, perr)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der, key
}

// badClientCSRs are the CSR shapes SPI-022 requires refused, both by this
// package before any call and by SPIRE's policy when the call is made anyway.
func badClientCSRs() []struct {
	name string
	uris []string
	dns  []string
} {
	td := "spiffe://" + testTrustDomain
	return []struct {
		name string
		uris []string
		dns  []string
	}{
		{"an agent run path", []string{td + "/agent/demo/rm-300/run-1"}, nil},
		{"the MCP admin identity", []string{td + "/innsegl/mcp"}, nil},
		{"a client id that is too short", []string{td + "/client/0123456789abcdef"}, nil},
		{"a client id in upper case", []string{td + "/client/0123456789ABCDEF0123456789ABCDEF"}, nil},
		{"a client id that is not hex", []string{td + "/client/0123456789abcdefg123456789abcdef"}, nil},
		{"a client path one level deeper", []string{td + "/client/" + testClientHex + "/x"}, nil},
		{"the bare client subtree", []string{td + "/client"}, nil},
		{"a client path in another trust domain", []string{"spiffe://example.org/client/" + testClientHex}, nil},
		{"two URI SANs, one of them a client", []string{testClientID(), td + "/agent/demo/rm-300/run-1"}, nil},
		{"two client URI SANs", []string{testClientID(), td + "/client/fedcba9876543210fedcba9876543210"}, nil},
		{"a client URI SAN plus a DNS SAN", []string{testClientID()}, []string{"client.example"}},
		{"no URI SAN at all", nil, []string{"client.example"}},
	}
}

// ---------------------------------------------------------------------------
// Local refusal (SPI-022, the client half). No SPIRE needed.
// ---------------------------------------------------------------------------

func TestSPI022ClientCSRShapesAreRefusedLocally(t *testing.T) {
	good, _ := newTestCSR(t, []string{testClientID()}, nil)
	id, err := CheckClientCSR(good, testTrustDomain)
	if err != nil {
		t.Fatalf("a well-formed client CSR was refused: %v", err)
	}
	if id != testClientHex {
		t.Fatalf("installation id = %q, want %q", id, testClientHex)
	}

	for _, tc := range badClientCSRs() {
		t.Run(tc.name, func(t *testing.T) {
			der, _ := newTestCSR(t, tc.uris, tc.dns)
			if _, err := CheckClientCSR(der, testTrustDomain); err == nil {
				t.Fatal("CheckClientCSR accepted it")
			} else if class, _ := ClassOf(err); class != ClassInvariantViolation {
				t.Errorf("class = %q, want %s", class, ClassInvariantViolation)
			}
		})
	}

	t.Run("bytes that are not a CSR", func(t *testing.T) {
		if _, err := CheckClientCSR([]byte{0x30, 0x00}, testTrustDomain); err == nil {
			t.Fatal("CheckClientCSR accepted garbage")
		}
	})
	t.Run("a CSR whose signature does not verify", func(t *testing.T) {
		der, _ := newTestCSR(t, []string{testClientID()}, nil)
		tampered := append([]byte(nil), der...)
		tampered[len(tampered)-3] ^= 0xff
		if _, err := CheckClientCSR(tampered, testTrustDomain); err == nil {
			t.Fatal("CheckClientCSR accepted a CSR with a broken signature")
		}
	})
}

// TestSPI022MintRefusesBeforeTheCall proves the local refusal happens before
// any RPC: the client is dialled at an address nothing listens on, so a call
// that went out would come back IDENTITY_UNAVAILABLE. Every refusal here must
// be INVARIANT_VIOLATION instead.
func TestSPI022MintRefusesBeforeTheCall(t *testing.T) {
	c := unreachableClient(t)
	ctx := context.Background()

	for _, tc := range badClientCSRs() {
		t.Run(tc.name, func(t *testing.T) {
			der, _ := newTestCSR(t, tc.uris, tc.dns)
			_, _, err := c.MintClientX509SVID(ctx, der, time.Hour)
			if class, _ := ClassOf(err); class != ClassInvariantViolation {
				t.Fatalf("err = %v (class %q), want a local INVARIANT_VIOLATION", err, class)
			}
		})
	}

	good, _ := newTestCSR(t, []string{testClientID()}, nil)
	for _, ttl := range []time.Duration{0, -time.Second, ClientCertTTL + time.Second, 48 * time.Hour} {
		_, _, err := c.MintClientX509SVID(ctx, good, ttl)
		if class, _ := ClassOf(err); class != ClassInvariantViolation {
			t.Errorf("ttl %v: err = %v (class %q), want a local INVARIANT_VIOLATION", ttl, err, class)
		}
	}

	// The positive control: a valid CSR with a valid TTL does go out, and so
	// fails as an outage — which shows the refusals above were not.
	_, _, err := c.MintClientX509SVID(ctx, good, ClientCertTTL)
	if class, _ := ClassOf(err); class != ClassIdentityUnavailable {
		t.Fatalf("a valid request against a dead address: err = %v (class %q), want %s",
			err, class, ClassIdentityUnavailable)
	}
}

func unreachableClient(t *testing.T) *Client {
	t.Helper()
	ca := newTestCA(t, time.Now())
	leaf := ca.issue(t, "spiffe://"+testTrustDomain+"/innsegl/mcp", time.Now(), time.Hour,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	c, err := Dial(context.Background(), Config{
		Address:     "127.0.0.1:1",
		TrustDomain: testTrustDomain,
		Source:      leaf.source(t),
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientSPIFFEIDGrammar(t *testing.T) {
	id, err := ClientSPIFFEID(testTrustDomain, testClientHex)
	if err != nil || id != testClientID() {
		t.Fatalf("ClientSPIFFEID = %q, %v; want %q", id, err, testClientID())
	}
	got, err := ClientIDOf(testClientID(), testTrustDomain)
	if err != nil || got != testClientHex {
		t.Fatalf("ClientIDOf = %q, %v; want %q", got, err, testClientHex)
	}
	for _, bad := range []string{"", "0123", strings.ToUpper(testClientHex), testClientHex + "0", "../" + testClientHex[3:]} {
		if _, err := ClientSPIFFEID(testTrustDomain, bad); err == nil {
			t.Errorf("ClientSPIFFEID accepted id %q", bad)
		}
	}
	for _, bad := range []string{
		"spiffe://" + testTrustDomain + "/agent/demo/rm-300/run-1",
		"spiffe://example.org/client/" + testClientHex,
		testClientID() + "/",
		testClientID() + "?x=1",
		testClientID() + "#f",
		"spiffe://u@" + testTrustDomain + "/client/" + testClientHex,
		"https://" + testTrustDomain + "/client/" + testClientHex,
	} {
		if _, err := ClientIDOf(bad, testTrustDomain); err == nil {
			t.Errorf("ClientIDOf accepted %q", bad)
		}
	}
	if _, err := ClientSPIFFEID("not a domain/", testClientHex); err == nil {
		t.Error("ClientSPIFFEID accepted a bad trust domain")
	}
}

// ---------------------------------------------------------------------------
// The verifier. No SPIRE needed: a CA of the test's own stands in for the
// deployment's bundle, and the integration cases below repeat the positive
// case against SPIRE's real one.
// ---------------------------------------------------------------------------

func TestVerifyClientCertificate(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t, now)
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	good := ca.issue(t, testClientID(), now, ClientCertTTL, clientAuth)
	id, err := VerifyClientCertificate(good.chain, ca.roots(), testTrustDomain, now)
	if err != nil {
		t.Fatalf("a valid client certificate was refused: %v", err)
	}
	if id != testClientHex {
		t.Fatalf("installation id = %q, want %q", id, testClientHex)
	}

	other := newTestCA(t, now)
	refuse := func(t *testing.T, chain []*x509.Certificate, roots []*x509.Certificate, at time.Time) {
		t.Helper()
		id, err := VerifyClientCertificate(chain, roots, testTrustDomain, at)
		if err == nil {
			t.Fatalf("accepted as installation %q", id)
		}
		if class, _ := ClassOf(err); class != ClassAttestationFailed {
			t.Errorf("class = %q, want %s", class, ClassAttestationFailed)
		}
	}

	t.Run("wrong CA", func(t *testing.T) {
		refuse(t, good.chain, other.roots(), now)
	})
	t.Run("expired", func(t *testing.T) {
		refuse(t, good.chain, ca.roots(), now.Add(ClientCertTTL+time.Minute))
	})
	t.Run("not yet valid", func(t *testing.T) {
		refuse(t, good.chain, ca.roots(), now.Add(-time.Hour))
	})
	t.Run("server-auth-only EKU", func(t *testing.T) {
		c := ca.issue(t, testClientID(), now, time.Hour, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("no EKU at all", func(t *testing.T) {
		c := ca.issue(t, testClientID(), now, time.Hour, nil)
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("a DNS SAN beside the client URI", func(t *testing.T) {
		c := ca.issue(t, testClientID(), now, time.Hour, clientAuth)
		c.chain[0].DNSNames = []string{"client.example"}
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("an agent run path", func(t *testing.T) {
		c := ca.issue(t, "spiffe://"+testTrustDomain+"/agent/demo/rm-300/run-1", now, time.Hour, clientAuth)
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("a bad client id", func(t *testing.T) {
		c := ca.issue(t, "spiffe://"+testTrustDomain+"/client/XYZ", now, time.Hour, clientAuth)
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("another trust domain", func(t *testing.T) {
		c := ca.issue(t, "spiffe://example.org/client/"+testClientHex, now, time.Hour, clientAuth)
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("two URI SANs", func(t *testing.T) {
		c := ca.issueURIs(t, []string{testClientID(), "spiffe://" + testTrustDomain + "/client/fedcba9876543210fedcba9876543210"},
			now, time.Hour, clientAuth)
		refuse(t, c.chain, ca.roots(), now)
	})
	t.Run("a CA certificate as the leaf", func(t *testing.T) {
		refuse(t, []*x509.Certificate{ca.cert}, ca.roots(), now)
	})
	t.Run("no chain", func(t *testing.T) {
		refuse(t, nil, ca.roots(), now)
	})
	t.Run("no roots", func(t *testing.T) {
		refuse(t, good.chain, nil, now)
	})
}

// ---------------------------------------------------------------------------
// Against the real SPIRE (layer I). The policy under test is the shipped
// deploy/compose/spire/authz-policy.rego, mounted by the harness unchanged.
// ---------------------------------------------------------------------------

// SPI-020: does SPIRE's authorization policy see the MintX509SVID request
// body, and can its embedded OPA read the URI SANs out of the CSR in it?
//
// MEASURED on SPIRE 1.15.3 (deploy/compose/spire.yml), 2026-10-01: yes.
// SPIRE hands the policy `input.req` as the JSON form of the request message,
// so a MintX509SVID request arrives as
//
//	input.req.csr  the CSR's DER bytes, base64 (standard alphabet)
//	input.req.ttl  the requested TTL in seconds, a number
//
// beside `input.full_method` and `input.caller`, and OPA's
// crypto.x509.parse_certificate_request decodes that string and yields the
// CSR's `URIs` (each a Go url.URL: Scheme, Host, Path, ...) and `DNSNames`.
//
// The proof is that the decision turns on the CSR alone: the same admin
// credential, on the same connection, calling the same method with the same
// TTL, is admitted when the CSR's one URI SAN is a client identity and refused
// by SPIRE's authorization when it is an agent path. A policy that could not
// read the CSR could only admit both or refuse both. And with the TTL as the
// only difference, a client CSR asking for more than 24 h is refused: the
// policy reads `ttl` too.
func TestSPI020SPIREPolicyReadsTheCSRInAMintX509SVIDRequest(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	svid := svidv1.NewSVIDClient(c.conn)

	clientCSR, _ := newTestCSR(t, []string{testClientID()}, nil)
	resp, err := svid.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{Csr: clientCSR, Ttl: 3600})
	if err != nil {
		t.Fatalf("SPIRE refused a client CSR from the admin identity: %v", err)
	}
	if got := idString(resp.GetSvid().GetId()); got != testClientID() {
		t.Fatalf("SPIRE minted %q, want %q", got, testClientID())
	}
	t.Logf("measured: client CSR admitted, SVID %s", idString(resp.GetSvid().GetId()))

	agentCSR, _ := newTestCSR(t, []string{"spiffe://" + testTrustDomain + "/agent/demo/rm-300/run-1"}, nil)
	_, err = svid.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{Csr: agentCSR, Ttl: 3600})
	requireAuthorizationDenied(t, err)
	t.Log("measured: agent-path CSR refused by authorization — the policy read input.req.csr")

	_, err = svid.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{Csr: clientCSR, Ttl: int32(ClientCertTTL.Seconds()) + 1})
	requireAuthorizationDenied(t, err)
	t.Log("measured: client CSR with a TTL over 24 h refused — the policy read input.req.ttl")
}

// SPI-021: a client CSR is minted and the result verifies.
func TestSPI021ClientCSRIsMintedAndVerifies(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	csr, key := newTestCSR(t, []string{testClientID()}, nil)
	before := time.Now()
	chain, bundle, err := c.MintClientX509SVID(ctx, csr, ClientCertTTL)
	if err != nil {
		t.Fatalf("MintClientX509SVID: %v", err)
	}
	if len(chain) == 0 || len(bundle) == 0 {
		t.Fatalf("chain has %d certificates, bundle %d", len(chain), len(bundle))
	}
	leaf := chain[0]
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		t.Fatal("the minted certificate does not carry the CSR's public key")
	}
	if life := leaf.NotAfter.Sub(before); life > ClientCertTTL+time.Minute {
		t.Fatalf("certificate lives %v, want at most %v", life, ClientCertTTL)
	}

	id, err := VerifyClientCertificate(chain, bundle, testTrustDomain, time.Now())
	if err != nil {
		t.Fatalf("the minted certificate does not verify against the deployment bundle: %v", err)
	}
	if id != testClientHex {
		t.Fatalf("installation id = %q, want %q", id, testClientHex)
	}
	t.Logf("minted %s, NotAfter %s (%v from request)", leaf.URIs[0], leaf.NotAfter.UTC(), leaf.NotAfter.Sub(before).Round(time.Second))

	// A shorter TTL is honoured, not widened.
	short, _, err := c.MintClientX509SVID(ctx, csr, 10*time.Minute)
	if err != nil {
		t.Fatalf("MintClientX509SVID(10m): %v", err)
	}
	if life := time.Until(short[0].NotAfter); life > 11*time.Minute {
		t.Fatalf("a 10m request lives %v", life)
	}
}

// GW-018's verifier input (#460): the bundle the gateway checks presented
// client certificates against is the deployment's own, read on its own, and
// it verifies a certificate SPIRE minted.
func TestX509BundleVerifiesAMintedClientCertificate(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	csr, _ := newTestCSR(t, []string{testClientID()}, nil)
	chain, _, err := c.MintClientX509SVID(ctx, csr, 10*time.Minute)
	if err != nil {
		t.Fatalf("MintClientX509SVID: %v", err)
	}
	bundle, err := c.X509Bundle(ctx)
	if err != nil {
		t.Fatalf("X509Bundle: %v", err)
	}
	if id, err := VerifyClientCertificate(chain, bundle, testTrustDomain, time.Now()); err != nil || id != testClientHex {
		t.Fatalf("VerifyClientCertificate against X509Bundle = %q, %v", id, err)
	}
}

func TestX509BundleOnAnUnreachableServerIsAnError(t *testing.T) {
	c := unreachableClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.X509Bundle(ctx); err == nil {
		t.Fatal("X509Bundle against an unreachable server answered no error")
	}
}

// SPI-022, the policy half: every refused shape is refused by SPIRE even when
// the local check is bypassed, as a stolen admin credential would bypass it.
func TestSPI022SPIREPolicyRefusesEveryOtherCSR(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	svid := svidv1.NewSVIDClient(c.conn)

	for _, tc := range badClientCSRs() {
		t.Run(tc.name, func(t *testing.T) {
			der, _ := newTestCSR(t, tc.uris, tc.dns)
			resp, err := svid.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{Csr: der, Ttl: 3600})
			if err == nil {
				t.Fatalf("SPIRE MINTED %s from the admin identity", idString(resp.GetSvid().GetId()))
			}
			requireAuthorizationDenied(t, err)
		})
	}
	t.Run("a zero TTL", func(t *testing.T) {
		der, _ := newTestCSR(t, []string{testClientID()}, nil)
		_, err := svid.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{Csr: der})
		requireAuthorizationDenied(t, err)
	})
}

// SPI-023: a client identity can never obtain a signing token, and is never
// accepted where an agent identity is required.
func TestSPI023AClientIdentityCannotBecomeAnAgent(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	t.Run("no JWT-SVID for a client path", func(t *testing.T) {
		resp, err := svidv1.NewSVIDClient(c.conn).MintJWTSVID(ctx, &svidv1.MintJWTSVIDRequest{
			Id:       &types.SPIFFEID{TrustDomain: testTrustDomain, Path: "/client/" + testClientHex},
			Audience: []string{"sigstore"},
		})
		if err == nil {
			t.Fatalf("SPIRE minted a JWT-SVID for a client identity: %s", resp.GetSvid().GetId())
		}
		requireAuthorizationDenied(t, err)
	})

	t.Run("a minted client certificate is not a run identity", func(t *testing.T) {
		csr, _ := newTestCSR(t, []string{testClientID()}, nil)
		chain, _, err := c.MintClientX509SVID(ctx, csr, time.Hour)
		if err != nil {
			t.Fatalf("MintClientX509SVID: %v", err)
		}
		if run, err := RunRefOf(chain[0].URIs[0].String()); err == nil {
			t.Fatalf("RunRefOf accepted a client certificate's ID as run %+v", run)
		}
	})

	t.Run("an agent SVID from the same authority is not a client certificate", func(t *testing.T) {
		agent, err := s.mintAdmin(ctx, "spiffe://"+testTrustDomain+"/agent/demo/rm-300/run-1")
		if err != nil {
			t.Fatalf("mint agent SVID on the local socket: %v", err)
		}
		chain := agent.svid.Certificates
		if id, err := VerifyClientCertificate(chain, agent.roots, testTrustDomain, time.Now()); err == nil {
			t.Fatalf("an agent SVID verified as installation %q", id)
		}
	})
}

func requireAuthorizationDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("the call succeeded; SPIRE's authorization policy was expected to refuse it")
	}
	st, ok := status.FromError(unwrapAll(err))
	if !ok || st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "authorization denied") {
		t.Fatalf("want SPIRE's PermissionDenied authorization denial, got %v", err)
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ak, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ak.Equal(b)
}

// ---------------------------------------------------------------------------
// A throwaway CA for the verifier cases.
// ---------------------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type testLeaf struct {
	chain []*x509.Certificate
	key   crypto.Signer
	ca    *testCA
}

func newTestCA(t *testing.T, now time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) roots() []*x509.Certificate { return []*x509.Certificate{ca.cert} }

func (ca *testCA) issue(t *testing.T, uri string, now time.Time, ttl time.Duration, eku []x509.ExtKeyUsage) testLeaf {
	t.Helper()
	return ca.issueURIs(t, []string{uri}, now, ttl, eku)
}

func (ca *testCA) issueURIs(t *testing.T, uris []string, now time.Time, ttl time.Duration, eku []x509.ExtKeyUsage) testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	for _, u := range uris {
		parsed, perr := url.Parse(u)
		if perr != nil {
			t.Fatal(perr)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testLeaf{chain: []*x509.Certificate{cert}, key: key, ca: ca}
}

// source turns a leaf into an admin-client Source, for the cases that only
// need a client that dials and never succeeds.
func (l testLeaf) source(t *testing.T) Source {
	t.Helper()
	svid, err := x509svidFromLeaf(l)
	if err != nil {
		t.Fatalf("x509svid: %v", err)
	}
	return mintedSVID{svid: svid, roots: l.ca.roots()}
}

func x509svidFromLeaf(l testLeaf) (*x509svid.SVID, error) {
	id, err := spiffeid.FromURI(l.chain[0].URIs[0])
	if err != nil {
		return nil, err
	}
	return &x509svid.SVID{ID: id, Certificates: l.chain, PrivateKey: l.key}, nil
}
