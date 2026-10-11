// SPDX-License-Identifier: Apache-2.0

package signprobe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
)

// The unit half of SIG-015 (RM-339, #583). The integration half, against a
// real SPIRE and a real Fulcio, is integration_test.go; these cases cover
// each refusal the probe can name, against a stand-in whose behaviour a case
// can choose. They prove the probe's arithmetic, not Fulcio's.

// testCA is a CA a case controls.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
	return &testCA{key: key, cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue makes a code-signing leaf for pub under the CA.
func (c *testCA) issue(t *testing.T, pub crypto.PublicKey, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakeFulcio answers the two paths the probe uses. answer decides the
// signing-certificate response; nil is a Fulcio that issues under ca.
type fakeFulcio struct {
	t      *testing.T
	ca     *testCA
	mu     sync.Mutex
	answer func(w http.ResponseWriter, req signingCertRequest, pub crypto.PublicKey)
	last   signingCertRequest
	calls  int
}

func (f *fakeFulcio) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+fulcioRootPath, func(w http.ResponseWriter, _ *http.Request) {
		put(f.t, w, string(f.ca.pem))
	})
	mux.HandleFunc("POST "+fulcioSigningCertPath, func(w http.ResponseWriter, r *http.Request) {
		var req signingCertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.last = req
		f.calls++
		answer := f.answer
		f.mu.Unlock()
		blk, _ := pem.Decode([]byte(req.PublicKeyRequest.PublicKey.Content))
		if blk == nil {
			http.Error(w, "no key", http.StatusBadRequest)
			return
		}
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Fulcio's proof of possession: the key signed the token's subject.
		ec, ok := pub.(*ecdsa.PublicKey)
		sum := sha256.Sum256([]byte(probeSubject(f.t)))
		if !ok || !ecdsa.VerifyASN1(ec, sum[:], req.PublicKeyRequest.ProofOfPossession) {
			http.Error(w, `{"code":3,"message":"proof of possession failed"}`, http.StatusBadRequest)
			return
		}
		if answer != nil {
			answer(w, req, pub)
			return
		}
		writeChain(f.t, w, true, f.ca.issue(f.t, pub, probeSubject(f.t)), f.ca.pem)
	})
	return mux
}

func put(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Error(err)
	}
}

func writeChain(t *testing.T, w http.ResponseWriter, embedded bool, certs ...[]byte) {
	t.Helper()
	chain := make([]string, len(certs))
	for i, c := range certs {
		chain[i] = string(c)
	}
	var body map[string]any
	if embedded {
		body = map[string]any{"signedCertificateEmbeddedSct": map[string]any{"chain": map[string]any{"certificates": chain}}}
	} else {
		body = map[string]any{"signedCertificateDetachedSct": map[string]any{"chain": map[string]any{"certificates": chain}}}
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Error(err)
	}
}

const testTrustDomain = "innsegl.dev"

func probeSubject(t *testing.T) string {
	t.Helper()
	id, err := Identity(testTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type mintCall struct{ id, audience string }

func newProber(t *testing.T, f *fakeFulcio, mint MintFunc) (*Prober, *[]mintCall) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	var calls []mintCall
	if mint == nil {
		mint = func(_ context.Context, id, audience string) (string, error) {
			calls = append(calls, mintCall{id, audience})
			return "header.payload.signature", nil
		}
	}
	p, err := New(Config{FulcioURL: srv.URL, TrustDomain: testTrustDomain, Mint: mint})
	if err != nil {
		t.Fatal(err)
	}
	return p, &calls
}

// SIG-015 — the probe identity is a run identity in the protected grammar
// (doc 02 §5) and in the subtree SPIRE's mint policy admits; no new grammar.
func TestSIG015TheProbeIdentityFitsTheExistingGrammar(t *testing.T) {
	id, err := Identity(testTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	if err := event.ValidateSPIFFEID(id); err != nil {
		t.Fatalf("the probe identity %q is outside the SPIFFE grammar: %v", id, err)
	}
	if !strings.HasPrefix(id, "spiffe://innsegl.dev/agent/") {
		t.Fatalf("the probe identity %q is outside the agent subtree the mint policy admits", id)
	}
	if _, err := Identity("Not A Domain"); err == nil {
		t.Fatal("an upper-case trust domain made a probe identity")
	}
	if Audience != signing.AudienceSigstore {
		t.Fatalf("the probe asks for audience %q; the signer uses %q", Audience, signing.AudienceSigstore)
	}
}

// SIG-015 — against a CA that issues, the probe passes: a certificate for
// the key it made, chaining to the trust root, for the probe identity, after
// minting one credential for that identity and audience.
func TestSIG015TheProbePassesAgainstACAThatSigns(t *testing.T) {
	f := &fakeFulcio{t: t, ca: newTestCA(t, "root")}
	p, calls := newProber(t, f, nil)
	for _, embedded := range []bool{true, false} {
		if !embedded {
			f.answer = func(w http.ResponseWriter, _ signingCertRequest, pub crypto.PublicKey) {
				writeChain(t, w, false, f.ca.issue(t, pub, probeSubject(t)), f.ca.pem)
			}
		}
		r := p.Probe(t.Context())
		if !r.OK || r.Reason != "" {
			t.Fatalf("embedded=%v: the probe failed against a working CA: %q", embedded, r.Reason)
		}
		if r.At.IsZero() {
			t.Fatal("a result with no time")
		}
	}
	if len(*calls) != 2 || (*calls)[0].id != probeSubject(t) || (*calls)[0].audience != Audience {
		t.Fatalf("minted %+v; want one credential per probe for %s, audience %s", *calls, probeSubject(t), Audience)
	}
	if f.last.Credentials.OIDCIdentityToken != "header.payload.signature" {
		t.Fatalf("the minted token was not presented: %+v", f.last.Credentials)
	}
	if f.last.PublicKeyRequest.PublicKey.Algorithm != "ECDSA" {
		t.Fatalf("algorithm %q", f.last.PublicKeyRequest.PublicKey.Algorithm)
	}
}

// SIG-015 — every way the CA can fail to sign is a failure that names the
// reason, never a pass.
func TestSIG015TheProbeFailsWithTheReasonWhenTheCACannotSign(t *testing.T) {
	other := newTestCA(t, "another root")
	for _, tc := range []struct {
		name   string
		answer func(t *testing.T, ca *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey)
		want   string
	}{
		{"the CA backend refuses", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				w.WriteHeader(http.StatusInternalServerError)
				put(t, w, `{"code":13,"message":"error communicating with CA backend","details":[]}`)
			}
		}, "HTTP 500: error communicating with CA backend"},
		{"a refusal that is not JSON", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				w.WriteHeader(http.StatusBadGateway)
				put(t, w, "upstream gone\n")
			}
		}, "HTTP 502: upstream gone"},
		{"an answer that is not JSON", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				put(t, w, "<html>")
			}
		}, "unreadable answer"},
		{"no chain at all", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				put(t, w, `{}`)
			}
		}, "no certificate"},
		{"a chain that is not PEM", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				writeChain(t, w, true, []byte("not pem"))
			}
		}, "not a PEM certificate"},
		{"a chain that does not parse", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				writeChain(t, w, true, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
			}
		}, "does not parse"},
		{"a certificate for another key", func(t *testing.T, ca *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, _ crypto.PublicKey) {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				writeChain(t, w, true, ca.issue(t, &k.PublicKey, probeSubject(t)), ca.pem)
			}
		}, "not the key the probe made"},
		{"a certificate for another identity", func(t *testing.T, ca *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, pub crypto.PublicKey) {
				writeChain(t, w, true, ca.issue(t, pub, "spiffe://innsegl.dev/agent/a/b/c"), ca.pem)
			}
		}, "names spiffe://innsegl.dev/agent/a/b/c"},
		{"a certificate from a key that is not the trust root's", func(t *testing.T, _ *testCA) func(http.ResponseWriter, signingCertRequest, crypto.PublicKey) {
			return func(w http.ResponseWriter, _ signingCertRequest, pub crypto.PublicKey) {
				writeChain(t, w, true, other.issue(t, pub, probeSubject(t)), other.pem)
			}
		}, "does not chain to the trust root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFulcio{t: t, ca: newTestCA(t, "root")}
			f.answer = tc.answer(t, f.ca)
			p, _ := newProber(t, f, nil)
			r := p.Probe(t.Context())
			if r.OK {
				t.Fatal("the probe passed")
			}
			if !strings.Contains(r.Reason, tc.want) {
				t.Fatalf("reason %q does not say %q", r.Reason, tc.want)
			}
		})
	}
}

// SIG-015 — a failure before Fulcio is reached names that step too.
func TestSIG015TheProbeNamesAFailureBeforeTheCA(t *testing.T) {
	t.Run("no credential", func(t *testing.T) {
		f := &fakeFulcio{t: t, ca: newTestCA(t, "root")}
		p, _ := newProber(t, f, func(context.Context, string, string) (string, error) {
			return "", errors.New("SPIRE said no")
		})
		r := p.Probe(t.Context())
		if r.OK || !strings.Contains(r.Reason, "minting the probe's credential: SPIRE said no") {
			t.Fatalf("%+v", r)
		}
		if f.calls != 0 {
			t.Fatal("Fulcio was asked with no credential")
		}
	})
	t.Run("no trust root", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET "+fulcioRootPath, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		p, err := New(Config{FulcioURL: srv.URL, TrustDomain: testTrustDomain,
			Mint: func(context.Context, string, string) (string, error) { return "t", nil }})
		if err != nil {
			t.Fatal(err)
		}
		if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "reading the trust root") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a trust root that is not a certificate", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET "+fulcioRootPath, func(w http.ResponseWriter, _ *http.Request) {
			put(t, w, "nothing")
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		p, err := New(Config{FulcioURL: srv.URL, TrustDomain: testTrustDomain,
			Mint: func(context.Context, string, string) (string, error) { return "t", nil }})
		if err != nil {
			t.Fatal(err)
		}
		if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "no certificate") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("an injected trust root that fails", func(t *testing.T) {
		f := &fakeFulcio{t: t, ca: newTestCA(t, "root")}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		p, err := New(Config{FulcioURL: srv.URL, TrustDomain: testTrustDomain,
			Mint:  func(context.Context, string, string) (string, error) { return "t", nil },
			Roots: func(context.Context) (*x509.CertPool, error) { return nil, errors.New("history unreadable") }})
		if err != nil {
			t.Fatal(err)
		}
		if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "history unreadable") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("Fulcio is not answering", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		addr := srv.URL
		srv.Close()
		ca := newTestCA(t, "root")
		pool := x509.NewCertPool()
		pool.AddCert(ca.cert)
		p, err := New(Config{FulcioURL: addr, TrustDomain: testTrustDomain,
			Mint:  func(context.Context, string, string) (string, error) { return "t", nil },
			Roots: func(context.Context) (*x509.CertPool, error) { return pool, nil }})
		if err != nil {
			t.Fatal(err)
		}
		if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "asking Fulcio for a certificate") {
			t.Fatalf("%+v", r)
		}
	})
}

// A probe that cannot be built is refused at start, not reported as an
// outage every five minutes.
func TestNewRefusesAProbeThatCannotRun(t *testing.T) {
	mint := func(context.Context, string, string) (string, error) { return "", nil }
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no Fulcio", Config{TrustDomain: testTrustDomain, Mint: mint}},
		{"Fulcio is not a URL", Config{FulcioURL: "http://[::1", TrustDomain: testTrustDomain, Mint: mint}},
		{"Fulcio has no scheme", Config{FulcioURL: "fulcio:5555", TrustDomain: testTrustDomain, Mint: mint}},
		{"Fulcio has no host", Config{FulcioURL: "http://", TrustDomain: testTrustDomain, Mint: mint}},
		{"no trust domain", Config{FulcioURL: "http://f", Mint: mint}},
		{"no minter", Config{FulcioURL: "http://f", TrustDomain: testTrustDomain}},
	} {
		if _, err := New(tc.cfg); err == nil {
			t.Errorf("%s: built", tc.name)
		}
	}
}

// The edges of the reasons: a long refusal is cut, a leaf with no identity
// says so, and a published root that does not parse is a trust-root failure.
func TestSIG015ReasonEdges(t *testing.T) {
	long := strings.Repeat("x", 500)
	if got := fulcioMessage([]byte(long)); len(got) != 200 {
		t.Fatalf("a %d-byte refusal became %d bytes", len(long), len(got))
	}

	f := &fakeFulcio{t: t, ca: newTestCA(t, "root")}
	f.answer = func(w http.ResponseWriter, _ signingCertRequest, pub crypto.PublicKey) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, pub, f.ca.key)
		if err != nil {
			t.Fatal(err)
		}
		writeChain(t, w, true, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	p, _ := newProber(t, f, nil)
	if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "names no identity") {
		t.Fatalf("%+v", r)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+fulcioRootPath, func(w http.ResponseWriter, _ *http.Request) {
		put(t, w, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	bad, err := New(Config{FulcioURL: srv.URL, TrustDomain: testTrustDomain,
		Mint: func(context.Context, string, string) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if r := bad.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "reading the trust root: "+fulcioRootPath) {
		t.Fatalf("%+v", r)
	}
}
