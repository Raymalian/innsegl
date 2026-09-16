// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OPS-049's unit half — RM-147 (#238).
//
// The CA's private key lives in a secret store and is reached over that store's
// own API. What makes that rung 3 rather than a longer path to the same place
// is that the key NEVER ENTERS this process: this signer holds a URL and a
// token, asks for a signature over a digest, and receives one.
//
// THE STORE IN THESE TESTS IS REAL CRYPTO BEHIND A FAKE TRANSPORT. The key is a
// genuine P-256 key held by the test server, signing genuine ECDSA signatures in
// the encoding the real store returns — measured on 2026-09-16 against the
// shipped store: `type: ecdsa-p256`, a PEM public key, and
// `prehashed=true, marshaling_algorithm=asn1` answering
// `vault:v1:<base64 ASN.1 DER>`. What is faked is the HTTP hop, because a test
// that needed the store running would not run in CI, and what is under test is
// this side of the wire.

// fakeTransit is the store's two endpoints, backed by a real key.
type fakeTransit struct {
	t       *testing.T
	key     *ecdsa.PrivateKey
	token   string
	signs   int
	revoked bool
}

func (f *fakeTransit) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/keys/innsegl-ca", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorised(w, r) {
			return
		}
		der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		if err != nil {
			f.t.Fatalf("marshalling the fake store's public key: %v", err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		writeJSON(w, map[string]any{"data": map[string]any{
			"type": "ecdsa-p256",
			"keys": map[string]any{"1": map[string]any{"public_key": string(pubPEM)}},
		}})
	})
	mux.HandleFunc("/v1/transit/sign/innsegl-ca", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorised(w, r) {
			return
		}
		var in struct {
			Input     string `json:"input"`
			Prehashed bool   `json:"prehashed"`
			Marshal   string `json:"marshaling_algorithm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.t.Fatalf("decoding the sign request: %v", err)
		}
		// The three properties the real store's contract turns on. A signer that
		// got any of them wrong would produce a signature nothing verifies, and
		// the failure would surface as an unusable CA rather than as an error.
		if !in.Prehashed {
			f.t.Error("the signer asked the store to hash for it; it must send a digest")
		}
		if in.Marshal != "asn1" {
			f.t.Errorf("marshaling_algorithm is %q, want asn1 — x509 wants ASN.1 DER", in.Marshal)
		}
		digest, err := base64.StdEncoding.DecodeString(in.Input)
		if err != nil {
			f.t.Fatalf("the input was not base64: %v", err)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest)
		if err != nil {
			f.t.Fatalf("the fake store could not sign: %v", err)
		}
		f.signs++
		writeJSON(w, map[string]any{"data": map[string]any{
			"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
		}})
	})
	return mux
}

func (f *fakeTransit) authorised(w http.ResponseWriter, r *http.Request) bool {
	if f.revoked || r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]any{"errors": []string{"permission denied"}})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func newFakeStore(t *testing.T) (*fakeTransit, *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the fake store's key: %v", err)
	}
	f := &fakeTransit{t: t, key: key, token: "test-token"}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv
}

// OPS-049: the signer holds no private key, and signs through the store.
func TestOPS049TheSignerHoldsNoPrivateKey(t *testing.T) {
	f, srv := newFakeStore(t)

	signer, err := newTransitSigner(srv.URL, f.token, "innsegl-ca")
	if err != nil {
		t.Fatalf("building the signer: %v", err)
	}

	// The public key is the store's, fetched over the wire.
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !pub.Equal(&f.key.PublicKey) {
		t.Error("the signer's public key is not the store's")
	}

	digest := sha256.Sum256([]byte("innsegl"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("signing through the store: %v", err)
	}
	if !ecdsa.VerifyASN1(&f.key.PublicKey, digest[:], sig) {
		t.Error("the signature does not verify under the store's public key")
	}
	if f.signs != 1 {
		t.Errorf("the store was asked for %d signatures, want 1", f.signs)
	}
}

// OPS-050: the minted certificate is a CA, self-signed, and verifies.
func TestOPS050TheMintedCertificateIsAUsableRoot(t *testing.T) {
	f, srv := newFakeStore(t)
	signer, err := newTransitSigner(srv.URL, f.token, "innsegl-ca")
	if err != nil {
		t.Fatalf("building the signer: %v", err)
	}

	der, err := mintRootCA(signer, "innsegl.dev")
	if err != nil {
		t.Fatalf("minting the root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the minted certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("the minted certificate is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the minted certificate may not sign certificates")
	}
	// Self-signed: it verifies under its own public key, which is the store's.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("the root does not verify under itself: %v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&f.key.PublicKey) {
		t.Error("the certificate does not carry the store's public key")
	}
}

// OPS-052: a revoked token stops issuance, and says so.
//
// A custody boundary whose failure is silent is worse than none: it reads as a
// working CA that has quietly stopped attesting.
func TestOPS052ARevokedTokenStopsIssuanceLoudly(t *testing.T) {
	f, srv := newFakeStore(t)
	signer, err := newTransitSigner(srv.URL, f.token, "innsegl-ca")
	if err != nil {
		t.Fatalf("building the signer: %v", err)
	}

	f.revoked = true
	digest := sha256.Sum256([]byte("innsegl"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err == nil {
		t.Fatalf("signing succeeded with a revoked token and returned %d bytes", len(sig))
	}
	// It has to be readable as a custody failure, not as a generic 403.
	for _, want := range []string{"transit", "token"} {
		if !strings.Contains(strings.ToLower(err.Error()), want) {
			t.Errorf("the refusal is %q; it does not mention %q, so an operator "+
				"cannot tell a revoked token from the store being down", err, want)
		}
	}
}

// A store that is unreachable at all is refused when the signer is built,
// rather than at first use — which would be during certificate issuance.
func TestOPS052AnUnreachableStoreIsRefusedAtStartup(t *testing.T) {
	_, err := newTransitSigner("http://127.0.0.1:1", "test-token", "innsegl-ca")
	if err == nil {
		t.Fatal("an unreachable store was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "transit") {
		t.Errorf("the refusal is %q; it never names the store", err)
	}
}
