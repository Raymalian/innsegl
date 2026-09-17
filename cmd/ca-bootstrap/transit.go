// SPDX-License-Identifier: Apache-2.0

// Command ca-bootstrap mints the Fulcio root whose private key lives in a
// secret store and never leaves it — rung 3 of RM-147 (#238).
//
// WHY THIS IS ITS OWN PROGRAM AND NOT AN `innsegl` SUBCOMMAND. The same
// argument deploy/compose/innsegl.yml makes about the pseudonymisation secret:
// "The innsegl image could have generated the secret itself, but that would put
// key generation inside the binary that holds SPIRE admin." Nothing here needs
// the ledger, SPIRE or the MCP, and a separate binary is a smaller thing to get
// right — and a smaller thing to reason about when it is the program that
// decides what the CA's certificate says.
//
// WHY IT SPEAKS HTTP RATHER THAN USING A CLIENT LIBRARY. The store's transit
// API is three calls and stdlib covers all three. A KMS client library would
// pull a dependency tree into a repository that has eleven direct dependencies,
// for the sake of two JSON requests whose shape is measured in the tests beside
// this file.
//
// WHAT RUNG 3 ACTUALLY BUYS, stated so nobody has to infer it: reading the CA's
// container stops yielding the KEY and starts yielding the ability to ask for
// signatures while a token is valid. That is revocable and auditable; a stolen
// key is neither. It is not "the CA cannot be abused" — it is "abuse has an
// expiry and a log".
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// transitSigner is a crypto.Signer whose private key is somewhere else.
//
// It holds a URL, a token and a key name. That is the whole of its state, and
// the whole of what an attacker who reads this process gets.
type transitSigner struct {
	base   string
	token  string
	key    string
	pub    *ecdsa.PublicKey
	client *http.Client
}

// newTransitSigner fetches the public key, which doubles as the reachability
// and authorisation check.
//
// FAILING HERE RATHER THAN AT FIRST USE IS THE POINT. First use is certificate
// issuance; a CA that starts and then cannot sign is the silent failure OPS-052
// exists to forbid.
func newTransitSigner(base, token, key string) (*transitSigner, error) {
	s := &transitSigner{
		base:   trimRight(base),
		token:  token,
		key:    key,
		client: httpClient(),
	}
	pub, err := s.publicKey()
	if err != nil {
		return nil, err
	}
	s.pub = pub
	return s, nil
}

func (s *transitSigner) Public() crypto.PublicKey { return s.pub }

// Sign sends a DIGEST and receives a signature. The message never leaves the
// caller, and the key never arrives.
//
// prehashed=true and marshaling_algorithm=asn1 are not defaults and not
// preferences: x509.CreateCertificate hands a digest and expects ASN.1 DER
// back. Measured against the shipped store on 2026-09-16; the tests beside this
// file assert both on every call, because getting either wrong produces a
// signature that verifies nowhere and an error message about certificates.
func (s *transitSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"input":                base64.StdEncoding.EncodeToString(digest),
		"prehashed":            true,
		"hash_algorithm":       "sha2-256",
		"marshaling_algorithm": "asn1",
	})
	if err != nil {
		return nil, fmt.Errorf("transit: encoding the sign request: %w", err)
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := s.call(http.MethodPost, "/v1/transit/sign/"+s.key, body, &out); err != nil {
		return nil, err
	}
	// `vault:v1:<base64>` — the version prefix is the store's key rotation, and
	// dropping it silently would be how a rotated key produced garbage.
	_, encoded, found := strings.Cut(strings.TrimPrefix(out.Data.Signature, "vault:"), ":")
	if !found {
		return nil, fmt.Errorf("transit: the store returned a signature this does not "+
			"recognise (%q); expected vault:v<n>:<base64>", out.Data.Signature)
	}
	sig, decodeErr := base64.StdEncoding.DecodeString(encoded)
	if decodeErr != nil {
		return nil, fmt.Errorf("transit: the signature was not base64: %w", decodeErr)
	}
	return sig, nil
}

func (s *transitSigner) publicKey() (*ecdsa.PublicKey, error) {
	var out struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := s.call(http.MethodGet, "/v1/transit/keys/"+s.key, nil, &out); err != nil {
		return nil, err
	}
	if out.Data.Type != "ecdsa-p256" {
		return nil, fmt.Errorf("transit: key %q is %q; this mints a P-256 root and the "+
			"key has to match, or the certificate would name an algorithm the store "+
			"cannot sign with", s.key, out.Data.Type)
	}
	// The HIGHEST version, which is the one the store signs with. Taking "1"
	// would keep working until the first rotation and then mint a root whose
	// public key is not the one signing.
	best := 0
	latest := ""
	for v, k := range out.Data.Keys {
		n := 0
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			continue
		}
		if n > best {
			best, latest = n, k.PublicKey
		}
	}
	if latest == "" {
		return nil, fmt.Errorf("transit: key %q has no versions", s.key)
	}
	block, _ := pem.Decode([]byte(latest))
	if block == nil {
		return nil, fmt.Errorf("transit: the public key for %q is not PEM", s.key)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("transit: parsing the public key for %q: %w", s.key, err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transit: the public key for %q is %T, not ECDSA", s.key, parsed)
	}
	return pub, nil
}

// call is the whole transport. Every failure names `transit` and, where the
// store said why, says that too — OPS-052 asserts an operator can tell a
// revoked token from a store that is down.
func (s *transitSigner) call(method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, reader)
	if err != nil {
		return fmt.Errorf("transit: building the request to %s: %w", path, err)
	}
	req.Header.Set("X-Vault-Token", s.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("transit: the secret store at %s is not answering: %w", s.base, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("transit: reading the reply from %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("transit: the store refused this token (%s on %s): %s. "+
			"The CA's token has been revoked or has expired; issuance stops until it is "+
			"replaced, which is the boundary working rather than the store being down",
			resp.Status, path, firstError(payload))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("transit: %s on %s: %s", resp.Status, path, firstError(payload))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("transit: decoding the reply from %s: %w", path, err)
	}
	return nil
}

// firstError pulls the store's own message out, so a refusal says what the
// store said rather than only what HTTP said.
func firstError(payload []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(payload, &e); err == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	if len(payload) == 0 {
		return "(no message)"
	}
	return strings.TrimSpace(string(payload))
}

// mintRootCA builds the self-signed root Fulcio will present, signed through
// the store.
//
// SELF-SIGNED, and the signature is made by a key this process cannot read.
// That is the whole trick: x509.CreateCertificate takes a crypto.Signer and
// never asks for the private key, so the root is produced without the key ever
// being in this address space.
func mintRootCA(signer crypto.Signer, trustDomain string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca-bootstrap: serial number: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{trustDomain},
			CommonName:   trustDomain + " innsegl CA",
		},
		NotBefore: now.Add(-5 * time.Minute),
		// Ten years. A root's life is not a security control — what bounds
		// exposure here is the TOKEN, which is revocable — and a root that
		// expires mid-deployment invalidates nothing already logged but stops
		// every new signature at once.
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
}

// trimRight and httpClient are shared with ensureKey, which builds a signer
// before there is a key to fetch a public half of.
func trimRight(base string) string { return strings.TrimRight(base, "/") }

func httpClient() *http.Client { return &http.Client{Timeout: 15 * time.Second} }
