// SPDX-License-Identifier: Apache-2.0

// Package signprobe asks the CA for a real certificate, on a schedule, so
// "signing works" is measured rather than assumed (RM-339, #583).
//
// # Why a certificate, and not the root
//
// Readiness used to call signing up when Fulcio served its root certificate.
// The root is a file; Fulcio serves it while its CA key is out of reach, and
// a CA that could not sign for twelve hours was reported up for all twelve.
// The only answer to "can the CA sign" is a signature by the CA, so the probe
// asks for one: a fresh key, a credential for a probe identity, one
// certificate. It passes when the certificate carries that key, names that
// identity, and chains to the trust root.
//
// # What it does not do
//
// It writes nothing to the transparency log: the certificate is thrown away
// with its key, and no Rekor entry, permanent and public, records a probe.
// It writes nothing to the ledger. The probe identity is a run identity in
// the existing grammar, spiffe://{trust-domain}/agent/{agent-type}/{task-id}/
// {run-id}, inside the subtree SPIRE's mint policy already admits; it has no
// registration entry and needs none, as get_credential's identities need none
// to be minted.
package signprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

const (
	// DefaultInterval is how often the core probes. With a result stale
	// after two intervals, a CA that stops signing is reported within ten
	// minutes.
	DefaultInterval = 5 * time.Minute

	// Audience is the audience the probe's credential is minted for: the one
	// Fulcio accepts, the signer's own (internal/signing.AudienceSigstore).
	Audience = "sigstore"

	// The probe identity's three path components. Literal on purpose: the
	// certificate never leaves this process and no log records it, so there
	// is nothing a pseudonym would hide.
	probeAgentType = "innsegl-signing-probe"
	probeTaskID    = "scheduled"
	probeRunID     = "probe"

	fulcioRootPath        = "/api/v1/rootCert"
	fulcioSigningCertPath = "/api/v2/signingCert"

	// defaultTimeout bounds one probe end to end.
	defaultTimeout = 30 * time.Second

	maxBody = 1 << 20
)

// Identity is the probe's SPIFFE ID in trustDomain. It is checked against
// the protected grammar (doc 02 §5), never a second definition of it.
func Identity(trustDomain string) (string, error) {
	id := "spiffe://" + trustDomain + "/agent/" + probeAgentType + "/" + probeTaskID + "/" + probeRunID
	if err := event.ValidateSPIFFEID(id); err != nil {
		return "", err
	}
	return id, nil
}

// MintFunc mints one JWT-SVID for spiffeID and audience and returns the
// token. In the core it is the SPIRE server's MintJWTSVID, over the admin
// connection get_credential already uses.
type MintFunc func(ctx context.Context, spiffeID, audience string) (string, error)

// Config configures a Prober.
type Config struct {
	// FulcioURL is the base URL of the CA. Required.
	FulcioURL string
	// TrustDomain names the probe identity's trust domain. Required.
	TrustDomain string
	// Mint mints the probe's credential. Required.
	Mint MintFunc
	// Roots is the trust root a certificate must chain to. Nil means the
	// root Fulcio publishes, read fresh on every probe: the root the signer
	// hands gitsign and a verifier checks against.
	Roots func(context.Context) (*x509.CertPool, error)
	// Client is the HTTP client. Nil means one bounded by Timeout.
	Client *http.Client
	// Timeout bounds one probe. Zero means 30 seconds.
	Timeout time.Duration
}

// Prober runs the signing probe.
type Prober struct {
	fulcio   *url.URL
	identity string
	mint     MintFunc
	roots    func(context.Context) (*x509.CertPool, error)
	client   *http.Client
	timeout  time.Duration
}

// Result is one probe's outcome.
type Result struct {
	// OK is true when the CA issued a certificate that passed every check.
	OK bool
	// At is when the probe finished.
	At time.Time
	// Reason says why it failed, in words an operator acts on. Empty on a
	// pass.
	Reason string
}

// New builds a Prober. A configuration that cannot probe is refused here,
// not reported as a signing outage every five minutes.
func New(cfg Config) (*Prober, error) {
	if cfg.FulcioURL == "" {
		return nil, errors.New("signing probe: no Fulcio URL")
	}
	u, err := url.Parse(cfg.FulcioURL)
	if err != nil {
		return nil, fmt.Errorf("signing probe: the Fulcio URL %q: %w", cfg.FulcioURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("signing probe: the Fulcio URL %q has no http(s) scheme", cfg.FulcioURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("signing probe: the Fulcio URL %q names no host", cfg.FulcioURL)
	}
	id, err := Identity(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("signing probe: %w", err)
	}
	if cfg.Mint == nil {
		return nil, errors.New("signing probe: nothing to mint the probe's credential with")
	}
	p := &Prober{fulcio: u, identity: id, mint: cfg.Mint, roots: cfg.Roots, client: cfg.Client, timeout: cfg.Timeout}
	if p.timeout <= 0 {
		p.timeout = defaultTimeout
	}
	if p.client == nil {
		p.client = &http.Client{Timeout: p.timeout}
	}
	if p.roots == nil {
		p.roots = p.fulcioRoots
	}
	return p, nil
}

// Probe asks the CA for one certificate and checks it.
func (p *Prober) Probe(ctx context.Context) Result {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	err := p.probe(ctx)
	r := Result{OK: err == nil, At: time.Now().UTC()}
	if err != nil {
		r.Reason = err.Error()
	}
	return r
}

func (p *Prober) probe(ctx context.Context) error {
	roots, err := p.roots(ctx)
	if err != nil {
		return fmt.Errorf("reading the trust root: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("making the probe's key: %w", err)
	}
	token, err := p.mint(ctx, p.identity, Audience)
	if err != nil {
		return fmt.Errorf("minting the probe's credential: %w", err)
	}
	chain, err := p.requestCertificate(ctx, key, token)
	if err != nil {
		return err
	}
	return p.check(chain, key, roots)
}

// signingCertRequest is Fulcio's v2 CreateSigningCertificate request, as its
// HTTP gateway spells it.
type signingCertRequest struct {
	Credentials struct {
		OIDCIdentityToken string `json:"oidcIdentityToken"`
	} `json:"credentials"`
	PublicKeyRequest struct {
		PublicKey struct {
			Algorithm string `json:"algorithm"`
			Content   string `json:"content"`
		} `json:"publicKey"`
		// ProofOfPossession is the key's signature over the token's
		// subject, the SPIFFE ID; JSON carries bytes as base64.
		ProofOfPossession []byte `json:"proofOfPossession"`
	} `json:"publicKeyRequest"`
}

type certificateChain struct {
	Chain struct {
		Certificates []string `json:"certificates"`
	} `json:"chain"`
}

type signingCertResponse struct {
	Embedded *certificateChain `json:"signedCertificateEmbeddedSct"`
	Detached *certificateChain `json:"signedCertificateDetachedSct"`
}

func (p *Prober) requestCertificate(ctx context.Context, key *ecdsa.PrivateKey, token string) ([]string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding the probe's key: %w", err)
	}
	sum := sha256.Sum256([]byte(p.identity))
	pop, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("signing the proof of possession: %w", err)
	}
	var req signingCertRequest
	req.Credentials.OIDCIdentityToken = token
	req.PublicKeyRequest.PublicKey.Algorithm = "ECDSA"
	req.PublicKeyRequest.PublicKey.Content = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	req.PublicKeyRequest.ProofOfPossession = pop
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding the request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.fulcio.JoinPath(fulcioSigningCertPath).String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("asking Fulcio for a certificate: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("asking Fulcio for a certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading Fulcio's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("the CA refused the certificate: HTTP %d: %s", resp.StatusCode, fulcioMessage(payload))
	}
	var got signingCertResponse
	if err := json.Unmarshal(payload, &got); err != nil {
		return nil, fmt.Errorf("the CA sent an unreadable answer: %w", err)
	}
	chain := got.Embedded
	if chain == nil {
		chain = got.Detached
	}
	if chain == nil || len(chain.Chain.Certificates) == 0 {
		return nil, errors.New("the CA answered with no certificate")
	}
	return chain.Chain.Certificates, nil
}

// fulcioMessage is the gateway's error message, or the body's first line.
func fulcioMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

// check is the pass condition: the leaf carries the probe's key, names the
// probe identity, and chains to the trust root.
func (p *Prober) check(chain []string, key *ecdsa.PrivateKey, roots *x509.CertPool) error {
	certs := make([]*x509.Certificate, 0, len(chain))
	for _, c := range chain {
		cert, err := parseCertificate([]byte(c))
		if err != nil {
			return fmt.Errorf("the CA's certificate %w", err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return errors.New("the CA issued a certificate for a key that is not the key the probe made")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != p.identity {
		return fmt.Errorf("the CA's certificate names %s, not the probe identity %s", uriList(leaf), p.identity)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	// At the moment of issue: the question is whose key signed it, and a
	// clock a second behind Fulcio's must not answer it.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: leaf.NotBefore,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("the CA's certificate does not chain to the trust root: %w", err)
	}
	return nil
}

func uriList(c *x509.Certificate) string {
	if len(c.URIs) == 0 {
		return "no identity"
	}
	s := make([]string, len(c.URIs))
	for i, u := range c.URIs {
		s[i] = u.String()
	}
	return strings.Join(s, ", ")
}

func parseCertificate(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("is not a PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	return c, nil
}

// fulcioRoots reads the chain Fulcio publishes. Every certificate in it is
// a trust anchor: it is the chain the signer hands gitsign, so a
// certificate that does not chain to it would not verify either.
func (p *Prober) fulcioRoots(ctx context.Context) (*x509.CertPool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.fulcio.JoinPath(fulcioRootPath).String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, fulcioRootPath)
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := body; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, perr := x509.ParseCertificate(blk.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", fulcioRootPath, perr)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s served no certificate", fulcioRootPath)
	}
	return pool, nil
}
