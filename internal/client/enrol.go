// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The core's enrolment contract (ADR-0063 decision 2).
const (
	EnrolPath = "/_core/enrol"
	RenewPath = "/_core/renew"
)

// ErrUnauthorized is the core's 401 to an enrolment: the token is unknown,
// spent or expired. The core does not say which.
var ErrUnauthorized = errors.New("the core refused the enrolment token (unknown, already used, or expired)")

// ErrRevoked is the core's 401 to a renewal: the installation was revoked
// or suspended.
var ErrRevoked = errors.New("the core refused renewal: this installation was revoked or suspended")

var (
	tokenShape = regexp.MustCompile(`^ie_[0-9a-f]{16}_[0-9a-f]{64}$`)
	idShape    = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ValidToken reports whether s has an enrolment token's shape.
func ValidToken(s string) bool { return tokenShape.MatchString(s) }

// EnrolOptions is one enrolment.
type EnrolOptions struct {
	CoreURL string
	Token   string
	Name    string
	// CA is the core's own CA, the only root trusted for the core.
	CA *x509.Certificate
}

// Enrolment is what a successful enrolment produced. Nothing is on disk
// until WriteEnrolment.
type Enrolment struct {
	CoreURL        string
	InstallationID string
	Key            *ecdsa.PrivateKey
	CA             *x509.Certificate
	issued
}

type issued struct {
	InstallationID string
	Chain          []*x509.Certificate
	ChainPEM       []byte
	BundlePEM      []byte
	ExpiresAt      time.Time
}

// Enrol generates a P-256 key, sends a certificate request with the token,
// and returns the result. The token goes only to a core whose certificate
// chains to opts.CA.
func Enrol(ctx context.Context, opts EnrolOptions) (*Enrolment, error) {
	if !ValidToken(opts.Token) {
		return nil, errors.New("the token does not have an enrolment token's shape (ie_<16 hex>_<64 hex>)")
	}
	if opts.CA == nil {
		return nil, errors.New("no CA for the core")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := newCSR(key)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(opts.CA)
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	body := map[string]string{"token": opts.Token, "csr": csr, "name": opts.Name}
	got, err := requestCertificate(ctx, httpClient, strings.TrimSuffix(opts.CoreURL, "/")+EnrolPath, body, key)
	if errors.Is(err, errStatus401) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	return &Enrolment{
		CoreURL: strings.TrimSuffix(opts.CoreURL, "/"), InstallationID: got.InstallationID,
		Key: key, CA: opts.CA, issued: got,
	}, nil
}

func newCSR(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

var errStatus401 = errors.New("401")

type issueResponse struct {
	InstallationID string `json:"installation_id"`
	Certificate    string `json:"certificate"`
	Bundle         string `json:"bundle"`
	ExpiresAt      string `json:"expires_at"`
}

// requestCertificate posts body to url and checks the answer: a 32-hex
// installation id, a chain whose leaf carries this machine's own public key,
// a bundle, and an expiry.
func requestCertificate(ctx context.Context, c *http.Client, url string, body any, key *ecdsa.PrivateKey) (issued, error) {
	var out issued
	payload, err := json.Marshal(body)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return out, fmt.Errorf("reaching the core: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return out, errStatus401
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the core answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var r issueResponse
	if uerr := json.Unmarshal(raw, &r); uerr != nil {
		return out, fmt.Errorf("the core's answer is not the enrolment shape: %w", uerr)
	}
	if !idShape.MatchString(r.InstallationID) {
		return out, fmt.Errorf("the core's installation id %q is not 32 lowercase hex", r.InstallationID)
	}
	chain, err := parseCertsPEM([]byte(r.Certificate))
	if err != nil {
		return out, fmt.Errorf("the core's certificate: %w", err)
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return out, errors.New("the core issued a certificate for a key other than this machine's")
	}
	if _, berr := parseCertsPEM([]byte(r.Bundle)); berr != nil {
		return out, fmt.Errorf("the core's trust bundle: %w", berr)
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return out, fmt.Errorf("the core's expires_at: %w", err)
	}
	return issued{
		InstallationID: r.InstallationID, Chain: chain,
		ChainPEM: []byte(r.Certificate), BundlePEM: []byte(r.Bundle), ExpiresAt: expires,
	}, nil
}

// ParseFingerprint reads "sha256:<64 hex>", colons between bytes allowed.
func ParseFingerprint(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:")
	if !ok {
		return nil, fmt.Errorf("fingerprint %q is not sha256:<hex>", s)
	}
	sum, err := hex.DecodeString(strings.ReplaceAll(rest, ":", ""))
	if err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("fingerprint %q is not sha256:<64 hex>", s)
	}
	return sum, nil
}

// FetchCA connects to the core once, finds the certificate in its chain
// whose SHA-256 fingerprint is the one given, and returns it only when it is
// a CA and the core's own certificate verifies against it for the core's
// name. Without a match it refuses: nothing is trusted on first use.
func FetchCA(ctx context.Context, coreURL, fingerprint string) (*x509.Certificate, error) {
	want, err := ParseFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(coreURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("the core URL %q is not https://<name>[:port]", coreURL)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	var found *x509.Certificate
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// The chain is checked below, against the pinned fingerprint, not
		// against the system roots: the core's CA is its own.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection against the pinned fingerprint
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				sum := sha256.Sum256(c.Raw)
				if bytes.Equal(sum[:], want) {
					found = c
					break
				}
			}
			if found == nil {
				return fmt.Errorf("no certificate the core presented matches the fingerprint %s", fingerprint)
			}
			if !found.IsCA {
				return fmt.Errorf("the certificate matching the fingerprint %s is not a CA", fingerprint)
			}
			roots := x509.NewCertPool()
			roots.AddCert(found)
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, verr := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
			if verr != nil {
				return fmt.Errorf("the core's certificate does not verify against the CA with fingerprint %s: %w", fingerprint, verr)
			}
			return nil
		},
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("fetching the core's CA: %w", err)
	}
	_ = conn.Close()
	return found, nil
}
