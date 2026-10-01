// SPDX-License-Identifier: Apache-2.0

// Package clienttest is a core that speaks the enrolment contract, for the
// tests of internal/client and of `innsegl connect` and `innsegl client
// serve`. It is a test helper only: nothing in a shipped binary imports it.
//
// The contract it implements: POST /_core/enrol without a client certificate
// takes {"token","csr","name"} and answers {"installation_id","certificate",
// "bundle","expires_at"}, or 401 for any token problem. POST /_core/renew
// with the current client certificate takes {"csr"} and answers the same
// shape. Every other route requires a client certificate the core issued.
// Its server certificate is issued by its own CA and served with that CA in
// the chain, as the gateway's is.
package clienttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// Token is the one enrolment token the fake core accepts.
const Token = "ie_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// InstallationID is the id the fake core gives the enrolled installation.
const InstallationID = "0123456789abcdef0123456789abcdef"

// Core is a running fake core.
type Core struct {
	Server *httptest.Server
	// CA is the core's own CA: it issued the server certificate.
	CA    *x509.Certificate
	CAPEM []byte
	// ClientCA issues client certificates; BundlePEM is its trust bundle.
	ClientCA  *x509.Certificate
	BundlePEM []byte

	caKey       *ecdsa.PrivateKey
	clientCAKey *ecdsa.PrivateKey

	mu sync.Mutex
	// Lifetime of issued client certificates (default 24h).
	Lifetime time.Duration
	// Now is the core's clock for NotBefore (default time.Now).
	Now func() time.Time
	// Revoked makes renew answer 401.
	Revoked bool
	// EnrolCalls and RenewCalls count the contract calls.
	EnrolCalls, RenewCalls int
	// Names records the name of each enrolment.
	Names []string
	// Seen records, for each request to any other route, the serial of
	// the client certificate it came with.
	Seen []*big.Int
	// Extra routes, served behind the client-certificate requirement.
	Mux       *http.ServeMux
	tokenUsed bool
	serial    int64
}

// New starts a fake core on 127.0.0.1.
func New() (*Core, error) {
	c := &Core{Lifetime: 24 * time.Hour, Now: time.Now, Mux: http.NewServeMux(), serial: 100}
	var err error
	if c.caKey, c.CA, err = selfSigned("fake core CA"); err != nil {
		return nil, err
	}
	if c.clientCAKey, c.ClientCA, err = selfSigned("fake client CA"); err != nil {
		return nil, err
	}
	c.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.CA.Raw})
	c.BundlePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ClientCA.Raw})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "core"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.CA, &leafKey.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.ClientCA)

	c.Server = httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	c.Server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der, c.CA.Raw}, PrivateKey: leafKey}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	c.Server.StartTLS()
	return c, nil
}

// Close stops the server.
func (c *Core) Close() { c.Server.Close() }

// URL is the core's https URL.
func (c *Core) URL() string { return c.Server.URL }

// HostPort is the core's listener address.
func (c *Core) HostPort() string {
	u, err := url.Parse(c.Server.URL)
	if err != nil {
		return ""
	}
	return u.Host
}

// Fingerprint is "sha256:<hex>" of the core CA's DER.
func (c *Core) Fingerprint() string {
	sum := sha256.Sum256(c.CA.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SetRevoked marks the installation revoked.
func (c *Core) SetRevoked(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Revoked = v
}

// Counts returns the enrol and renew call counts.
func (c *Core) Counts() (enrol, renew int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.EnrolCalls, c.RenewCalls
}

// SeenSerials returns the client certificate serials of forwarded requests.
func (c *Core) SeenSerials() []*big.Int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*big.Int(nil), c.Seen...)
}

func (c *Core) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_core/enrol":
		c.enrol(w, r)
		return
	case "/_core/renew":
		c.renew(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "a client certificate is required", http.StatusUnauthorized)
		return
	}
	c.mu.Lock()
	c.Seen = append(c.Seen, r.TLS.PeerCertificates[0].SerialNumber)
	c.mu.Unlock()
	c.Mux.ServeHTTP(w, r)
}

type enrolRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
	Name  string `json:"name"`
}

type issueResponse struct {
	InstallationID string `json:"installation_id"`
	Certificate    string `json:"certificate"`
	Bundle         string `json:"bundle"`
	ExpiresAt      string `json:"expires_at"`
}

func (c *Core) enrol(w http.ResponseWriter, r *http.Request) {
	var req enrolRequest
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.EnrolCalls++
	ok := req.Token == Token && !c.tokenUsed
	if ok {
		c.tokenUsed = true
		c.Names = append(c.Names, req.Name)
	}
	c.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c.issue(w, req.CSR)
}

func (c *Core) renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.RenewCalls++
	revoked := c.Revoked
	c.mu.Unlock()
	if revoked {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c.issue(w, req.CSR)
}

func (c *Core) issue(w http.ResponseWriter, csrB64 string) {
	der, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.serial++
	serial := c.serial
	notBefore := c.Now()
	lifetime := c.Lifetime
	c.mu.Unlock()
	id := &url.URL{Scheme: "spiffe", Host: "innsegl.test", Path: "/client/" + InstallationID}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{id},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, c.ClientCA, csr.PublicKey, c.clientCAKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("issue: %v", err), http.StatusInternalServerError)
		return
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ClientCA.Raw})...)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(issueResponse{
		InstallationID: InstallationID,
		Certificate:    string(chain),
		Bundle:         string(c.BundlePEM),
		ExpiresAt:      tmpl.NotAfter.UTC().Format(time.RFC3339),
	}); err != nil {
		return
	}
}

func selfSigned(cn string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}
