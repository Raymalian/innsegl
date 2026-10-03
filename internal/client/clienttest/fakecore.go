// SPDX-License-Identifier: Apache-2.0

// Package clienttest is a core that speaks the enrolment contract, for the
// tests of internal/client and of `innsegl connect` and `innsegl client
// serve`. It is a test helper only: nothing in a shipped binary imports it.
//
// The contract it enforces (#460):
//
//   - GET /_core/enrol, no client certificate, answers {"trust_domain"}.
//   - POST /_core/enrol, no client certificate, takes {"token","csr","name"}.
//     The CSR must carry exactly one SAN, the URI
//     spiffe://<td>/client/<32 lowercase hex>, chosen by the client. A bad
//     CSR is 400 before the token is touched; an id already in use is 400
//     without spending the token; a mint failure is 503 with nothing spent;
//     any token problem is 401. It answers {"installation_id","certificate",
//     "bundle","expires_at"}, the installation id being the CSR's.
//   - POST /_core/renew with the current client certificate takes {"csr"},
//     whose SAN must be the certificate's own, and answers the same shape; a
//     revoked installation is 401.
//   - Every other route needs a client certificate the core issued: 401
//     {"error":"innsegl core: request refused"} without one.
//
// Its server certificate is issued by its own CA and served with that CA in
// the chain, as the gateway's is.
package clienttest

import (
	"context"
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
	"regexp"
	"strings"
	"sync"
	"time"
)

// Token is the one enrolment token the fake core accepts.
const Token = "ie_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TrustDomain is the fake core's trust domain.
const TrustDomain = "innsegl.test"

var clientPath = regexp.MustCompile(`^/client/[0-9a-f]{32}$`)

// Core is a running fake core.
type Core struct {
	Server *httptest.Server
	// CA is the core's own CA: it issued the server certificate.
	CA    *x509.Certificate
	CAPEM []byte
	// ClientCA issues client certificates; BundlePEM is its trust bundle.
	ClientCA  *x509.Certificate
	BundlePEM []byte
	addr      string
	tlsConfig *tls.Config

	// Mux holds extra routes, served behind the client-certificate
	// requirement.
	Mux *http.ServeMux

	caKey       *ecdsa.PrivateKey
	clientCAKey *ecdsa.PrivateKey

	mu           sync.Mutex
	lifetime     time.Duration
	revoked      bool
	unavailable  bool
	idTaken      int
	echoWrongID  bool
	tokenUsed    bool
	serial       int64
	enrolCalls   int
	renewCalls   int
	calls        []string
	names        []string
	requestedIDs []string
	enrolledID   string
	lastCSR      *x509.CertificateRequest
	seen         []*big.Int
}

// New starts a fake core on 127.0.0.1.
func New() (*Core, error) {
	c := &Core{lifetime: 24 * time.Hour, Mux: http.NewServeMux(), serial: 100}
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

// SetRevoked marks the installation revoked: renew answers 401.
func (c *Core) SetRevoked(v bool) { c.locked(func() { c.revoked = v }) }

// SetUnavailable makes enrolment answer 503, spending nothing.
func (c *Core) SetUnavailable(v bool) { c.locked(func() { c.unavailable = v }) }

// SetIDTaken makes the next n enrolments answer 400 "id in use".
func (c *Core) SetIDTaken(n int) { c.locked(func() { c.idTaken = n }) }

// SetEchoWrongID makes enrolment answer with an installation id other than
// the CSR's.
func (c *Core) SetEchoWrongID(v bool) { c.locked(func() { c.echoWrongID = v }) }

func (c *Core) locked(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// Counts returns the enrol (POST) and renew call counts.
func (c *Core) Counts() (enrol, renew int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enrolCalls, c.renewCalls
}

// Calls lists "METHOD path" of every request to the contract's routes.
func (c *Core) Calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// Names lists the name of each successful enrolment.
func (c *Core) Names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
}

// RequestedIDs lists the installation id of each enrolment request.
func (c *Core) RequestedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requestedIDs...)
}

// EnrolledID is the installation id the core recorded.
func (c *Core) EnrolledID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enrolledID
}

// LastCSR is the most recent certificate request, enrolment or renewal.
func (c *Core) LastCSR() *x509.CertificateRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastCSR
}

// SeenSerials returns the client certificate serials of forwarded requests.
func (c *Core) SeenSerials() []*big.Int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*big.Int(nil), c.seen...)
}

func (c *Core) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_core/enrol", "/_core/renew":
		c.locked(func() { c.calls = append(c.calls, r.Method+" "+r.URL.Path) })
		if r.URL.Path == "/_core/enrol" {
			c.enrol(w, r)
		} else {
			c.renew(w, r)
		}
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		refuse(w)
		return
	}
	c.locked(func() { c.seen = append(c.seen, r.TLS.PeerCertificates[0].SerialNumber) })
	c.Mux.ServeHTTP(w, r)
}

func refuse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `{"error":"innsegl core: request refused"}`)
}

// clientID checks the CSR names exactly one SAN, the client URI in this
// trust domain, and returns its id.
func clientID(csr *x509.CertificateRequest) (string, bool) {
	if len(csr.URIs) != 1 || len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses) != 0 {
		return "", false
	}
	u := csr.URIs[0]
	if u.Scheme != "spiffe" || u.Host != TrustDomain || !clientPath.MatchString(u.Path) {
		return "", false
	}
	return strings.TrimPrefix(u.Path, "/client/"), true
}

func (c *Core) enrol(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"trust_domain":%q}`, TrustDomain)
		return
	}
	var req struct {
		Token string `json:"token"`
		CSR   string `json:"csr"`
		Name  string `json:"name"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.enrolCalls++
	c.mu.Unlock()
	csr, ok := parseCSR(req.CSR)
	if !ok {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	id, ok := clientID(csr)
	c.mu.Lock()
	c.lastCSR = csr
	c.requestedIDs = append(c.requestedIDs, id)
	switch {
	case !ok:
		c.mu.Unlock()
		http.Error(w, "the csr must name exactly spiffe://"+TrustDomain+"/client/<32 hex>", http.StatusBadRequest)
		return
	case c.unavailable:
		c.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "identity authority unavailable", http.StatusServiceUnavailable)
		return
	case req.Token != Token || c.tokenUsed:
		c.mu.Unlock()
		refuse(w)
		return
	case c.idTaken > 0:
		c.idTaken--
		c.mu.Unlock()
		http.Error(w, "installation id in use", http.StatusBadRequest)
		return
	}
	c.tokenUsed = true
	c.names = append(c.names, req.Name)
	c.enrolledID = id
	echo := id
	if c.echoWrongID {
		echo = strings.Repeat("f", 32)
	}
	c.mu.Unlock()
	c.issue(w, csr, echo)
}

func (c *Core) renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		refuse(w)
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
	c.renewCalls++
	revoked := c.revoked
	c.mu.Unlock()
	if revoked {
		refuse(w)
		return
	}
	csr, ok := parseCSR(req.CSR)
	if !ok {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	c.locked(func() { c.lastCSR = csr })
	id, ok := clientID(csr)
	peer := r.TLS.PeerCertificates[0]
	if !ok || len(peer.URIs) != 1 || peer.URIs[0].String() != csr.URIs[0].String() {
		http.Error(w, "the csr must name this installation", http.StatusBadRequest)
		return
	}
	c.issue(w, csr, id)
}

func parseCSR(b64 string) (*x509.CertificateRequest, bool) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, false
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, false
	}
	return csr, true
}

func (c *Core) issue(w http.ResponseWriter, csr *x509.CertificateRequest, installationID string) {
	c.mu.Lock()
	c.serial++
	serial := c.serial
	lifetime := c.lifetime
	c.mu.Unlock()
	notBefore := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         csr.URIs,
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, c.ClientCA, csr.PublicKey, c.clientCAKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("issue: %v", err), http.StatusServiceUnavailable)
		return
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ClientCA.Raw})...)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"installation_id": installationID,
		"certificate":     string(chain),
		"bundle":          string(c.BundlePEM),
		"expires_at":      tmpl.NotAfter.UTC().Format(time.RFC3339),
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

// Stop closes the core's listener, as a core that went down; Restart serves
// again on the same address with the same certificate, as one that came
// back.
func (c *Core) Stop() {
	c.addr = c.Server.Listener.Addr().String()
	c.tlsConfig = c.Server.TLS
	c.Server.Close()
}

// Restart serves the core again on the address Stop left. It fails the test
// when the address cannot be bound again.
func (c *Core) Restart(t interface {
	Helper()
	Fatalf(string, ...any)
}) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", c.addr)
	if err != nil {
		t.Fatalf("restart the fake core on %s: %v", c.addr, err)
	}
	c.Server = httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	c.Server.Listener = ln
	c.Server.TLS = c.tlsConfig
	c.Server.StartTLS()
}
