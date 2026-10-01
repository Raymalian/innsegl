// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StatusPath is the client service's own health route. Everything else is
// forwarded to the core.
const StatusPath = "/_client/status"

// renewRetry is how long a failed renewal (other than a refusal) waits
// before it is tried again.
const renewRetry = time.Minute

// Server is `innsegl client serve`: the one holder of the machine's key, a
// reverse proxy from loopback to the core over the client certificate.
type Server struct {
	// Now is the clock renewal decisions read; tests replace it.
	Now func() time.Time

	paths     Paths
	core      CoreConfig
	target    *url.URL
	key       *ecdsa.PrivateKey
	cert      atomic.Pointer[tls.Certificate]
	revoked   atomic.Bool
	transport *http.Transport
	proxy     *httputil.ReverseProxy
	log       *log.Logger
	renewMu   sync.Mutex
}

// NewServer loads the enrolment from paths. It refuses a key that is not
// the certificate's, and stays refusing once the core refused a renewal.
func NewServer(paths Paths, logw io.Writer) (*Server, error) {
	core, err := ReadCoreConfig(paths)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(core.CoreURL)
	if err != nil || target.Scheme != "https" {
		return nil, fmt.Errorf("%s: core_url %q is not an https URL", paths.Core, core.CoreURL)
	}
	key, err := loadKey(paths.Key)
	if err != nil {
		return nil, fmt.Errorf("reading the client key: %w", err)
	}
	chain, err := loadCerts(paths.Cert)
	if err != nil {
		return nil, fmt.Errorf("reading the client certificate: %w", err)
	}
	cas, err := loadCerts(paths.CA)
	if err != nil {
		return nil, fmt.Errorf("reading the core's CA: %w", err)
	}
	s := &Server{
		Now: time.Now, paths: paths, core: core, target: target, key: key,
		log: log.New(logw, "innsegl client: ", log.LstdFlags),
	}
	if err := s.setCert(chain); err != nil {
		return nil, err
	}
	if _, err := os.Stat(paths.Revoked); err == nil {
		s.revoked.Store(true)
		s.log.Printf("%v; refusing every request. Run `innsegl connect --disconnect`, then enrol again.", ErrRevoked)
	}

	roots := x509.NewCertPool()
	for _, c := range cas {
		roots.AddCert(c)
	}
	s.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			// Only the core's own CA: never the system roots.
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return s.cert.Load(), nil
			},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	s.proxy = &httputil.ReverseProxy{
		// The request goes on unchanged apart from its destination: the
		// harness's own Authorization header passes through, and no
		// forwarding headers are added.
		Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		// Flush every write at once: a model reply is a server-sent event
		// stream, and each event must reach the harness as it arrives.
		FlushInterval: -1,
		Transport:     s.transport,
		ErrorLog:      s.log,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.log.Printf("forwarding to %s: %v", core.CoreURL, err)
			http.Error(w, fmt.Sprintf("innsegl client: the core at %s did not answer: %v", core.CoreURL, err), http.StatusBadGateway)
		},
	}
	return s, nil
}

func (s *Server) setCert(chain []*x509.Certificate) error {
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&s.key.PublicKey) {
		return errors.New("the client certificate is not for the client key")
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	s.cert.Store(&tls.Certificate{Certificate: ders, PrivateKey: s.key, Leaf: chain[0]})
	return nil
}

// Leaf is the client certificate currently presented.
func (s *Server) Leaf() *x509.Certificate { return s.cert.Load().Leaf }

// RenewAt is the current certificate's half-life.
func (s *Server) RenewAt() time.Time {
	leaf := s.Leaf()
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
}

// Handler serves the status route and forwards everything else.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == StatusPath {
			s.serveStatus(w, r)
			return
		}
		if s.revoked.Load() {
			http.Error(w, "innsegl client: this installation was revoked; the core refused its renewal. "+
				"Run `innsegl connect --disconnect`, then enrol again with a new token.", http.StatusForbidden)
			return
		}
		s.proxy.ServeHTTP(w, r)
	})
}

// Status is the body of GET /_client/status.
type Status struct {
	InstallationID       string    `json:"installation_id"`
	CoreURL              string    `json:"core_url"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	RenewAt              time.Time `json:"renew_at"`
	CoreReachable        bool      `json:"core_reachable"`
	Revoked              bool      `json:"revoked"`
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	st := Status{
		InstallationID: s.core.InstallationID, CoreURL: s.core.CoreURL,
		CertificateExpiresAt: s.Leaf().NotAfter, RenewAt: s.RenewAt(), Revoked: s.revoked.Load(),
	}
	st.CoreReachable = s.reachable(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(st); err != nil {
		s.log.Printf("writing the status: %v", err)
	}
}

// reachable asks whether the core completes a mutually authenticated
// exchange: any HTTP answer counts.
func (s *Server) reachable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.core.CoreURL+"/", nil)
	if err != nil {
		return false
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// MaybeRenew renews the certificate when its half-life has passed, with a
// fresh request from the same key. A 401 means the installation was revoked
// or suspended: the service then refuses every request, says so in its log,
// and never asks again.
func (s *Server) MaybeRenew(ctx context.Context) (bool, error) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	if s.revoked.Load() {
		return false, ErrRevoked
	}
	if s.Now().Before(s.RenewAt()) {
		return false, nil
	}
	csr, err := newCSR(s.key)
	if err != nil {
		return false, err
	}
	c := &http.Client{Transport: s.transport, Timeout: 30 * time.Second}
	got, err := requestCertificate(ctx, c, strings.TrimSuffix(s.core.CoreURL, "/")+RenewPath, map[string]string{"csr": csr}, s.key)
	if errors.Is(err, errStatus401) {
		s.revoked.Store(true)
		// #nosec G306 -- a marker; its presence is the whole content.
		if werr := os.WriteFile(s.paths.Revoked, []byte(s.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); werr != nil {
			s.log.Printf("recording the revocation: %v", werr)
		}
		s.log.Printf("%v. Refusing every request from now on. Run `innsegl connect --disconnect`, then enrol again with a new token.", ErrRevoked)
		return false, ErrRevoked
	}
	if err != nil {
		s.log.Printf("renewing the client certificate: %v", err)
		return false, err
	}
	if err := writeFileAtomic(s.paths.Cert, got.ChainPEM, 0o644); err != nil {
		return false, fmt.Errorf("writing the renewed certificate: %w", err)
	}
	if err := writeFileAtomic(s.paths.Bundle, got.BundlePEM, 0o644); err != nil {
		return false, fmt.Errorf("writing the renewed bundle: %w", err)
	}
	if err := s.setCert(got.Chain); err != nil {
		return false, err
	}
	// Connections already open still carry the old certificate.
	s.transport.CloseIdleConnections()
	s.log.Printf("renewed the client certificate; it expires %s", got.Chain[0].NotAfter.UTC().Format(time.RFC3339))
	return true, nil
}

// RunRenewal renews at each half-life until ctx ends or the core refuses.
// A certificate already past half-life at start is renewed at once.
func (s *Server) RunRenewal(ctx context.Context) {
	for {
		wait := s.RenewAt().Sub(s.Now())
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		_, err := s.MaybeRenew(ctx)
		if errors.Is(err, ErrRevoked) {
			return
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(renewRetry):
			}
		}
	}
}

// CheckLoopback refuses a listen address that is not loopback: the local
// endpoint forwards with the machine's certificate and authenticates no
// caller of its own.
func CheckLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("listen address %q is not a loopback address; the client endpoint must listen on loopback only", addr)
}
