// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StatusPath is the client service's own health route. Everything else is
// forwarded to the core.
const StatusPath = "/_client/status"

// SessionStatementPath is the core's session-workspace endpoint, where the
// session hook states each session's workspace through this service.
const SessionStatementPath = "/_gateway/session-workspace"

// StatementHeader carries the cached statement on a forwarded request: the
// statement's JSON body, base64url without padding (RM-313).
const StatementHeader = "X-Innsegl-Statement"

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
	// statements is the newest statement per (session, agent) the hook sent
	// through this service (RM-313).
	statements *statementCache

	// The availability layer (ADR-0068, fallback.go, journal.go).
	provider       *url.URL
	providerClient *http.Client
	coreDownFor    time.Duration
	downUntil      atomic.Int64
	journal        *journal
	uploadInterval time.Duration
	uploadKick     chan struct{}
	uploadMu       sync.Mutex
	lastUploadMu   sync.Mutex
	lastUpload     *UploadStatus
	bypassed       *seenSet
}

// ServerOptions are the client service's settings beyond its enrolment.
// The zero value is the shipped default.
type ServerOptions struct {
	// ProviderURL is where a model request goes when the core does not
	// answer; empty means core.json's provider_url, else
	// DefaultProviderURL. https only.
	ProviderURL string
	// ProviderClient sends to the provider; nil means one over the system
	// roots.
	ProviderClient *http.Client
	// JournalMaxBytes bounds the journal; zero means DefaultJournalMaxBytes.
	JournalMaxBytes int64
	// UploadInterval is the upload loop's period; zero means
	// DefaultUploadInterval.
	UploadInterval time.Duration
	// CoreDownFor is how long model requests skip the core after it failed
	// to answer; zero means DefaultCoreDownFor.
	CoreDownFor time.Duration
}

// NewServer loads the enrolment from paths. It refuses a key that is not
// the certificate's, and stays refusing once the core refused a renewal.
func NewServer(paths Paths, logw io.Writer) (*Server, error) {
	return NewServerWith(paths, logw, ServerOptions{})
}

// NewServerWith is NewServer with opts.
func NewServerWith(paths Paths, logw io.Writer, opts ServerOptions) (*Server, error) {
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
	providerRaw := opts.ProviderURL
	if providerRaw == "" {
		providerRaw = core.ProviderURL
	}
	provider, err := parseProvider(providerRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", paths.Core, err)
	}
	s := &Server{
		Now: time.Now, paths: paths, core: core, target: target, key: key,
		log:        log.New(logw, "innsegl client: ", log.LstdFlags),
		statements: newStatementCache(DefaultMaxStatements),
		provider:   provider, providerClient: opts.ProviderClient,
		coreDownFor: opts.CoreDownFor, uploadInterval: opts.UploadInterval,
		uploadKick: make(chan struct{}, 1), bypassed: newSeenSet(DefaultMaxStatements),
	}
	if s.providerClient == nil {
		s.providerClient = &http.Client{Transport: providerTransport()}
	}
	if s.coreDownFor <= 0 {
		s.coreDownFor = DefaultCoreDownFor
	}
	if s.uploadInterval <= 0 {
		s.uploadInterval = DefaultUploadInterval
	}
	if err := s.setCert(chain); err != nil {
		return nil, err
	}
	journalDir := paths.Journal
	if journalDir == "" {
		journalDir = filepath.Join(paths.Dir, "journal")
	}
	s.journal = openJournal(journalDir, core.InstallationID, key, opts.JournalMaxBytes)
	if s.journal.openErr != nil {
		s.log.Printf("the client journal at %s cannot be opened (%v): a request the core cannot record will be "+
			"refused until it can", journalDir, s.journal.openErr)
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
		// A core that does not answer is found out in seconds, so the
		// request goes to the provider instead (ADR-0068).
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	s.proxy = &httputil.ReverseProxy{
		// The request goes on unchanged apart from its destination and the
		// session's statement (attachStatement): the harness's own
		// Authorization header passes through, and no forwarding headers
		// are added.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			s.attachStatement(pr.Out)
		},
		// Flush every write at once: a model reply is a server-sent event
		// stream, and each event must reach the harness as it arrives.
		FlushInterval: -1,
		Transport:     s.transport,
		ErrorLog:      s.log,
		// The core's refusal reaches the harness unchanged; the local log
		// says what this service knows about it. A model exchange the core
		// cannot record is journaled (fallback.go).
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.proxyError,
	}
	return s, nil
}

// maxRefusalLogBytes bounds how much of a refusal's body is logged.
const maxRefusalLogBytes = 512

// explainRefusal logs a refusal of a request by the core. A 401 names no
// cause, on purpose: the log lists what it can mean. Any other refusal
// carries its own reason (the core's, or the provider's relayed), which is logged. The response itself is
// left as it came.
func (s *Server) explainRefusal(resp *http.Response) error {
	req := resp.Request
	if req.URL.Path == SessionStatementPath && resp.StatusCode >= 400 {
		s.logStatementRefusal(req, resp.StatusCode)
		return nil
	}
	if resp.StatusCode < 400 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return nil
	}
	session := req.Header.Get("X-Claude-Code-Session-Id")
	if session == "" {
		session = "(none)"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		s.log.Printf("the core refused %s %s for session %s (401). The core names no cause: this machine's "+
			"certificate or installation (revoked, suspended, expired), the stated repository's scope, or a session "+
			"pinned to another installation. GET %s shows the certificate and the installation.",
			req.Method, req.URL.Path, session, StatusPath)
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, maxRefusalLogBytes))
	if err != nil {
		return err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	s.log.Printf("the core answered %s %s for session %s with %d: %s",
		req.Method, req.URL.Path, session, resp.StatusCode, strings.TrimSpace(string(head)))
	return nil
}

// statementSessionKey carries a statement's session id from Handler to the
// response's log line.
type statementSessionKey struct{}

// rememberStatement keeps the statement r carries (statementCache) and
// leaves r's body as it was, for the core.
func (s *Server) rememberStatement(r *http.Request) (*http.Request, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxStatementBytes+1))
	if err != nil {
		return nil, err
	}
	// An oversized body goes on whole, for the core to refuse; it is not
	// remembered.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
	session := s.statements.remember(body)
	return r.WithContext(context.WithValue(r.Context(), statementSessionKey{}, session)), nil
}

// attachStatement sets the session's cached statement on a forwarded request,
// and removes any the harness sent itself: the statement is this service's
// to state.
func (s *Server) attachStatement(out *http.Request) {
	out.Header.Del(StatementHeader)
	if out.URL.Path == SessionStatementPath {
		return
	}
	session := out.Header.Get("X-Claude-Code-Session-Id")
	if session == "" {
		return
	}
	if v, ok := s.statements.lookup(session, out.Header.Get("X-Claude-Code-Agent-Id")); ok {
		out.Header.Set(StatementHeader, v)
	}
}

// logStatementRefusal says, with the session and a reason class, that the
// core did not accept a statement. The session is not stuck: its model
// requests are forwarded, unrecorded where the core cannot record them.
func (s *Server) logStatementRefusal(req *http.Request, status int) {
	session, ok := req.Context().Value(statementSessionKey{}).(string)
	if !ok || session == "" {
		session = "(none)"
	}
	var class string
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		class = "refused: the repository is outside this installation's scope, or the session belongs to " +
			"another installation"
	case status == http.StatusBadRequest:
		class = "malformed"
	case status == http.StatusTooManyRequests:
		class = "rate-limited"
	case status >= 500:
		class = "core-unavailable"
	default:
		class = "other"
	}
	s.log.Printf("the core did not accept the statement for session %s (%d, %s); "+
		"its model requests are forwarded, unrecorded where the core cannot record them", session, status, class)
}

func (s *Server) setCert(chain []*x509.Certificate) error {
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&s.key.PublicKey) {
		return errors.New("the client certificate is not for the client key")
	}
	if len(chain[0].URIs) != 1 {
		return errors.New("the client certificate does not name exactly one installation")
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
		if r.URL.Path == SessionStatementPath && r.Method == http.MethodPost {
			kept, err := s.rememberStatement(r)
			if err != nil {
				http.Error(w, "innsegl client: reading the statement: "+err.Error(), http.StatusBadRequest)
				return
			}
			r = kept
		}
		if r.Method == http.MethodPost && isModelPath(r.URL.Path) {
			s.serveModel(w, r)
			return
		}
		s.proxy.ServeHTTP(w, r)
	})
}

// Status is the body of GET /_client/status.
type Status struct {
	InstallationID       string        `json:"installation_id"`
	CoreURL              string        `json:"core_url"`
	CertificateExpiresAt time.Time     `json:"certificate_expires_at"`
	RenewAt              time.Time     `json:"renew_at"`
	CoreReachable        bool          `json:"core_reachable"`
	Revoked              bool          `json:"revoked"`
	Journal              JournalStatus `json:"journal"`
}

// Status answers what GET /_client/status shows.
func (s *Server) Status(ctx context.Context) Status {
	st := Status{
		InstallationID: s.core.InstallationID, CoreURL: s.core.CoreURL,
		CertificateExpiresAt: s.Leaf().NotAfter, RenewAt: s.RenewAt(), Revoked: s.revoked.Load(),
		Journal: s.journal.status(),
	}
	st.Journal.LastUpload = s.uploadStatus()
	st.CoreReachable = s.reachable(ctx)
	return st
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Status(r.Context())
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
	// The renewal names the same installation: the same single SAN.
	uri := s.Leaf().URIs[0]
	csr, err := newCSR(s.key, uri)
	if err != nil {
		return false, err
	}
	c := &http.Client{Transport: s.transport, Timeout: 30 * time.Second}
	got, err := requestCertificate(ctx, c, strings.TrimSuffix(s.core.CoreURL, "/")+RenewPath, map[string]string{"csr": csr}, s.key, uri)
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
