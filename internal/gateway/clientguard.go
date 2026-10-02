// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/spire"
)

// The client-certificate guard (RM-284, #460; ADR-0063 decision 5).
//
// In hosted mode every client-facing route of the gateway's listener (model
// traffic, the session endpoints, the commit path, telemetry) requires a
// client certificate that verifies against the deployment's X.509 bundle,
// names spiffe://<td>/client/<installation id>, and belongs to an
// installation that is active. The TLS layer only requests the certificate;
// this guard decides, in the HTTP layer, so that one route (enrolment) can
// be reached without one and every other refusal has one shape.
//
// A refusal is one identical 401 whatever the cause -- no certificate, the
// wrong authority, an agent's identity, a revoked, suspended or unknown
// installation -- with nothing recorded and no idempotency claim: the guard
// wraps the whole route table, so nothing behind it runs. An outage of the
// bundle or the installation table is not a certificate problem and is
// answered 503 with Retry-After instead.
//
// The installation's status is read on every request; the certificate's
// 24-hour lifetime bounds what an outage of that read could cost.

// ClientRefusalMessage is the one refusal a client sees for a certificate or
// installation problem. It names no cause: distinguishing them would be an
// oracle.
const ClientRefusalMessage = "innsegl core: request refused"

// clientOutageMessage answers a dependency outage behind the guard.
const clientOutageMessage = "innsegl core: the client check is unavailable; retry"

// DefaultBundleTTL is how long the guard keeps the deployment bundle before
// reading it again. Short against the authority's rotation, long against the
// request rate.
const DefaultBundleTTL = time.Minute

// Per-installation rate-limit defaults (ADR-0025 as amended by ADR-0063):
// an installation runs several sessions, each with its own per-session
// budget, so its own budget is a multiple of one session's.
const (
	DefaultInstallationRateLimitRate  = 4 * DefaultSessionRateLimitRate
	DefaultInstallationRateLimitBurst = 4 * DefaultSessionRateLimitBurst
)

// BundleSource reads the deployment's X.509 authorities. *spire.Client is
// one, reached through the MCP's own admin client.
type BundleSource interface {
	X509Bundle(ctx context.Context) ([]*x509.Certificate, error)
}

// InstallationChecker reads installations. InstallationActive answers false,
// nil for an unknown installation.
type InstallationChecker interface {
	InstallationActive(ctx context.Context, installationID string) (bool, error)
	ScopeChecker
}

// ScopeChecker answers whether an installation may act on a repository
// (accounts.Store.InScope). The hosted core's own implementation also makes
// the installation's organisation the holder of a repository nobody holds,
// on first use (ADR-0063, amended 2026-10-02).
type ScopeChecker interface {
	InScope(ctx context.Context, installationID, repo string) (bool, error)
}

// ClientGuardConfig is what a ClientGuard runs on.
type ClientGuardConfig struct {
	// TrustDomain is the deployment's SPIFFE trust domain. Required.
	TrustDomain string
	// Bundle supplies the roots client certificates are verified against.
	// Required.
	Bundle BundleSource
	// Installations reads status and scope. Required.
	Installations InstallationChecker
	// RateLimit is the per-installation limiter, keyed by installation id.
	// Required.
	RateLimit *SessionRateLimiter
	// BundleTTL: zero or less means DefaultBundleTTL.
	BundleTTL time.Duration
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// ClientGuard is the client-certificate guard.
type ClientGuard struct {
	trustDomain   string
	bundle        BundleSource
	installations InstallationChecker
	limiter       *SessionRateLimiter
	ttl           time.Duration
	now           func() time.Time

	mu        sync.Mutex
	roots     []*x509.Certificate
	pool      *x509.CertPool
	fetchedAt time.Time
}

// NewClientGuard builds a ClientGuard, or refuses an incomplete
// configuration.
func NewClientGuard(cfg ClientGuardConfig) (*ClientGuard, error) {
	switch {
	case cfg.TrustDomain == "":
		return nil, errors.New("innsegl gateway: client guard configuration: no trust domain")
	case cfg.Bundle == nil:
		return nil, errors.New("innsegl gateway: client guard configuration: no bundle source")
	case cfg.Installations == nil:
		return nil, errors.New("innsegl gateway: client guard configuration: no installation reader")
	case cfg.RateLimit == nil:
		return nil, errors.New("innsegl gateway: client guard configuration: no per-installation rate limit")
	}
	ttl := cfg.BundleTTL
	if ttl <= 0 {
		ttl = DefaultBundleTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &ClientGuard{
		trustDomain:   cfg.TrustDomain,
		bundle:        cfg.Bundle,
		installations: cfg.Installations,
		limiter:       cfg.RateLimit,
		ttl:           ttl,
		now:           now,
	}, nil
}

// clientOutcome is what authenticate decided.
type clientOutcome int

const (
	clientAdmitted clientOutcome = iota
	clientRefused
	clientUnavailable
)

// Wrap puts the guard in front of next. A request next sees carries its
// installation id (InstallationFromContext).
func (g *ClientGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, outcome := g.authenticate(r)
		switch outcome {
		case clientRefused:
			WriteClientRefusal(w)
			return
		case clientUnavailable:
			w.Header().Set("Retry-After", strconv.Itoa(int(outageRetryAfter/time.Second)))
			writeGatewayError(w, http.StatusServiceUnavailable, clientOutageMessage)
			return
		}
		if retryAfter, refused := g.limiter.Allow(r.Context(), id); refused {
			w.Header().Set("Retry-After", strconv.Itoa(ceilSeconds(retryAfter)))
			writeGatewayError(w, http.StatusTooManyRequests, "innsegl core: too many requests from this installation")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithInstallation(r.Context(), id)))
	})
}

// authenticate verifies the presented chain and the installation's status.
func (g *ClientGuard) authenticate(r *http.Request) (string, clientOutcome) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", clientRefused
	}
	roots, err := g.currentRoots(r.Context())
	if err != nil {
		return "", clientUnavailable
	}
	id, err := spire.VerifyClientCertificate(r.TLS.PeerCertificates, roots, g.trustDomain, g.now())
	if err != nil {
		return "", clientRefused
	}
	active, err := g.installations.InstallationActive(r.Context(), id)
	if err != nil {
		return "", clientUnavailable
	}
	if !active {
		return "", clientRefused
	}
	return id, clientAdmitted
}

// currentRoots answers the cached bundle, reading it again once it is older
// than the TTL. A failed read keeps nothing stale beyond the TTL.
func (g *ClientGuard) currentRoots(ctx context.Context) ([]*x509.Certificate, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.roots != nil && g.now().Sub(g.fetchedAt) < g.ttl {
		return g.roots, nil
	}
	roots, err := g.bundle.X509Bundle(ctx)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, errors.New("innsegl gateway: the deployment bundle holds no X.509 authority")
	}
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	g.roots, g.pool, g.fetchedAt = roots, pool, g.now()
	return roots, nil
}

// ClientCAs answers the bundle as a pool, for the TLS layer's certificate
// request. Nil when the bundle cannot be read: the request then names no
// authority, and a client sends its certificate anyway.
func (g *ClientGuard) ClientCAs(ctx context.Context) *x509.CertPool {
	if _, err := g.currentRoots(ctx); err != nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pool
}

// WriteClientRefusal writes the one 401 a client sees.
func WriteClientRefusal(w http.ResponseWriter) {
	writeGatewayError(w, http.StatusUnauthorized, ClientRefusalMessage)
}

// clientRefusal is the same refusal from inside the proxy's guard chain.
func clientRefusal() *Refusal {
	return &Refusal{Status: http.StatusUnauthorized, Reason: ClientRefusalMessage}
}

type installationContextKey struct{}

// WithInstallation attaches the verified installation id to ctx.
func WithInstallation(ctx context.Context, installationID string) context.Context {
	return context.WithValue(ctx, installationContextKey{}, installationID)
}

// InstallationFromContext answers the installation the client guard
// verified, if any. Single-host mode never sets one.
func InstallationFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(installationContextKey{}).(string)
	return id, ok && id != ""
}

// ---------------------------------------------------------------------------
// Session pinning.
// ---------------------------------------------------------------------------

// DefaultMaxSessionPins bounds the pin table.
const DefaultMaxSessionPins = 65536

// SessionPins pins each session to the first installation that stated or
// used it (ADR-0063 decision 5). Another installation naming the same
// session is refused.
//
// Memory only, and bounded: the oldest pin is forgotten first. A forgotten
// pin can be taken by another installation only by one that knows the
// session id and is in scope for the repository it states.
type SessionPins struct {
	mu    sync.Mutex
	max   int
	order []string
	pins  map[string]string
}

// NewSessionPins builds an empty table; zero or less means
// DefaultMaxSessionPins.
func NewSessionPins(maxPins int) *SessionPins {
	if maxPins <= 0 {
		maxPins = DefaultMaxSessionPins
	}
	return &SessionPins{max: maxPins, pins: make(map[string]string)}
}

// Pin pins sessionID to installationID if it is unpinned, and reports
// whether the session belongs to installationID.
func (p *SessionPins) Pin(sessionID, installationID string) bool {
	if sessionID == "" || installationID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if owner, ok := p.pins[sessionID]; ok {
		return owner == installationID
	}
	if len(p.order) >= p.max {
		delete(p.pins, p.order[0])
		p.order = p.order[1:]
	}
	p.pins[sessionID] = installationID
	p.order = append(p.order, sessionID)
	return true
}
