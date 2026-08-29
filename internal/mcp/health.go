// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
	"innsegl.dev/innsegl/internal/version"
)

// health — RM-026 (#34), IP §6.6:
//
//	Health endpoints: `ready` is false unless SPIRE, ledger, and Sigstore are
//	all reachable; per-dependency status is exposed so operators see *which*
//	dependency is failing.
//
// # Why this is not a boolean
//
// The whole of the requirement is in the second clause. A single `ready` flag
// tells an operator that something is wrong at the moment they already know
// something is wrong, and tells them nothing they can act on; the three
// systems below have three different owners, three different runbooks and
// three different blast radii. So readiness here is a LIST — one status per
// dependency, each naming its IP §4 error class — and `ready` is derived from
// it rather than being the thing that is measured.
//
// The corollary is the failure mode this file is written against: an outage in
// one dependency must not make the other two LOOK broken, because a report
// that goes uniformly red during an incident is no more useful than a boolean.
// Two structural choices follow. The three probes run CONCURRENTLY, each under
// its own deadline, so a hung SPIRE cannot eat a shared budget and time the
// ledger out behind it. And each probe's failure is classified from its own
// carrier, so the class an operator reads names the system that actually
// failed. MCP-012 asserts exactly this: block each dependency in turn, the
// failing one is named and the other two are still measured healthy.
//
// # Read-only, and what that costs
//
// No probe below writes anything. Nothing is appended to the ledger, no SPIRE
// entry is created, nothing is signed and nothing is logged to Rekor. That is
// not merely tidiness: a readiness endpoint is polled by every replica of
// every load balancer, and I3 makes the ledger the product — a probe event
// every two seconds would be a chain of noise, and I4 means it could never be
// deleted again.
//
// The honest cost, stated rather than hidden: a read-only probe cannot prove a
// dependency is WRITABLE. A Postgres promoted to a read-only replica, a full
// disk, a Fulcio that serves its root but refuses to issue — each of those
// answers the probes below and is reported healthy. Readiness here means "the
// dependency is reachable and answering", which is what IP §6.6 asks for.
// Proving writability requires a write, and the write is not available to us.
//
// # What "reachable" means, per dependency, and why
//
// SPIRE — an admin RPC that reads and writes nothing: ListAgents, via
// spire.Client.AttestedNodes. A TCP connect would prove a port is open; it
// would not prove that the admin SVID is still accepted, that the mTLS
// handshake still authorizes the server ID, or that the OPA policy of
// ADR-0012 still admits this caller. IP §6.1 makes "could not be reached OR
// could not answer" one class, IDENTITY_UNAVAILABLE, and an authorization
// denial is the second half of that sentence. ListAgents is chosen from the
// methods the shipped policy ALREADY grants the MCP admin credential
// (authz-policy.rego, mcp_admin_methods), so readiness costs no widening of
// the admin surface — a probe that required a new grant would be buying
// observability with blast radius.
//
// Ledger — ledger.Store.Head: one indexed read of the chain tip. A pool Ping
// would prove a socket; Head proves the pool has a usable connection, the
// innsegl schema is present, and the chain is readable — which is what a tool
// needs before it can append. It is the cheapest query that touches all three.
//
// Sigstore — whichever Fulcio/Rekor pair is configured. ADR-0010 flipped the
// shipped default to the self-hosted pair, so "Sigstore" is an address, not a
// vendor. Reachability is defined as: each half serves its TRUST MATERIAL —
// Fulcio its root certificate, Rekor its log public key — and the bytes parse
// as that material. See SigstoreEndpoints for the argument; the short version
// is that a signing round trip is both too expensive for a probe and a write,
// while a bare TCP dial or an unexamined 200 is a check that never fails, and
// a check that never fails is worse than none. ADR-0024 records all three
// definitions, what they do not prove, and what was measured.
//
// # Liveness is a different question
//
// Live() contacts nothing. A liveness probe answers "should this process be
// restarted", and the answer to "Postgres is down" is never "restart the MCP":
// a liveness check wired to dependencies turns one dependency's outage into a
// restart loop across every replica, which is a total outage. Readiness
// answers "should this replica receive traffic", and that one does depend on
// the three systems below. A process that is alive and not ready says both.

// Dependency names one of the three systems IP §6.6 requires readiness to
// report on. The three names are part of the health wire contract.
type Dependency string

// The three dependencies of IP §6.6.
const (
	// DependencySPIRE is the SPIRE server reached over the admin API.
	DependencySPIRE Dependency = "spire"
	// DependencyLedger is the append-only event store (doc 05 §1: Postgres).
	DependencyLedger Dependency = "ledger"
	// DependencySigstore is the configured Fulcio/Rekor pair (ADR-0010).
	DependencySigstore Dependency = "sigstore"
)

// dependencyOrder is the surface in IP §6.6 order, which is the order a report
// lists them in so an operator reads the same three rows every time.
var dependencyOrder = []Dependency{DependencySPIRE, DependencyLedger, DependencySigstore}

// dependencyOutage is the IP §4 class each dependency's own unreachability
// takes when the failure arrives carrying no class of its own — a bare dial
// error, a context deadline. Sigstore's entry is the Fulcio half's class;
// probeSigstore always classifies its own failures, so it never falls back
// here, and the entry exists so the table is total.
var dependencyOutage = map[Dependency]Class{
	DependencySPIRE:    ClassIdentityUnavailable,
	DependencyLedger:   ClassLedgerUnavailable,
	DependencySigstore: ClassSigningUnavailable,
}

// Dependencies returns the three dependencies of IP §6.6, in IP §6.6 order.
func Dependencies() []Dependency { return slices.Clone(dependencyOrder) }

func (d Dependency) String() string { return string(d) }

// unavailableClass is the class an unclassified failure of d takes.
func (d Dependency) unavailableClass() Class { return dependencyOutage[d] }

// HealthIdentities is the SPIRE surface readiness probes. *spire.Client
// satisfies it; it is an interface here for the same reason the tools declare
// theirs, so that this file holds no SPIRE client of its own.
//
// AttestedNodes is a read. Readiness never creates an entry.
type HealthIdentities interface {
	AttestedNodes(ctx context.Context) ([]string, error)
}

// HealthLedger is the ledger surface readiness probes. *ledger.Store satisfies
// it. Head is a read: readiness never appends to the chain.
type HealthLedger interface {
	Head(ctx context.Context) (ledger.Head, error)
}

// HealthSigstore is the configured Fulcio/Rekor pair. *SigstoreEndpoints is
// the shipped implementation; E5's signing client may supersede it by
// satisfying this interface, which is why the seam is here rather than a
// concrete type in the config.
//
// The two halves are separate methods because IP §6.3 gives them separate
// classes — Fulcio down is SIGNING_UNAVAILABLE, Rekor down is
// TRANSPARENCY_UNAVAILABLE — and that distinction is how a single "sigstore"
// row still tells an operator which service to look at.
type HealthSigstore interface {
	// ProbeSigning reaches the configured Fulcio. It must not request a
	// certificate.
	ProbeSigning(ctx context.Context) error
	// ProbeTransparency reaches the configured Rekor. It must not write an
	// entry.
	ProbeTransparency(ctx context.Context) error
}

// HealthToolSurface is the advertised tool surface. *Server satisfies it.
type HealthToolSurface interface {
	BoundTools() []ToolName
	MissingTools() []ToolName
}

// The production implementations must satisfy the interfaces above, or the
// fakes the contract tests use would be free to drift from what health will
// actually be handed.
var (
	_ HealthIdentities  = (*spire.Client)(nil)
	_ HealthLedger      = (*ledger.Store)(nil)
	_ HealthSigstore    = (*SigstoreEndpoints)(nil)
	_ HealthToolSurface = (*Server)(nil)
)

const (
	// DefaultHealthTimeout bounds one dependency probe. Short: a readiness
	// endpoint that takes longer than the load balancer's own timeout is a
	// replica the balancer removes for the wrong reason.
	DefaultHealthTimeout = 5 * time.Second

	// DefaultFulcioRootPath is Fulcio's root certificate. MEASURED against
	// https://fulcio.sigstore.dev on 2026-08-29: HTTP 200,
	// content-type application/pem-certificate-chain, a PEM CA certificate.
	DefaultFulcioRootPath = "/api/v1/rootCert"

	// DefaultRekorPublicKeyPath is the log's public key — the same path
	// internal/segment's Rekor client uses. MEASURED against
	// https://rekor.sigstore.dev on 2026-08-29: HTTP 200, content-type
	// application/x-pem-file, a PKIX public key.
	DefaultRekorPublicKeyPath = "/api/v1/log/publicKey"

	// LivePath and ReadyPath are the endpoints Handler serves. No spec
	// document fixes these names; they are the conventional ones, and they are
	// constants so a deployment manifest and a test cannot disagree.
	LivePath  = "/healthz"
	ReadyPath = "/readyz"

	// maxTrustMaterialBytes bounds a trust-material response. A root chain is
	// a few kilobytes; anything larger is not the artifact, and an unbounded
	// read from a dependency is a way for that dependency to take the MCP
	// down with it.
	maxTrustMaterialBytes = 1 << 20

	acceptPEMCertificateChain = "application/pem-certificate-chain"
	acceptPEMFile             = "application/x-pem-file"
)

// HealthConfig configures a Health. Every field but the three probes is
// optional.
type HealthConfig struct {
	// Identities, Ledger and Sigstore are the three probes. All three are
	// required: see NewHealth.
	Identities HealthIdentities
	Ledger     HealthLedger
	Sigstore   HealthSigstore
	// Tools is the advertised tool surface, reported by both endpoints. Nil
	// omits it.
	Tools HealthToolSurface
	// Timeout bounds one dependency probe. Zero means DefaultHealthTimeout.
	Timeout time.Duration
	// ClockSkewBound is IP §6.8's bound, surfaced because doc 05 §2 requires
	// it: "the §6.8 skew bound is a config value surfaced in health output".
	//
	// It is SURFACED, never invented. Zero means "not configured", and is
	// reported as absent rather than as "0s" — an operator reading 0s would
	// conclude the deployment tolerates no skew at all. IP §6.8 owns the
	// bound's value and VER-005 owns its boundary test; a default chosen here
	// would silently become the project's bound.
	ClockSkewBound time.Duration
	// Version is reported by both endpoints. Empty means the build version.
	Version string
	// Logger receives the one thing that can go wrong while answering: a
	// response that could not be written. Nil disables it.
	Logger *slog.Logger
}

// Health answers the two questions of IP §6.6.
type Health struct {
	probes         []healthProbe
	tools          HealthToolSurface
	timeout        time.Duration
	clockSkewBound time.Duration
	version        string
	logger         *slog.Logger
}

// healthProbe is one dependency and the read that reaches it. Built once, in
// IP §6.6 order, so that answering a request involves no dispatch on a name.
type healthProbe struct {
	dependency Dependency
	run        func(context.Context) error
}

// NewHealth builds a Health.
//
// A missing probe is refused rather than defaulted. A nil probe would have to
// be treated as either "healthy" — reporting a dependency reachable that was
// never contacted, which is precisely the vacuous green MCP-012 exists to
// catch — or as "unhealthy", which would make a misconfigured deployment
// indistinguishable from an outage. Neither is reportable, so the server does
// not start with one.
func NewHealth(cfg HealthConfig) (*Health, error) {
	missing := make([]string, 0, len(dependencyOrder))
	if cfg.Identities == nil {
		missing = append(missing, string(DependencySPIRE))
	}
	if cfg.Ledger == nil {
		missing = append(missing, string(DependencyLedger))
	}
	if cfg.Sigstore == nil {
		missing = append(missing, string(DependencySigstore))
	}
	if len(missing) > 0 {
		return nil, Errorf(ClassInvariantViolation, "",
			"readiness has no probe for %s; a dependency with no probe would have to be "+
				"reported healthy without ever being contacted", strings.Join(missing, ", "))
	}

	h := &Health{
		tools:          cfg.Tools,
		timeout:        cfg.Timeout,
		clockSkewBound: cfg.ClockSkewBound,
		version:        cfg.Version,
		logger:         cfg.Logger,
	}
	if h.timeout <= 0 {
		h.timeout = DefaultHealthTimeout
	}
	if h.version == "" {
		h.version = version.Version()
	}
	h.probes = []healthProbe{
		{DependencySPIRE, func(ctx context.Context) error {
			_, err := cfg.Identities.AttestedNodes(ctx)
			return err
		}},
		{DependencyLedger, func(ctx context.Context) error {
			_, err := cfg.Ledger.Head(ctx)
			return err
		}},
		{DependencySigstore, func(ctx context.Context) error {
			return probeSigstore(ctx, cfg.Sigstore)
		}},
	}
	return h, nil
}

// Liveness is the answer to "is this process running": is a restart the
// remedy. It is never derived from a dependency.
type Liveness struct {
	// Alive is true whenever this process can compose an answer at all.
	//
	// It has no false case on purpose. The only way this endpoint reports
	// not-alive is by failing to answer — a hung process, a crashed process, a
	// closed port — which is exactly what a liveness probe measures, and
	// exactly what a restart repairs. Every condition that a restart would NOT
	// repair belongs in Readiness, and putting one here would make an
	// orchestrator restart healthy replicas over somebody else's outage.
	Alive bool
	// Version is the version advertised in the MCP initialize handshake.
	Version string
	// BoundTools and MissingTools are the advertised surface. MissingTools is
	// informational and never gates traffic: the surface is legitimately
	// incomplete before E5 lands sign_commit, and refusing traffic for the
	// four tools that exist because a fifth does not would be a self-inflicted
	// outage. Server.MissingTools names this reporting duty.
	BoundTools   []ToolName
	MissingTools []ToolName
	// ObservedAt is when the answer was composed.
	ObservedAt time.Time
}

// DependencyStatus is one dependency's contribution to readiness.
type DependencyStatus struct {
	// Dependency is which of the three this is.
	Dependency Dependency
	// Reachable is whether its probe succeeded.
	Reachable bool
	// Class is the IP §4 error class of the failure, empty when reachable.
	// For Sigstore it also names which half failed: SIGNING_UNAVAILABLE is
	// Fulcio, TRANSPARENCY_UNAVAILABLE is Rekor (IP §6.3).
	Class Class
	// Retryable is IP §4's flag, taken from the class or narrowed by the
	// layer that raised the failure.
	Retryable bool
	// Detail is the human-readable failure, empty when reachable. It carries
	// no credential: the probes read public trust material and a chain tip.
	Detail string
	// Latency is how long the probe took. Non-zero even on the fast path, so
	// "healthy" can be distinguished from "not measured".
	Latency time.Duration
	// CheckedAt is when the probe started.
	CheckedAt time.Time
}

// Readiness is the answer to "should this replica receive traffic".
type Readiness struct {
	// Ready is false unless every dependency is reachable (IP §6.6). It is
	// derived from Dependencies, never measured on its own.
	Ready bool
	// Dependencies is one status per dependency, in IP §6.6 order.
	Dependencies []DependencyStatus
	// ClockSkewBound is the configured IP §6.8 bound (doc 05 §2). Zero means
	// unconfigured and is absent from the wire.
	ClockSkewBound time.Duration
	// Version is the version advertised in the MCP initialize handshake.
	Version string
	// MissingTools is the part of the IP §4 surface with no binder. Reported,
	// never a reason to be unready — see Liveness.MissingTools.
	MissingTools []ToolName
	// ObservedAt is when the report was composed.
	ObservedAt time.Time
}

// Status returns the status recorded for d.
func (r Readiness) Status(d Dependency) (DependencyStatus, bool) {
	for _, s := range r.Dependencies {
		if s.Dependency == d {
			return s, true
		}
	}
	return DependencyStatus{}, false
}

// Unreachable names the dependencies whose probe failed, in report order. It
// is the answer to the operator's question — which one is it — as a value
// rather than as prose.
func (r Readiness) Unreachable() []Dependency {
	var out []Dependency
	for _, s := range r.Dependencies {
		if !s.Reachable {
			out = append(out, s.Dependency)
		}
	}
	return out
}

// Live reports process liveness. It contacts no dependency and takes no lock.
func (h *Health) Live() Liveness {
	l := Liveness{Alive: true, Version: h.version, ObservedAt: time.Now()}
	if h.tools != nil {
		l.BoundTools = h.tools.BoundTools()
		l.MissingTools = h.tools.MissingTools()
	}
	return l
}

// Ready probes every dependency and reports per-dependency status.
//
// The probes run concurrently, each under its own deadline. Sequentially they
// would share one budget, and a dependency that hangs rather than refusing —
// the common shape of a real outage — would consume it and time the others out
// behind it. The report would then be uniformly red and would name the wrong
// systems, which is the failure MCP-012 checks for.
func (h *Health) Ready(ctx context.Context) Readiness {
	statuses := make([]DependencyStatus, len(h.probes))
	var wg sync.WaitGroup
	for i, p := range h.probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = h.check(ctx, p)
		}()
	}
	wg.Wait()

	r := Readiness{
		Ready:          true,
		Dependencies:   statuses,
		ClockSkewBound: h.clockSkewBound,
		Version:        h.version,
		ObservedAt:     time.Now(),
	}
	for _, s := range statuses {
		if !s.Reachable {
			r.Ready = false
		}
	}
	if h.tools != nil {
		r.MissingTools = h.tools.MissingTools()
	}
	return r
}

// check runs one probe under its own deadline.
func (h *Health) check(ctx context.Context, p healthProbe) DependencyStatus {
	probeCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	started := time.Now()
	err := p.run(probeCtx)
	status := DependencyStatus{
		Dependency: p.dependency,
		Reachable:  err == nil,
		Latency:    time.Since(started),
		CheckedAt:  started,
	}
	if err != nil {
		e := probeError(p.dependency, err)
		status.Class, status.Retryable, status.Detail = e.Class, e.Retryable, e.Message
	}
	return status
}

// probeSigstore reaches both halves of the configured pair, concurrently, and
// classifies the result so that the one "sigstore" row still names which half
// is down.
//
// Both halves are probed even when the first fails: an operator paging at 3am
// needs to know whether one service or the whole Sigstore deployment is gone,
// and a short-circuit would report Fulcio and leave Rekor unmeasured.
func probeSigstore(ctx context.Context, s HealthSigstore) error {
	var signing, transparency error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		signing = s.ProbeSigning(ctx)
	}()
	go func() {
		defer wg.Done()
		transparency = s.ProbeTransparency(ctx)
	}()
	wg.Wait()

	switch {
	case signing != nil && transparency != nil:
		// Both. IP §4 order picks the class; the detail carries both, so
		// nothing is lost by there being one row.
		return Errorf(ClassSigningUnavailable, "",
			"Fulcio: %v; and Rekor: %v", signing, transparency)
	case signing != nil:
		return Errorf(ClassSigningUnavailable, "", "Fulcio: %w", signing)
	case transparency != nil:
		return Errorf(ClassTransparencyUnavailable, "", "Rekor: %w", transparency)
	}
	return nil
}

// probeError renders a probe failure as an IP §4 structured error.
//
// A failure that already carries a class keeps it: internal/spire measured
// whether SPIRE was unreachable or merely refused, internal/ledger measured
// whether the database was gone or the schema was wrong, and this file is
// further from the failure than either. Only a failure that carries no class —
// a bare dial error, a context deadline — takes its dependency's own outage
// class, which is right because the probe is the only thing that was being
// attempted.
func probeError(d Dependency, err error) *Error {
	if carried := healthCarriedClass(err); carried != nil {
		return carried
	}
	return Errorf(d.unavailableClass(), "", "%s is unreachable: %w", d, err)
}

// healthCarriedClass returns the class the error already carries, or nil.
func healthCarriedClass(err error) *Error {
	var stored *ledger.StoreError
	if errors.As(err, &stored) {
		// internal/ledger predates mcp.Classified; runs.go already owns the
		// one mapping across, and a second one here could disagree with it.
		return Classify(credentialLedgerError("", err))
	}
	var own *Error
	if errors.As(err, &own) {
		return own
	}
	var fromSPIRE *spire.Error
	if errors.As(err, &fromSPIRE) {
		return Classify(err)
	}
	var self Classified
	if errors.As(err, &self) {
		return Classify(err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The endpoints.
// ---------------------------------------------------------------------------

// Handler serves LivePath and ReadyPath.
//
// GET only, and that is not decoration: a health endpoint is a read, and this
// process is the one holding SPIRE admin. A surface that accepted a body would
// be a second door into it.
func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+LivePath, h.serveLive)
	mux.HandleFunc("GET "+ReadyPath, h.serveReady)
	return mux
}

func (h *Health) serveLive(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, h.Live())
}

func (h *Health) serveReady(w http.ResponseWriter, r *http.Request) {
	ready := h.Ready(r.Context())
	code := http.StatusOK
	if !ready.Ready {
		code = http.StatusServiceUnavailable
	}
	h.writeJSON(w, code, ready)
}

func (h *Health) writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	// A cached readiness answer is a stale readiness answer, and a balancer
	// acting on one routes to a replica that cannot serve.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logWriteFailure(err)
	}
}

// logWriteFailure records a response that could not be written. There is
// nothing else to do with it — the status line is already sent and the client
// is already gone — but a silent discard would hide a broken endpoint.
func (h *Health) logWriteFailure(err error) {
	if h.logger == nil {
		return
	}
	h.logger.Warn("writing the health response", "error", err)
}

// ---------------------------------------------------------------------------
// The wire shape. Operators and the dashboard (doc 06) read this.
// ---------------------------------------------------------------------------

type readinessWire struct {
	Ready          bool               `json:"ready"`
	Version        string             `json:"version,omitempty"`
	ObservedAt     string             `json:"observed_at"`
	ClockSkewBound string             `json:"clock_skew_bound,omitempty"`
	Dependencies   []DependencyStatus `json:"dependencies"`
	MissingTools   []ToolName         `json:"missing_tools,omitempty"`
}

type dependencyWire struct {
	Dependency Dependency `json:"dependency"`
	Reachable  bool       `json:"reachable"`
	Class      Class      `json:"error_class,omitempty"`
	Retryable  bool       `json:"retryable,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	LatencyMS  int64      `json:"latency_ms"`
	CheckedAt  string     `json:"checked_at"`
}

type livenessWire struct {
	Alive        bool       `json:"alive"`
	Version      string     `json:"version,omitempty"`
	ObservedAt   string     `json:"observed_at"`
	BoundTools   []ToolName `json:"bound_tools,omitempty"`
	MissingTools []ToolName `json:"missing_tools,omitempty"`
}

// MarshalJSON renders the readiness report.
func (r Readiness) MarshalJSON() ([]byte, error) {
	return json.Marshal(readinessWire{
		Ready:          r.Ready,
		Version:        r.Version,
		ObservedAt:     event.NewTimestamp(r.ObservedAt).String(),
		ClockSkewBound: healthDurationString(r.ClockSkewBound),
		Dependencies:   r.Dependencies,
		MissingTools:   r.MissingTools,
	})
}

// MarshalJSON renders one dependency's status.
func (s DependencyStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(dependencyWire{
		Dependency: s.Dependency,
		Reachable:  s.Reachable,
		Class:      s.Class,
		Retryable:  s.Retryable,
		Detail:     s.Detail,
		LatencyMS:  s.Latency.Milliseconds(),
		CheckedAt:  event.NewTimestamp(s.CheckedAt).String(),
	})
}

// MarshalJSON renders the liveness answer.
func (l Liveness) MarshalJSON() ([]byte, error) {
	return json.Marshal(livenessWire{
		Alive:        l.Alive,
		Version:      l.Version,
		ObservedAt:   event.NewTimestamp(l.ObservedAt).String(),
		BoundTools:   l.BoundTools,
		MissingTools: l.MissingTools,
	})
}

// healthDurationString renders a configured duration, or "" for an unset one
// so that omitempty drops it. doc 05 §2's skew bound must read as absent when
// it is absent, never as "0s".
func healthDurationString(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

// ---------------------------------------------------------------------------
// The shipped Sigstore probe.
// ---------------------------------------------------------------------------

// SigstoreConfig configures a SigstoreEndpoints. Both URLs are required;
// ADR-0010 makes the self-hosted pair the shipped default, so there is no
// address to fall back to.
type SigstoreConfig struct {
	// FulcioURL and RekorURL are the base URLs of the configured pair.
	FulcioURL string
	RekorURL  string
	// FulcioRootPath and RekorPublicKeyPath override the trust-material paths.
	// Empty means the defaults above.
	FulcioRootPath     string
	RekorPublicKeyPath string
	// Client is the HTTP client. Nil means one bounded by
	// DefaultHealthTimeout.
	Client *http.Client
}

// SigstoreEndpoints is the shipped HealthSigstore: an unauthenticated GET of
// each half's trust material.
//
// # Why trust material, and not something else
//
// A full signing round trip — mint a JWT-SVID, exchange it at Fulcio for a
// certificate, log an entry at Rekor — is the only thing that proves Sigstore
// will do its job. It is also unusable as a readiness probe on two independent
// grounds. It is a WRITE: it issues a real certificate and appends a real
// entry to a transparency log that is append-only by construction, so a probe
// every two seconds from every replica would fill the log with entries nobody
// can remove. And it is expensive enough that the probe would become the
// dominant load on the CA.
//
// The opposite error is worse. A TCP dial, or a GET whose body is never
// examined, succeeds against anything that is listening — a misconfigured
// reverse proxy, an unrelated web server on a reused port, a Fulcio serving a
// 200 error page. That check never fails, and a check that never fails is
// worse than none, because it converts an outage into silence.
//
// So the probe fetches the artifact each half must publish before it can do
// anything at all, and PARSES it: Fulcio's root certificate must decode as a
// PEM CA certificate, Rekor's log key must decode as a PKIX public key.
// Cheap, read-only, unauthenticated, and it fails when the service is broken
// in the ways that matter — down, replaced, or not that service. It does not
// prove Fulcio would accept our OIDC token or that Rekor would accept an
// entry. Those need a write, and are not readiness.
type SigstoreEndpoints struct {
	fulcio *url.URL
	rekor  *url.URL
	client *http.Client
}

// NewSigstoreEndpoints builds a Sigstore reachability probe.
//
// An unusable address is refused here rather than reported as an outage every
// five seconds forever: a deployment that cannot address its Fulcio has a
// configuration defect, and a readiness endpoint that renders it as
// SIGNING_UNAVAILABLE sends an operator to look at a service that is fine.
func NewSigstoreEndpoints(cfg SigstoreConfig) (*SigstoreEndpoints, error) {
	fulcio, err := sigstoreEndpointURL("Fulcio", cfg.FulcioURL,
		healthPathOr(cfg.FulcioRootPath, DefaultFulcioRootPath))
	if err != nil {
		return nil, err
	}
	rekor, err := sigstoreEndpointURL("Rekor", cfg.RekorURL,
		healthPathOr(cfg.RekorPublicKeyPath, DefaultRekorPublicKeyPath))
	if err != nil {
		return nil, err
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultHealthTimeout}
	}
	return &SigstoreEndpoints{fulcio: fulcio, rekor: rekor, client: client}, nil
}

func healthPathOr(path, fallback string) string {
	if path == "" {
		return fallback
	}
	return path
}

func sigstoreEndpointURL(name, base, path string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, "",
			"the %s endpoint %q is not a URL: %w", name, base, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, Errorf(ClassInvariantViolation, "",
			"the %s endpoint %q has no http(s) scheme", name, base)
	}
	if u.Host == "" {
		return nil, Errorf(ClassInvariantViolation, "",
			"the %s endpoint %q names no host", name, base)
	}
	return u.JoinPath(path), nil
}

// Endpoints returns the two addresses this probe reads, for an operator who
// needs to know which trust root is being checked (ADR-0010 makes that
// load-bearing: whoever deploys Innsegl now runs the log that attests their
// own agents).
func (s *SigstoreEndpoints) Endpoints() (fulcio, rekor string) {
	return s.fulcio.Redacted(), s.rekor.Redacted()
}

// ProbeSigning fetches Fulcio's root certificate. It requests no certificate
// and presents no token.
func (s *SigstoreEndpoints) ProbeSigning(ctx context.Context) error {
	if err := s.fetch(ctx, s.fulcio, acceptPEMCertificateChain, sigstoreRootCertificate); err != nil {
		return Errorf(ClassSigningUnavailable, "", "%s: %w", s.fulcio.Redacted(), err)
	}
	return nil
}

// ProbeTransparency fetches Rekor's log public key. It writes no entry.
func (s *SigstoreEndpoints) ProbeTransparency(ctx context.Context) error {
	if err := s.fetch(ctx, s.rekor, acceptPEMFile, sigstoreLogPublicKey); err != nil {
		return Errorf(ClassTransparencyUnavailable, "", "%s: %w", s.rekor.Redacted(), err)
	}
	return nil
}

// fetch GETs u and hands the body to check.
func (s *SigstoreEndpoints) fetch(ctx context.Context, u *url.URL, accept string, check func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Accept", accept)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustMaterialBytes))
	if err != nil {
		return fmt.Errorf("read the response: %w", err)
	}
	return check(body)
}

// sigstoreRootCertificate checks that body is Fulcio's root: a PEM CA
// certificate. Not merely a PEM block, and not merely a certificate — a CA
// certificate, because that is what a root is and it is the cheapest way to
// tell "Fulcio" from "something that serves PEM".
func sigstoreRootCertificate(body []byte) error {
	blk, _ := pem.Decode(body)
	if blk == nil {
		return fmt.Errorf("answered %d bytes that are not PEM; this is not a Fulcio root certificate", len(body))
	}
	if blk.Type != "CERTIFICATE" {
		return fmt.Errorf("served a %q PEM block, not a CERTIFICATE", blk.Type)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("served an unparseable certificate: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("served the non-CA certificate %q; a Fulcio root is a CA", cert.Subject)
	}
	return nil
}

// sigstoreLogPublicKey checks that body is the transparency log's key: a PKIX
// public key in PEM. It is the key a verifier needs to check any inclusion
// proof, so a Rekor that cannot serve it is a Rekor whose entries cannot be
// verified.
func sigstoreLogPublicKey(body []byte) error {
	blk, _ := pem.Decode(body)
	if blk == nil {
		return fmt.Errorf("answered %d bytes that are not PEM; this is not a Rekor log key", len(body))
	}
	if blk.Type != "PUBLIC KEY" {
		return fmt.Errorf("served a %q PEM block, not a PUBLIC KEY", blk.Type)
	}
	if _, err := x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
		return fmt.Errorf("served an unparseable public key: %w", err)
	}
	return nil
}
