// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-026 (#34) — health and readiness.
//
// IP §6.6, verbatim:
//
//	Health endpoints: `ready` is false unless SPIRE, ledger, and Sigstore are
//	all reachable; per-dependency status is exposed so operators see *which*
//	dependency is failing.
//
// Doc 07, MCP-012:
//
//	Health: each dependency (SPIRE, ledger, Sigstore) blocked in turn →
//	`ready=false` with the failing dependency named; others reported healthy.
//
// The sentence that carries the work is "others reported healthy". A bare
// boolean satisfies "ready=false"; so does a process that has fallen over for
// an unrelated reason. What an operator needs at 3am is the second half, and
// the second half is only worth anything if the healthy answers were measured
// rather than defaulted.
//
// Two controls run against that:
//
//  1. A POSITIVE CONTROL. Every case below that asserts a dependency healthy
//     runs in a test where that same dependency is also observed UNHEALTHY,
//     against the same code. A probe that never runs cannot produce both.
//  2. A CALL COUNT. The Sigstore endpoints count their fetches, so "Sigstore
//     healthy" is asserted together with "and it was actually fetched during
//     this call".

// ---------------------------------------------------------------------------
// MCP-012 — the real one. Real dependencies, really blocked.
// See healthharness_test.go for what each block does.
// ---------------------------------------------------------------------------

func TestMCP012ReadinessNamesTheFailingDependency(t *testing.T) {
	// No t.Parallel: this test kills containers.
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s); MCP-012 cannot be proved without "+
			"a ledger that can actually be taken away", dockerSkip)
	}
	ctx := testCtx(t, 15*time.Minute)

	// --- the ledger: a Postgres of this test's own, because it gets killed.
	pg, err := startPG(ctx)
	if err != nil {
		t.Fatalf("start a dedicated postgres: %v", err)
	}
	t.Cleanup(func() {
		if rerr := pg.remove(); rerr != nil {
			t.Logf("warning: removing the postgres container: %v", rerr)
		}
	})
	dsn := pg.dsn(postgresDB)
	migrate(t, dsn)
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)

	// --- SPIRE: the shipped compose stack, this process's own project.
	stack, err := startHealthSPIRE(ctx, healthRepoRoot(t))
	if err != nil {
		stack.stop()
		t.Skipf("skipping: could not start deploy/compose/spire.yml (%v). "+
			"MCP-012's SPIRE half proves nothing without a real spire-server; "+
			"start Docker and re-run.", err)
	}
	t.Cleanup(stack.stop)
	identities := stack.client(t)

	// --- Sigstore: real endpoints serving real trust material.
	sig := newHealthSigstore(t)

	newHealth := func(t *testing.T, s *healthSigstore) *Health {
		t.Helper()
		h, herr := NewHealth(HealthConfig{
			Identities:     identities,
			Ledger:         store,
			Sigstore:       s.probe(t),
			Tools:          healthTestServer(t),
			Timeout:        20 * time.Second,
			ClockSkewBound: 5 * time.Second,
			Version:        "mcp-012",
		})
		if herr != nil {
			t.Fatalf("NewHealth: %v", herr)
		}
		return h
	}
	h := newHealth(t, sig)

	// ready runs one probe and returns the report plus how many times each
	// Sigstore endpoint was fetched during it.
	type fetches struct{ fulcio, rekor int64 }
	ready := func(t *testing.T, h *Health, s *healthSigstore) (Readiness, fetches) {
		t.Helper()
		before := fetches{s.fulcio.calls.Load(), s.rekor.calls.Load()}
		r := h.Ready(ctx)
		if len(r.Dependencies) != len(Dependencies()) {
			t.Fatalf("report carries %d dependencies, want the %d of IP §6.6: %+v",
				len(r.Dependencies), len(Dependencies()), r.Dependencies)
		}
		for i, d := range Dependencies() {
			if r.Dependencies[i].Dependency != d {
				t.Fatalf("dependency %d is %q, want %q (IP §6.6 order)",
					i, r.Dependencies[i].Dependency, d)
			}
		}
		after := fetches{s.fulcio.calls.Load(), s.rekor.calls.Load()}
		return r, fetches{after.fulcio - before.fulcio, after.rekor - before.rekor}
	}

	healthy := func(t *testing.T, r Readiness, d Dependency) {
		t.Helper()
		st, ok := r.Status(d)
		if !ok {
			t.Fatalf("no status for %s", d)
		}
		if !st.Reachable {
			t.Fatalf("%s reported unreachable (%s: %s); blocking another dependency "+
				"must not make this one look broken", d, st.Class, st.Detail)
		}
		if st.Class != "" {
			t.Fatalf("%s is reachable but carries error class %q", d, st.Class)
		}
		if st.Latency <= 0 {
			t.Fatalf("%s reports zero latency; the probe did not run", d)
		}
	}

	named := func(t *testing.T, r Readiness, d Dependency, want Class) {
		t.Helper()
		if r.Ready {
			t.Fatalf("ready is true with %s blocked (IP §6.6: ready is false unless "+
				"SPIRE, ledger and Sigstore are ALL reachable)", d)
		}
		st, ok := r.Status(d)
		if !ok {
			t.Fatalf("no status for %s", d)
		}
		if st.Reachable {
			t.Fatalf("%s is blocked but reported reachable", d)
		}
		if st.Class != want {
			t.Fatalf("%s failed as %q, want %q", d, st.Class, want)
		}
		if st.Detail == "" {
			t.Fatalf("%s is unreachable with no detail; an operator is told nothing", d)
		}
		if got := r.Unreachable(); len(got) != 1 || got[0] != d {
			t.Fatalf("Unreachable() = %v, want exactly [%s]", got, d)
		}
	}

	t.Run("positive control: all three reachable", func(t *testing.T) {
		r, f := ready(t, h, sig)
		if !r.Ready {
			t.Fatalf("ready is false with every dependency up: %s", healthDump(r))
		}
		for _, d := range Dependencies() {
			healthy(t, r, d)
		}
		if f.fulcio != 1 || f.rekor != 1 {
			t.Fatalf("Sigstore was fetched %d/%d times (fulcio/rekor) during the probe, want 1/1; "+
				"a 'healthy' answer nobody measured is the vacuous pass MCP-012 exists to catch", f.fulcio, f.rekor)
		}
		if r.ClockSkewBound != 5*time.Second {
			t.Fatalf("clock skew bound is %s, want 5s (doc 05 §2: surfaced in health output)", r.ClockSkewBound)
		}
	})

	t.Run("SPIRE blocked", func(t *testing.T) {
		if berr := stack.block(ctx); berr != nil {
			t.Fatalf("close the admin port: %v", berr)
		}
		r, f := ready(t, h, sig)
		named(t, r, DependencySPIRE, ClassIdentityUnavailable)
		healthy(t, r, DependencyLedger)
		healthy(t, r, DependencySigstore)
		if f.fulcio != 1 || f.rekor != 1 {
			t.Fatalf("Sigstore fetched %d/%d times while SPIRE was down, want 1/1", f.fulcio, f.rekor)
		}
		if !r.Dependencies[0].Retryable {
			t.Fatalf("an unreachable SPIRE is not retryable; IP §6.1 says it is")
		}

		// Restore, and prove the "unreachable" answer was responsive rather
		// than stuck: the same checker must see SPIRE come back.
		if rerr := stack.startProxy(ctx); rerr != nil {
			t.Fatalf("reopen the admin port: %v", rerr)
		}
		healthEventually(ctx, t, 90*time.Second, func() error {
			r, _ := ready(t, h, sig)
			st, _ := r.Status(DependencySPIRE)
			if st.Reachable {
				return nil
			}
			return fmt.Errorf("%s: %s", st.Class, st.Detail)
		})
	})

	t.Run("ledger blocked", func(t *testing.T) {
		if kerr := pg.kill(ctx); kerr != nil {
			t.Fatalf("kill postgres: %v", kerr)
		}
		r, f := ready(t, h, sig)
		named(t, r, DependencyLedger, ClassLedgerUnavailable)
		healthy(t, r, DependencySPIRE)
		healthy(t, r, DependencySigstore)
		if f.fulcio != 1 || f.rekor != 1 {
			t.Fatalf("Sigstore fetched %d/%d times while the ledger was down, want 1/1", f.fulcio, f.rekor)
		}

		if rerr := pg.restart(ctx); rerr != nil {
			t.Fatalf("restart postgres: %v", rerr)
		}
		healthEventually(ctx, t, 90*time.Second, func() error {
			r, _ := ready(t, h, sig)
			st, _ := r.Status(DependencyLedger)
			if st.Reachable {
				return nil
			}
			return fmt.Errorf("%s: %s", st.Class, st.Detail)
		})
	})

	t.Run("Sigstore blocked at Fulcio", func(t *testing.T) {
		s := newHealthSigstore(t)
		hh := newHealth(t, s)
		if r, _ := ready(t, hh, s); !r.Ready {
			t.Fatalf("positive control for this case failed: %s", healthDump(r))
		}
		s.fulcio.block()
		r, _ := ready(t, hh, s)
		named(t, r, DependencySigstore, ClassSigningUnavailable)
		healthy(t, r, DependencySPIRE)
		healthy(t, r, DependencyLedger)
		st, _ := r.Status(DependencySigstore)
		if !strings.Contains(strings.ToLower(st.Detail), "fulcio") {
			t.Fatalf("Fulcio is down and the detail does not name it: %q", st.Detail)
		}
	})

	t.Run("Sigstore blocked at Rekor", func(t *testing.T) {
		s := newHealthSigstore(t)
		hh := newHealth(t, s)
		if r, _ := ready(t, hh, s); !r.Ready {
			t.Fatalf("positive control for this case failed: %s", healthDump(r))
		}
		s.rekor.block()
		r, _ := ready(t, hh, s)
		named(t, r, DependencySigstore, ClassTransparencyUnavailable)
		healthy(t, r, DependencySPIRE)
		healthy(t, r, DependencyLedger)
		st, _ := r.Status(DependencySigstore)
		if !strings.Contains(strings.ToLower(st.Detail), "rekor") {
			t.Fatalf("Rekor is down and the detail does not name it: %q", st.Detail)
		}
	})

	t.Run("alive but not ready", func(t *testing.T) {
		// All three gone at once. IP §6.6 asks for readiness; a process that
		// is running must still say it is running, or an orchestrator will
		// restart every replica when one shared dependency blips — and a
		// restart cannot fix Postgres.
		if berr := stack.block(ctx); berr != nil {
			t.Fatalf("close the admin port: %v", berr)
		}
		if kerr := pg.kill(ctx); kerr != nil {
			t.Fatalf("kill postgres: %v", kerr)
		}
		sig.fulcio.block()
		sig.rekor.block()

		r, _ := ready(t, h, sig)
		if r.Ready {
			t.Fatalf("ready is true with all three dependencies down")
		}
		if got := len(r.Unreachable()); got != 3 {
			t.Fatalf("Unreachable() named %d of 3 dependencies: %s", got, healthDump(r))
		}
		live := h.Live()
		if !live.Alive {
			t.Fatalf("the process reports not alive because its dependencies are down; " +
				"liveness and readiness are different questions")
		}
	})
}

// healthEventually retries until fn succeeds or the deadline passes.
func healthEventually(ctx context.Context, t *testing.T, within time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		if last = fn(); last == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended while waiting: %v (last: %v)", ctx.Err(), last)
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("not satisfied within %s; last: %v", within, last)
}

func healthDump(r Readiness) string {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf("%+v", r)
	}
	return string(b)
}

func healthTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{Version: "mcp-012"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// Fakes for the error paths a real dependency cannot be made to take on
// demand. The behavioural claims of MCP-012 are proved above, against real
// systems; these hold the classification table and the wire shape.
// ---------------------------------------------------------------------------

type healthFakeIdentities struct {
	err   error
	delay time.Duration
	calls atomic.Int64
}

func (f *healthFakeIdentities) AttestedNodes(ctx context.Context) ([]string, error) {
	f.calls.Add(1)
	if err := healthWait(ctx, f.delay); err != nil {
		return nil, err
	}
	return nil, f.err
}

type healthFakeLedger struct {
	err   error
	delay time.Duration
	calls atomic.Int64
}

func (f *healthFakeLedger) Head(ctx context.Context) (ledger.Head, error) {
	f.calls.Add(1)
	if err := healthWait(ctx, f.delay); err != nil {
		return ledger.Head{}, err
	}
	return ledger.Head{}, f.err
}

type healthFakeSigstore struct {
	signing      error
	transparency error
	calls        atomic.Int64
}

func (f *healthFakeSigstore) ProbeSigning(context.Context) error {
	f.calls.Add(1)
	return f.signing
}

func (f *healthFakeSigstore) ProbeTransparency(context.Context) error {
	f.calls.Add(1)
	return f.transparency
}

func healthWait(ctx context.Context, d time.Duration) error {
	if d == 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func healthWithFakes(t *testing.T, cfg HealthConfig) *Health {
	t.Helper()
	if cfg.Identities == nil {
		cfg.Identities = &healthFakeIdentities{}
	}
	if cfg.Ledger == nil {
		cfg.Ledger = &healthFakeLedger{}
	}
	if cfg.Sigstore == nil {
		cfg.Sigstore = &healthFakeSigstore{}
	}
	h, err := NewHealth(cfg)
	if err != nil {
		t.Fatalf("NewHealth: %v", err)
	}
	return h
}

// ---------------------------------------------------------------------------
// Construction — a probe that is absent must not be reported healthy.
// ---------------------------------------------------------------------------

func TestNewHealthRefusesAMissingProbe(t *testing.T) {
	t.Parallel()
	full := func() HealthConfig {
		return HealthConfig{
			Identities: &healthFakeIdentities{},
			Ledger:     &healthFakeLedger{},
			Sigstore:   &healthFakeSigstore{},
		}
	}
	cases := map[string]func(*HealthConfig){
		"no SPIRE":    func(c *HealthConfig) { c.Identities = nil },
		"no ledger":   func(c *HealthConfig) { c.Ledger = nil },
		"no Sigstore": func(c *HealthConfig) { c.Sigstore = nil },
	}
	for name, drop := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := full()
			drop(&cfg)
			h, err := NewHealth(cfg)
			if err == nil {
				t.Fatalf("NewHealth accepted a config with %s: a dependency with no probe "+
					"would be reported healthy without ever being contacted (got %+v)", name, h)
			}
			if e := Classify(err); e.Class != ClassInvariantViolation {
				t.Fatalf("class %q, want %q", e.Class, ClassInvariantViolation)
			}
		})
	}

	if _, err := NewHealth(full()); err != nil {
		t.Fatalf("a complete config was refused: %v", err)
	}
}

func TestHealthDefaultsAreUsable(t *testing.T) {
	t.Parallel()
	h := healthWithFakes(t, HealthConfig{})
	r := h.Ready(t.Context())
	if !r.Ready {
		t.Fatalf("three succeeding probes did not produce ready: %s", healthDump(r))
	}
	if r.ClockSkewBound != 0 {
		t.Fatalf("an unconfigured clock-skew bound was reported as %s", r.ClockSkewBound)
	}
	if r.Version == "" {
		t.Fatalf("no version in the report")
	}
	if h.Live().Version != r.Version {
		t.Fatalf("liveness and readiness disagree about the version")
	}
}

// ---------------------------------------------------------------------------
// Classification — a failure keeps a class it already carries, and otherwise
// takes its dependency's own outage class.
// ---------------------------------------------------------------------------

type healthClassifiedErr struct{ class Class }

func (e healthClassifiedErr) Error() string { return "classified: " + string(e.class) }
func (e healthClassifiedErr) ErrorClass() (Class, string, bool) {
	return e.class, "", e.class.Retryable()
}

func TestReadinessClassifiesEachDependencyFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		want  Class
		retry bool
	}{
		{"a plain error takes the dependency's outage class", errors.New("dial tcp: refused"), ClassIdentityUnavailable, true},
		{"a context deadline takes the outage class", context.DeadlineExceeded, ClassIdentityUnavailable, true},
		{"an *Error keeps its class", Errorf(ClassAttestationFailed, "", "selector mismatch"), ClassAttestationFailed, false},
		{"a *spire.Error keeps its class", &spire.Error{
			Class: spire.Class(ClassIdentityUnavailable), Message: "unreachable", Retryable: true,
		}, ClassIdentityUnavailable, true},
		{"a Classified keeps its class", healthClassifiedErr{ClassInvariantViolation}, ClassInvariantViolation, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := healthWithFakes(t, HealthConfig{Identities: &healthFakeIdentities{err: tc.err}})
			r := h.Ready(t.Context())
			st, ok := r.Status(DependencySPIRE)
			if !ok {
				t.Fatalf("no spire status")
			}
			if st.Reachable {
				t.Fatalf("a failing probe was reported reachable")
			}
			if st.Class != tc.want {
				t.Fatalf("class %q, want %q", st.Class, tc.want)
			}
			if st.Retryable != tc.retry {
				t.Fatalf("retryable %v, want %v", st.Retryable, tc.retry)
			}
		})
	}
}

func TestReadinessCarriesTheLedgersOwnClassAcross(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want Class
	}{
		{"unavailable", &ledger.StoreError{
			Class: ledger.ClassLedgerUnavailable, Op: "head", Retryable: true,
			Err: errors.New("connection refused"),
		}, ClassLedgerUnavailable},
		{"invariant", &ledger.StoreError{
			Class: ledger.ClassInvariantViolation, Op: "head", Retryable: false,
			Err: errors.New("relation does not exist"),
		}, ClassInvariantViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := healthWithFakes(t, HealthConfig{Ledger: &healthFakeLedger{err: tc.err}})
			st, _ := h.Ready(t.Context()).Status(DependencyLedger)
			if st.Class != tc.want {
				t.Fatalf("class %q, want %q", st.Class, tc.want)
			}
		})
	}
}

func TestReadinessNamesWhichHalfOfSigstoreIsDown(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		fake        *healthFakeSigstore
		want        Class
		mustMention []string
	}{
		{"Fulcio", &healthFakeSigstore{signing: errors.New("refused")},
			ClassSigningUnavailable, []string{"fulcio"}},
		{"Rekor", &healthFakeSigstore{transparency: errors.New("refused")},
			ClassTransparencyUnavailable, []string{"rekor"}},
		{"both", &healthFakeSigstore{signing: errors.New("refused"), transparency: errors.New("refused")},
			ClassSigningUnavailable, []string{"fulcio", "rekor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := healthWithFakes(t, HealthConfig{Sigstore: tc.fake})
			r := h.Ready(t.Context())
			if r.Ready {
				t.Fatalf("ready with Sigstore down")
			}
			st, _ := r.Status(DependencySigstore)
			if st.Class != tc.want {
				t.Fatalf("class %q, want %q", st.Class, tc.want)
			}
			for _, want := range tc.mustMention {
				if !strings.Contains(strings.ToLower(st.Detail), want) {
					t.Fatalf("detail %q does not name %q", st.Detail, want)
				}
			}
			if tc.fake.calls.Load() != 2 {
				t.Fatalf("Sigstore probed %d times, want both halves probed", tc.fake.calls.Load())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// One dependency's outage must not become another's.
// ---------------------------------------------------------------------------

func TestOneHungProbeDoesNotFailTheOthers(t *testing.T) {
	t.Parallel()
	slow := &healthFakeIdentities{delay: time.Minute}
	fastLedger := &healthFakeLedger{}
	fastSigstore := &healthFakeSigstore{}

	h := healthWithFakes(t, HealthConfig{
		Identities: slow, Ledger: fastLedger, Sigstore: fastSigstore,
		Timeout: 200 * time.Millisecond,
	})

	started := time.Now()
	r := h.Ready(t.Context())
	elapsed := time.Since(started)

	if elapsed > 30*time.Second {
		t.Fatalf("one hung probe held the whole check for %s", elapsed)
	}
	st, _ := r.Status(DependencySPIRE)
	if st.Reachable {
		t.Fatalf("a probe that never answered was reported reachable")
	}
	if st.Class != ClassIdentityUnavailable {
		t.Fatalf("a timed-out SPIRE probe is %q, want %q", st.Class, ClassIdentityUnavailable)
	}
	for _, d := range []Dependency{DependencyLedger, DependencySigstore} {
		other, _ := r.Status(d)
		if !other.Reachable {
			t.Fatalf("%s was reported unreachable because SPIRE hung: %s", d, other.Detail)
		}
	}
	if fastLedger.calls.Load() != 1 || fastSigstore.calls.Load() != 2 {
		t.Fatalf("the other probes did not run: ledger=%d sigstore=%d",
			fastLedger.calls.Load(), fastSigstore.calls.Load())
	}
}

// ---------------------------------------------------------------------------
// Liveness is a different question from readiness.
// ---------------------------------------------------------------------------

func TestLivenessIgnoresDependencies(t *testing.T) {
	t.Parallel()
	down := errors.New("everything is down")
	idents := &healthFakeIdentities{err: down}
	led := &healthFakeLedger{err: down}
	sigs := &healthFakeSigstore{signing: down, transparency: down}

	srv := healthTestServer(t)
	h := healthWithFakes(t, HealthConfig{
		Identities: idents, Ledger: led, Sigstore: sigs, Tools: srv, Version: "v-live",
	})

	live := h.Live()
	if !live.Alive {
		t.Fatalf("not alive with every dependency down; a restart cannot fix Postgres")
	}
	if idents.calls.Load() != 0 || led.calls.Load() != 0 || sigs.calls.Load() != 0 {
		t.Fatalf("liveness contacted a dependency: spire=%d ledger=%d sigstore=%d",
			idents.calls.Load(), led.calls.Load(), sigs.calls.Load())
	}
	if len(live.BoundTools) != len(srv.BoundTools()) {
		t.Fatalf("liveness reports %d bound tools, the server has %d",
			len(live.BoundTools), len(srv.BoundTools()))
	}
	if r := h.Ready(t.Context()); r.Ready {
		t.Fatalf("ready with every dependency down")
	}
}

func TestReadinessSurfacesTheIncompleteToolSurface(t *testing.T) {
	t.Parallel()
	srv := healthTestServer(t)
	h := healthWithFakes(t, HealthConfig{Tools: srv})

	r := h.Ready(t.Context())
	if len(r.MissingTools) != len(srv.MissingTools()) {
		t.Fatalf("readiness reports %v missing, the server reports %v",
			r.MissingTools, srv.MissingTools())
	}
	// A tool the surface does not yet carry is reported, never a reason to
	// refuse traffic for the tools it does carry.
	if len(srv.MissingTools()) > 0 && !r.Ready {
		t.Fatalf("an incomplete tool surface made the server unready: %s", healthDump(r))
	}

	// With no surface configured at all, the fields are simply absent.
	bare := healthWithFakes(t, HealthConfig{})
	if got := bare.Live().BoundTools; got != nil {
		t.Fatalf("bound tools %v reported with no tool surface configured", got)
	}
	if got := bare.Ready(t.Context()).MissingTools; got != nil {
		t.Fatalf("missing tools %v reported with no tool surface configured", got)
	}
}

// ---------------------------------------------------------------------------
// The wire shape an operator and the dashboard read.
// ---------------------------------------------------------------------------

func TestReadinessWireShape(t *testing.T) {
	t.Parallel()
	h := healthWithFakes(t, HealthConfig{
		Ledger: &healthFakeLedger{err: &ledger.StoreError{
			Class: ledger.ClassLedgerUnavailable, Op: "head", Retryable: true,
			Err: errors.New("connection refused"),
		}},
		Tools:          healthTestServer(t),
		ClockSkewBound: 5 * time.Second,
		Version:        "v-wire",
	})
	raw, err := json.Marshal(h.Ready(t.Context()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if uerr := json.Unmarshal(raw, &got); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if got["ready"] != false {
		t.Fatalf("ready = %v, want false: %s", got["ready"], raw)
	}
	if got["clock_skew_bound"] != "5s" {
		t.Fatalf("clock_skew_bound = %v, want \"5s\" (doc 05 §2): %s", got["clock_skew_bound"], raw)
	}
	if _, perr := event.ParseTimestamp(fmt.Sprint(got["observed_at"])); perr != nil {
		t.Fatalf("observed_at %v is not doc 02 §1's timestamp form: %v", got["observed_at"], perr)
	}
	deps, ok := got["dependencies"].([]any)
	if !ok || len(deps) != 3 {
		t.Fatalf("dependencies = %v, want three: %s", got["dependencies"], raw)
	}
	first, ok := deps[0].(map[string]any)
	if !ok {
		t.Fatalf("dependency 0 is %T", deps[0])
	}
	if first["dependency"] != string(DependencySPIRE) {
		t.Fatalf("dependency 0 is %v, want %q", first["dependency"], DependencySPIRE)
	}
	if first["reachable"] != true {
		t.Fatalf("a succeeding probe rendered as %v", first["reachable"])
	}
	if _, present := first["error_class"]; present {
		t.Fatalf("a reachable dependency carries an error_class: %v", first)
	}
	second, ok := deps[1].(map[string]any)
	if !ok {
		t.Fatalf("dependency 1 is %T", deps[1])
	}
	for key, want := range map[string]any{
		"dependency":  string(DependencyLedger),
		"reachable":   false,
		"error_class": string(ClassLedgerUnavailable),
		"retryable":   true,
	} {
		if second[key] != want {
			t.Fatalf("dependency 1 %s = %v, want %v: %s", key, second[key], want, raw)
		}
	}
	if fmt.Sprint(second["detail"]) == "" {
		t.Fatalf("no detail on the failing dependency: %s", raw)
	}

	// An unset clock-skew bound is absent, never rendered as "0s" — which an
	// operator would read as "no tolerance at all".
	bare := healthWithFakes(t, HealthConfig{})
	raw, err = json.Marshal(bare.Ready(t.Context()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "clock_skew_bound") {
		t.Fatalf("an unconfigured skew bound reached the wire: %s", raw)
	}
}

func TestLivenessWireShape(t *testing.T) {
	t.Parallel()
	h := healthWithFakes(t, HealthConfig{Tools: healthTestServer(t), Version: "v-live"})
	raw, err := json.Marshal(h.Live())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if uerr := json.Unmarshal(raw, &got); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if got["alive"] != true {
		t.Fatalf("alive = %v: %s", got["alive"], raw)
	}
	if got["version"] != "v-live" {
		t.Fatalf("version = %v: %s", got["version"], raw)
	}
	if _, err := event.ParseTimestamp(fmt.Sprint(got["observed_at"])); err != nil {
		t.Fatalf("observed_at %v is not doc 02 §1's timestamp form: %v", got["observed_at"], err)
	}
	if _, present := got["bound_tools"]; !present {
		t.Fatalf("no bound_tools: %s", raw)
	}
}

// ---------------------------------------------------------------------------
// The endpoints.
// ---------------------------------------------------------------------------

func TestHealthHandlerAnswersBothQuestions(t *testing.T) {
	t.Parallel()
	down := errors.New("ledger is gone")
	h := healthWithFakes(t, HealthConfig{Ledger: &healthFakeLedger{err: down}})
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)

	get := func(t *testing.T, path string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			if derr := json.NewDecoder(resp.Body).Decode(&body); derr != nil {
				t.Fatalf("decode %s: %v", path, derr)
			}
		}
		return resp.StatusCode, body
	}

	code, body := get(t, ReadyPath)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("%s with the ledger down returned %d, want %d", ReadyPath, code, http.StatusServiceUnavailable)
	}
	if body["ready"] != false {
		t.Fatalf("%s body says ready=%v", ReadyPath, body["ready"])
	}

	code, body = get(t, LivePath)
	if code != http.StatusOK {
		t.Fatalf("%s returned %d while the process is running, want 200", LivePath, code)
	}
	if body["alive"] != true {
		t.Fatalf("%s body says alive=%v", LivePath, body["alive"])
	}

	if code, _ = get(t, "/nope"); code != http.StatusNotFound {
		t.Fatalf("an unknown path returned %d, want 404", code)
	}

	// A health endpoint is a read. It must not accept a write.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+ReadyPath, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", ReadyPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s returned %d, want 405", ReadyPath, resp.StatusCode)
	}
}

func TestHealthHandlerReportsReadyWithEveryProbeGreen(t *testing.T) {
	t.Parallel()
	h := healthWithFakes(t, HealthConfig{})
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+ReadyPath, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d with every probe green, want 200", resp.StatusCode)
	}
}

// healthBrokenWriter fails every Write, the way a client that has hung up
// does.
type healthBrokenWriter struct {
	header http.Header
	code   int
}

func (w *healthBrokenWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *healthBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("client hung up") }
func (w *healthBrokenWriter) WriteHeader(code int)      { w.code = code }

func TestHealthHandlerSurvivesAClientThatHangsUp(t *testing.T) {
	t.Parallel()
	for _, path := range []string{LivePath, ReadyPath} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			h := healthWithFakes(t, HealthConfig{})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			w := &healthBrokenWriter{}
			h.Handler().ServeHTTP(w, req)
			if w.code == 0 {
				t.Fatalf("no status written")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The Sigstore probe itself. ADR-0010 made the self-hosted pair the shipped
// default, so "Sigstore" is whichever Fulcio/Rekor pair is configured.
// ---------------------------------------------------------------------------

func TestSigstoreEndpointsRefusesAnUnusableConfig(t *testing.T) {
	t.Parallel()
	cases := map[string]SigstoreConfig{
		"no Fulcio":         {RekorURL: "https://rekor.example"},
		"no Rekor":          {FulcioURL: "https://fulcio.example"},
		"unparseable":       {FulcioURL: "://", RekorURL: "https://rekor.example"},
		"unparseable rekor": {FulcioURL: "https://fulcio.example", RekorURL: "://"},
		"no scheme":         {FulcioURL: "fulcio.example", RekorURL: "https://rekor.example"},
		"no host":           {FulcioURL: "https:///path", RekorURL: "https://rekor.example"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewSigstoreEndpoints(cfg); err == nil {
				t.Fatalf("accepted %+v; a probe that cannot address its endpoint "+
					"would report Sigstore healthy without reaching it", cfg)
			}
		})
	}
	if _, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: "https://fulcio.example", RekorURL: "https://rekor.example",
	}); err != nil {
		t.Fatalf("a usable config was refused: %v", err)
	}
}

func TestSigstoreProbeRejectsAServerThatIsNotServingTrustMaterial(t *testing.T) {
	t.Parallel()
	// The whole point. A probe that accepts any 200 never fails, and a check
	// that never fails is worse than none: point it at an ordinary web server
	// and it reports Sigstore healthy for the rest of the outage.
	sig := newHealthSigstore(t)
	probe := sig.probe(t)

	if err := probe.ProbeSigning(t.Context()); err != nil {
		t.Fatalf("positive control: a real root certificate was refused: %v", err)
	}
	if err := probe.ProbeTransparency(t.Context()); err != nil {
		t.Fatalf("positive control: a real log key was refused: %v", err)
	}

	sig.fulcio.serveWrong.Store(true)
	sig.rekor.serveWrong.Store(true)

	err := probe.ProbeSigning(t.Context())
	if err == nil {
		t.Fatalf("Fulcio answered 200 with an HTML page and the probe passed")
	}
	if e := Classify(err); e.Class != ClassSigningUnavailable {
		t.Fatalf("class %q, want %q", e.Class, ClassSigningUnavailable)
	}
	err = probe.ProbeTransparency(t.Context())
	if err == nil {
		t.Fatalf("Rekor answered 200 with an HTML page and the probe passed")
	}
	if e := Classify(err); e.Class != ClassTransparencyUnavailable {
		t.Fatalf("class %q, want %q", e.Class, ClassTransparencyUnavailable)
	}
}

func TestSigstoreProbeFailsOnAClosedPortAndOnAnErrorStatus(t *testing.T) {
	t.Parallel()

	t.Run("closed port", func(t *testing.T) {
		t.Parallel()
		sig := newHealthSigstore(t)
		probe := sig.probe(t)
		sig.fulcio.block()
		sig.rekor.block()
		if err := probe.ProbeSigning(t.Context()); err == nil {
			t.Fatalf("a closed Fulcio port passed the probe")
		}
		if err := probe.ProbeTransparency(t.Context()); err == nil {
			t.Fatalf("a closed Rekor port passed the probe")
		}
	})

	t.Run("error status", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusBadGateway)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		probe, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: srv.URL, RekorURL: srv.URL})
		if err != nil {
			t.Fatalf("NewSigstoreEndpoints: %v", err)
		}
		if err := probe.ProbeSigning(t.Context()); err == nil {
			t.Fatalf("a 502 from Fulcio passed the probe")
		} else if !strings.Contains(err.Error(), "502") {
			t.Fatalf("the detail does not carry the status: %v", err)
		}
		if err := probe.ProbeTransparency(t.Context()); err == nil {
			t.Fatalf("a 502 from Rekor passed the probe")
		}
	})

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		probe, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: srv.URL, RekorURL: srv.URL})
		if err != nil {
			t.Fatalf("NewSigstoreEndpoints: %v", err)
		}
		if err := probe.ProbeSigning(t.Context()); err == nil {
			t.Fatalf("an empty body passed the Fulcio probe")
		}
		if err := probe.ProbeTransparency(t.Context()); err == nil {
			t.Fatalf("an empty body passed the Rekor probe")
		}
	})
}

func TestSigstoreProbeRejectsMaterialOfTheWrongKind(t *testing.T) {
	t.Parallel()
	// A well-formed PEM of the wrong type: Rekor's key served by Fulcio and
	// Fulcio's certificate served by Rekor. Both are valid PEM and both are
	// the wrong artifact.
	cert := healthFulcioRootPEM(t)
	key := healthRekorPublicKeyPEM(t)

	swapped := newHealthEndpointPair(t, key, cert)
	probe, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: swapped.fulcio.url(), RekorURL: swapped.rekor.url(),
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	if err := probe.ProbeSigning(t.Context()); err == nil {
		t.Fatalf("a public key passed as a Fulcio root certificate")
	}
	if err := probe.ProbeTransparency(t.Context()); err == nil {
		t.Fatalf("a certificate passed as a Rekor log key")
	}
}

func newHealthEndpointPair(t *testing.T, fulcioBody, rekorBody []byte) *healthSigstore {
	t.Helper()
	s := &healthSigstore{
		fulcio: newHealthEndpoint(DefaultFulcioRootPath, "application/pem-certificate-chain", fulcioBody),
		rekor:  newHealthEndpoint(DefaultRekorPublicKeyPath, "application/x-pem-file", rekorBody),
	}
	t.Cleanup(func() {
		s.fulcio.server.Close()
		s.rekor.server.Close()
	})
	return s
}

func TestSigstoreProbeHonoursConfiguredPaths(t *testing.T) {
	t.Parallel()
	fulcio := newHealthEndpoint("/custom/root", "application/pem-certificate-chain", healthFulcioRootPEM(t))
	rekor := newHealthEndpoint("/custom/key", "application/x-pem-file", healthRekorPublicKeyPEM(t))
	t.Cleanup(func() { fulcio.server.Close(); rekor.server.Close() })

	probe, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: fulcio.url(), RekorURL: rekor.url(),
		FulcioRootPath: "/custom/root", RekorPublicKeyPath: "/custom/key",
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	if err := probe.ProbeSigning(t.Context()); err != nil {
		t.Fatalf("ProbeSigning: %v", err)
	}
	if err := probe.ProbeTransparency(t.Context()); err != nil {
		t.Fatalf("ProbeTransparency: %v", err)
	}
	if fulcio.calls.Load() != 1 || rekor.calls.Load() != 1 {
		t.Fatalf("configured paths were not used: fulcio=%d rekor=%d",
			fulcio.calls.Load(), rekor.calls.Load())
	}
}

// ---------------------------------------------------------------------------
// Small surfaces.
// ---------------------------------------------------------------------------

func TestDependenciesAreTheThreeOfIP66(t *testing.T) {
	t.Parallel()
	got := Dependencies()
	want := []Dependency{DependencySPIRE, DependencyLedger, DependencySigstore}
	if len(got) != len(want) {
		t.Fatalf("Dependencies() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Dependencies()[%d] = %q, want %q", i, got[i], want[i])
		}
		if got[i].String() != string(want[i]) {
			t.Fatalf("String() = %q", got[i].String())
		}
	}
	got[0] = "mutated"
	if Dependencies()[0] != DependencySPIRE {
		t.Fatalf("Dependencies() handed out its own slice")
	}
}

func TestReadinessStatusOfAnUnknownDependency(t *testing.T) {
	t.Parallel()
	r := healthWithFakes(t, HealthConfig{}).Ready(t.Context())
	if _, ok := r.Status("postgres-but-spelled-wrong"); ok {
		t.Fatalf("Status answered for a dependency it does not track")
	}
	if got := r.Unreachable(); got != nil {
		t.Fatalf("Unreachable() = %v with everything up", got)
	}
}

// ---------------------------------------------------------------------------
// The trust-material checks, one refusal at a time. Each of these is a way for
// a probe to pass against something that is not the service it names, which is
// the "check that never fails" this file exists to avoid.
// ---------------------------------------------------------------------------

func TestSigstoreRootCertificateRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"not PEM at all":     []byte("<html>hello</html>"),
		"empty":              nil,
		"the wrong PEM type": healthRekorPublicKeyPEM(t),
		"unparseable DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00, 0x99}}),
		"a leaf, not a root": healthLeafCertificatePEM(t),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := sigstoreRootCertificate(body); err == nil {
				t.Fatalf("accepted %q as a Fulcio root certificate", name)
			}
		})
	}
	if err := sigstoreRootCertificate(healthFulcioRootPEM(t)); err != nil {
		t.Fatalf("a real root certificate was refused: %v", err)
	}
}

func TestSigstoreLogPublicKeyRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"not PEM at all":     []byte("<html>hello</html>"),
		"empty":              nil,
		"the wrong PEM type": healthFulcioRootPEM(t),
		"unparseable DER":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x30, 0x00, 0x99}}),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := sigstoreLogPublicKey(body); err == nil {
				t.Fatalf("accepted %q as a Rekor log key", name)
			}
		})
	}
	if err := sigstoreLogPublicKey(healthRekorPublicKeyPEM(t)); err != nil {
		t.Fatalf("a real log key was refused: %v", err)
	}
}

// healthLeafCertificatePEM is a valid, parseable, NON-CA certificate: the
// shape a misconfigured Fulcio (or a TLS terminator answering for it) would
// serve. A probe that stopped at "it parsed" would accept it.
func healthLeafCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "not-a-root.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSigstoreProbeReportsAnUnbuildableRequest(t *testing.T) {
	t.Parallel()
	// Constructed directly rather than through NewSigstoreEndpoints, because
	// the constructor exists to make this state unreachable in a deployment.
	// The test is here so the failure is still classified if it ever is
	// reached — a probe that panicked would take the endpoint down with it.
	hostile := &url.URL{Scheme: "http", Host: "exa\x7fmple"}
	probe := &SigstoreEndpoints{fulcio: hostile, rekor: hostile, client: &http.Client{}}

	err := probe.ProbeSigning(t.Context())
	if err == nil {
		t.Fatalf("an unbuildable request passed the Fulcio probe")
	}
	if e := Classify(err); e.Class != ClassSigningUnavailable {
		t.Fatalf("class %q, want %q", e.Class, ClassSigningUnavailable)
	}
	if err = probe.ProbeTransparency(t.Context()); err == nil {
		t.Fatalf("an unbuildable request passed the Rekor probe")
	}
}

func TestSigstoreProbeReportsATruncatedResponse(t *testing.T) {
	t.Parallel()
	// A real TCP peer that answers with a well-formed 200, promises 4096
	// bytes, sends a few, and resets the connection. The status line and the
	// headers arrive, so the failure lands in the body read rather than in the
	// round trip — which is what a service dying mid-response looks like, and
	// what an httptest handler cannot produce (its abort fails the round trip
	// instead).
	base := healthTruncatingListener(t)

	probe, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: base, RekorURL: base})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	err = probe.ProbeSigning(t.Context())
	if err == nil {
		t.Fatalf("a truncated body passed the Fulcio probe")
	}
	if !strings.Contains(err.Error(), "read the response") {
		t.Fatalf("the failure was not attributed to the body read: %v", err)
	}
	if e := Classify(err); e.Class != ClassSigningUnavailable {
		t.Fatalf("class %q, want %q", e.Class, ClassSigningUnavailable)
	}
	if err = probe.ProbeTransparency(t.Context()); err == nil {
		t.Fatalf("a truncated body passed the Rekor probe")
	}
}

// healthTruncatingListener serves a 200 whose body is cut short by a
// connection reset, and returns its base URL.
func healthTruncatingListener(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				healthIgnore(c.Read(make([]byte, 4096)))
				healthIgnore(c.Write([]byte("HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/pem-certificate-chain\r\n" +
					"Content-Length: 4096\r\n\r\n-----BEGIN CERTIFICATE-----")))
				// Reset rather than a clean FIN, so the read fails instead of
				// returning short.
				if tcp, ok := c.(*net.TCPConn); ok {
					healthIgnore(tcp.SetLinger(0))
				}
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestSigstoreEndpointsAreReportable(t *testing.T) {
	t.Parallel()
	// ADR-0010 makes "which trust root is this deployment checking" a question
	// an operator has to be able to answer, so the probe can say.
	probe, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: "https://fulcio.innsegl.test",
		RekorURL:  "https://rekor.innsegl.test",
		Client:    &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	fulcio, rekor := probe.Endpoints()
	if !strings.HasPrefix(fulcio, "https://fulcio.innsegl.test") ||
		!strings.HasSuffix(fulcio, DefaultFulcioRootPath) {
		t.Fatalf("fulcio endpoint = %q", fulcio)
	}
	if !strings.HasPrefix(rekor, "https://rekor.innsegl.test") ||
		!strings.HasSuffix(rekor, DefaultRekorPublicKeyPath) {
		t.Fatalf("rekor endpoint = %q", rekor)
	}
}

func TestHealthLogsAResponseItCouldNotWrite(t *testing.T) {
	t.Parallel()
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h := healthWithFakes(t, HealthConfig{Logger: logger})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ReadyPath, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	h.Handler().ServeHTTP(&healthBrokenWriter{}, req)

	if !strings.Contains(logged.String(), "writing the health response") {
		t.Fatalf("a response that could not be written was discarded silently: %q", logged.String())
	}
}
