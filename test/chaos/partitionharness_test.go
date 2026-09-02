// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/segment"
)

// ===========================================================================
// OPS-001's world: five real dependencies, and a switch on the route to each.
//
// Every identifier in this file and in partition_test.go carries a `prt`/
// `partition` prefix. That is not house style — it is the only thing keeping
// this file compilable beside test/chaos/kill_test.go (#61), which is being
// written into the same package at the same time. A collision here is a build
// failure for both issues, so nothing generic is declared: no `docker`, no
// `freeHostPort`, no `waitFor`, and above all NO TestMain. See "Why there is
// no TestMain" below.
//
// WHAT IS REAL
// ------------
// IP §2: "a mocked Fulcio proves nothing about I5", and the same sentence
// applies to every other dependency in the matrix. So:
//
//   - SPIRE is the shipped trio from deploy/compose/spire.yml, scoped to this
//     process by deploy/compose/spire-testscope.yml.
//   - Fulcio and Rekor (and Trillian, and Redis) are the shipped stack from
//     deploy/compose/sigstore.yml, scoped by
//     internal/signing/testdata/sigstore-testscope.yml.
//   - Postgres is a real postgres:16 container.
//   - Object storage is a real MinIO with a real object-lock bucket.
//   - The system under test is the SHIPPED `innsegl serve` binary as a
//     subprocess, reached over the MCP transport by the SDK client, with all
//     five tools bound.
//   - The commits are made by the released gitsign through internal/signing.
//
// Nothing here is faked, stubbed or in-memory.
//
// WHY A PARTITION IS A SEVERED ROUTE AND NOT A STOPPED CONTAINER
// --------------------------------------------------------------
// test/failure's stopSigService takes a dependency away by stopping its
// container, and for SIG-002 and SIG-003 that is exactly right: those cases
// are about ONE dependency being gone. OPS-001 is a different shape and the
// difference is measured, not stylistic:
//
//  1. FIFTEEN CELLS. Five singles plus ten pairs, each needing the dependency
//     back afterwards. A `docker compose start` of Fulcio is not complete
//     until the trust material parses again, which this repository's own
//     harness budgets three minutes for. Doing that up to twice per cell puts
//     the package past `go test`'s ten-minute default timeout, which no file
//     in this repository can raise from the inside. The matrix would not run.
//
//  2. A PARTITION IS NOT A CRASH. OPS-003 is the kill campaign; OPS-001 is
//     the partition matrix, and the word is in the title. The interesting
//     failure — the one IP §6 is written about — is a healthy dependency that
//     cannot be reached, because that is the state in which a system is
//     tempted to degrade silently rather than fail explicitly (doc 04 §2,
//     "dependency loss -> correct error classes, never silent degradation").
//
//  3. IT PROVES MORE, NOT LESS. Every partition below is confirmed twice: the
//     route refuses connections, AND the dependency behind it is proved still
//     healthy on a path the system under test cannot use. A stopped container
//     cannot give the second half. So each cell establishes that the error
//     class is about REACHABILITY and not about a process having died.
//
// The route is severed by prtGate: an in-process TCP forwarder that the system
// under test is configured to reach the dependency through, and through which
// it has no other path. `sever` closes the listener AND resets every live
// connection, so a pooled or long-lived connection is cut exactly as a network
// partition would cut it; `restore` re-binds the same port. This is the same
// device test/failure/harness_test.go already puts in front of the SPIRE admin
// API (countingProxy) and internal/segment's anchor test puts in front of
// Rekor, generalised to all five dependencies.
//
// The honesty cost is named rather than hidden: a gate proves nothing about a
// dependency that has CRASHED, only about one that cannot be reached. OPS-003
// (#61) is the case for the other half, and prtGateFidelity in
// partition_test.go pins the two together by taking Fulcio away for real, with
// `docker compose stop`, and asserting the same class the gate produced.
//
// WHY THERE IS NO TestMain
// -------------------------
// One per package, and test/chaos/kill_test.go is being written into this
// package in the same wave. So the stacks are built lazily under a sync.Once
// and torn down on the FIRST caller's t.Cleanup — the constraint ADR-0032
// already records for test/failure's Sigstore harness, hit again here for a
// different reason.
//
// The consequence is that bring-up counts against the package's test timeout
// instead of running before the clock starts. That is measured in the report
// for #59, and it is why requirePartitionWorld brings up the two compose
// projects CONCURRENTLY with Postgres and MinIO.
//
// ISSUE #101: A FAILED DEPENDENCY IS NOT A SKIP
// ----------------------------------------------
// internal/verify/verifyharness_test.go's shape is copied here deliberately.
// errPrtDependencyAbsent marks the only two honest reasons to skip — no Docker
// daemon, no gitsign binary — and NOTHING ELSE wraps it. A compose network
// that cannot be created, a port that cannot be bound, a container that never
// becomes healthy: every one of those is an infrastructure fault, it is
// recorded in prtFailure, and requirePartitionWorld calls t.Fatalf on it.
//
// The distinction is the whole point. OPS-001 is the case that turns IP §6's
// claims into measurements; reporting "the stack did not start" as a skip
// makes `go test` exit zero with the matrix never having run, which is the
// exact false-green scripts/test-no-skips.sh exists to catch and which eight
// harnesses in this repository still produce (#101). Both branches are
// exercised — see TestOPS001AbsentDependencyIsASkipAndAFaultIsAFailure.
// ===========================================================================

const (
	// PROTECTED STRINGS (IP §1, doc 08 §3). Spelled out rather than derived,
	// so a silent change to deploy/compose/spire/server.conf fails this file.
	prtTrustDomain = "innsegl.dev"
	prtAdminID     = "spiffe://innsegl.dev/innsegl/mcp"
	prtServerID    = "spiffe://innsegl.dev/spire/server"

	// The issuer both stacks must agree on (ADR-0029 decision 3). Pinned
	// rather than defaulted: when the three files that read it disagree,
	// Fulcio refuses every token with a message naming neither.
	prtIssuer = "http://spire-oidc:8080"

	// gitsign is used as a released upstream component (IP §7).
	prtGitsignVersion = "v0.17.1"

	prtSPIREAdminSocket = "/run/spire/admin/api.sock"
	prtSPIREAdminNet    = "-spire-admin"

	// The mixed workload's agent type and task, held to doc 02 §5's
	// identifier grammar because they become SPIFFE ID components.
	prtAgentType = "partition"
	prtTaskID    = "ops-001"

	// The author of every commit this file signs. ADR-0028 decision 6: a
	// `.invalid` domain can never be delegated, so no GitHub account can hold
	// it and no contributor can appear (I6).
	prtAuthorName  = "Innsegl Operator"
	prtAuthorEmail = "operator@innsegl.invalid"

	// The Sigstore documents both the readiness probe and this harness read.
	// Spelled out rather than imported: internal/mcp keeps them unexported,
	// and a harness deriving them from the code under test could not notice
	// the code changing which endpoint it probes.
	prtFulcioRootPath = "/api/v1/rootCert"
	prtRekorKeyPath   = "/api/v1/log/publicKey"

	prtPostgresImage = "postgres:16"
	prtMinIOImage    = "minio/minio:RELEASE.2025-09-07T16-13-09Z"
	prtSocatImage    = "alpine/socat:1.8.0.3"

	prtPGUser     = "innsegl"
	prtPGPassword = "innsegl-partition-test"
	prtPGDatabase = "innsegl"

	prtMinIOUser     = "innsegl"
	prtMinIOPassword = "innsegl-partition-secret"

	// prtExpireAfter is the reconciler's bounded window for this suite.
	prtExpireAfter = 250 * time.Millisecond

	// A short idempotency lease. The shipped default is a minute (ADR-0017
	// §5), which is right for a deployment and wrong here: a call whose claim
	// was orphaned by a Postgres partition would otherwise hold the key for a
	// minute and stall the cell that follows.
	prtIdempotencyLease = 750 * time.Millisecond
)

// The five dependencies of doc 07 OPS-001, and the only values a cell names.
const (
	prtSPIRE    = "spire"
	prtPostgres = "postgres"
	prtFulcio   = "fulcio"
	prtRekor    = "rekor"
	prtObject   = "object storage"
)

// prtDependencies is the matrix's alphabet, in doc 07 OPS-001's order.
func prtDependencies() []string {
	return []string{prtSPIRE, prtPostgres, prtFulcio, prtRekor, prtObject}
}

// errPrtDependencyAbsent marks the ONLY two conditions under which skipping
// OPS-001 is honest: there is no Docker daemon, or there is no gitsign binary.
// See the header. Nothing else may wrap it.
var errPrtDependencyAbsent = errors.New("a required dependency is absent")

var (
	prtOnce    sync.Once
	prtShared  *prtWorld
	prtSkip    string
	prtFailure string
	prtSeq     atomic.Int64
)

// prtRoute is #101's decision, isolated so that BOTH of its branches can be
// exercised without a Docker daemon — see
// TestOPS001AbsentDependencyIsASkipAndAFaultIsAFailure.
//
// An absent dependency is a skip. Everything else is a failure. There is no
// third answer, and the reason there is no third answer is that the third
// answer is how eight harnesses in this repository came to exit zero with
// their integration cases never having run.
func prtRoute(err error) (skip, failure string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, errPrtDependencyAbsent):
		return err.Error(), ""
	default:
		return "", err.Error()
	}
}

// ---------------------------------------------------------------------------
// Docker.
// ---------------------------------------------------------------------------

func prtDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, prtOneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// prtDockerUsable reports whether a docker daemon is reachable. Its errors are
// the only ones in this file that wrap errPrtDependencyAbsent, alongside
// prtFindGitsign's.
func prtDockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errPrtDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errPrtDependencyAbsent)
	}
	if _, err := prtDocker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errPrtDependencyAbsent)
	}
	return nil
}

// prtOneLine collapses a multi-line subprocess error onto one line, so Go's
// test JSON stream does not scatter it across events with the cause on a line
// the summary never shows.
func prtOneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func prtFreePort(ctx context.Context) (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if cerr := l.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return port, err
}

func prtFindGitsign(ctx context.Context) (string, error) {
	if p := os.Getenv("INNSEGL_GITSIGN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("INNSEGL_GITSIGN=%s: %w: %w", p, err, errPrtDependencyAbsent)
		}
		return p, nil
	}
	if p, err := exec.LookPath("gitsign"); err == nil {
		return p, nil
	}
	out, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(strings.TrimSpace(string(out)), "bin", "gitsign")
		if _, serr := os.Stat(p); serr == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no gitsign binary; install the pinned release with "+
		"`go install github.com/sigstore/gitsign@%s` or set INNSEGL_GITSIGN: %w",
		prtGitsignVersion, errPrtDependencyAbsent)
}

func prtWaitFor(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// The gate: one severable route to one real dependency.
// ---------------------------------------------------------------------------

// prtGate forwards TCP from a fixed loopback port to a real dependency, and
// can sever the route without touching the dependency.
//
// It is deliberately dumb. It parses nothing, understands neither gRPC nor
// Postgres wire protocol nor HTTP, and never answers on the dependency's
// behalf — so it cannot fake a reply, cannot inject an error the dependency
// would not have produced, and cannot make the system under test take a
// different code path while the route is up. The only thing it can do is stop
// being a route.
type prtGate struct {
	name    string
	backend string // host:port of the real dependency
	port    string // the loopback port this gate owns for its whole life

	// health probes the REAL dependency by a path that does not go through
	// this gate, so a severed cell can prove the dependency is still up.
	health func(ctx context.Context) error

	mu     sync.Mutex
	ln     net.Listener
	live   map[net.Conn]struct{}
	closed bool
}

func (g *prtGate) addr() string { return "127.0.0.1:" + g.port }

func (g *prtGate) url() string { return "http://" + g.addr() }

// listen binds the gate's port and starts forwarding.
func (g *prtGate) listen(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln != nil {
		return nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", g.addr())
	if err != nil {
		return fmt.Errorf("gate %s: bind %s: %w", g.name, g.addr(), err)
	}
	g.ln = ln
	g.closed = false
	if g.live == nil {
		g.live = map[net.Conn]struct{}{}
	}
	go g.accept(ln)
	return nil
}

func (g *prtGate) accept(ln net.Listener) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		go g.forward(client)
	}
}

func (g *prtGate) forward(client net.Conn) {
	d := net.Dialer{Timeout: 10 * time.Second}
	backend, err := d.DialContext(context.Background(), "tcp", g.backend)
	if err != nil {
		prtReset(client)
		return
	}
	if !g.track(client, backend) {
		prtReset(client)
		prtReset(backend)
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, cerr := io.Copy(backend, client)
		prtDropped(cerr)
		done <- struct{}{}
	}()
	go func() {
		_, cerr := io.Copy(client, backend)
		prtDropped(cerr)
		done <- struct{}{}
	}()
	<-done
	g.untrack(client, backend)
	prtReset(client)
	prtReset(backend)
}

func (g *prtGate) track(conns ...net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	for _, c := range conns {
		g.live[c] = struct{}{}
	}
	return true
}

func (g *prtGate) untrack(conns ...net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range conns {
		delete(g.live, c)
	}
}

// prtReset closes a connection with RST rather than FIN where the platform
// allows it, which is what a partitioned peer looks like: the far end does not
// get an orderly half-close it could mistake for a completed response.
func prtReset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		// A platform that will not set SO_LINGER gives an orderly FIN instead
		// of a reset, which is a weaker partition and not a wrong one.
		prtDropped(tc.SetLinger(0))
	}
	prtDropped(c.Close())
}

// prtDropped names what happens to an error this harness deliberately does not
// act on, so that the discard is a decision in the source rather than a blank
// identifier a reader has to interpret.
//
// Every use is a place where there is no caller to tell and nothing to do: a
// forwarding copy that ended because the route was severed (which is this
// gate's whole purpose), a socket teardown, the final close of a gate at the
// end of the suite, and the SIGKILL of a subprocess that is already going away.
// Anything an assertion could act on is returned, never dropped here.
func prtDropped(error) {}

// sever takes the route away and does not return until it is provably gone.
//
// Two things happen, and both are necessary. The listener is closed, so no new
// connection can be made; and every connection already open through the gate
// is RESET, because a pooled Postgres connection or a long-lived gRPC channel
// that survived would mean the dependency was still reachable while the test
// asserted it was not. That is the failure mode a listener-only "partition"
// hides, and it is silent.
func (g *prtGate) sever() error {
	g.mu.Lock()
	ln := g.ln
	g.ln = nil
	g.closed = true
	live := make([]net.Conn, 0, len(g.live))
	for c := range g.live {
		live = append(live, c)
	}
	g.live = map[net.Conn]struct{}{}
	g.mu.Unlock()

	if ln != nil {
		if err := ln.Close(); err != nil {
			return fmt.Errorf("gate %s: close listener: %w", g.name, err)
		}
	}
	for _, c := range live {
		prtReset(c)
	}
	return nil
}

// restore re-binds the gate's own port.
//
// Bounded retry rather than a single attempt: the port is released for the
// duration of the outage, and a bind that loses a race with something else on
// the machine must fail loudly here rather than leave the next cell asserting
// against a route that silently never came back.
func (g *prtGate) restore(ctx context.Context) error {
	var last error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		last = g.listen(ctx)
		if last == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("gate %s never got its port back: %w", g.name, last)
}

// refuses reports whether the gate's address refuses connections outright. A
// dial that succeeds — to anything — means the route is not severed.
func (g *prtGate) refuses() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", g.addr())
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

func (g *prtGate) close() { prtDropped(g.sever()) }

// ---------------------------------------------------------------------------
// The world.
// ---------------------------------------------------------------------------

type prtWorld struct {
	root    string
	project string
	workDir string

	spireFiles []string
	sigFiles   []string
	env        []string

	// The DIRECT addresses of the real dependencies. Nothing the system under
	// test is configured with ever names one of these; they exist so a severed
	// cell can prove the dependency behind the gate is still healthy.
	oidcURL      string
	fulcioDirect string
	rekorDirect  string
	spireDirect  string
	pgDirect     string
	minioDirect  string

	socatName string
	pgName    string
	minioName string

	// The gates. Every address the system under test holds is one of these.
	gates map[string]*prtGate

	gitsignPath string
	binary      string
	pemDir      string
	dsn         string
	bucket      string

	// The test process's own readers. The server opens its own.
	store *ledger.Store
	pool  *pgxpool.Pool
	worm  *segment.WORM

	daemon *prtDaemon
}

func prtProject() string { return fmt.Sprintf("innsegl-partition-%d", os.Getpid()) }

func (w *prtWorld) compose(ctx context.Context, files []string, args ...string) (string, error) {
	full := []string{"compose", "-p", w.project}
	for _, f := range files {
		full = append(full, "-f", f)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Env = append(os.Environ(), w.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(full, " "), err, prtOneLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// spireServer runs the SPIRE server CLI on the container-private admin socket.
// That socket is unauthenticated and unfiltered, so it is the ground truth for
// what the datastore holds — and it does not travel the SPIRE gate, which is
// what makes it usable as the health probe of a severed cell.
func (w *prtWorld) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", prtSPIREAdminSocket)
	return w.compose(ctx, w.spireFiles, full...)
}

// ---------------------------------------------------------------------------
// Bring-up.
// ---------------------------------------------------------------------------

func prtStartWorld(ctx context.Context, root, workDir string) (*prtWorld, error) {
	gitsign, err := prtFindGitsign(ctx)
	if err != nil {
		return nil, err
	}

	ports := make([]string, 0, 8)
	for range 8 {
		p, perr := prtFreePort(ctx)
		if perr != nil {
			return nil, fmt.Errorf("reserve a loopback port: %w", perr)
		}
		ports = append(ports, p)
	}

	project := prtProject()
	w := &prtWorld{
		root:    root,
		project: project,
		workDir: workDir,
		spireFiles: []string{
			filepath.Join(root, "deploy", "compose", "spire.yml"),
			filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		},
		// ADR-0031 asked for this overlay to move to deploy/compose/ "the
		// moment a second suite needs it"; ADR-0034 repeats the request.
		// deploy/ is not this issue's to change, so it is referenced where it
		// lives, exactly as internal/verify's harness does.
		sigFiles: []string{
			filepath.Join(root, "deploy", "compose", "sigstore.yml"),
			filepath.Join(root, "internal", "signing", "testdata", "sigstore-testscope.yml"),
		},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + prtIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + ports[0],
			"INNSEGL_FULCIO_PORT=" + ports[1],
			"INNSEGL_REKOR_PORT=" + ports[2],
		},
		oidcURL:      "http://127.0.0.1:" + ports[0],
		fulcioDirect: "127.0.0.1:" + ports[1],
		rekorDirect:  "127.0.0.1:" + ports[2],
		spireDirect:  "127.0.0.1:" + ports[3],
		pgDirect:     "127.0.0.1:" + ports[4],
		minioDirect:  "127.0.0.1:" + ports[5],
		socatName:    project + "-adminproxy",
		pgName:       project + "-postgres",
		minioName:    project + "-minio",
		gitsignPath:  gitsign,
		gates:        map[string]*prtGate{},
	}

	// The two compose projects and the two plain containers come up together.
	// Serially this is the slowest thing in the package by a wide margin, and
	// with no TestMain to hide behind (see the header) every second of it is
	// charged to the ten-minute test timeout.
	var (
		wg                              sync.WaitGroup
		spireErr, sigErr, pgErr, minErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		spireErr = w.startSPIRE(ctx)
	}()
	go func() {
		defer wg.Done()
		pgErr = w.startPostgres(ctx)
		if pgErr == nil {
			minErr = w.startMinIO(ctx)
		}
	}()
	wg.Wait()
	if spireErr != nil {
		return w, spireErr
	}
	if pgErr != nil {
		return w, pgErr
	}
	if minErr != nil {
		return w, minErr
	}
	// Sigstore's fulcio joins the SPIRE stack's OIDC frontend network, so it
	// cannot start until that network exists. Sequential by construction.
	if sigErr = w.startSigstore(ctx); sigErr != nil {
		return w, sigErr
	}

	if err := w.buildGates(ctx); err != nil {
		return w, err
	}
	if err := w.buildServer(ctx); err != nil {
		return w, err
	}
	return w, nil
}

func (w *prtWorld) startSPIRE(ctx context.Context) error {
	if _, err := w.compose(ctx, w.spireFiles, "up", "-d", "--wait",
		"spire-server", "spire-agent", "spire-oidc"); err != nil {
		return fmt.Errorf("bringing up the SPIRE stack: %w", err)
	}
	if err := w.registerOIDCProvider(ctx); err != nil {
		return fmt.Errorf("registering the OIDC discovery provider: %w", err)
	}
	return w.startAdminBridge(ctx)
}

// startAdminBridge publishes the SPIRE admin API on loopback.
//
// ADR-0011 puts the admin API on an internal network with no published port,
// and Docker will not publish a port for a container whose only network is
// internal. So a socat container is created on the default bridge, joined to
// the admin network, and the SPIRE gate forwards to it.
func (w *prtWorld) startAdminBridge(ctx context.Context) error {
	_, port, err := net.SplitHostPort(w.spireDirect)
	if err != nil {
		return err
	}
	if _, err := prtDocker(ctx, "run", "--detach", "--name", w.socatName,
		"--publish", w.spireDirect+":8081",
		prtEnvOr("INNSEGL_TEST_PROXY_IMAGE", prtSocatImage),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		return fmt.Errorf("start the SPIRE admin bridge: %w", err)
	}
	if _, err := prtDocker(ctx, "network", "connect",
		w.project+prtSPIREAdminNet, w.socatName); err != nil {
		return fmt.Errorf("join %s: %w", w.project+prtSPIREAdminNet, err)
	}
	if !prtWaitFor(60*time.Second, func() bool {
		var d net.Dialer
		dial, derr := d.DialContext(ctx, "tcp", "127.0.0.1:"+port)
		if derr != nil {
			return false
		}
		_ = dial.Close()
		return true
	}) {
		return fmt.Errorf("the SPIRE admin bridge never published %s", w.spireDirect)
	}
	return nil
}

// registerOIDCProvider derives the five selectors deploy/compose/spire/
// register.sh hardcodes for a stack it cannot parameterise.
//
// This is the fifth reimplementation of it in this repository. ADR-0031 and
// ADR-0034 both ask for register.sh to take a project and container name;
// deploy/ is not this issue's to change, so it is derived here again. Without
// this entry the provider holds no SVID, `GET /keys` answers HTTP 500, and
// Fulcio refuses every token with a message that names neither the issuer nor
// the mismatch.
func (w *prtWorld) registerOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://" + prtTrustDomain + "/innsegl/oidc-discovery-provider"
	container := w.project + "-spire-oidc"

	parent, err := w.attestedNode(ctx)
	if err != nil {
		return err
	}
	imageConfigDigest, err := prtDocker(ctx, "inspect", "--format", "{{.Image}}", container)
	if err != nil {
		return err
	}
	imageRef, err := prtDocker(ctx, "inspect", "--format", "{{.Config.Image}}", container)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "innsegl-prt-oidc-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary := filepath.Join(dir, "oidc")
	if _, cperr := prtDocker(ctx, "cp",
		container+":/opt/spire/bin/oidc-discovery-provider", binary); cperr != nil {
		return cperr
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if _, err := w.spireServer(ctx, "entry", "create",
		"-parentID", parent,
		"-spiffeID", spiffeID,
		"-selector", "unix:sha256:"+hex.EncodeToString(sum[:]),
		"-selector", "unix:uid:1000",
		"-selector", "docker:image_config_digest:"+imageConfigDigest,
		"-selector", "docker:label:dev.innsegl.component:oidc-discovery-provider",
		"-selector", "docker:image_id:"+imageRef,
		"-x509SVIDTTL", "1800",
		"-jwtSVIDTTL", "300",
	); err != nil {
		return err
	}
	return w.awaitJWKS(ctx)
}

func (w *prtWorld) attestedNode(ctx context.Context) (string, error) {
	deadline := time.Now().Add(150 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		out, err := w.spireServer(ctx, "agent", "list")
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
					return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":")), nil
				}
			}
			last = fmt.Errorf("no attested agent in `agent list`:\n%s", out)
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("no attested SPIRE agent: %w", last)
}

func (w *prtWorld) awaitJWKS(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := prtGET(ctx, w.oidcURL+"/keys")
		if err == nil && strings.Contains(string(body), "\"keys\"") {
			return nil
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("the OIDC discovery provider never served a JWKS: %w", last)
}

func (w *prtWorld) startSigstore(ctx context.Context) error {
	if _, err := w.compose(ctx, w.sigFiles, "up", "-d"); err != nil {
		return fmt.Errorf("bringing up the Sigstore stack: %w", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		last = errors.Join(
			w.probeFulcioAt(ctx, "http://"+w.fulcioDirect),
			w.probeRekorAt(ctx, "http://"+w.rekorDirect),
		)
		if last == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("Sigstore never served parseable trust material: %w", last)
}

func (w *prtWorld) startPostgres(ctx context.Context) error {
	if _, err := prtDocker(ctx, "run", "--detach", "--name", w.pgName,
		"--publish", w.pgDirect+":5432",
		"--env", "POSTGRES_USER="+prtPGUser,
		"--env", "POSTGRES_PASSWORD="+prtPGPassword,
		"--env", "POSTGRES_DB="+prtPGDatabase,
		prtEnvOr("INNSEGL_TEST_POSTGRES_IMAGE", prtPostgresImage),
	); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}
	deadline := time.Now().Add(150 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = prtPingPostgres(ctx, prtDSN(w.pgDirect, prtPGDatabase))
		if last == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("postgres never became ready: %w", last)
}

func prtDSN(hostPort, database string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		prtPGUser, prtPGPassword, hostPort, database)
}

func prtPingPostgres(ctx context.Context, dsn string) error {
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(attempt, dsn)
	if err != nil {
		return err
	}
	perr := conn.Ping(attempt)
	cerr := conn.Close(attempt)
	if perr != nil {
		return perr
	}
	return cerr
}

func (w *prtWorld) startMinIO(ctx context.Context) error {
	if _, err := prtDocker(ctx, "run", "--detach", "--name", w.minioName,
		"--publish", w.minioDirect+":9000",
		"--env", "MINIO_ROOT_USER="+prtMinIOUser,
		"--env", "MINIO_ROOT_PASSWORD="+prtMinIOPassword,
		prtEnvOr("INNSEGL_TEST_MINIO_IMAGE", prtMinIOImage), "server", "/data",
	); err != nil {
		return fmt.Errorf("start minio: %w", err)
	}
	deadline := time.Now().Add(150 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = prtMinIOReady(ctx, w.minioDirect)
		if last == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("minio never became ready: %w", last)
}

func prtMinIOClient(endpoint string) (*minio.Client, error) {
	return minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(prtMinIOUser, prtMinIOPassword, ""),
		Secure: false,
	})
}

func prtMinIOReady(ctx context.Context, endpoint string) error {
	cl, err := prtMinIOClient(endpoint)
	if err != nil {
		return err
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = cl.ListBuckets(attempt)
	return err
}

func prtEnvOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// buildGates puts one severable route in front of each of the five real
// dependencies, and confirms every one of them carries traffic before any cell
// is allowed to sever it.
func (w *prtWorld) buildGates(ctx context.Context) error {
	spec := []struct {
		name    string
		backend string
		health  func(ctx context.Context) error
	}{
		{prtSPIRE, w.spireDirect, w.probeSPIREDirect},
		{prtPostgres, w.pgDirect, func(c context.Context) error {
			return prtPingPostgres(c, prtDSN(w.pgDirect, prtPGDatabase))
		}},
		{prtFulcio, w.fulcioDirect, func(c context.Context) error {
			return w.probeFulcioAt(c, "http://"+w.fulcioDirect)
		}},
		{prtRekor, w.rekorDirect, func(c context.Context) error {
			return w.probeRekorAt(c, "http://"+w.rekorDirect)
		}},
		{prtObject, w.minioDirect, func(c context.Context) error {
			return prtMinIOReady(c, w.minioDirect)
		}},
	}
	for _, s := range spec {
		port, err := prtFreePort(ctx)
		if err != nil {
			return fmt.Errorf("reserve a gate port for %s: %w", s.name, err)
		}
		g := &prtGate{name: s.name, backend: s.backend, port: port, health: s.health}
		if err := g.listen(ctx); err != nil {
			return err
		}
		w.gates[s.name] = g
	}
	return nil
}

func (w *prtWorld) gate(name string) *prtGate { return w.gates[name] }

// probeSPIREDirect asks the SPIRE server itself, on the container-private
// admin socket, whether it is serving. It travels no gate, so it is what a
// severed cell uses to prove the dependency is healthy and only unreachable.
func (w *prtWorld) probeSPIREDirect(ctx context.Context) error {
	if _, err := w.spireServer(ctx, "healthcheck"); err != nil {
		return fmt.Errorf("spire-server healthcheck: %w", err)
	}
	return nil
}

// probeFulcioAt is ADR-0024's Fulcio half, and internal/mcp's readiness probe
// verbatim: a PEM CA certificate, parsed.
func (w *prtWorld) probeFulcioAt(ctx context.Context, base string) error {
	root, err := prtGET(ctx, base+prtFulcioRootPath)
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("fulcio: %s is not a PEM certificate", prtFulcioRootPath)
	}
	return nil
}

// probeRekorAt is ADR-0024's Rekor half, parsed by internal/segment's own
// parser rather than by a second one written here.
func (w *prtWorld) probeRekorAt(ctx context.Context, base string) error {
	key, err := prtGET(ctx, base+prtRekorKeyPath)
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, err := segment.ParseLogPublicKey(key); err != nil {
		return fmt.Errorf("rekor: %s does not parse: %w", prtRekorKeyPath, err)
	}
	return nil
}

func prtGET(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", endpoint, resp.StatusCode, body)
	}
	return body, nil
}

// buildServer compiles the SHIPPED binary. ./cmd/innsegl, not a purpose-built
// daemon: the process the matrix partitions must be the process a deployment
// runs, or the error classes it reports are some other program's.
func (w *prtWorld) buildServer(ctx context.Context) error {
	out := filepath.Join(w.workDir, "innsegl")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/innsegl")
	cmd.Dir = w.root
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build ./cmd/innsegl: %w: %s", err, prtOneLine(string(b)))
	}
	w.binary = out
	return nil
}

func (w *prtWorld) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	if w.daemon != nil {
		w.daemon.reap()
	}
	for _, g := range w.gates {
		g.close()
	}
	if w.pool != nil {
		w.pool.Close()
	}
	if w.store != nil {
		w.store.Close()
	}
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	for _, name := range []string{w.socatName, w.pgName, w.minioName} {
		if name == "" {
			continue
		}
		if _, err := prtDocker(ctx, "rm", "--force", "--volumes", name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", name, err)
		}
	}
	for _, files := range [][]string{w.sigFiles, w.spireFiles} {
		if _, err := w.compose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// requirePartitionWorld — #101's corrected shape, without a TestMain.
// ---------------------------------------------------------------------------

func requirePartitionWorld(t *testing.T) *prtWorld {
	t.Helper()
	prtOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
		defer cancel()
		wd, err := os.Getwd()
		if err != nil {
			prtFailure = err.Error()
			return
		}
		root := filepath.Dir(filepath.Dir(wd))
		workDir, err := os.MkdirTemp("", "innsegl-partition-")
		if err != nil {
			prtFailure = err.Error()
			return
		}
		if derr := prtDockerUsable(ctx); derr != nil {
			prtSkip = derr.Error()
			return
		}
		world, werr := prtStartWorld(ctx, root, workDir)
		// The two outcomes are not the same thing, and were treated as the
		// same thing across this repository until CI proved the difference
		// (#101). Only an ABSENT dependency skips.
		prtSkip, prtFailure = prtRoute(werr)
		if werr == nil {
			prtShared = world
		} else if world != nil {
			world.stop()
		}
	})

	if prtFailure != "" {
		t.Fatalf("OPS-001's world did not come up, and Docker and gitsign are both "+
			"present: %s\n\nThis is a FAILURE and not a skip. OPS-001 is the case that "+
			"turns IP §6's failure-mode claims into measurements; reporting an "+
			"infrastructure fault as a skip exits zero and reports ok while not one "+
			"cell of the matrix ran (#101).", prtFailure)
	}
	if prtShared == nil {
		t.Skipf("skipping OPS-001: no real SPIRE + Sigstore + Postgres + MinIO and no "+
			"gitsign (%s). A partition matrix with no dependency to partition proves "+
			"nothing, and IP §2 is explicit that \"a mocked Fulcio proves nothing about "+
			"I5\". Start Docker, `go install github.com/sigstore/gitsign@%s`, and re-run.",
			prtSkip, prtGitsignVersion)
	}

	t.Cleanup(func() {
		if prtShared != nil {
			prtShared.stop()
			prtShared = nil
		}
		prtOnce = sync.Once{}
	})
	return prtShared
}

// ---------------------------------------------------------------------------
// The system under test: `innsegl serve`, reached only through the gates.
// ---------------------------------------------------------------------------

type prtDaemon struct {
	cmd     *exec.Cmd
	addr    string
	health  string
	stderr  *prtBuffer
	session *sdk.ClientSession
	dead    bool
}

type prtBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *prtBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *prtBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// writeAdminPEMs mints the admin SVID and puts it where a subprocess can read
// it. In a deployment the MCP is an attested workload and takes none of these
// three flags; there is no attested innsegl-mcp on this host.
func (w *prtWorld) writeAdminPEMs(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := w.spireServer(ctx, "x509", "mint", "-spiffeID", prtAdminID, "-ttl", "3h")
	if err != nil {
		t.Fatalf("mint the admin SVID: %v", err)
	}
	svidPEM, keyPEM, rootsPEM, err := prtParseMint(out)
	if err != nil {
		t.Fatalf("parse `x509 mint` output: %v", err)
	}
	dir := filepath.Join(w.workDir, "admin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for name, body := range map[string]string{
		"svid.pem": svidPEM, "key.pem": keyPEM, "bundle.pem": rootsPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func prtParseMint(out string) (svidPEM, keyPEM, rootsPEM string, err error) {
	const (
		hSVID  = "X509-SVID:"
		hKey   = "Private key:"
		hRoots = "Root CAs:"
	)
	i, j, k := strings.Index(out, hSVID), strings.Index(out, hKey), strings.Index(out, hRoots)
	if i < 0 || j < i || k < j {
		return "", "", "", fmt.Errorf("unrecognised `x509 mint` output: %.200q", out)
	}
	return out[i+len(hSVID) : j], out[j+len(hKey) : k], out[k+len(hRoots):], nil
}

// startDaemon launches one `innsegl serve` whose every dependency address is a
// GATE address.
//
// That is the load-bearing line in this function. If the process held a direct
// address for any of the five, a severed cell would be asserting against a
// route the process was not using, and the matrix would measure nothing. The
// only addresses below that are not gates are the OIDC issuer — which is a
// string Fulcio and the verifier must agree on, not an endpoint this process
// dials — and the loopback listeners the server publishes for itself.
func (w *prtWorld) startDaemon(t *testing.T) *prtDaemon {
	t.Helper()
	addrFile := filepath.Join(w.workDir, "mcp.addr")
	repos := filepath.Join(w.workDir, "workspace")
	if err := os.MkdirAll(repos, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", repos, err)
	}

	parent, err := w.attestedNode(context.Background())
	if err != nil {
		t.Fatalf("the attested node every run entry parents to: %v", err)
	}
	w.pemDir = w.writeAdminPEMs(t)

	cmd := exec.CommandContext(context.Background(), w.binary, "serve",
		"-dsn", w.dsn,
		"-spire-address", w.gate(prtSPIRE).addr(),
		"-trust-domain", prtTrustDomain,
		"-spire-server-id", prtServerID,
		"-parent-id", parent,
		"-svid", filepath.Join(w.pemDir, "svid.pem"),
		"-key", filepath.Join(w.pemDir, "key.pem"),
		"-bundle", filepath.Join(w.pemDir, "bundle.pem"),
		"-fulcio-url", w.gate(prtFulcio).url(),
		"-rekor-url", w.gate(prtRekor).url(),
		"-oidc-issuer", prtIssuer,
		"-workspace", repos,
		"-gitsign", w.gitsignPath,
		"-sign-author-name", prtAuthorName,
		"-sign-author-email", prtAuthorEmail,
		"-sign-author-allow-unlinked",
		"-listen", "127.0.0.1:0",
		"-health-listen", "127.0.0.1:0",
		"-addr-file", addrFile,
		"-idempotency-lease", prtIdempotencyLease.String(),
		// AB-07's control is MCP-013's subject. An unmetered tool is what this
		// matrix measures error classes against; a limiter would add a class
		// nothing here is asking about.
		"-register-rate-calls", "0",
	)
	stderr := &prtBuffer{}
	cmd.Stderr = stderr
	if serr := cmd.Start(); serr != nil {
		t.Fatalf("starting `innsegl serve`: %v", serr)
	}
	d := &prtDaemon{cmd: cmd, stderr: stderr}
	w.daemon = d
	t.Cleanup(d.reap)

	deadline := time.Now().Add(90 * time.Second)
	for {
		raw, rerr := os.ReadFile(addrFile)
		if rerr == nil && len(raw) > 0 {
			d.addr = strings.TrimSpace(string(raw))
			break
		}
		if cmd.ProcessState != nil {
			t.Fatalf("`innsegl serve` exited before it served:\n%s", stderr.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("`innsegl serve` never published its address:\n%s", stderr.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	d.health = prtHealthAddr(t, d)

	if !strings.Contains(stderr.String(), "sign_commit is configured") {
		t.Fatalf("sign_commit is not configured, so no cell of the matrix could "+
			"exercise Fulcio or Rekor at all:\n%s", stderr.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-ops-001", Version: "v0"}, nil)
	session, err := client.Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: "http://" + d.addr}, nil)
	if err != nil {
		t.Fatalf("connecting to `innsegl serve` at %s: %v\n%s", d.addr, err, stderr.String())
	}
	d.session = session
	return d
}

func prtHealthAddr(t *testing.T, d *prtDaemon) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, field := range strings.Fields(d.stderr.String()) {
			if rest, ok := strings.CutPrefix(field, "health="); ok {
				return strings.Trim(rest, `"`)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("`innsegl serve` never reported its health address:\n%s", d.stderr.String())
	return ""
}

func (d *prtDaemon) reap() {
	if d.dead || d.cmd == nil || d.cmd.Process == nil {
		return
	}
	d.dead = true
	if d.session != nil {
		prtDropped(d.session.Close())
	}
	prtDropped(d.cmd.Process.Kill())
	if _, werr := d.cmd.Process.Wait(); werr != nil {
		prtDropped(werr)
	}
}

// ---------------------------------------------------------------------------
// Calling the tools, and reading the IP §4 error off the wire.
// ---------------------------------------------------------------------------

// prtWireError is IP §4's structured error as an agent reads it. Declared here
// rather than imported: internal/mcp renders it through an unexported struct,
// and a test decoding through the same type that wrote it would not be reading
// the wire at all.
type prtWireError struct {
	Class     string `json:"error_class"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RunID     string `json:"run_id"`
}

// prtOutcome is one operation's result: either a reply, or IP §4's error.
type prtOutcome struct {
	op    string
	ok    bool
	reply map[string]any
	fail  prtWireError
	// transport is a failure of the MCP transport itself rather than a
	// classified tool error. It is never an acceptable outcome: doc 04 §2 asks
	// for "correct error classes, never silent degradation", and a dropped
	// connection is neither.
	transport error
	took      time.Duration
}

func (o prtOutcome) String() string {
	switch {
	case o.transport != nil:
		return fmt.Sprintf("%s: TRANSPORT FAILURE after %s: %v", o.op, o.took, o.transport)
	case o.ok:
		return fmt.Sprintf("%s: ok in %s", o.op, o.took)
	default:
		return fmt.Sprintf("%s: %s (retryable=%v) in %s: %s",
			o.op, o.fail.Class, o.fail.Retryable, o.took, o.fail.Message)
	}
}

func (w *prtWorld) call(ctx context.Context, op string, tool mcp.ToolName, args map[string]any) prtOutcome {
	started := time.Now()
	res, err := w.daemon.session.CallTool(ctx,
		&sdk.CallToolParams{Name: string(tool), Arguments: args})
	took := time.Since(started)
	if err != nil {
		return prtOutcome{op: op, transport: err, took: took}
	}
	body, merr := json.Marshal(res.StructuredContent)
	if merr != nil {
		return prtOutcome{op: op, transport: merr, took: took}
	}
	if res.IsError {
		var wire prtWireError
		if uerr := json.Unmarshal(body, &wire); uerr != nil {
			return prtOutcome{op: op, transport: fmt.Errorf(
				"a tool error whose body is not IP §4's object: %s: %w", body, uerr), took: took}
		}
		return prtOutcome{op: op, fail: wire, took: took}
	}
	reply := map[string]any{}
	if uerr := json.Unmarshal(body, &reply); uerr != nil {
		return prtOutcome{op: op, transport: fmt.Errorf(
			"a reply that is not an object: %s: %w", body, uerr), took: took}
	}
	return prtOutcome{op: op, ok: true, reply: reply, took: took}
}

func (w *prtWorld) key(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, os.Getpid()%100000, prtSeq.Add(1))
}

// ---------------------------------------------------------------------------
// The ledger and the invariant sweep.
// ---------------------------------------------------------------------------

func (w *prtWorld) openLedger(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	name := fmt.Sprintf("ops001_%d", os.Getpid()%100000)
	admin, err := pgx.Connect(ctx, prtDSN(w.pgDirect, prtPGDatabase))
	if err != nil {
		t.Fatalf("connect to %s: %v", prtPGDatabase, err)
	}
	_, err = admin.Exec(ctx, `CREATE DATABASE "`+name+`"`)
	closeErr := admin.Close(ctx)
	if err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	if closeErr != nil {
		t.Fatalf("close the admin connection: %v", closeErr)
	}

	// The SERVER's DSN goes through the gate; the TEST's reader goes direct,
	// so the sweep can still read the chain in a cell where Postgres is
	// partitioned from the server.
	w.dsn = prtDSN(w.gate(prtPostgres).addr(), name)

	store, err := ledger.Open(ctx, prtDSN(w.pgDirect, name))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	if merr := store.Migrate(ctx); merr != nil {
		t.Fatalf("ledger.Migrate: %v", merr)
	}
	w.store = store

	pool, err := pgxpool.New(ctx, prtDSN(w.pgDirect, name))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	w.pool = pool
}

func (w *prtWorld) chain(t *testing.T) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	head, err := w.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger Head: %v", err)
	}
	if head.IsEmpty() {
		return nil
	}
	records, err := w.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("ledger Events: %v", err)
	}
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, r)
	}
	return out
}

// verifyChain is I4, asked of the whole chain and of its TIP.
//
// VerifyTip rather than Verify, for internal/ledger/chain.go's own stated
// reason: a truncated prefix of a valid chain is itself a valid chain, so
// Verify alone cannot see a removed tail.
func (w *prtWorld) verifyChain(t *testing.T, when string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	head, err := w.store.Head(ctx)
	if err != nil {
		t.Fatalf("%s: ledger Head: %v", when, err)
	}
	if head.IsEmpty() {
		return
	}
	records, err := w.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("%s: ledger Events: %v", when, err)
	}
	if err := ledger.VerifyTip(records, head); err != nil {
		t.Fatalf("%s: the hash chain does not verify: %v\n\nI4: the ledger is "+
			"append-only and every event links to the one before it. A partition "+
			"must not be able to break that.", when, err)
	}
}

// reconcile runs ONE synchronous pass of the shipped reconciler.
//
// Every dependency it is given is the REAL one: the ledger it appends to is
// the chain the server wrote, the repositories are the server's own workspace,
// and the transparency log is the Rekor the commits went into. IP §6.5 makes
// this a required component, so a matrix that healed and did not reconcile
// would be asserting the weaker half of doc 07 OPS-001's expectation.
func (w *prtWorld) reconcile(t *testing.T, when string) reconciler.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	repos, err := reconciler.NewGitWorkspace(filepath.Join(w.workDir, "workspace"))
	if err != nil {
		t.Fatalf("%s: reconciler.NewGitWorkspace: %v", when, err)
	}
	// Direct, not gated: the reconciler is an operator-side component here,
	// and the sweep must be able to run in a cell that has just healed rather
	// than wait on a gRPC channel's backoff.
	log, err := reconciler.NewRekorLog("http://"+w.rekorDirect, nil)
	if err != nil {
		t.Fatalf("%s: reconciler.NewRekorLog: %v", when, err)
	}
	r, err := reconciler.New(reconciler.Config{
		Ledger:      w.store,
		Appender:    w.store,
		Repos:       repos,
		Log:         log,
		TrustDomain: prtTrustDomain,
		// Short, so an intent this matrix orphaned is expirable inside the
		// test rather than fifteen minutes after it (the shipped default is
		// DefaultExpireAfter, and it is the right number for a deployment).
		// Short is not ZERO: an expiry window of zero would expire an intent
		// whose signature is still in flight, and the caller waits this window
		// out rather than shortening it away — see prtRequireConverged.
		ExpireAfter: prtExpireAfter,
	})
	if err != nil {
		t.Fatalf("%s: reconciler.New: %v", when, err)
	}
	res, err := r.Reconcile(ctx)
	if err != nil {
		t.Fatalf("%s: the reconciler could not run: %v", when, err)
	}
	return res
}

// ---------------------------------------------------------------------------
// The object-storage half: a real WORM bucket the sealer writes through.
// ---------------------------------------------------------------------------

func (w *prtWorld) openWORM(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	w.bucket = fmt.Sprintf("ops001-%d", os.Getpid()%100000)
	cl, err := prtMinIOClient(w.minioDirect)
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	// Object lock on, because doc 05 §2 says a segment store has it and a
	// bucket without it is a different store than the one under test.
	if berr := cl.MakeBucket(ctx, w.bucket,
		minio.MakeBucketOptions{ObjectLocking: true}); berr != nil {
		t.Fatalf("create bucket %s: %v", w.bucket, berr)
	}

	// The WORM the SEALER writes through addresses the GATE. It is built while
	// the route is healthy, so a severed cell exercises Put and not NewWORM's
	// configuration check.
	worm, err := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  w.gate(prtObject).addr(),
		Bucket:    w.bucket,
		AccessKey: prtMinIOUser,
		SecretKey: prtMinIOPassword,
		UseTLS:    false,
		Mode:      segment.RetentionCompliance,
		Retention: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("segment.NewWORM: %v", err)
	}
	w.worm = worm
}
