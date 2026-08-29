// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"innsegl.dev/innsegl/internal/spire"
)

// A SPIRE stack of this suite's own, from the shipped compose file, that these
// tests are allowed to destroy.
//
// WHY NOT internal/spire's HARNESS
// --------------------------------
// internal/spire has one (spireharness_test.go) and it is the right shape, but
// it is a _test.go file in package spire: not importable, by construction. The
// duplication below is the cost of that, and it is deliberate rather than
// regrettable — the two harnesses differ in the thing that matters. That one
// must leave the stack intact for the next case; this one exists to kill it.
//
// WHY A STACK OF ITS OWN, ONE PER TEST PROCESS
// --------------------------------------------
// SPI-006 SIGKILLs spire-server and SPI-007 SIGKILLs spire-agent. `go test
// ./...` runs packages concurrently, so a kill landing on the shared
// `innsegl-spire-server` would break internal/spire's TC-SPI cases, break a
// developer's running stack, and — the reason that actually matters — make a
// green SPI-006 depend on scheduling. And a single failure stack shared by
// this suite is not enough either: two concurrent `go test ./...` runs start
// two copies of THIS binary, which put one process's entry into the other's
// datastore and produced a false "That is a queued identity" (see
// stackPrefix). So the compose project, every container name and every network
// name carry a per-process prefix — that is the whole of what
// test/failure/spire-isolated.yml changes, apart from the restart policy.
// internal/ledger's LED-009 states the principle in one line: "A container of
// its own: this test kills the server." ADR-0015 records the decision.
//
// REACHING THE ADMIN API
// ----------------------
// Same two problems internal/spire's harness solves, solved the same way, for
// the same reasons (ADR-0011): the admin API is on an internal network with no
// published port, so a socat container joins that network and publishes a
// loopback port; and there is no innsegl-mcp workload yet, so the admin SVID is
// minted with `spire-server x509 mint` on the container-private admin socket.
//
// One thing is added. The test process does not talk to the socat port
// directly: it talks to a counting proxy of its own (countingProxy below) that
// forwards to it. That is what turns "RegisterRun returned an error" into "the
// client opened a connection and it failed", which is the difference between a
// failure-injection test and a test that would pass if the call had never been
// made at all. internal/segment's anchor test counts round trips in an
// http.RoundTripper for the same reason.
//
// Without Docker every case skips, naming what went unproven. Nothing here
// passes without a real SPIRE.

const (
	// PROTECTED STRINGS (doc 01 §1). Spelled out rather than derived, so that a
	// silent change to deploy/compose/spire/server.conf fails these tests.
	failureTrustDomain = "innsegl.dev"
	failureAdminID     = "spiffe://innsegl.dev/innsegl/mcp"
	failureServerID    = "spiffe://innsegl.dev/spire/server"

	// stackEnv is the variable test/failure/spire-isolated.yml interpolates
	// into the compose project, every container_name and every network name.
	// The harness sets it to a value unique to this process — see stackPrefix.
	stackEnv = "INNSEGL_FAILURE_STACK"

	adminSocket      = "/run/spire/admin/api.sock"
	agentSocketMount = "/run/spire/agent-sockets"
	workloadUID      = "10001"

	// Pinned by tag, like internal/ledger's postgres:16. Nothing here depends
	// on their contents: one holds a statically linked binary and starts it,
	// the other forwards TCP.
	defaultProbeImage = "busybox:1.37"
	defaultProxyImage = "alpine/socat:1.8.0.3"
)

var (
	sharedStack *stack
	stackSkip   string
	nameSeq     atomic.Int64

	errDockerAbsent = errors.New("docker is not available")
)

// stackPrefix names this process's stack, and everything in it.
//
// Unique per process, and that is load bearing rather than tidy. Two concurrent
// `go test ./...` invocations — routine while scripts/coverage-floors.sh runs
// beside an ordinary test run — start two copies of THIS binary. Sharing one
// SPIRE between them put a second process's registration entry into the first
// process's datastore mid-case and failed SPI-006 with "an entry appeared
// 18.99s after recovery without anybody asking for one. That is a queued
// identity." SPI-006's central assertion is that the ENTIRE entry set is
// unchanged; that is only sound with exactly one writer, so each process gets
// a SPIRE of its own.
func stackPrefix() string {
	return fmt.Sprintf("innsegl-failure-%d", os.Getpid())
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// docker runs one docker command and returns its trimmed stdout.
func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// dockerUsable reports whether a docker daemon is reachable.
func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDockerAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errDockerAbsent, err)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errDockerAbsent, err)
	}
	return nil
}

// freeHostPort reserves an ephemeral loopback port and hands it back.
func freeHostPort(ctx context.Context) (string, error) {
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

// ---------------------------------------------------------------------------
// The counting proxy.
//
// A loopback listener in the test process, in front of the socat container.
// Every connection the gRPC client opens is one accept here, so a test can
// assert that a call reached the wire rather than assuming it did.
//
// It forwards bytes and nothing else. The gRPC channel is mTLS between this
// process's minted X509-SVID and the server's, end to end through both hops, so
// neither proxy authenticates anything and neither can read anything.
// ---------------------------------------------------------------------------

type countingProxy struct {
	ln      net.Listener
	backend string

	mu       sync.Mutex
	accepted int

	wg     sync.WaitGroup
	closed atomic.Bool
}

func newCountingProxy(ctx context.Context, backend string) (*countingProxy, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &countingProxy{ln: ln, backend: backend}
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

func (p *countingProxy) accept() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.accepted++
		p.mu.Unlock()
		p.wg.Add(1)
		go p.serve(conn)
	}
}

func (p *countingProxy) serve(client net.Conn) {
	defer p.wg.Done()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", p.backend)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyQuietly(upstream, client); _ = upstream.Close() }()
	go func() { defer wg.Done(); copyQuietly(client, upstream); _ = client.Close() }()
	wg.Wait()
}

// copyQuietly forwards until either side goes away. Both ends of a proxied
// connection end in an error the moment spire-server is killed, which is the
// normal case here and there is nobody to report it to.
func copyQuietly(dst io.Writer, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil {
		return
	}
}

// addr is the address a client dials.
func (p *countingProxy) addr() string { return p.ln.Addr().String() }

// connections is the number of TCP connections opened through this proxy.
func (p *countingProxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

func (p *countingProxy) close() {
	if p.closed.Swap(true) {
		return
	}
	_ = p.ln.Close()
	p.wg.Wait()
}

// ---------------------------------------------------------------------------
// The stack.
// ---------------------------------------------------------------------------

type stack struct {
	root        string
	composeFile string
	overlayFile string

	// prefix is this process's stack name; every container and network in it
	// starts with it, and it is also the compose project name.
	prefix          string
	serverContainer string
	agentContainer  string
	adminNetwork    string

	proxyName string
	// socatAddr is the published loopback port of the socat container.
	socatAddr string
	// counter is the in-process proxy in front of it; clients dial its address.
	counter *countingProxy

	// parentID is the attested node every run entry is parented to.
	parentID string
	// socketVolume carries the Workload API socket.
	socketVolume string
	// probeBinary is internal/spire/svidprobe, cross-compiled for the daemon.
	probeBinary string
	probeImage  string
}

func (s *stack) compose(ctx context.Context, args ...string) (string, error) {
	full := []string{"compose", "-p", s.prefix, "-f", s.composeFile, "-f", s.overlayFile}
	return docker(ctx, append(full, args...)...)
}

// spireLocal runs the SPIRE server CLI inside the server container against the
// container-private admin socket (ADR-0011's operator path).
//
// It is the ground truth for "what does the datastore actually hold": that
// socket is unauthenticated and unfiltered, so it sees every entry, including
// any an authorization policy would have hidden from the admin API. SPI-006's
// "no queued or provisional identity anywhere" is asked here for that reason.
func (s *stack) spireLocal(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", adminSocket)
	return s.compose(ctx, full...)
}

// ---------------------------------------------------------------------------
// Admin credentials.
// ---------------------------------------------------------------------------

type mintedSVID struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (m mintedSVID) GetX509SVID() (*x509svid.SVID, error) { return m.svid, nil }

func (m mintedSVID) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, m.roots), nil
}

// parseMint splits `spire-server x509 mint` output into its three PEM sections.
func parseMint(out string) (svidPEM, keyPEM, rootsPEM string, err error) {
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

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			if len(out) == 0 {
				return nil, errors.New("no PEM certificate found")
			}
			return out, nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

func (s *stack) mintAdmin(ctx context.Context, id string) (mintedSVID, error) {
	out, err := s.spireLocal(ctx, "x509", "mint", "-spiffeID", id, "-ttl", "1h")
	if err != nil {
		return mintedSVID{}, fmt.Errorf("mint %s: %w", id, err)
	}
	svidPEM, keyPEM, rootsPEM, err := parseMint(out)
	if err != nil {
		return mintedSVID{}, err
	}
	svid, err := x509svid.Parse([]byte(svidPEM), []byte(keyPEM))
	if err != nil {
		return mintedSVID{}, fmt.Errorf("parse minted SVID: %w", err)
	}
	roots, err := parseCerts([]byte(rootsPEM))
	if err != nil {
		return mintedSVID{}, fmt.Errorf("parse trust bundle: %w", err)
	}
	return mintedSVID{svid: svid, roots: roots}, nil
}

// adminClient dials the admin API through the counting proxy with a freshly
// minted admin SVID.
func (s *stack) adminClient(t *testing.T) *spire.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	src, err := s.mintAdmin(ctx, failureAdminID)
	if err != nil {
		t.Fatalf("mint admin SVID: %v", err)
	}
	if got := src.svid.ID.String(); got != failureAdminID {
		t.Fatalf("minted SVID is %s, want %s", got, failureAdminID)
	}
	c, err := spire.Dial(ctx, spire.Config{
		Address:     s.counter.addr(),
		TrustDomain: failureTrustDomain,
		ServerID:    failureServerID,
		Source:      src,
		// Short, so an unreachable server is reported inside a test's patience
		// rather than at the 15s default. IP §6.3 forbids indefinite hangs;
		// this only makes the bound tighter.
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial(%s): %v", s.counter.addr(), err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// ---------------------------------------------------------------------------
// Container control.
// ---------------------------------------------------------------------------

// containerField reads one docker inspect field, or "" when the container is
// gone.
func containerField(ctx context.Context, name, format string) string {
	out, err := docker(ctx, "inspect", "--format", format, name)
	if err != nil {
		return ""
	}
	return out
}

func containerRunning(ctx context.Context, name string) bool {
	return containerField(ctx, name, "{{.State.Running}}") == "true"
}

func containerHealthy(ctx context.Context, name string) bool {
	return containerField(ctx, name, "{{.State.Health.Status}}") == "healthy"
}

// killContainer SIGKILLs a container and does not return until the daemon
// reports it stopped.
//
// SIGKILL rather than a graceful stop, for LED-009's reason: a process that got
// to shut down cleanly is not the failure being injected. And the wait is not
// politeness — it is what makes the injection deterministic. Without it the
// call under test races the kill, and a test that happened to run before the
// process died would pass while proving nothing.
func killContainer(ctx context.Context, name string) error {
	if _, err := docker(ctx, "kill", "--signal", "KILL", name); err != nil {
		// Already dead is the one acceptable failure, and only if it really is
		// dead — checked immediately below.
		if containerRunning(ctx, name) {
			return err
		}
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if !containerRunning(ctx, name) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s was still running 60s after SIGKILL", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startContainer starts a stopped container and waits for its healthcheck.
func startContainer(ctx context.Context, name string, deadline time.Duration) error {
	if !containerRunning(ctx, name) {
		if _, err := docker(ctx, "start", name); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
	}
	until := time.Now().Add(deadline)
	for {
		if containerHealthy(ctx, name) {
			return nil
		}
		if time.Now().After(until) {
			return fmt.Errorf("%s did not become healthy within %s (state %q, health %q)",
				name, deadline, containerField(ctx, name, "{{.State.Status}}"),
				containerField(ctx, name, "{{.State.Health.Status}}"))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// adminAPIRefusesConnections reports whether the admin endpoint no longer has a
// server behind it.
//
// "The container is stopped" is what docker says; this is what a client sees,
// and the two are what make the down window observable rather than assumed. A
// live SPIRE server accepts the connection and waits for a TLS ClientHello, so
// a connection that stays open with nothing written is a server that is up. A
// dead one is either refused outright or accepted by socat and closed the
// instant socat fails to reach its backend.
func adminAPIRefusesConnections(ctx context.Context, addr string) bool {
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return true
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return false
	}
	var b [1]byte
	_, rerr := conn.Read(b[:])
	// io.EOF or a reset means nobody is serving. A timeout means somebody is
	// waiting for our ClientHello, which is a live server.
	return rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded)
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(deadline time.Duration, cond func() bool) bool {
	until := time.Now().Add(deadline)
	for {
		if cond() {
			return true
		}
		if time.Now().After(until) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// requireHealthy brings both SPIRE containers back up if a previous case left
// one dead, so that no case here inherits another's damage.
func (s *stack) requireHealthy(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, name := range []string{s.serverContainer, s.agentContainer} {
		if err := startContainer(ctx, name, 120*time.Second); err != nil {
			t.Fatalf("%s is not healthy at the start of this case: %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// The datastore, enumerated.
// ---------------------------------------------------------------------------

// allEntrySPIFFEIDs returns every registration entry SPIRE holds, as SPIFFE ID
// strings, sorted, with duplicates preserved.
//
// Read from the container-private admin socket, so it is the whole datastore
// and not the admin API's filtered view of it. SPI-006 compares the set before
// the kill with the set after recovery: anything queued, deferred, provisional
// or "registered later", under any path and by any name, shows up as a
// difference.
func (s *stack) allEntrySPIFFEIDs(ctx context.Context) ([]string, error) {
	out, err := s.spireLocal(ctx, "entry", "show")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "SPIFFE ID")
		if !ok {
			continue
		}
		ids = append(ids, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":")))
	}
	// `entry show` prints "Found N entries"; a parse that silently found none
	// would make every "nothing was created" assertion vacuous.
	found, ferr := parseFoundCount(out)
	if ferr != nil {
		return nil, ferr
	}
	if found != len(ids) {
		return nil, fmt.Errorf("`entry show` reported %d entries and %d SPIFFE ID lines were parsed; "+
			"the output format changed:\n%s", found, len(ids), out)
	}
	slices.Sort(ids)
	return ids, nil
}

// parseFoundCount reads the "Found N entries" header `entry show` prints.
func parseFoundCount(out string) (int, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "Found ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, fmt.Errorf("unparsable entry count %q: %w", line, err)
		}
		return n, nil
	}
	return 0, fmt.Errorf("`entry show` printed no \"Found N entries\" header:\n%s", out)
}

// ---------------------------------------------------------------------------
// Workload probes.
//
// A workload has to *be* a container: SPIRE attests the process on the other
// end of the socket — its uid and the Docker metadata of the container it lives
// in — so a fetch from the test process would be testing nothing. The binary is
// internal/spire/svidprobe, built unmodified from RM-015, so what these cases
// observe is shipped client code classifying a real refusal.
// ---------------------------------------------------------------------------

type probeRun struct {
	Outcome  spire.FetchOutcome
	ExitCode int
	Raw      string
}

// createProbeContainer creates (but does not start) a container carrying run's
// selectors, with svidprobe copied in and cmd as its command.
func (s *stack) createProbeContainer(ctx context.Context, name string, is spire.RunRef, cmd []string) error {
	args := []string{
		"create", "--name", name,
		// A workload reaches SPIRE over a socket, never over the network.
		"--network", "none",
		// Non-root: unix:uid:0 selects every container on the node and is the
		// weak selector doc 04 names.
		"--user", workloadUID + ":" + workloadUID,
		"--label", "dev.innsegl.agent-type=" + is.AgentType,
		"--label", "dev.innsegl.task-id=" + is.TaskID,
		"--label", "dev.innsegl.run-id=" + is.RunID,
		"--volume", s.socketVolume + ":" + agentSocketMount,
		"--entrypoint", cmd[0],
		s.probeImage,
	}
	args = append(args, cmd[1:]...)
	if _, err := docker(ctx, args...); err != nil {
		return fmt.Errorf("create probe container: %w", err)
	}
	if _, err := docker(ctx, "cp", s.probeBinary, name+":/svidprobe"); err != nil {
		return fmt.Errorf("copy svidprobe into %s: %w", name, err)
	}
	return nil
}

func (s *stack) probeName() string {
	return fmt.Sprintf("%s-probe-%d", s.prefix, nameSeq.Add(1))
}

func removeContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := docker(ctx, "rm", "--force", name); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", name, err)
	}
}

// svidprobeArgs is the command line one svidprobe run takes.
func svidprobeArgs(want spire.RunRef, timeout time.Duration) []string {
	return []string{
		"/svidprobe",
		"-agent-type", want.AgentType,
		"-task-id", want.TaskID,
		"-run-id", want.RunID,
		"-trust-domain", failureTrustDomain,
		"-timeout", timeout.String(),
	}
}

// runProbe runs svidprobe once inside a container carrying is's selectors,
// asking for want's identity, and returns what it printed.
func (s *stack) runProbe(t *testing.T, is, want spire.RunRef) probeRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	name := s.probeName()
	if err := s.createProbeContainer(ctx, name, is, svidprobeArgs(want, 20*time.Second)); err != nil {
		t.Fatalf("%v", err)
	}
	defer removeContainer(name)

	cmd := exec.CommandContext(ctx, "docker", "start", "--attach", name)
	raw, runErr := cmd.CombinedOutput()
	exitCode := 0
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		exitCode = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("run probe %s: %v (output %q)", name, runErr, raw)
	}

	out := probeRun{ExitCode: exitCode, Raw: strings.TrimSpace(string(raw))}
	line := lastLine(out.Raw)
	if err := json.Unmarshal([]byte(line), &out.Outcome); err != nil {
		t.Fatalf("probe %s printed no outcome JSON (exit %d): %q", name, exitCode, out.Raw)
	}
	return out
}

func lastLine(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// probeUntilIssued runs the probe until SPIRE issues the run's SVID, or gives
// up. Entries reach the agent through its cache, not synchronously, so a single
// attempt would be a race — and a single *failed* attempt would look exactly
// like a refusal.
func (s *stack) probeUntilIssued(t *testing.T, run spire.RunRef, deadline time.Duration) probeRun {
	t.Helper()
	started := time.Now()
	var last probeRun
	for attempt := 1; time.Since(started) < deadline; attempt++ {
		last = s.runProbe(t, run, run)
		if last.ExitCode == 0 {
			t.Logf("SVID issued after %s (%d probe attempt(s)): %s",
				time.Since(started).Round(time.Millisecond), attempt, last.Outcome.SPIFFEID)
			return last
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no SVID for %+v within %s; last outcome %+v", run, deadline, last.Outcome)
	return last
}

// ---------------------------------------------------------------------------
// The probe loop: a workload that keeps asking, across a failure.
//
// SPI-007 is "socket lost MID-RUN", and a run is not a single fetch. This
// starts one container that calls svidprobe on a timer and streams one JSON
// line per attempt, so the test can watch the answers change from "here is your
// SVID" to a classified refusal at the moment the agent dies — and can count
// how many attempts really happened on each side of it.
// ---------------------------------------------------------------------------

type probeAttempt struct {
	At      time.Time
	Outcome spire.FetchOutcome
	Raw     string
}

type probeLoop struct {
	name string
	cmd  *exec.Cmd

	mu       sync.Mutex
	attempts []probeAttempt
	scanErr  error

	done chan struct{}
}

// startProbeLoop starts a container that runs svidprobe `iterations` times,
// `interval` apart, and returns as soon as the container is running.
func (s *stack) startProbeLoop(t *testing.T, run spire.RunRef, iterations int,
	interval, probeTimeout time.Duration,
) *probeLoop {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := s.probeName()
	// busybox sh, because the loop has to live inside the container: the
	// workload is what SPIRE attests, so re-entering the container per attempt
	// from outside would be a different workload each time.
	script := fmt.Sprintf("i=1; while [ $i -le %d ]; do %s || true; sleep %d; i=$((i+1)); done",
		iterations, strings.Join(svidprobeArgs(run, probeTimeout), " "),
		int(interval.Seconds()))
	if err := s.createProbeContainer(ctx, name, run, []string{"/bin/sh", "-c", script}); err != nil {
		t.Fatalf("%v", err)
	}

	// No CommandContext: this process must outlive the deadline of the
	// bring-up context above, and it is stopped by removing the container in
	// the cleanup below.
	cmd := exec.Command("docker", "start", "--attach", name) //nolint:noctx // lifetime is the container's, see above
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		removeContainer(name)
		t.Fatalf("probe loop stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		removeContainer(name)
		t.Fatalf("start probe loop: %v", err)
	}

	l := &probeLoop{name: name, cmd: cmd, done: make(chan struct{})}
	go l.scan(stdout)
	t.Cleanup(func() {
		removeContainer(name)
		<-l.done
		// `docker start --attach` exits non-zero when the container is removed
		// under it, which is exactly how this one is stopped.
		if werr := cmd.Wait(); werr != nil {
			t.Logf("probe loop %s ended: %v", name, werr)
		}
	})
	return l
}

func (l *probeLoop) scan(r io.Reader) {
	defer close(l.done)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var out spire.FetchOutcome
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			l.mu.Lock()
			if l.scanErr == nil {
				l.scanErr = fmt.Errorf("probe loop printed a non-JSON line %q: %w", line, err)
			}
			l.mu.Unlock()
			continue
		}
		l.mu.Lock()
		l.attempts = append(l.attempts, probeAttempt{At: time.Now(), Outcome: out, Raw: line})
		l.mu.Unlock()
	}
}

// count is how many attempts have been recorded so far. Taken immediately
// before a kill, it is the index that separates "definitely emitted before the
// failure" from "possibly in flight across it" — a boundary a wall-clock
// comparison cannot draw, because the test reads a line some milliseconds
// after the container wrote it.
func (l *probeLoop) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.attempts)
}

// seen returns the attempts recorded so far.
func (l *probeLoop) seen() ([]probeAttempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]probeAttempt, len(l.attempts))
	copy(out, l.attempts)
	return out, l.scanErr
}

// waitForIssued blocks until at least n attempts have come back with an SVID,
// and returns the wall-clock time of the nth.
func (l *probeLoop) waitForIssued(t *testing.T, n int, deadline time.Duration) time.Time {
	t.Helper()
	until := time.Now().Add(deadline)
	for {
		seen, err := l.seen()
		if err != nil {
			t.Fatalf("%v", err)
		}
		issued := 0
		for _, a := range seen {
			if a.Outcome.SPIFFEID != "" {
				issued++
				if issued == n {
					return a.At
				}
			}
		}
		if time.Now().After(until) {
			t.Fatalf("the probe loop produced %d SVIDs in %s, want %d; attempts so far: %+v",
				issued, deadline, n, seen)
		}
		select {
		case <-l.done:
			// One more read, so a loop that finished between the poll above
			// and here is not reported as short.
			final, ferr := l.seen()
			t.Fatalf("the probe loop exited before issuing %d SVIDs; attempts: %+v (scan error: %v)",
				n, final, ferr)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// wait blocks until the loop container exits or the deadline passes.
func (l *probeLoop) wait(t *testing.T, deadline time.Duration) {
	t.Helper()
	select {
	case <-l.done:
	case <-time.After(deadline):
		t.Fatalf("the probe loop did not finish within %s", deadline)
	}
}

// ---------------------------------------------------------------------------
// Runs.
// ---------------------------------------------------------------------------

func newRun(t *testing.T, agentType, taskID string) spire.RunRef {
	t.Helper()
	return spire.RunRef{
		AgentType: agentType,
		TaskID:    taskID,
		RunID:     fmt.Sprintf("run-%d-%d", os.Getpid()%100000, nameSeq.Add(1)),
	}
}

// runSelectors is the per-run selector set of doc 04 and RM-014's verify.sh:
// the three SPIFFE ID components as docker labels, plus a non-root uid.
func runSelectors(run spire.RunRef) []spire.Selector {
	return []spire.Selector{
		{Type: "docker", Value: "label:dev.innsegl.run-id:" + run.RunID},
		{Type: "docker", Value: "label:dev.innsegl.agent-type:" + run.AgentType},
		{Type: "docker", Value: "label:dev.innsegl.task-id:" + run.TaskID},
		{Type: "unix", Value: "uid:" + workloadUID},
	}
}

func (s *stack) registration(run spire.RunRef) spire.Registration {
	return spire.Registration{
		Run:       run,
		ParentID:  s.parentID,
		Selectors: runSelectors(run),
		TTL:       spire.DefaultRunTTL,
	}
}

// registerForTest registers a run and deletes its entry afterwards, so a failed
// case does not leave the reaper work to do.
func (s *stack) registerForTest(t *testing.T, c *spire.Client, run spire.RunRef) spire.Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	entry, err := c.RegisterRun(ctx, s.registration(run))
	if err != nil {
		t.Fatalf("RegisterRun(%+v): %v", run, err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanCancel()
		if _, err := c.RetireRun(cleanCtx, run); err != nil {
			t.Errorf("cleaning up the entry for %+v: %v", run, err)
		}
	})
	return entry
}

// ---------------------------------------------------------------------------
// Bring-up.
// ---------------------------------------------------------------------------

// buildProbe cross-compiles internal/spire/svidprobe for the daemon's platform.
func buildProbe(ctx context.Context, root, outDir string) (string, error) {
	goos, err := docker(ctx, "version", "--format", "{{.Server.Os}}")
	if err != nil {
		return "", err
	}
	goarch, err := docker(ctx, "version", "--format", "{{.Server.Arch}}")
	if err != nil {
		return "", err
	}
	out := filepath.Join(outDir, "svidprobe")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./internal/spire/svidprobe")
	cmd.Dir = root
	// CGO off so the binary runs in a container that has no libc of its own.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build svidprobe for %s/%s: %w: %s", goos, goarch, err, b)
	}
	return out, nil
}

func startStack(ctx context.Context, root, outDir string) (*stack, error) {
	prefix := stackPrefix()
	// The overlay interpolates this into the project, the container names and
	// the network names. Set before the first compose call and never changed.
	if err := os.Setenv(stackEnv, prefix); err != nil {
		return nil, fmt.Errorf("set %s: %w", stackEnv, err)
	}
	s := &stack{
		root:            root,
		composeFile:     filepath.Join(root, "deploy", "compose", "spire.yml"),
		overlayFile:     filepath.Join(root, "test", "failure", "spire-isolated.yml"),
		probeImage:      envOr("INNSEGL_TEST_PROBE_IMAGE", defaultProbeImage),
		prefix:          prefix,
		serverContainer: prefix + "-spire-server",
		agentContainer:  prefix + "-spire-agent",
		adminNetwork:    prefix + "-spire-admin",
	}

	// Only the two services these cases need. spire-oidc publishes a host port
	// and wants a bootstrap entry it does not have here.
	if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server", "spire-agent"); err != nil {
		return nil, fmt.Errorf("compose up: %w", err)
	}

	vol, err := docker(ctx, "inspect", "--format",
		`{{range .Mounts}}{{if eq .Destination "`+agentSocketMount+`"}}{{.Name}}{{end}}{{end}}`,
		s.agentContainer)
	if err != nil || vol == "" {
		return nil, fmt.Errorf("find the Workload API socket volume on %s: %w", s.agentContainer, err)
	}
	s.socketVolume = vol

	// The attested node, polled: the agent attests shortly after start.
	deadline := time.Now().Add(120 * time.Second)
	for {
		out, lerr := s.spireLocal(ctx, "agent", "list")
		if lerr == nil {
			for _, line := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
					s.parentID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
					break
				}
			}
		}
		if s.parentID != "" {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no attested agent within the deadline, last error: %w", lerr)
		}
		time.Sleep(2 * time.Second)
	}

	// The admin proxy. Created on the default bridge so the port can be
	// published — docker skips port publishing for a container whose only
	// network is `internal: true` — then joined to the admin network, which is
	// the membership that grants admin reachability (ADR-0011).
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	s.proxyName = s.prefix + "-adminproxy"
	if _, err = docker(ctx, "run", "--detach", "--name", s.proxyName,
		"--publish", "127.0.0.1:"+port+":8081",
		envOr("INNSEGL_TEST_PROXY_IMAGE", defaultProxyImage),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		return nil, fmt.Errorf("start the admin proxy: %w", err)
	}
	if _, err = docker(ctx, "network", "connect", s.adminNetwork, s.proxyName); err != nil {
		return nil, fmt.Errorf("join %s: %w", s.adminNetwork, err)
	}
	s.socatAddr = "127.0.0.1:" + port

	if s.counter, err = newCountingProxy(ctx, s.socatAddr); err != nil {
		return nil, fmt.Errorf("start the counting proxy: %w", err)
	}

	if _, err = docker(ctx, "pull", "--quiet", s.probeImage); err != nil {
		return nil, fmt.Errorf("pull %s: %w", s.probeImage, err)
	}
	if s.probeBinary, err = buildProbe(ctx, root, outDir); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *stack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if s.counter != nil {
		s.counter.close()
	}
	if s.proxyName != "" {
		if _, err := docker(ctx, "rm", "--force", s.proxyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.proxyName, err)
		}
	}
	if os.Getenv("INNSEGL_TEST_KEEP_SPIRE") != "" {
		return
	}
	// Always torn down, unlike internal/spire's harness: this project is this
	// suite's own, nobody else's stack is behind it, and leaving a half-killed
	// SPIRE running would be leaving a trap.
	if _, err := s.compose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
	}
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	outDir, err := os.MkdirTemp("", "innsegl-failure-harness-")
	if err != nil {
		panic(err)
	}

	if derr := dockerUsable(ctx); derr != nil {
		stackSkip = derr.Error()
	} else if s, serr := startStack(ctx, root, outDir); serr != nil {
		stackSkip = serr.Error()
		if s != nil {
			s.stop()
		}
	} else {
		sharedStack = s
	}
	cancel()

	code := m.Run()

	if sharedStack != nil {
		sharedStack.stop()
	}
	stopPostgres()
	if err := os.RemoveAll(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", outDir, err)
	}
	os.Exit(code)
}

// requireStack skips the calling test when no real SPIRE is available, naming
// what went unproven. It never lets a case here pass without one.
func requireStack(t *testing.T) *stack {
	t.Helper()
	if sharedStack == nil {
		t.Skipf("skipping: no isolated SPIRE stack from deploy/compose/spire.yml + "+
			"test/failure/spire-isolated.yml (%s). A failure-injection case with no "+
			"dependency to remove proves nothing; start Docker and re-run.", stackSkip)
	}
	sharedStack.requireHealthy(t)
	return sharedStack
}
