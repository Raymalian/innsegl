// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// A real SPIRE, from deploy/compose/, never a mock.
//
// TC-SPI's cases are layer I in doc 07, and doc 01 §2 draws the line: "a mocked
// Fulcio proves nothing about I5". The same holds for attestation. A fake
// Workload API that answers "no identity issued" on cue would prove that our
// switch statement has a PermissionDenied arm, and nothing about whether SPIRE
// refuses a workload carrying the wrong labels — which is the entire content of
// SPI-002 and of abuse case AB-01.
//
// So this harness boots the shipped stack, `deploy/compose/spire.yml`, and
// every integration case here runs against it:
//
//   - spire-server with the real x509pop node attestation, the real SQLite
//     datastore, the real admin_ids, and the authorization policy this issue
//     added (deploy/compose/spire/authz-policy.rego);
//   - spire-agent with the real docker and unix workload attestors;
//   - workloads that are actual containers carrying actual selectors.
//
// Without Docker every case skips with a message naming what went unproven,
// rather than passing quietly.
//
// # Two things the harness has to do that the deployment does not
//
//  1. REACH THE ADMIN API FROM THE TEST PROCESS. ADR-0011 puts the server's TCP
//     endpoint on `innsegl-spire-admin`, an internal network with no published
//     port, whose only future member is innsegl-mcp. The test process is on the
//     host, and on a Docker Desktop VM the host has no route to a container
//     address at all. So the harness starts one socat container, joins it to
//     that network, and publishes a loopback port — standing in for exactly the
//     membership ADR-0011 says innsegl-mcp will have. It forwards TCP and
//     nothing else: the gRPC channel is mTLS between this process's minted
//     X509-SVID and the server's, end to end through the proxy, so the proxy
//     authenticates nothing and can read nothing.
//
//  2. OBTAIN AN ADMIN CREDENTIAL. In the deployment innsegl-mcp is an attested
//     workload and its SVID comes from the Workload API. There is no
//     innsegl-mcp yet (E4), so the harness mints one with `spire-server x509
//     mint` on the local admin socket, inside the server container. That is the
//     unauthenticated socket ADR-0011 contains with a private tmpfs, reached
//     the way ADR-0011 says an operator reaches it: `docker compose exec`. The
//     resulting SVID is an ordinary X509-SVID bearing
//     spiffe://innsegl.dev/innsegl/mcp, and the server admits it for the same
//     reason it will admit the MCP's: admin_ids says so.
//
// # A STACK OF ITS OWN, ONE PER TEST PROCESS (RM-065, #81)
//
// The shipped compose file pins `name: innsegl-spire` and a fixed
// container_name per service, so every process that runs `docker compose -f
// deploy/compose/spire.yml up` selects the SAME stack. This harness and
// internal/mcp's both did, and `go test ./...` runs their packages
// concurrently: whichever finished first ran `compose down --volumes` on the
// server the other was mid-case against, which is the measured
// `service "spire-server" is not running`. Two concurrent `go test`
// invocations — routine while scripts/coverage-floors.sh runs beside an
// ordinary test run — multiply it again, and RM-018 measured where that ends:
// one process's entry in another's datastore, failing SPI-006 with "an entry
// appeared 18.99s after recovery ... That is a queued identity", a false
// accusation of the thing SPI-006 exists to detect.
//
// So the project, every container name and every network name carry
// stackPrefix(), which is unique to this process. That is the whole of what
// deploy/compose/spire-testscope.yml changes. Two consequences follow and are
// deliberate: this harness never reuses a stack a developer already had up —
// it cannot see one, by construction — and it therefore always tears its own
// down.

const (
	// The trust domain and the two SPIFFE IDs below are PROTECTED STRINGS
	// (doc 01 §1). They are spelled out rather than derived so that a silent
	// change to deploy/compose/spire/server.conf fails these tests.
	testTrustDomain = "innsegl.dev"
	testAdminID     = "spiffe://innsegl.dev/innsegl/mcp"
	testServerID    = "spiffe://innsegl.dev/spire/server"

	// stackEnv is the variable deploy/compose/spire-testscope.yml interpolates
	// into the compose project, every container_name and every network name.
	// The harness sets it to a value unique to this process — see stackPrefix.
	stackEnv = "INNSEGL_SPIRE_TEST_STACK"

	adminSocket      = "/run/spire/admin/api.sock"
	agentSocketMount = "/run/spire/agent-sockets"

	// defaultProbeImage only has to hold a statically linked binary and start
	// it. Pinned by tag, like internal/ledger's postgres:16: nothing here
	// depends on its contents.
	defaultProbeImage = "busybox:1.37"
	// defaultProxyImage forwards TCP. Same reasoning.
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
// The suite component is not decoration: it makes "no two packages can select
// the same compose project name" true by reading, not merely true because two
// live processes cannot share a pid. internal/mcp's harness uses
// innsegl-mcptest-<pid> and test/failure's uses innsegl-failure-<pid>, so the
// three cannot collide even if one of them were somehow driven from another's
// process.
func stackPrefix() string {
	return fmt.Sprintf("innsegl-spiretest-%d", os.Getpid())
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

// stack is the running compose stack plus everything the harness had to add to
// talk to it.
type stack struct {
	composeFile string
	overlayFile string

	// prefix is this process's stack name; every container and network in it
	// starts with it, and it is also the compose project name.
	prefix         string
	agentContainer string
	adminNetwork   string

	proxyName string
	adminAddr string
	// parentID is the attested node every run entry is parented to.
	parentID string
	// socketVolume is the docker volume carrying the Workload API socket.
	socketVolume string
	// probeBinary is the cross-compiled svidprobe, on the host.
	probeBinary string
	probeImage  string
}

func (s *stack) compose(ctx context.Context, args ...string) (string, error) {
	full := []string{"compose", "-p", s.prefix, "-f", s.composeFile, "-f", s.overlayFile}
	return docker(ctx, append(full, args...)...)
}

// spireLocal runs the SPIRE server CLI inside the server container against the
// unauthenticated local admin socket. It is the operator path of ADR-0011, and
// it is used here for exactly two things: minting the harness's admin SVID, and
// as the control in SPI-005 that shows the server itself has no objection to an
// out-of-subtree entry — only the admin authorization policy does.
func (s *stack) spireLocal(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", adminSocket)
	return s.compose(ctx, full...)
}

// mintedSVID is the parsed output of `spire-server x509 mint`.
type mintedSVID struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (m mintedSVID) GetX509SVID() (*x509svid.SVID, error) { return m.svid, nil }

func (m mintedSVID) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, m.roots), nil
}

// parseMint splits `spire-server x509 mint` output into its three PEM sections.
// The CLI prints them under fixed headings and in a fixed order.
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

// mintAdmin mints a fresh X509-SVID for the admin ID on the local socket.
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

// adminClient dials the admin API with a freshly minted admin SVID.
func (s *stack) adminClient(t *testing.T) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	src, err := s.mintAdmin(ctx, testAdminID)
	if err != nil {
		t.Fatalf("mint admin SVID: %v", err)
	}
	if got := src.svid.ID.String(); got != testAdminID {
		t.Fatalf("minted SVID is %s, want %s", got, testAdminID)
	}
	c, err := Dial(ctx, Config{
		Address:     s.adminAddr,
		TrustDomain: testTrustDomain,
		ServerID:    testServerID,
		Source:      src,
	})
	if err != nil {
		t.Fatalf("Dial(%s): %v", s.adminAddr, err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// clientAs dials with an SVID for some other SPIFFE ID. Used to show that the
// admin path is admin_ids and nothing else.
func (s *stack) clientAs(t *testing.T, id string) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	src, err := s.mintAdmin(ctx, id)
	if err != nil {
		t.Fatalf("mint %s: %v", id, err)
	}
	c, err := Dial(ctx, Config{
		Address:     s.adminAddr,
		TrustDomain: testTrustDomain,
		ServerID:    testServerID,
		Source:      src,
	})
	if err != nil {
		t.Fatalf("Dial as %s: %v", id, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ---------------------------------------------------------------------------
// Workload probes.
// ---------------------------------------------------------------------------

// probeRun is one execution of svidprobe inside a container.
type probeRun struct {
	Outcome  FetchOutcome
	ExitCode int
	Raw      string
}

// runProbe starts a probe container and returns what it printed.
//
// The two arguments are the whole of how a wrong-selector workload is expressed
// (SPI-002): `is` becomes the container's docker labels — the selector material
// doc 04 calls the realistic failure surface, which is why a run entry selects
// on all three components and not just the run id — while `want` is the
// identity the workload asks the Workload API for. When they disagree, SPIRE
// has a workload claiming to be something its selectors do not support.
func (s *stack) runProbe(t *testing.T, is, want RunRef) probeRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := fmt.Sprintf("innsegl-test-probe-%d-%d", os.Getpid()%100000, nameSeq.Add(1))
	args := []string{
		"create", "--name", name,
		// A workload reaches SPIRE over a socket, never over the network.
		"--network", "none",
		// Non-root: unix:uid:0 selects every container on the node and is the
		// weak selector doc 04 names.
		"--user", "10001:10001",
		"--label", "dev.innsegl.agent-type=" + is.AgentType,
		"--label", "dev.innsegl.task-id=" + is.TaskID,
		"--label", "dev.innsegl.run-id=" + is.RunID,
		"--volume", s.socketVolume + ":" + agentSocketMount,
		"--entrypoint", "/svidprobe",
		s.probeImage,
		"-agent-type", want.AgentType,
		"-task-id", want.TaskID,
		"-run-id", want.RunID,
		"-trust-domain", testTrustDomain,
	}
	if _, err := docker(ctx, args...); err != nil {
		t.Fatalf("create probe container: %v", err)
	}
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		if _, err := docker(rmCtx, "rm", "--force", name); err != nil {
			t.Logf("warning: removing probe container %s: %v", name, err)
		}
	}()

	if _, err := docker(ctx, "cp", s.probeBinary, name+":/svidprobe"); err != nil {
		t.Fatalf("copy svidprobe into %s: %v", name, err)
	}

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
	// The probe prints exactly one JSON line; anything else is a harness
	// failure and must not be read as a refusal.
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
// attempt would be a race — and, worse, a single *failed* attempt would look
// exactly like a refusal.
func (s *stack) probeUntilIssued(t *testing.T, run RunRef, deadline time.Duration) probeRun {
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
// Bring-up.
// ---------------------------------------------------------------------------

// buildProbe cross-compiles svidprobe for the docker daemon's platform.
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

// startStack brings up the shipped compose stack and everything around it.
func startStack(ctx context.Context, root, outDir string) (*stack, error) {
	prefix := stackPrefix()
	// The overlay interpolates this into the project, the container names and
	// the network names. Set before the first compose call and never changed.
	if err := os.Setenv(stackEnv, prefix); err != nil {
		return nil, fmt.Errorf("set %s: %w", stackEnv, err)
	}
	s := &stack{
		composeFile:    filepath.Join(root, "deploy", "compose", "spire.yml"),
		overlayFile:    filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		probeImage:     envOr("INNSEGL_TEST_PROBE_IMAGE", defaultProbeImage),
		prefix:         prefix,
		agentContainer: prefix + "-spire-agent",
		adminNetwork:   prefix + "-spire-admin",
	}

	// Only the two services TC-SPI needs. spire-oidc publishes a host port and
	// wants a bootstrap entry it does not have here; leaving it out keeps the
	// harness from depending on either.
	if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server", "spire-agent"); err != nil {
		return nil, fmt.Errorf("compose up: %w", err)
	}

	// The Workload API socket volume, read off the running agent rather than
	// reconstructed from the compose project name.
	vol, err := docker(ctx, "inspect", "--format",
		`{{range .Mounts}}{{if eq .Destination "`+agentSocketMount+`"}}{{.Name}}{{end}}{{end}}`,
		s.agentContainer)
	if err != nil || vol == "" {
		return nil, fmt.Errorf("find the Workload API socket volume on %s: %w", s.agentContainer, err)
	}
	s.socketVolume = vol

	// The attested node, polled: the agent attests shortly after start.
	deadline := time.Now().Add(90 * time.Second)
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
	// A leftover from an interrupted run whose pid this process inherited, if
	// there is one. Its absence is the normal case, so a failure here is not
	// one.
	if _, rmErr := docker(ctx, "rm", "--force", s.proxyName); rmErr != nil {
		_ = rmErr
	}
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
	s.adminAddr = "127.0.0.1:" + port

	if _, err = docker(ctx, "pull", "--quiet", s.probeImage); err != nil {
		return nil, fmt.Errorf("pull %s: %w", s.probeImage, err)
	}
	if s.probeBinary, err = buildProbe(ctx, root, outDir); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *stack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if s.proxyName != "" {
		if _, err := docker(ctx, "rm", "--force", s.proxyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.proxyName, err)
		}
	}
	if os.Getenv("INNSEGL_TEST_KEEP_SPIRE") != "" {
		return
	}
	// Unconditional: this project is this process's own. Nobody else's stack is
	// behind it, so there is nothing to preserve, and leaving it up would leak
	// three containers, three networks and five volumes per run.
	if _, err := s.compose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
	}
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	outDir, err := os.MkdirTemp("", "innsegl-spire-harness-")
	if err != nil {
		panic(err)
	}

	switch err := dockerUsable(ctx); {
	case err != nil:
		stackSkip = err.Error()
	default:
		if s, serr := startStack(ctx, root, outDir); serr != nil {
			stackSkip = serr.Error()
			if s != nil {
				s.stop()
			}
		} else {
			sharedStack = s
		}
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
// what went unproven. It never lets an integration case pass without one.
func requireStack(t *testing.T) *stack {
	t.Helper()
	if sharedStack == nil {
		t.Skipf("skipping: no real SPIRE from deploy/compose/spire.yml (%s). "+
			"This case proves nothing about attestation or admin authorization "+
			"without one; start Docker and re-run.", stackSkip)
	}
	return sharedStack
}

// newRun returns a run reference unique to this test.
func newRun(t *testing.T, agentType, taskID string) RunRef {
	t.Helper()
	return RunRef{
		AgentType: agentType,
		TaskID:    taskID,
		RunID:     fmt.Sprintf("run-%d-%d", os.Getpid()%100000, nameSeq.Add(1)),
	}
}

// runSelectors is the per-run selector set of doc 04 and RM-014's verify.sh:
// the three SPIFFE ID components as docker labels, plus a non-root uid.
func runSelectors(run RunRef) []Selector {
	return []Selector{
		{Type: "docker", Value: "label:dev.innsegl.run-id:" + run.RunID},
		{Type: "docker", Value: "label:dev.innsegl.agent-type:" + run.AgentType},
		{Type: "docker", Value: "label:dev.innsegl.task-id:" + run.TaskID},
		{Type: "unix", Value: "uid:10001"},
	}
}

// registerForTest registers a run and deletes its entry afterwards, so a failed
// case does not leave the reaper (RM-017) work to do.
func registerForTest(t *testing.T, c *Client, s *stack, run RunRef) Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	entry, err := c.RegisterRun(ctx, Registration{
		Run:       run,
		ParentID:  s.parentID,
		Selectors: runSelectors(run),
		TTL:       DefaultRunTTL,
	})
	if err != nil {
		t.Fatalf("RegisterRun(%+v): %v", run, err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if _, err := c.RetireRun(cleanCtx, run); err != nil {
			t.Errorf("cleaning up the entry for %+v: %v", run, err)
		}
	})
	return entry
}
