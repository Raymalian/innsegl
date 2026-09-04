// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"crypto/x509"
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
	"syscall"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/segment"
)

// ---------------------------------------------------------------------------
// The reference stack, brought up the way the README says to bring it up.
//
// Every other harness in this repository applies an ADR-0022 overlay so that
// two test processes never drive the same SPIRE. This one deliberately does
// not: OPS-004 is the adopter's first-run experience, the adopter has no
// overlay, and `deploy/compose/spire/register.sh` addresses the shipped
// container names. So this package owns the shipped compose projects for the
// length of a run — it tears them down with their volumes before it starts and
// again when it finishes, and a `make sigstore-up` stack left running on the
// same machine is removed by the first of those. That is stated in the
// Makefile and in deploy/compose/README.md, because a smoke test that silently
// deletes a developer's stack is a worse first-run experience than the one it
// is testing.
// ---------------------------------------------------------------------------

const (
	trustDomain = "innsegl.dev"
	// demoAgentType and demoTaskRef are what the demo agent registers as, and
	// since RM-079 (#116) they are also what OPS-004 SCANS the public record
	// for. They are deliberately distinctive strings rather than "demo" and
	// "ops-004": a scan for a substring that occurs elsewhere in a certificate,
	// a transcript or a commit object is a scan that can pass by accident.
	demoAgentType = "refactor-billing"
	demoTaskRef   = "ACME-90210"

	// smokeIdentitySecret keys the demo deployment's pseudonyms. A fixture:
	// the stack it configures lives for the length of one test binary.
	smokeIdentitySecret = "ops004-smoke-fixture-secret-0123"
	// demoRepo is doc 02 §5's host/org/name, not a path. The MCP resolves it
	// beneath the workspace root it was configured with.
	demoRepo = "github.com/innsegl-demo/scratch"

	// jwtIssuer is the one string SPIRE stamps, spire-oidc advertises and
	// Fulcio believes (ADR-0029 decision 3). It is the value the README
	// exports, and it is spelled once, here.
	jwtIssuer = "http://spire-oidc:8080"

	// gitsignVersion is the release the signing harnesses assert and CI
	// installs. The MCP container gets a linux build of exactly this.
	gitsignVersion = "v0.17.1"

	// The shipped stack's published loopback endpoints, as spire.yml and
	// sigstore.yml default them. OPS-004 runs the README's commands verbatim,
	// which means it takes the README's ports — for oidc and fulcio, which
	// are not this defect's subject.
	oidcURL   = "http://127.0.0.1:8443"
	fulcioURL = "http://127.0.0.1:5555"

	// Rekor is different (#131). Host port 3000 is a common development
	// port, and a hardcoded rekorURL silently redirected OPS-004's trust
	// material probe at whatever else already held it — measured on this
	// machine as juice-authz, not hypothetical. So Rekor's host port is
	// chosen fresh per run (stack.rekorPort, stack.rekorURL) and threaded
	// through INNSEGL_REKOR_PORT, which sigstore.yml already reads
	// (deploy/compose/sigstore.yml:320). rekorContainerName is that
	// service's container_name there, fixed regardless of compose project
	// name, and is what assertRekorPortIsOurs checks the chosen port
	// against before anything is allowed to treat a response on it as
	// evidence about Innsegl.
	rekorContainerName = "innsegl-sigstore-rekor"

	// Inside the container network the same two services answer to their
	// compose names. The MCP and the verifier both use these.
	fulcioInternalURL = "http://fulcio:5555"
	rekorInternalURL  = "http://rekor:3000"

	// publishedNetwork is sigstore.yml's one non-internal network, carrying
	// fulcio and rekor and nothing else. The verifier joins it and joins
	// nothing else, which is what makes the ledger unreachable.
	publishedNetwork = "innsegl-sigstore-published"

	// The containers this harness owns beyond the compose stacks.
	ledgerNetwork   = "innsegl-smoke-ledger"
	ledgerContainer = "innsegl-smoke-postgres"
	mcpContainer    = "innsegl-smoke-mcp"
	relayContainer  = "innsegl-smoke-ledger-relay"

	ledgerUser     = "innsegl"
	ledgerPassword = "innsegl-smoke"
	ledgerDatabase = "innsegl"

	// runnerImage carries git and busybox's `nc`, and nothing of ours. It is
	// also what the MCP binary runs inside, because sign_commit execs git.
	runnerImage   = "alpine/git:latest"
	postgresImage = "postgres:16"
	// relayImage forwards one TCP port. See openLedgerThroughARelay for why a
	// relay exists at all, and why it is started only after the verification.
	relayImage = "alpine/socat:latest"

	// The two lines the ledger-detached verification prints before it verifies
	// anything. They are asserted by OPS-004: a verification that ran with a
	// route to the database would prove nothing about I5.
	noRouteByAddress = "no route from this container"
	noRouteByName    = "name does not resolve"
)

// documentedBootCommands is the README's boot block, verbatim, as lines of
// shell.
//
// The harness does not re-implement these steps: it joins them with newlines
// and runs the result through `sh`. That is the same thing an adopter does
// when they copy the block out of deploy/compose/README.md, and OPS-005
// asserts that each line really is in that file. "The README must be
// executable as written" is otherwise a claim about a document nobody
// executes.
var documentedBootCommands = []string{
	"export INNSEGL_SPIRE_JWT_ISSUER=" + jwtIssuer,
	"docker compose -f deploy/compose/spire.yml up -d",
	"deploy/compose/spire/register.sh",
	"docker compose -f deploy/compose/sigstore.yml up -d",
}

// documentedTeardownCommands is the README's teardown block, verbatim.
//
// The export is not decoration. sigstore.yml REQUIRES the issuer rather than
// defaulting it (`${INNSEGL_SPIRE_JWT_ISSUER:?...}`, ADR-0029 decision 3), so
// a `down` without it is a compose error and the stack stays up. An adopter
// who copies a teardown block that cannot tear down has been handed a worse
// problem than no teardown block.
var documentedTeardownCommands = []string{
	"export INNSEGL_SPIRE_JWT_ISSUER=" + jwtIssuer,
	"docker compose -f deploy/compose/sigstore.yml down -v",
	"docker compose -f deploy/compose/spire.yml --profile verify down -v",
}

// documentedCommands is what OPS-005 holds deploy/compose/README.md to.
var documentedCommands = append(
	append([]string{}, documentedBootCommands...), documentedTeardownCommands...)

// ---------------------------------------------------------------------------
// #101 — an absent dependency and a broken stack are not the same outcome.
//
// internal/verify/verifyharness_test.go's shape, copied deliberately. A stack
// that failed to start on a machine that HAS Docker is an infrastructure fault,
// and reporting it as a skip turns it into a pass: `go test` exits zero, the
// package reports ok, and OPS-004 — the one case that measures whether an
// adopter can start this system at all — did not run. Both branches are
// asserted by OPS-006.
// ---------------------------------------------------------------------------

var errDependencyAbsent = errors.New("a required dependency is absent")

// wrapDependencyAbsent marks an error as an absent dependency. It exists so
// OPS-006 can build one without knowing how the marking is done.
func wrapDependencyAbsent(err error) error {
	return fmt.Errorf("%w: %w", err, errDependencyAbsent)
}

// startupOutcome routes a start-up error to exactly one of the two variables.
func startupOutcome(err error) (skip, failure string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, errDependencyAbsent):
		return err.Error(), ""
	default:
		return "", err.Error()
	}
}

// requirement is what requireStack must do for the calling test.
type requirement int

const (
	proceed requirement = iota
	skipTest
	failTest
)

// stackRequirement decides between the three. A failure outranks a skip:
// if the stack broke, the reason it broke is what the developer needs to see.
func stackRequirement(up bool, skip, failure string) requirement {
	switch {
	case failure != "":
		return failTest
	case !up:
		return skipTest
	default:
		return proceed
	}
}

// ---------------------------------------------------------------------------
// The stack.
// ---------------------------------------------------------------------------

type stack struct {
	// clone is the fresh-clone approximation everything runs from: a copy of
	// this repository's tracked and not-ignored files, and nothing else.
	clone string
	// binDir holds the linux `innsegl` built from the clone and the pinned
	// linux `gitsign`. Bind-mounted into the MCP and into the verifier.
	binDir string
	// workspace is the MCP's -workspace root, shared with the host so the
	// demo agent can stage into the working tree the MCP signs in.
	workspace string

	arch      string
	mcpURL    string
	healthURL string
	// rekorPort and rekorURL are chosen fresh per run rather than taking the
	// compose default (#131): a fixed host port silently hands OPS-004's
	// trust-material probe to whatever else already holds it. rekorPort is
	// threaded through INNSEGL_REKOR_PORT to `docker compose ... up` via
	// stack.sh, and rekorURL is the host-side URL built from it.
	rekorPort string
	rekorURL  string
	// ledgerIP is the ledger's address on its own network. It is the address
	// the verifier's container is shown to have no route to. NOTHING on the
	// ledger network publishes a host port while that is being measured — see
	// startLedger.
	ledgerIP string

	parentID string
}

var (
	sharedStack  *stack
	stackSkip    string
	stackFailure string
	stackOnce    sync.Once
	teardownOnce sync.Once
)

// requireStack brings the whole reference stack up once per test binary.
//
// It is lazy rather than TestMain-eager so that OPS-005 and OPS-006 — which
// hold the compatibility surface and this harness's own honesty, and need no
// containers — stay instant.
func requireStack(t *testing.T) *stack {
	t.Helper()
	stackOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		s, err := startStack(ctx, t)
		stackSkip, stackFailure = startupOutcome(err)
		if err != nil && s != nil {
			s.stop()
		}
		if err == nil {
			sharedStack = s
		}
	})

	switch stackRequirement(sharedStack != nil, stackSkip, stackFailure) {
	case failTest:
		t.Fatalf("the reference compose stack did not come up on a machine that has "+
			"Docker: %s\n\nThis is a FAILURE and not a skip (#101). OPS-004 is the "+
			"adopter's first-run experience treated as a release gate; a stack that "+
			"would not start is exactly the thing it exists to catch, and reporting "+
			"it as a skip exits zero while nothing ran.", stackFailure)
	case skipTest:
		t.Skipf("skipping OPS-004: %s. The fresh-clone contract is measured against "+
			"real containers — doc 05 §1's reference stack, not a substitute for "+
			"it. Start Docker and re-run.", stackSkip)
	case proceed:
	}
	return sharedStack
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedStack != nil {
		sharedStack.stop()
	}
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Start-up.
// ---------------------------------------------------------------------------

func startStack(ctx context.Context, t *testing.T) (*stack, error) {
	if err := dockerUsable(ctx); err != nil {
		return nil, err
	}
	if err := lockTheShippedStack(ctx, t); err != nil {
		return nil, err
	}

	// From here on every error returns a non-nil stack, because requireStack
	// only calls stop() — which releases the lock taken above — when it gets
	// one. An error path that returned nil would hold the lock for the rest of
	// the process.
	s := &stack{}
	arch, err := docker(ctx, "version", "--format", "{{.Server.Arch}}")
	if err != nil {
		return s, err
	}
	s.arch = arch

	clone, err := freshClone(ctx, repoRoot(t))
	if err != nil {
		return s, err
	}
	s.clone = clone

	// 1. The clean slate. Both shipped projects down WITH THEIR VOLUMES, and
	//    this harness's own containers removed, before anything starts. What
	//    it proves is narrow and worth stating exactly: no volume, container
	//    or network left by an earlier run of this repository is carrying the
	//    boot below.
	if cleanErr := s.cleanSlate(ctx, t); cleanErr != nil {
		return s, cleanErr
	}

	// 2. The README's boot block, run as shell.
	//
	// Rekor's host port is picked here, immediately before it is used, to
	// keep the window between choosing it and `docker compose up` binding
	// it as small as this harness can make it. #143 measured that a
	// probed-then-released port can be taken before it is bound; this does
	// not close that window, it only declines to widen it — and (below)
	// does not trust anything that answers in it without checking first.
	rekorPort, err := freeHostPort(ctx)
	if err != nil {
		return s, fmt.Errorf("choosing a host port for Rekor: %w", err)
	}
	s.rekorPort = rekorPort
	s.rekorURL = "http://127.0.0.1:" + rekorPort

	if bootErr := s.boot(ctx, t); bootErr != nil {
		return s, bootErr
	}
	// #131's fix, the part that matters: a response on the port this
	// harness chose is not evidence about Innsegl until Docker itself says
	// our own Rekor container is what is bound to it. This runs once, right
	// after boot and before any probe, so a conflict is reported in seconds
	// and by name — not after minutes of retries that end in a Rekor fault
	// that never happened.
	if conflictErr := s.assertRekorPortIsOurs(ctx); conflictErr != nil {
		return s, conflictErr
	}
	if trustErr := s.awaitTrustMaterial(ctx); trustErr != nil {
		return s, trustErr
	}
	parent, err := s.attestedNode(ctx)
	if err != nil {
		return s, err
	}
	s.parentID = parent

	// 3. The rest of doc 05 §1 that the compose stack does not yet ship:
	//    the ledger's Postgres, and the MCP itself. See deploy/compose/README.md,
	//    "What the reference stack does not contain yet".
	if err := s.buildBinaries(ctx); err != nil {
		return s, err
	}
	if err := s.startLedger(ctx, t); err != nil {
		return s, err
	}
	if err := s.startMCP(ctx, t); err != nil {
		return s, err
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// One OPS-004 at a time, per machine.
// ---------------------------------------------------------------------------

// smokeLockPath is a fixed path, deliberately: the thing being serialized is
// not this process's stack but the machine's `innsegl-spire` and
// `innsegl-sigstore` compose projects, which every invocation shares.
const smokeLockPath = "/tmp/innsegl-ops004.lock"

var smokeLockFile *os.File

// lockTheShippedStack serializes OPS-004 against every other process on this
// machine.
//
// This package drives the SHIPPED compose project names on purpose — the
// adopter has no ADR-0022 overlay and register.sh addresses the shipped
// container names — and the price is that two invocations would tear each
// other's stack down mid-run. That is RM-065's finding (#81, "a single
// invocation passing where two concurrent ones failed") arriving from the one
// direction a per-process overlay cannot cover, because the overlay is exactly
// what OPS-004 must not use.
//
// MEASURED, not anticipated: while this was being written two `go test ./...`
// runs were in flight on the same machine, each of them reaching this package.
//
// So the stack is built under an advisory lock. A second invocation waits and
// says so; a crashed one releases the lock when the kernel closes its
// descriptor, so there is no stale lock to clear by hand.
func lockTheShippedStack(ctx context.Context, t *testing.T) error {
	f, err := os.OpenFile(smokeLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("opening the OPS-004 lock at %s: %w", smokeLockPath, err)
	}
	deadline := time.Now().Add(30 * time.Minute)
	announced := false
	for {
		if lerr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lerr == nil {
			smokeLockFile = f
			return nil
		}
		if !announced {
			t.Logf("OPS-004 is waiting for %s: another process on this machine holds "+
				"the shipped compose projects. Only one fresh-clone bootstrap can run "+
				"at a time, because there is only one `innsegl-spire`.", smokeLockPath)
			announced = true
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return fmt.Errorf("another process held %s for 30 minutes", smokeLockPath)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func unlockTheShippedStack() {
	if smokeLockFile == nil {
		return
	}
	// Closing the descriptor releases the advisory lock: there is no separate
	// unlock step to get wrong, and a process that dies is released the same
	// way, so there is never a stale lock to clear by hand.
	if err := smokeLockFile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: releasing %s: %v\n", smokeLockPath, err)
	}
	smokeLockFile = nil
}

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return wrapDependencyAbsent(errors.New("INNSEGL_TEST_NO_DOCKER is set"))
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return wrapDependencyAbsent(fmt.Errorf("docker is not on PATH: %w", err))
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return wrapDependencyAbsent(fmt.Errorf("no reachable docker daemon: %w", err))
	}
	return nil
}

// cleanSlate is the closest this can get to "a clean machine" from inside one
// that is not.
//
// It removes both shipped compose projects and their volumes, removes the
// three containers and one network this harness creates, and then ASSERTS that
// no volume belonging to either project survived. What it does not do is prune
// images: pulling every image cold would take longer than the whole test and
// would empty a developer's cache. So the images are the one part of "clean
// machine" this cannot demonstrate; the compose files pin them by digest,
// which is what makes a cold pull deterministic rather than merely likely.
func (s *stack) cleanSlate(ctx context.Context, t *testing.T) error {
	t.Log("OPS-004 clean slate: removing both shipped compose projects, their " +
		"volumes, and this harness's containers before anything starts")
	s.teardownContainers(ctx)
	if out, err := s.sh(ctx, strings.Join(documentedTeardownCommands, "\n")); err != nil {
		return fmt.Errorf("tearing the shipped stacks down before starting: %w\n%s", err, out)
	}

	left, err := docker(ctx, "volume", "ls", "--quiet")
	if err != nil {
		return err
	}
	var stale []string
	for _, v := range strings.Fields(left) {
		if strings.HasPrefix(v, "innsegl-spire_") || strings.HasPrefix(v, "innsegl-sigstore_") {
			stale = append(stale, v)
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("volumes from a previous run survived `down -v`: %v. "+
			"OPS-004 must boot from nothing; a stack that only works because an "+
			"old volume is still there is not the adopter's experience", stale)
	}
	return nil
}

// boot runs the README's documented boot block through a shell, from the
// fresh clone.
//
// register.sh needs an attested agent, and attestation is a few seconds behind
// `up -d`. The block is therefore retried rather than run once: every line in
// it is idempotent, which is what makes retrying the right advice to give an
// adopter — and it is the advice the README gives.
func (s *stack) boot(ctx context.Context, t *testing.T) error {
	script := strings.Join(documentedBootCommands, "\n")
	deadline := time.Now().Add(6 * time.Minute)
	var last error
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		out, err := s.sh(ctx, script)
		if err == nil {
			t.Logf("OPS-004 boot: the README's block succeeded on attempt %d", attempt)
			return nil
		}
		last = fmt.Errorf("%w\n%s", err, out)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("the README's boot block never succeeded: %w", last)
}

// awaitTrustMaterial is ADR-0024's readiness question, asked of the stack the
// adopter just booted: bytes that parse, not a status code.
func (s *stack) awaitTrustMaterial(ctx context.Context) error {
	deadline := time.Now().Add(4 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		last = s.probeTrustMaterial(ctx)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the booted stack never served parseable trust material: %w", last)
}

// probeTrustMaterial does not re-check who owns s.rekorURL's port: that is
// assertRekorPortIsOurs's job, and startStack runs it once, right after boot
// and before the first call here — so by the time this ever asks Rekor
// anything, "who is answering" is already a settled question, not one this
// retry loop reopens on every 2-second attempt.
func (s *stack) probeTrustMaterial(ctx context.Context) error {
	root, err := httpGET(ctx, fulcioURL+"/api/v1/rootCert")
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil {
		return errors.New("fulcio: /api/v1/rootCert did not return PEM")
	}
	if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
		return fmt.Errorf("fulcio: /api/v1/rootCert did not return a certificate: %w", parseErr)
	}
	key, err := httpGET(ctx, s.rekorURL+"/api/v1/log/publicKey")
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, parseErr := segment.ParseLogPublicKey(key); parseErr != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", parseErr)
	}
	jwks, err := httpGET(ctx, oidcURL+"/keys")
	if err != nil {
		return fmt.Errorf("spire-oidc: %w", err)
	}
	if !strings.Contains(string(jwks), "\"keys\"") {
		return errors.New("spire-oidc: /keys served no JWKS, so register.sh's entry is missing")
	}
	return nil
}

// ---------------------------------------------------------------------------
// #131 — a response on Rekor's port is not evidence about Rekor unless the
// container answering it is ours.
//
// MEASURED on this machine: `curl 127.0.0.1:3000/api/v1/log/publicKey`
// returned HTTP 500 titled "Unexpected path: /api/v1/log/publicKey" from
// bkimminich/juice-shop, not from Rekor, because juice-authz already held
// the host port sigstore.yml was hardcoded to. Picking a free port (above)
// removes today's collision; it cannot remove every future one — the next
// thing running on whatever port this harness happens to pick reproduces
// the identical false report unless the harness checks who is actually
// there before it trusts anything the port says. So it does, once, right
// after boot and before the first probe.
// ---------------------------------------------------------------------------

// assertRekorPortIsOurs asks Docker, not HTTP, who is bound to the host port
// this run chose for Rekor. Docker's own port-publish table settles the
// question in a way no HTTP response can: a 500, a 200, a hang and a
// connection reset are all equally consistent with "someone else is there,"
// so none of them is asked first.
func (s *stack) assertRekorPortIsOurs(ctx context.Context) error {
	out, err := docker(ctx, "ps", "--filter", "publish="+s.rekorPort,
		"--format", "{{.Names}}\t{{.Image}}")
	if err != nil {
		return fmt.Errorf("checking what Docker has bound to host port %s before "+
			"trusting anything that answers on it: %w", s.rekorPort, err)
	}
	return rekorPortConflict(s.rekorPort, out)
}

// rekorPortConflict is assertRekorPortIsOurs's decision, pulled out as a pure
// function of `docker ps`'s own output so OPS-014 can exercise every branch
// without a container, and OPS-015 can exercise it against a real one.
func rekorPortConflict(port, psOutput string) error {
	var owners []string
	for _, line := range strings.Split(strings.TrimSpace(psOutput), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, _, _ := strings.Cut(line, "\t")
		if name == rekorContainerName {
			return nil
		}
		owners = append(owners, line)
	}
	if len(owners) == 0 {
		return fmt.Errorf("host port %s was chosen for Rekor and passed as "+
			"INNSEGL_REKOR_PORT, but no container has it published — %s never came "+
			"up on it. This is a port conflict or a boot failure, not a Rekor fault "+
			"(#131)", port, rekorContainerName)
	}
	return fmt.Errorf("host port %s was chosen for Rekor and passed as "+
		"INNSEGL_REKOR_PORT, but Docker has it bound to %s, not %s. Whatever answers "+
		"on 127.0.0.1:%s is that container, not our Rekor, and nothing it says is "+
		"evidence about Innsegl (#131)",
		port, strings.Join(owners, "; "), rekorContainerName, port)
}

// attestedNode is the SPIFFE ID every run entry hangs off.
func (s *stack) attestedNode(ctx context.Context) (string, error) {
	out, err := s.spireServer(ctx, "agent", "list")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":")), nil
		}
	}
	return "", fmt.Errorf("no attested agent in `agent list`:\n%s", out)
}

func (s *stack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{
		"compose", "-f", "deploy/compose/spire.yml", "exec", "-T", "spire-server",
		"/opt/spire/bin/spire-server",
	}, args...)
	full = append(full, "-socketPath", "/run/spire/admin/api.sock")
	return s.dockerIn(ctx, full...)
}

// ---------------------------------------------------------------------------
// The two binaries the MCP container runs.
// ---------------------------------------------------------------------------

// buildBinaries cross-compiles the SHIPPED innsegl binary — from the fresh
// clone, not from this working tree — and the pinned gitsign, for the
// container's platform.
//
// doc 05 §1 lists `innsegl-mcp` and `demo-agent` as *built* compose services.
// They have no Dockerfile and no compose service; until they do, the shipped
// binary is bind-mounted into a stock image, which is exactly what
// internal/verify's VER-001 already does with the verifier. It is the same
// bytes an adopter would run.
func (s *stack) buildBinaries(ctx context.Context) error {
	dir, err := os.MkdirTemp("/tmp", "innsegl-smoke-bin-")
	if err != nil {
		return err
	}
	s.binDir = dir

	build := exec.CommandContext(ctx, "go", "build",
		"-o", filepath.Join(dir, "innsegl"), "./cmd/innsegl")
	build.Dir = s.clone
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+s.arch, "CGO_ENABLED=0")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		return fmt.Errorf("cross-compiling the clone's innsegl for linux/%s: %w\n%s",
			s.arch, buildErr, out)
	}

	gitsign, err := buildGitsign(ctx, s.arch)
	if err != nil {
		return err
	}
	return copyFile(gitsign, filepath.Join(dir, "gitsign"), 0o755)
}

// buildGitsign produces a linux gitsign of the pinned version.
//
// gitsign is deliberately not a go.mod dependency (ADR-0031: importing it
// drags cosign and sigstore-go into a fourteen-entry module for a binary we
// exec), so it is installed the way CI installs it. A cross-compiled
// `go install` refuses a GOBIN, and lands in $GOPATH/bin/$GOOS_$GOARCH — or in
// $GOPATH/bin when the target happens to be the host, which it is on a linux
// runner. Both are checked rather than one being assumed.
func buildGitsign(ctx context.Context, arch string) (string, error) {
	install := exec.CommandContext(ctx, "go", "install",
		"github.com/sigstore/gitsign@"+gitsignVersion)
	install.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOBIN=")
	if out, err := install.CombinedOutput(); err != nil {
		return "", fmt.Errorf("installing gitsign@%s for linux/%s: %w\n%s",
			gitsignVersion, arch, err, out)
	}
	gopath, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(strings.TrimSpace(string(gopath)), "bin")
	for _, candidate := range []string{
		filepath.Join(bin, "linux_"+arch, "gitsign"),
		filepath.Join(bin, "gitsign"),
	} {
		if info, serr := os.Stat(candidate); serr == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("gitsign@%s installed but is under neither %s/linux_%s nor %s",
		gitsignVersion, bin, arch, bin)
}

// ---------------------------------------------------------------------------
// The ledger.
// ---------------------------------------------------------------------------

// startLedger runs doc 05 §1's `postgres` row on a network of its own.
//
// IT PUBLISHES NO HOST PORT, AND THAT IS LOAD-BEARING. MEASURED, by the first
// run of OPS-004 that got this far: publishing a container's port to the host
// inserts an ACCEPT rule for that container's address into Docker's own
// filter chain, and the rule is matched BEFORE the isolation rules that keep
// one bridge network out of another. A published Postgres is reachable, by
// address, from a container on an unrelated network — so the last stage of
// OPS-004 failed with "FAIL: the ledger is reachable by address" while the
// topology was, on paper, correct.
//
// The consequence is worth carrying beyond this test: on this deployment
// shape, `ports:` is not a convenience, it is a hole in the segmentation that
// the compose file's network membership does not describe.
//
// So nothing on the ledger network publishes anything, the MCP applies the
// shipped migrations itself with its own `-migrate`, and the host's route for
// reading the chain back is created only after the verification has been
// measured — see openLedgerThroughARelay.
func (s *stack) startLedger(ctx context.Context, t *testing.T) error {
	if _, err := docker(ctx, "network", "create", ledgerNetwork); err != nil {
		return fmt.Errorf("creating the ledger network: %w", err)
	}
	if _, err := docker(ctx, "run", "-d",
		"--name", ledgerContainer,
		"--network", ledgerNetwork,
		"--env", "POSTGRES_USER="+ledgerUser,
		"--env", "POSTGRES_PASSWORD="+ledgerPassword,
		"--env", "POSTGRES_DB="+ledgerDatabase,
		postgresImage); err != nil {
		return fmt.Errorf("starting the ledger's postgres: %w", err)
	}
	ip, err := docker(ctx, "inspect", "-f",
		`{{(index .NetworkSettings.Networks "`+ledgerNetwork+`").IPAddress}}`, ledgerContainer)
	if err != nil {
		return fmt.Errorf("reading the ledger's address: %w", err)
	}
	s.ledgerIP = ip

	deadline := time.Now().Add(3 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		if _, last = docker(ctx, "exec", ledgerContainer,
			"pg_isready", "-U", ledgerUser, "-d", ledgerDatabase); last == nil {
			t.Logf("OPS-004 ledger: postgres at %s on %s, publishing nothing", ip, ledgerNetwork)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the ledger never accepted a connection: %w", last)
}

// openLedgerThroughARelay gives the host a route to the ledger, for as long as
// it takes to read the chain back, and takes it away again.
//
// The route has to be built rather than kept, because keeping it would destroy
// the thing OPS-004 measures: a published port on the ledger network is
// reachable from every other bridge network (see startLedger). The relay is a
// separate container with its own address, so the ledger's own address and
// name stay isolated — and it is started only AFTER the ledger-detached
// verification has run, so that during the verification there is nothing on
// that network for anything to reach.
//
// Reading the chain through the shipped `internal/ledger` rather than a hand
// written SELECT is deliberate: SIG-001's ledger half is an assertion about
// what the chain holds, and a second reader would be asserting it against a
// second interpretation of the same bytes.
func (s *stack) openLedgerThroughARelay(t *testing.T) (*ledger.Store, func()) {
	t.Helper()
	ctx := t.Context()
	port, err := freeHostPort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := docker(ctx, "run", "-d",
		"--name", relayContainer,
		"--network", ledgerNetwork,
		"--publish", "127.0.0.1:"+port+":5432",
		relayImage,
		"tcp-listen:5432,fork,reuseaddr", "tcp-connect:"+ledgerContainer+":5432",
	); err != nil {
		t.Fatalf("starting the ledger read relay: %v", err)
	}
	stop := func() { dockerIgnore(docker(context.Background(), "rm", "--force", relayContainer)) }

	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		ledgerUser, ledgerPassword, port, ledgerDatabase)
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		store, oerr := ledger.Open(ctx, dsn)
		if oerr == nil {
			return store, func() { store.Close(); stop() }
		}
		last = oerr
		time.Sleep(time.Second)
	}
	stop()
	t.Fatalf("the ledger never answered through the read relay: %v", last)
	return nil, func() {}
}

// ---------------------------------------------------------------------------
// The MCP server.
// ---------------------------------------------------------------------------

// startMCP runs `innsegl serve` in a container joined to the three networks
// doc 05 §1 puts it on and no others.
//
//	innsegl-spire-admin           the admin path, and the only thing that
//	                              grants admin reachability
//	innsegl-sigstore-published    fulcio and rekor
//	innsegl-smoke-ledger          the chain
//
// The admin credential is an X509-SVID for spiffe://innsegl.dev/innsegl/mcp,
// the one ID server.conf lists in admin_ids, minted over the server's local
// socket by the operator. serve.go calls a file-held credential "not what a
// deployment uses", and it is right: a deployment attests the MCP through the
// Workload API and gets rotation. That needs a registration entry carrying the
// MCP container's own selectors, which needs the container to exist first —
// register.sh solves the same circularity for spire-oidc and would have to
// grow a second case. `deploy/compose/spire/register.sh` is RM-014's file.
func (s *stack) startMCP(ctx context.Context, t *testing.T) error {
	credDir, err := s.mintAdminCredential(ctx)
	if err != nil {
		return err
	}
	workspace, err := os.MkdirTemp("/tmp", "innsegl-smoke-work-")
	if err != nil {
		return err
	}
	s.workspace = workspace

	mcpPort, err := freeHostPort(ctx)
	if err != nil {
		return err
	}
	healthPort, err := freeHostPort(ctx)
	if err != nil {
		return err
	}
	s.mcpURL = "http://127.0.0.1:" + mcpPort
	s.healthURL = "http://127.0.0.1:" + healthPort

	dsn := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable",
		ledgerUser, ledgerPassword, ledgerContainer, ledgerDatabase)

	// `create` then `network connect` then `start`: a container started on one
	// network resolves nothing on the other two, and `innsegl serve` fails
	// fast on an unreachable ledger rather than retrying — which is correct
	// behaviour and has to be worked with rather than around.
	args := []string{
		"create", "--name", mcpContainer,
		"--network", publishedNetwork,
		"--publish", "127.0.0.1:" + mcpPort + ":8080",
		"--publish", "127.0.0.1:" + healthPort + ":8081",
		// The container writes the commit into the shared working tree, so it
		// runs as the user that owns it. Ownership git disagrees with is
		// "dubious ownership", and the signer builds its child environment as
		// a whitelist — there is no safe.directory to inject.
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--volume", s.binDir + ":/innsegl:ro",
		"--volume", credDir + ":/cred:ro",
		"--volume", workspace + ":/work",
		"--env", "INNSEGL_LEDGER_DSN=" + dsn,
		"--env", "INNSEGL_SPIRE_ADDRESS=spire-server:8081",
		"--env", "INNSEGL_TRUST_DOMAIN=" + trustDomain,
		"--env", "INNSEGL_SPIRE_PARENT_ID=" + s.parentID,
		"--env", "INNSEGL_MCP_SVID_FILE=/cred/svid.pem",
		"--env", "INNSEGL_MCP_KEY_FILE=/cred/key.pem",
		"--env", "INNSEGL_MCP_BUNDLE_FILE=/cred/bundle.pem",
		"--env", "INNSEGL_FULCIO_URL=" + fulcioInternalURL,
		"--env", "INNSEGL_REKOR_URL=" + rekorInternalURL,
		"--env", "INNSEGL_MCP_LISTEN=0.0.0.0:8080",
		"--env", "INNSEGL_MCP_HEALTH_LISTEN=0.0.0.0:8081",
		// The deployment's own migration step. Nothing else has a route to
		// the ledger at this point, by design.
		"--env", "INNSEGL_MIGRATE=1",
		"--env", "INNSEGL_WORKSPACE=/work",
		"--env", "INNSEGL_SPIRE_JWT_ISSUER=" + jwtIssuer,
		"--env", "INNSEGL_SIGN_AUTHOR_NAME=Innsegl Demo Agent",
		// A .invalid address: I6's author gate admits a reserved, undelegatable
		// domain only when told to, and a demo must not claim a real person.
		"--env", "INNSEGL_SIGN_AUTHOR_EMAIL=demo-agent@innsegl.invalid",
		"--env", "INNSEGL_SIGN_AUTHOR_ALLOW_UNLINKED=true",
		"--env", "INNSEGL_GITSIGN=/innsegl/gitsign",
		// RM-079 (#116). Pseudonymous identity is the shipped default, so the
		// server refuses to start without a secret — which is the point: an
		// adopter's first run cannot silently put its ticket references into
		// Rekor. The reference stack generates one; this is the fixture's.
		"--env", "INNSEGL_IDENTITY_SECRET=" + smokeIdentitySecret,
		"--env", "HOME=/tmp",
		"--entrypoint", "/innsegl/innsegl",
		runnerImage, "serve",
	}
	if _, err := docker(ctx, args...); err != nil {
		return fmt.Errorf("creating the MCP container: %w", err)
	}
	for _, network := range []string{"innsegl-spire-admin", ledgerNetwork} {
		if _, err := docker(ctx, "network", "connect", network, mcpContainer); err != nil {
			return fmt.Errorf("joining the MCP to %s: %w", network, err)
		}
	}
	if _, err := docker(ctx, "start", mcpContainer); err != nil {
		return fmt.Errorf("starting the MCP container: %w", err)
	}
	if err := s.awaitReady(ctx); err != nil {
		logs, logErr := docker(ctx, "logs", mcpContainer)
		if logErr != nil {
			logs = "the server's own logs could not be read either: " + logErr.Error()
		}
		return fmt.Errorf("%w\n--- innsegl serve ---\n%s", err, logs)
	}
	t.Logf("OPS-004 MCP: serving on %s, health on %s", s.mcpURL, s.healthURL)
	return nil
}

// mintAdminCredential writes the MCP's admin SVID, its key and the trust
// bundle as three PEM files. `spire-server x509 mint` prints all three to
// stdout under three headings; the container is distroless and has no shell to
// split them with, so they are split here.
func (s *stack) mintAdminCredential(ctx context.Context) (string, error) {
	out, err := s.spireServer(ctx, "x509", "mint",
		"-spiffeID", "spiffe://"+trustDomain+"/innsegl/mcp")
	if err != nil {
		return "", fmt.Errorf("minting the MCP's admin SVID: %w", err)
	}
	dir, err := os.MkdirTemp("/tmp", "innsegl-smoke-cred-")
	if err != nil {
		return "", err
	}
	sections := map[string]string{
		"svid.pem":   sectionOf(out, "X509-SVID:", "Private key:"),
		"key.pem":    sectionOf(out, "Private key:", "Root CAs:"),
		"bundle.pem": sectionOf(out, "Root CAs:", ""),
	}
	for name, body := range sections {
		if !strings.Contains(body, "-----BEGIN") {
			return "", fmt.Errorf("`x509 mint` produced no %s:\n%s", name, out)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// sectionOf returns the lines strictly between two headings. An empty `until`
// runs to the end.
func sectionOf(text, from, until string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == from:
			in = true
		case until != "" && trimmed == until:
			in = false
		case in:
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// readiness is the shape of the MCP's /readyz body, read only as far as
// OPS-004 needs it.
type readiness struct {
	Ready        bool `json:"ready"`
	Dependencies []struct {
		Dependency string `json:"dependency"`
		Reachable  bool   `json:"reachable"`
	} `json:"dependencies"`
}

func (s *stack) awaitReady(ctx context.Context) error {
	deadline := time.Now().Add(3 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := httpGET(ctx, s.healthURL+"/readyz")
		if err == nil {
			var r readiness
			if last = json.Unmarshal(body, &r); last == nil && r.Ready {
				return nil
			}
			if last == nil {
				last = fmt.Errorf("/readyz says ready=false: %s", body)
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the MCP never became ready: %w", last)
}

// reportReadiness prints what the adopter's own readiness probe would print.
// It is the evidence that the stack the README booted is the stack under test:
// three named dependencies, each reachable, from the process that holds SPIRE
// admin.
func (s *stack) reportReadiness(t *testing.T) {
	t.Helper()
	body, err := httpGET(t.Context(), s.healthURL+"/readyz")
	if err != nil {
		t.Fatalf("reading the MCP's readiness: %v", err)
	}
	var r readiness
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	if !r.Ready {
		t.Fatalf("the MCP is not ready: %s", body)
	}
	for _, d := range r.Dependencies {
		if !d.Reachable {
			t.Errorf("%s is not reachable from the MCP: %s", d.Dependency, body)
		}
		t.Logf("OPS-004 readiness: %-8s reachable=%v", d.Dependency, d.Reachable)
	}
	if len(r.Dependencies) < 3 {
		t.Errorf("/readyz named %d dependencies; doc 05 §1's stack has SPIRE, the "+
			"ledger and Sigstore: %s", len(r.Dependencies), body)
	}
}

// ---------------------------------------------------------------------------
// Teardown.
// ---------------------------------------------------------------------------

// stop removes everything this harness created, including the shipped compose
// projects' volumes. A machine that ran OPS-004 is left as clean as OPS-004
// needed it to be at the start, which is the only way the next run is also a
// fresh-clone run.
func (s *stack) stop() {
	teardownOnce.Do(func() {
		if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
			fmt.Fprintf(os.Stderr,
				"INNSEGL_TEST_KEEP_STACK is set: the shipped compose projects, %s and %s "+
					"are left running. `make smoke-down` removes them.\n",
				mcpContainer, ledgerContainer)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.teardownContainers(ctx)
		if out, err := s.sh(ctx, strings.Join(documentedTeardownCommands, "\n")); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tearing the shipped stacks down: %v\n%s\n", err, out)
		}
		for _, dir := range []string{s.clone, s.binDir, s.workspace} {
			if dir != "" {
				_ = os.RemoveAll(dir)
			}
		}
		unlockTheShippedStack()
	})
}

func (s *stack) teardownContainers(ctx context.Context) {
	for _, name := range []string{mcpContainer, relayContainer, ledgerContainer} {
		dockerIgnore(docker(ctx, "rm", "--force", "--volumes", name))
	}
	dockerIgnore(docker(ctx, "network", "rm", ledgerNetwork))
}

// ---------------------------------------------------------------------------
// The fresh clone.
// ---------------------------------------------------------------------------

// repoRoot is the module root, two directories above test/smoke.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// freshClone copies this repository's tracked and not-ignored files into a
// temporary directory, and everything downstream runs from there.
//
// WHAT THIS DOES AND DOES NOT PROVE. `git ls-files --cached --others
// --exclude-standard` is exactly the set a clone would hold once the working
// tree is committed: tracked files at their working-tree content, plus new
// files that are not gitignored. Everything gitignored — build output, cover
// profiles, editor state, node_modules, the tool caches — is left behind. So
// what this demonstrates is that the boot below depends on no untracked local
// state. It does not demonstrate a machine with no Docker images, no module
// cache and no Go toolchain; those are named in the report rather than
// claimed here.
func freshClone(ctx context.Context, root string) (string, error) {
	list := exec.CommandContext(ctx, "git", "-C", root,
		"ls-files", "-z", "--cached", "--others", "--exclude-standard")
	raw, err := list.Output()
	if err != nil {
		return "", fmt.Errorf("listing the repository's clonable files: %w", err)
	}
	dest, err := os.MkdirTemp("/tmp", "innsegl-freshclone-")
	if err != nil {
		return "", err
	}
	n := 0
	for _, name := range strings.Split(string(raw), "\x00") {
		if name == "" {
			continue
		}
		src := filepath.Join(root, name)
		info, serr := os.Lstat(src)
		if serr != nil || !info.Mode().IsRegular() {
			// A deleted-but-tracked file, or a symlink. Neither is part of what
			// a clone would boot from here.
			continue
		}
		out := filepath.Join(dest, name)
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return dest, err
		}
		if err := copyFile(src, out, info.Mode().Perm()); err != nil {
			return dest, err
		}
		n++
	}
	if n == 0 {
		return dest, errors.New("the fresh clone is empty; `git ls-files` found nothing")
	}
	return dest, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------------------
// Small tools.
// ---------------------------------------------------------------------------

// sh runs a block of shell from the fresh clone, which is how the README's
// commands are executed rather than re-implemented.
func (s *stack) sh(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-e", "-c", script)
	cmd.Dir = s.clone
	// INNSEGL_REKOR_PORT is the escape hatch deploy/compose/sigstore.yml
	// already offers (line 320). This is the one place a chosen port reaches
	// it, through the process environment rather than a line appended to
	// documentedBootCommands — an appended line is exactly what OPS-005
	// would then have to find, verbatim, in the README, and a per-run port
	// number cannot be.
	if s.rekorPort != "" {
		cmd.Env = append(os.Environ(), "INNSEGL_REKOR_PORT="+s.rekorPort)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sh: %w", err)
	}
	return string(out), nil
}

// dockerIn runs a docker command from the fresh clone, so that `-f
// deploy/compose/...` resolves there.
func (s *stack) dockerIn(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = s.clone
	cmd.Env = append(os.Environ(), "INNSEGL_SPIRE_JWT_ISSUER="+jwtIssuer)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, oneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// dockerIgnore discards the result of a best-effort cleanup command, in the
// one place where failing to remove something already absent is the expected
// outcome rather than an error worth reporting.
func dockerIgnore(string, error) {}

func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, oneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// oneLine collapses a multi-line subprocess error into a single line, so the
// cause survives Go's per-line test JSON stream.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

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

func httpGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return body, nil
}
