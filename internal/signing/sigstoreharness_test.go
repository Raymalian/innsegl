// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
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
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// A real SPIRE and a real self-hosted Sigstore, from deploy/compose/, never a
// mock.
//
// IP §2 draws the line in one sentence — "a mocked Fulcio proves nothing about
// I5" — and TC-SIG is where that bites hardest. SIG-001 is the first
// end-to-end proof that this product works at all: a commit object that exists
// in a repository, signed under a short-lived certificate a real CA issued to
// a real JWT-SVID, with a real transparency-log entry that a real inclusion
// proof places in a real Merkle tree. Every one of those adjectives is load
// bearing, and a fake at any position turns the case into a test of our own
// switch statements.
//
// So this harness boots BOTH shipped stacks and runs the shipped `gitsign`
// binary against them:
//
//   - deploy/compose/spire.yml — spire-server, spire-agent and the OIDC
//     discovery provider Fulcio fetches its JWKS from.
//   - deploy/compose/sigstore.yml — Fulcio, Rekor, the Trillian pair, MySQL
//     and Redis, wired and segmented as ADR-0029 decided.
//
// Without Docker, or without a `gitsign` binary, every integration case skips
// with a message naming what went unproven rather than passing quietly.
//
// # Two stacks, one per test process
//
// Both compose files pin a project name and a fixed container_name per
// service, so every process that brings one up selects the SAME stack —
// RM-065 (#81) measured where that ends when `go test ./...` runs packages
// concurrently. deploy/compose/spire-testscope.yml already solves it for the
// SPIRE trio; testdata/sigstore-testscope.yml is this issue's equivalent for
// the Sigstore half, and does nothing but rename. Published ports are
// ephemeral for the same reason: 5555, 3000 and 8443 are one process's.
//
// # Where the credential comes from
//
// `spire-server jwt mint`, on the server's admin socket, inside the server
// container. That is the SHIPPED path and not a shortcut around one: ADR-0019
// has the MCP mint JWT-SVIDs through the server's SVID API rather than through
// the Workload API, so a server-minted token is exactly what `get_credential`
// hands back. Attestation is upstream of this, at register_agent, and is
// TC-SPI's subject.

const (
	// Protected strings (IP §1). Spelled out rather than derived, so a silent
	// change to deploy/compose/spire/server.conf fails these cases.
	harnessTrustDomain = "innsegl.dev"

	// The issuer BOTH stacks must agree on. ADR-0029 decision 3: three files
	// read INNSEGL_SPIRE_JWT_ISSUER and Fulcio refuses every token if they
	// disagree. `spire-oidc` is the service name on the shared network.
	harnessIssuer = "http://spire-oidc:8080"

	// The gitsign release this suite pins. gitsign is used as a released
	// upstream component (IP §7); the version is named here so a move is a
	// deliberate edit rather than whatever happened to be on PATH.
	harnessGitsignVersion = "v0.17.1"

	harnessAdminSocket = "/run/spire/admin/api.sock"
)

var (
	sharedStack *stack
	stackSkip   string
	// stackFailure: Docker and gitsign are both present and the stack still
	// did not come up. A failure, never a skip (#101).
	stackFailure string
	nameSeq      atomic.Int64
)

// stack is one process's pair of compose projects.
type stack struct {
	root        string
	project     string
	spireFiles  []string
	sigFiles    []string
	env         []string
	fulcioURL   string
	rekorURL    string
	oidcURL     string
	gitsignPath string
}

func stackPrefix() string { return fmt.Sprintf("innsegl-signtest-%d", os.Getpid()) }

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

// ---------------------------------------------------------------------------
// #101: a failed dependency is not a skip.
//
// errDependencyAbsent marks the ONLY conditions under which skipping TC-SIG's
// integration cases is honest: there is no Docker daemon (or
// INNSEGL_TEST_NO_DOCKER asks for none), or there is no gitsign binary.
// Nothing else wraps it.
//
// Everything else that can go wrong while standing the stacks up — an image
// that cannot be pulled, a port that cannot be bound, a network Docker refuses
// to create because its predefined address pools are used up, a container that
// never becomes healthy — is a FAILURE. Reporting one of those as a skip turns
// it into a pass-shaped outcome: `go test` exits zero, the package reports ok,
// and the SIG-* suite — I2, I3 and the signing half of I5 — did not run. That
// is what CI produced on a runner whose "Require Docker" step had already
// passed, on a message that even claimed a gitsign the preceding step had
// installed was missing, because that was the only text the branch could
// produce.
//
// internal/verify/verifyharness_test.go carries the reference shape; both
// branches here are exercised by
// TestHAR008AnAbsentDependencyIsASkipAndAFaultIsAFailure.
// ---------------------------------------------------------------------------
var errDependencyAbsent = errors.New("a required dependency is absent")

// startupOutcome routes a start-up error to exactly one of the two variables.
// An absent dependency is a skip; anything else is a failure. There is no
// third answer, and the third answer is how this package came to report ok
// with nothing having run.
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

// harnessRequirement is what a require-function must do for the calling test.
type harnessRequirement int

const (
	harnessProceed harnessRequirement = iota
	harnessSkipTest
	harnessFailTest
)

// harnessNeed decides between the three. A failure outranks a skip: if the
// dependency broke, the reason it broke is what the developer needs to read.
func harnessNeed(up bool, skip, failure string) harnessRequirement {
	switch {
	case failure != "":
		return harnessFailTest
	case !up:
		return harnessSkipTest
	default:
		return harnessProceed
	}
}

// oneLine collapses a multi-line subprocess error into a single line.
//
// `docker compose` reports progress on stderr, so a failure arrives as several
// lines of which only the last usually names the cause. Go's test JSON stream
// emits each line as its own event, and the CI failure behind #101 read
// "Network innsegl-verifytest-40427-spire-admin  Creating" — compose's first
// progress line, with the fault itself on a line the summary never showed.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errDependencyAbsent)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errDependencyAbsent)
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

// findGitsign locates the released gitsign binary. It never builds one from
// source: IP §7 says Sigstore is used as a released upstream component.
func findGitsign(ctx context.Context) (string, error) {
	if p := os.Getenv("INNSEGL_GITSIGN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("INNSEGL_GITSIGN=%s: %w: %w", p, err, errDependencyAbsent)
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
		harnessGitsignVersion, errDependencyAbsent)
}

func (s *stack) compose(ctx context.Context, files []string, args ...string) (string, error) {
	full := []string{"compose", "-p", s.project}
	for _, f := range files {
		full = append(full, "-f", f)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Env = append(os.Environ(), s.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(full, " "), err, oneLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func startStack(ctx context.Context, root string) (*stack, error) {
	gitsignPath, err := findGitsign(ctx)
	if err != nil {
		return nil, err
	}

	oidcPort, err := freeHostPort(ctx)
	if err != nil {
		return nil, err
	}
	fulcioPort, err := freeHostPort(ctx)
	if err != nil {
		return nil, err
	}
	rekorPort, err := freeHostPort(ctx)
	if err != nil {
		return nil, err
	}

	project := stackPrefix()
	s := &stack{
		root:    root,
		project: project,
		spireFiles: []string{
			filepath.Join(root, "deploy", "compose", "spire.yml"),
			filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		},
		sigFiles: []string{
			filepath.Join(root, "deploy", "compose", "sigstore.yml"),
			filepath.Join(root, "internal", "signing", "testdata", "sigstore-testscope.yml"),
		},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
			// ADR-0029 decision 2: Fulcio joins the network spire.yml declares
			// for the discovery provider. Per process, that network is the
			// renamed one.
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + harnessIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
			"INNSEGL_REKOR_PORT=" + rekorPort,
		},
		fulcioURL:   "http://127.0.0.1:" + fulcioPort,
		rekorURL:    "http://127.0.0.1:" + rekorPort,
		oidcURL:     "http://127.0.0.1:" + oidcPort,
		gitsignPath: gitsignPath,
	}

	if _, err := s.compose(ctx, s.spireFiles, "up", "-d", "--wait",
		"spire-server", "spire-agent", "spire-oidc"); err != nil {
		return s, fmt.Errorf("bringing up the SPIRE stack: %w", err)
	}
	if err := s.registerOIDCProvider(ctx); err != nil {
		return s, fmt.Errorf("registering the OIDC discovery provider: %w", err)
	}
	if _, err := s.compose(ctx, s.sigFiles, "up", "-d"); err != nil {
		return s, fmt.Errorf("bringing up the Sigstore stack: %w", err)
	}
	if err := s.awaitTrustMaterial(ctx); err != nil {
		return s, err
	}
	return s, nil
}

// registerOIDCProvider does what deploy/compose/spire/register.sh does, for a
// per-process stack.
//
// It is not optional and it is not setup noise. The discovery provider reads
// the trust domain's JWT keys through the WORKLOAD API (ADR-0011: it is the
// one SPIRE component with a public listener, so it is an ordinary attested
// workload rather than a holder of the admin socket). Until it has a
// registration entry it holds no SVID, `GET /keys` answers
//
//	HTTP 500  document not available
//
// and Fulcio refuses every JWT-SVID with "There was an error processing the
// identity token" — an error that names neither the provider nor the missing
// entry. MEASURED, and it is the same class of trap ADR-0029 recorded for the
// issuer string.
//
// register.sh cannot be reused directly: it hardcodes the container name
// `innsegl-spire-oidc` and addresses `-f spire.yml` with no project, so it
// registers into whichever shared stack happens to be up. The selectors below
// are its five, derived from the running container the same way.
func (s *stack) registerOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://" + harnessTrustDomain + "/innsegl/oidc-discovery-provider"
	container := s.project + "-spire-oidc"

	out, err := s.spireServer(ctx, "agent", "list")
	if err != nil {
		return err
	}
	parent := ""
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
			parent = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
			break
		}
	}
	if parent == "" {
		return fmt.Errorf("no attested agent in `agent list`:\n%s", out)
	}

	imageConfigDigest, err := docker(ctx, "inspect", "--format", "{{.Image}}", container)
	if err != nil {
		return err
	}
	imageRef, err := docker(ctx, "inspect", "--format", "{{.Config.Image}}", container)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "innsegl-oidc-bin-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary := filepath.Join(dir, "oidc")
	if _, cperr := docker(ctx, "cp",
		container+":/opt/spire/bin/oidc-discovery-provider", binary); cperr != nil {
		return cperr
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)

	if _, err := s.spireServer(ctx, "entry", "create",
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
	return s.awaitJWKS(ctx)
}

// awaitJWKS waits for the provider to serve the trust domain's public JWT keys.
// Entries reach the agent through its cache, so this polls rather than sleeps.
func (s *stack) awaitJWKS(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := harnessGET(ctx, s.oidcURL+"/keys")
		if err == nil && strings.Contains(string(body), "\"keys\"") {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the OIDC discovery provider never served a JWKS: %w", last)
}

// spireServer runs one spire-server CLI command on the admin socket.
func (s *stack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", harnessAdminSocket)
	return s.compose(ctx, s.spireFiles, full...)
}

// awaitTrustMaterial waits for ADR-0024's definition of "Sigstore is
// reachable": bytes that PARSE as the trust material, not a status code. A TCP
// dial or an unexamined 200 passes against any listening socket, including a
// proxy in front of a dead Fulcio.
//
// The probe is the harness's own and does not call the wrapper's. A readiness
// check that used production code would make every integration case depend on
// the thing it is meant to be testing, and would skip — silently green —
// whenever that code was broken.
func (s *stack) awaitTrustMaterial(ctx context.Context) error {
	deadline := time.Now().Add(3 * time.Minute)
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
	return fmt.Errorf("Sigstore never served parseable trust material: %w", last)
}

func (s *stack) probeTrustMaterial(ctx context.Context) error {
	root, err := harnessGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("fulcio: /api/v1/rootCert is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("fulcio: /api/v1/rootCert does not parse: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("fulcio: /api/v1/rootCert is not a CA certificate")
	}
	key, err := s.rekorLogKeyPEM(ctx)
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, err := segment.ParseLogPublicKey(key); err != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", err)
	}
	return nil
}

func (s *stack) rekorLogKeyPEM(ctx context.Context) ([]byte, error) {
	return harnessGET(ctx, s.rekorURL+"/api/v1/log/publicKey")
}

// harnessGET fetches one document, with no retry and no interpretation.
func harnessGET(ctx context.Context, url string) ([]byte, error) {
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

func (s *stack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	for _, files := range [][]string{s.sigFiles, s.spireFiles} {
		if _, err := s.compose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
}

// mintJWTSVID mints one audience-bound JWT-SVID through the SPIRE server's
// admin socket — the ADR-0019 path the MCP's get_credential uses.
func (s *stack) mintJWTSVID(ctx context.Context, spiffeID string, ttl time.Duration) (Credential, error) {
	out, err := s.spireServer(ctx, "jwt", "mint",
		"-spiffeID", spiffeID,
		"-audience", AudienceSigstore,
		"-ttl", ttl.String(),
		"-output", "json")
	if err != nil {
		return Credential{}, err
	}
	// The CLI prints a human note before the JSON when it caps the TTL.
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		return Credential{}, fmt.Errorf("no JSON in `jwt mint` output: %s", out)
	}
	var got struct {
		SVID struct {
			ExpiresAt string `json:"expires_at"`
			Token     string `json:"token"`
		} `json:"svid"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		return Credential{}, fmt.Errorf("decoding `jwt mint` output %q: %w", line, err)
	}
	if got.SVID.Token == "" {
		return Credential{}, fmt.Errorf("`jwt mint` returned no token: %s", out)
	}
	var unix int64
	if _, err := fmt.Sscanf(got.SVID.ExpiresAt, "%d", &unix); err != nil {
		return Credential{}, fmt.Errorf("decoding expires_at %q: %w", got.SVID.ExpiresAt, err)
	}
	return Credential{
		Token:     got.SVID.Token,
		SPIFFEID:  spiffeID,
		Audience:  AudienceSigstore,
		ExpiresAt: time.Unix(unix, 0).UTC(),
	}, nil
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	switch err := dockerUsable(ctx); {
	case err != nil:
		// The only honest skip: there is no daemon to ask.
		stackSkip = err.Error()
	default:
		if s, serr := startStack(ctx, root); serr != nil {
			// An absent gitsign is still a skip; anything else — a network
			// Docker will not create, a container that never goes healthy —
			// is a FAILURE (#101).
			stackSkip, stackFailure = startupOutcome(serr)
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
	os.Exit(code)
}

// requireStack skips the calling case when no real Fulcio, Rekor, SPIRE and
// gitsign are available, naming what went unproven. It never lets an
// integration case pass without them.
func requireStack(t *testing.T) *stack {
	t.Helper()
	switch harnessNeed(sharedStack != nil, stackSkip, stackFailure) {
	case harnessFailTest:
		t.Fatalf("the SPIRE + Sigstore stack did not come up, and Docker and "+
			"gitsign are both present: %s\n\nThis is a FAILURE and not a skip "+
			"(#101). TC-SIG's integration cases are what demonstrate I5; "+
			"reporting an infrastructure fault as a skip exits zero and reports "+
			"ok while none of them ran.", stackFailure)
	case harnessSkipTest:
		t.Skipf("skipping: no real SPIRE + Sigstore from deploy/compose/ and no gitsign (%s). "+
			"TC-SIG proves nothing about I2, I3 or I5 against a mock — IP §2, "+
			"\"a mocked Fulcio proves nothing about I5\". Start Docker, "+
			"`go install github.com/sigstore/gitsign@%s`, and re-run.",
			stackSkip, harnessGitsignVersion)
	case harnessProceed:
	}
	return sharedStack
}

// newRunClaim returns a claim for a run unique to this test.
func newRunClaim(t *testing.T, taskID string) Claim {
	t.Helper()
	runID := fmt.Sprintf("run-%d-%d", os.Getpid()%100000, nameSeq.Add(1))
	return Claim{
		Identity: fmt.Sprintf("spiffe://%s/agent/%s/%s/%s", harnessTrustDomain, "demo", taskID, runID),
		Run:      runID,
		Task:     taskID,
	}
}

// testAuthorPolicy admits the deliberately unlinked address the cases author
// with. ADR-0028 decision 6: a `.invalid` domain can never be delegated, so no
// GitHub account can ever hold it and no contributor can appear (I6).
func testAuthorPolicy() AuthorPolicy { return AuthorPolicy{AllowUnlinked: true} }

const testAuthorEmail = "operator@innsegl.invalid"
const testAuthorName = "Innsegl Operator"

// newRepo makes a git repository with one staged file, ready to commit.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "nonexistent-gitconfig"),
			"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"),
		[]byte("innsegl RM-032\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "work.txt")
	return dir
}

// stageMore stages a second change so a second commit has something to record.
func stageMore(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo, "add", name)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(repo, "nonexistent-gitconfig"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s: %v: %s", name, err, out)
	}
}

// gitOut runs one read-only git command in repo and returns its stdout.
func gitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(repo, "nonexistent-gitconfig"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// countObjects returns how many commit objects the repository holds anywhere —
// including unreferenced ones. IP §6.3's "the repo has no new commit object at
// all" is a claim about git plumbing, not about HEAD.
func countCommitObjects(t *testing.T, repo string) int {
	t.Helper()
	out := gitOut(t, repo, "rev-list", "--all", "--objects", "--no-object-names")
	all := gitOut(t, repo, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype)")
	_ = out
	n := 0
	for _, line := range strings.Split(all, "\n") {
		if strings.TrimSpace(line) == "commit" {
			n++
		}
	}
	return n
}

// fetchJSON is the harness's own reader for Rekor, deliberately separate from
// the production lookup so a case checks the log rather than checking that the
// wrapper agrees with itself.
func fetchJSON(t *testing.T, url string, into any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decoding %s: %v: %s", url, err, body)
	}
}

// ---------------------------------------------------------------------------
// HAR-008 — #101. Both branches of the routing rule, exercised.
//
// A routing rule nothing exercises is a routing rule nobody has checked, which
// is exactly how #101 survived in nine harnesses at once. This case pins the
// two outcomes apart: an ABSENT dependency is a skip, and anything else is a
// failure that says so.
// ---------------------------------------------------------------------------

func TestHAR008AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
	t.Run("no docker is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
		err := dockerUsable(t.Context())
		if err == nil {
			t.Fatal("dockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, errDependencyAbsent) {
			t.Fatalf("%v does not wrap errDependencyAbsent, so it would be routed to a "+
				"FAILURE and a developer with no Docker could not run this package", err)
		}
		skip, failure := startupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("no gitsign is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_GITSIGN", filepath.Join(t.TempDir(), "no-such-gitsign"))
		_, err := findGitsign(t.Context())
		if err == nil {
			t.Fatal("findGitsign accepted a path that does not exist")
		}
		if !errors.Is(err, errDependencyAbsent) {
			t.Fatalf("%v does not wrap errDependencyAbsent; a machine without gitsign "+
				"would be told the suite FAILED", err)
		}
		skip, failure := startupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine, and the shape the CI
		// run in #101 produced: Docker is present, working, and refuses to
		// create the network because its address pools are used up.
		err := fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, errDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errDependencyAbsent; it would " +
				"be reported as a skip and the SIG-* suite would silently not run")
		}
		skip, failure := startupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("a healthy start-up is neither", func(t *testing.T) {
		if skip, failure := startupOutcome(nil); skip != "" || failure != "" {
			t.Fatalf("startupOutcome(nil) = (%q, %q), want both empty", skip, failure)
		}
	})

	t.Run("a failure outranks a skip", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			up            bool
			skip, failure string
			want          harnessRequirement
		}{
			{"a failure outranks everything", false, "no docker", "boom", harnessFailTest},
			{"nothing up and no failure is a skip", false, "no docker", "", harnessSkipTest},
			{"a live dependency proceeds", true, "", "", harnessProceed},
		} {
			if got := harnessNeed(tc.up, tc.skip, tc.failure); got != tc.want {
				t.Errorf("%s: harnessNeed(%v, %q, %q) = %d, want %d",
					tc.name, tc.up, tc.skip, tc.failure, got, tc.want)
			}
		}
	})
}
