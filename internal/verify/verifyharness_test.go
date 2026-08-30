// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"innsegl.dev/innsegl/internal/signing"
)

// The real stacks, from deploy/compose/, for the integration half of TC-VER.
//
// IP §2: "a mocked Fulcio proves nothing about I5", and VER-001 IS I5. So the
// commits these cases verify are signed by the released gitsign binary,
// against a real Fulcio that issued a real short-lived certificate to a real
// JWT-SVID minted by a real SPIRE server, and logged in a real Rekor backed by
// a real Trillian. The verifier under test then reads them with no access to
// any of that configuration except two URLs a stranger could be given.
//
// # This is the fourth reimplementation of register.sh's five selectors
//
// deploy/compose/spire/register.sh registers the OIDC discovery provider, and
// cannot drive a per-process stack: it hardcodes the container name
// `innsegl-spire-oidc` and addresses `-f spire.yml` with no project. Without
// that entry the provider holds no SVID, `GET /keys` answers HTTP 500, and
// Fulcio refuses every token with "There was an error processing the identity
// token" — the same message an expired token produces. ADR-0031 recorded this
// and asked for register.sh to be parameterised by project and container name.
// It has not been, so the selectors are derived here for the fourth time.
// ADR-0034 repeats the request; `deploy/` is not this issue's to change.

const (
	harnessTrustDomain = "innsegl.dev"
	harnessIssuer      = "http://spire-oidc:8080"
	harnessGitsignVer  = "v0.17.1"
	harnessAdminSocket = "/run/spire/admin/api.sock"
	harnessAuthorEmail = "operator@innsegl.invalid"
	harnessAuthorName  = "Innsegl Operator"
)

var (
	sharedStack *stack
	stackSkip   string
	// stackFailure is set when Docker and gitsign are both present and the
	// stack still did not come up. It is a failure, never a skip.
	stackFailure string
	nameSeq      atomic.Int64
)

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
	// publishedNetwork is the per-process non-internal network fulcio and
	// rekor are both on. VER-001's container joins it and nothing else.
	publishedNetwork string
}

func stackPrefix() string { return fmt.Sprintf("innsegl-verifytest-%d", os.Getpid()) }

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

// errDependencyAbsent marks the only two conditions under which skipping
// TC-VER's integration cases is honest: there is no Docker daemon, or there is
// no gitsign binary. On a developer's machine either is a legitimate reason
// not to run them.
//
// Everything else that can go wrong while standing the stack up — a compose
// network that cannot be created, a port that cannot be bound, a container
// that never becomes healthy — is a FAILURE, and this distinction is the
// point. A stack that failed to start on a machine that has Docker is an
// infrastructure fault, and reporting it as a skip converts it into a
// pass-shaped outcome: `go test` exits zero, the package reports ok, and
// VER-001, VER-002, VER-003 and VER-006 did not run. That happened in CI —
// five cases skipped on a runner where the "Require Docker" step had already
// passed and every other package's stack came up. Only scripts/test-no-skips.sh
// caught it, and a gate outside the test is the wrong place for a test to be
// caught. IP §2 is explicit that a mocked Fulcio proves nothing about I5; a
// Fulcio that never started proves exactly as little.
var errDependencyAbsent = errors.New("a required dependency is absent")

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

// oneLine collapses a multi-line subprocess error into a single line.
//
// `docker compose` reports progress on stderr, so a failure arrives as several
// lines of which only the last usually names the cause. Go's test JSON stream
// emits each line as its own event, and the CI failure that prompted this read
// "Network innsegl-verifytest-40427-spire-admin  Creating" — compose's first
// progress line, with the actual error on a line the summary never showed.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

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
		harnessGitsignVer, errDependencyAbsent)
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
		// ADR-0031 flagged the move of this overlay to deploy/compose/ "the
		// moment a second suite needs it". This is that second suite, and
		// deploy/ is not this issue's to change, so it is referenced where it
		// lives. ADR-0034 repeats the request.
		sigFiles: []string{
			filepath.Join(root, "deploy", "compose", "sigstore.yml"),
			filepath.Join(root, "internal", "signing", "testdata", "sigstore-testscope.yml"),
		},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + harnessIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
			"INNSEGL_REKOR_PORT=" + rekorPort,
		},
		fulcioURL:        "http://127.0.0.1:" + fulcioPort,
		rekorURL:         "http://127.0.0.1:" + rekorPort,
		oidcURL:          "http://127.0.0.1:" + oidcPort,
		gitsignPath:      gitsignPath,
		publishedNetwork: project + "-sigstore-published",
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

func (s *stack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", harnessAdminSocket)
	return s.compose(ctx, s.spireFiles, full...)
}

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
	if _, err := harnessGET(ctx, s.fulcioURL+"/api/v1/rootCert"); err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	key, err := harnessGET(ctx, s.rekorURL+"/api/v1/log/publicKey")
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, err := segment.ParseLogPublicKey(key); err != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", err)
	}
	return nil
}

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

func (s *stack) mintJWTSVID(ctx context.Context, spiffeID string, ttl time.Duration) (signing.Credential, error) {
	out, err := s.spireServer(ctx, "jwt", "mint",
		"-spiffeID", spiffeID,
		"-audience", signing.AudienceSigstore,
		"-ttl", ttl.String(),
		"-output", "json")
	if err != nil {
		return signing.Credential{}, err
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		return signing.Credential{}, fmt.Errorf("no JSON in `jwt mint` output: %s", out)
	}
	var got struct {
		SVID struct {
			ExpiresAt string `json:"expires_at"`
			Token     string `json:"token"`
		} `json:"svid"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		return signing.Credential{}, fmt.Errorf("decoding `jwt mint` output %q: %w", line, err)
	}
	var unix int64
	if _, err := fmt.Sscanf(got.SVID.ExpiresAt, "%d", &unix); err != nil {
		return signing.Credential{}, fmt.Errorf("decoding expires_at %q: %w", got.SVID.ExpiresAt, err)
	}
	return signing.Credential{
		Token:     got.SVID.Token,
		SPIFFEID:  spiffeID,
		Audience:  signing.AudienceSigstore,
		ExpiresAt: time.Unix(unix, 0).UTC(),
	}, nil
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	switch err := dockerUsable(ctx); {
	case err != nil:
		stackSkip = err.Error()
	default:
		if s, serr := startStack(ctx, root); serr != nil {
			// The two outcomes are not the same thing, and were treated as the
			// same thing until CI proved the difference. See errDependencyAbsent.
			if errors.Is(serr, errDependencyAbsent) {
				stackSkip = serr.Error()
			} else {
				stackFailure = serr.Error()
			}
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

func requireStack(t *testing.T) *stack {
	t.Helper()
	if stackFailure != "" {
		t.Fatalf("the SPIRE + Sigstore stack did not come up, and Docker and gitsign "+
			"are both present: %s\n\nThis is a failure and not a skip. TC-VER's "+
			"integration cases are what demonstrate I5; reporting an infrastructure "+
			"fault as a skip exits zero and reports ok while VER-001, VER-002, "+
			"VER-003 and VER-006 did not run.", stackFailure)
	}
	if sharedStack == nil {
		t.Skipf("skipping: no real SPIRE + Sigstore from deploy/compose/ and no gitsign (%s). "+
			"TC-VER's integration cases prove nothing about I5 against a mock — IP §2, "+
			"\"a mocked Fulcio proves nothing about I5\". Start Docker, "+
			"`go install github.com/sigstore/gitsign@%s`, and re-run.",
			stackSkip, harnessGitsignVer)
	}
	return sharedStack
}

// staticCredential is the MCP's get_credential, faked. The TOKEN IS REAL: it
// was minted by the harness's real SPIRE server.
type staticCredential struct{ c signing.Credential }

func (s staticCredential) Credential(context.Context) (signing.Credential, error) {
	return s.c, nil
}

// signedCommit is one real signed commit and everything the cases need to
// talk about it.
type signedCommit struct {
	repo   string
	sha    string
	tree   string
	claim  signing.Claim
	result signing.Result
}

// sharedRepo is a git repository under /tmp rather than under t.TempDir().
//
// VER-001 bind-mounts the repository into a container, and macOS's TMPDIR
// (/var/folders/...) is not in Docker Desktop's default file-sharing set while
// /tmp is. The directory is removed by the test's own cleanup.
func sharedRepo(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "innsegl-verify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	harnessGit(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"),
		[]byte("innsegl RM-037\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	harnessGit(t, dir, "add", "work.txt")
	return dir
}

func harnessGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(repo, "no-such-gitconfig"),
		"GIT_CEILING_DIRECTORIES=/tmp")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// signOne signs one commit with the shipped wrapper against the real stack.
func signOne(t *testing.T, s *stack, repo, message, task string) signedCommit {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	runID := fmt.Sprintf("run-%d-%d", os.Getpid()%100000, nameSeq.Add(1))
	claim := signing.Claim{
		Identity: fmt.Sprintf("spiffe://%s/agent/demo/%s/%s", harnessTrustDomain, task, runID),
		Run:      runID,
		Task:     task,
	}
	cred, err := s.mintJWTSVID(ctx, claim.Identity, 10*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	signer, err := signing.NewSigner(signing.Config{
		FulcioURL:   s.fulcioURL,
		RekorURL:    s.rekorURL,
		Issuer:      harnessIssuer,
		GitsignPath: s.gitsignPath,
		Author:      signing.AuthorPolicy{AllowUnlinked: true},
	}, staticCredential{cred})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	res, err := signer.Sign(ctx, signing.Request{
		Repo:        repo,
		Message:     message,
		AuthorName:  harnessAuthorName,
		AuthorEmail: harnessAuthorEmail,
		Claim:       claim,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signedCommit{
		repo:   repo,
		sha:    res.CommitSHA,
		tree:   harnessGit(t, repo, "rev-parse", res.CommitSHA+"^{tree}"),
		claim:  claim,
		result: res,
	}
}

// stageMore stages another change so the next commit has content.
func stageMore(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	harnessGit(t, repo, "add", name)
}

// stackVerifier builds the verifier under test against the stack's PUBLISHED
// endpoints only — two URLs and nothing else. No trust root from disk, no
// configuration shared with the signer, no database.
func stackVerifier(t *testing.T, s *stack) *Verifier {
	t.Helper()
	v, err := New(Config{FulcioURL: s.fulcioURL, RekorURL: s.rekorURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}
