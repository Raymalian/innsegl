// SPDX-License-Identifier: Apache-2.0

package signprobe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// SIG-015 against the shipped stacks: a real SPIRE server mints the probe's
// JWT-SVID and a real Fulcio, from deploy/compose/sigstore.yml, issues (or
// refuses) the certificate. IP §2: "a mocked Fulcio proves nothing about I5".
//
// Only the services the probe touches come up: the SPIRE trio (the server
// mints, the discovery provider serves Fulcio the keys) and Fulcio with its
// bootstrap. Rekor is not started; the probe never writes to it.
//
// The stack is started on first use, so `go test -run` over the unit cases
// needs no Docker. Names are per process (spire-testscope.yml and
// internal/signing/testdata/sigstore-testscope.yml), so no shared stack is
// touched.

const (
	harnessIssuer      = "http://spire-oidc:8080"
	harnessAdminSocket = "/run/spire/admin/api.sock"
)

type stack struct {
	project    string
	spireFiles []string
	sigFiles   []string
	env        []string
	fulcioURL  string
	oidcURL    string
}

var (
	stackOnce    sync.Once
	sharedStack  *stack
	stackSkip    string
	stackFailure string
)

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Dir(wd)), nil
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
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(full, " "), err, dockertest.OneLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (s *stack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", harnessAdminSocket)
	return s.compose(ctx, s.spireFiles, full...)
}

func startStack(ctx context.Context) (*stack, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	oidcPort, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		return nil, err
	}
	fulcioPort, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		return nil, err
	}
	project := fmt.Sprintf("innsegl-signprobetest-%d", os.Getpid())
	s := &stack{
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
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + harnessIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
		},
		fulcioURL: "http://127.0.0.1:" + fulcioPort,
		oidcURL:   "http://127.0.0.1:" + oidcPort,
	}
	if _, err := s.compose(ctx, s.spireFiles, "up", "-d", "--wait", "spire-server", "spire-agent", "spire-oidc"); err != nil {
		return s, fmt.Errorf("bringing up the SPIRE stack: %w", err)
	}
	if err := s.registerOIDCProvider(ctx); err != nil {
		return s, fmt.Errorf("registering the OIDC discovery provider: %w", err)
	}
	if _, err := s.compose(ctx, s.sigFiles, "up", "-d", "fulcio"); err != nil {
		return s, fmt.Errorf("bringing up Fulcio: %w", err)
	}
	if err := s.await(ctx, s.fulcioURL+fulcioRootPath, "BEGIN CERTIFICATE"); err != nil {
		return s, fmt.Errorf("Fulcio never served its root: %w", err)
	}
	return s, nil
}

// registerOIDCProvider is deploy/compose/spire/register.sh's entry for the
// discovery provider, for a per-process stack (internal/signing's harness
// says why it cannot run register.sh itself). Without it Fulcio can fetch no
// keys and refuses every token.
func (s *stack) registerOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://innsegl.dev/innsegl/oidc-discovery-provider"
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
	digest, err := dockertest.Docker(ctx, "inspect", "--format", "{{.Image}}", container)
	if err != nil {
		return err
	}
	ref, err := dockertest.Docker(ctx, "inspect", "--format", "{{.Config.Image}}", container)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "innsegl-signprobe-oidc-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	bin := filepath.Join(dir, "oidc")
	if _, cerr := dockertest.Docker(ctx, "cp", container+":/opt/spire/bin/oidc-discovery-provider", bin); cerr != nil {
		return cerr
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if _, err := s.spireServer(ctx, "entry", "create",
		"-parentID", parent, "-spiffeID", spiffeID,
		"-selector", "unix:sha256:"+hex.EncodeToString(sum[:]),
		"-selector", "unix:uid:1000",
		"-selector", "docker:image_config_digest:"+digest,
		"-selector", "docker:label:dev.innsegl.component:oidc-discovery-provider",
		"-selector", "docker:image_id:"+ref,
		"-x509SVIDTTL", "1800", "-jwtSVIDTTL", "300"); err != nil {
		return err
	}
	return s.await(ctx, s.oidcURL+"/keys", `"keys"`)
}

func (s *stack) await(ctx context.Context, url, want string) error {
	deadline := time.Now().Add(3 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if rerr == nil && resp.StatusCode == http.StatusOK && strings.Contains(string(body), want) {
				return nil
			}
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return last
}

// mint is the SPIRE server's own `jwt mint` on its admin socket: the server
// mints, as MintJWTSVID does for the core (ADR-0019).
func (s *stack) mint(audience string) MintFunc {
	return func(ctx context.Context, id, _ string) (string, error) {
		out, err := s.spireServer(ctx, "jwt", "mint", "-spiffeID", id, "-audience", audience, "-output", "json")
		if err != nil {
			return "", err
		}
		for _, l := range strings.Split(out, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "{") {
				continue
			}
			var got struct {
				SVID struct {
					Token string `json:"token"`
				} `json:"svid"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(l)), &got); err != nil {
				return "", err
			}
			return got.SVID.Token, nil
		}
		return "", fmt.Errorf("no token in `jwt mint` output: %s", out)
	}
}

func (s *stack) stop() {
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, files := range [][]string{s.sigFiles, s.spireFiles} {
		if _, err := s.compose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedStack != nil {
		sharedStack.stop()
	}
	os.Exit(code)
}

// requireStack starts the stack once. No Docker is a skip; Docker present
// and the stack not up is a FAILURE (#101).
func requireStack(t *testing.T) *stack {
	t.Helper()
	stackOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := dockertest.Usable(ctx); err != nil {
			stackSkip = err.Error()
			return
		}
		s, err := startStack(ctx)
		if err != nil {
			stackSkip, stackFailure = dockertest.StartupOutcome(err)
			if s != nil {
				s.stop()
			}
			return
		}
		sharedStack = s
	})
	switch dockertest.Need(sharedStack != nil, stackSkip, stackFailure) {
	case dockertest.FailTest:
		t.Fatalf("the SPIRE + Fulcio stack did not come up, and Docker is present: %s\n\n"+
			"This is a FAILURE and not a skip (#101).", stackFailure)
	case dockertest.SkipTest:
		t.Skipf("skipping: no Docker (%s); SIG-015 proves nothing against a mock Fulcio (IP §2)", stackSkip)
	case dockertest.Proceed:
	}
	return sharedStack
}

// SIG-015 — against the shipped Fulcio and a SPIRE-minted credential for the
// probe identity, the probe passes; the identity needs no registration entry,
// as the core's MintJWTSVID needs none.
func TestSIG015RealFulcioIssuesTheProbeACertificate(t *testing.T) {
	s := requireStack(t)
	p, err := New(Config{FulcioURL: s.fulcioURL, TrustDomain: "innsegl.dev", Mint: s.mint(Audience)})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Probe(t.Context())
	if !r.OK {
		t.Fatalf("the probe failed against a working Fulcio: %s", r.Reason)
	}
	t.Logf("measured: a certificate for the probe identity, chaining to Fulcio's root, at %s", r.At.Format(time.RFC3339))
}

// SIG-015 — a real Fulcio that will not issue is a failure that carries
// Fulcio's own words; and a certificate that does not chain to the trust
// root the probe holds (the CA signing under a key that is not the root's)
// is a failure that says so. The readiness state follows: failed, since the
// first failure.
func TestSIG015RealFulcioRefusalsAreFailuresWithTheReason(t *testing.T) {
	s := requireStack(t)

	refused, err := New(Config{FulcioURL: s.fulcioURL, TrustDomain: "innsegl.dev", Mint: s.mint("not-sigstore")})
	if err != nil {
		t.Fatal(err)
	}
	r := refused.Probe(t.Context())
	if r.OK || !strings.Contains(r.Reason, "the CA refused the certificate: HTTP ") {
		t.Fatalf("a token Fulcio must refuse: %+v", r)
	}
	t.Logf("measured refusal: %s", r.Reason)

	other := newTestCA(t, "not the trust root")
	pool := x509.NewCertPool()
	pool.AddCert(other.cert)
	drifted, err := New(Config{FulcioURL: s.fulcioURL, TrustDomain: "innsegl.dev", Mint: s.mint(Audience),
		Roots: func(context.Context) (*x509.CertPool, error) { return pool, nil }})
	if err != nil {
		t.Fatal(err)
	}
	m := NewMonitor(drifted, time.Minute, nil)
	first := m.Check(t.Context())
	if first.OK || !strings.Contains(first.Reason, "does not chain to the trust root") {
		t.Fatalf("a certificate under another root: %+v", first)
	}
	st := m.State()
	if st.OK || !strings.HasPrefix(st.Detail(), "FAILING since ") || !strings.Contains(st.Detail(), "trust root") {
		t.Fatalf("the readiness state after a failure: %+v %q", st, st.Detail())
	}
}

// SIG-015 — a Fulcio that is not answering is a failure naming the step.
// Last, because it stops this process's Fulcio.
func TestSIG015ZRealFulcioStoppedIsAFailure(t *testing.T) {
	s := requireStack(t)
	p, err := New(Config{FulcioURL: s.fulcioURL, TrustDomain: "innsegl.dev", Mint: s.mint(Audience)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.compose(t.Context(), s.sigFiles, "stop", "fulcio"); err != nil {
		t.Fatal(err)
	}
	if r := p.Probe(t.Context()); r.OK || !strings.Contains(r.Reason, "reading the trust root") {
		t.Fatalf("a stopped Fulcio: %+v", r)
	}
}
