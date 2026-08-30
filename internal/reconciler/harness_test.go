// SPDX-License-Identifier: Apache-2.0

package reconciler_test

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

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/ledger"
)

// A real Postgres, a real SPIRE, a real self-hosted Fulcio and Rekor, and the
// released gitsign binary. Never a mock.
//
// IP §2 draws the line in one sentence — "a mocked Fulcio proves nothing about
// I5" — and REC-002 is where it bites hardest for this component. The claim is
// that a ledger which lost its Phase C append converges, under repair, to the
// state a run that never crashed reached. Every noun in that sentence has to be
// real or the case tests this package's agreement with its own fakes: a real
// commit object, a real Fulcio certificate carrying a real SPIFFE ID, a real
// Rekor entry, and a real hash chain in a real Postgres.
//
// The harness is not internal/signing's and not internal/mcp's. Both live in
// their packages' test files and cannot be imported, and ADR-0033 already
// recorded the cost of that: this is the FOURTH copy of the five-selector
// `spire-oidc` registration, and `deploy/compose/spire/register.sh` still
// hardcodes one container name and one project. It should be parameterised.
//
// Without Docker, or without a gitsign binary, the integration case SKIPS with
// a message naming what went unproven rather than passing quietly.

const (
	// Protected strings (IP §1), spelled out rather than derived so a silent
	// change to deploy/compose/spire/server.conf fails these cases.
	harnessTrustDomain = "innsegl.dev"
	// The issuer BOTH stacks must agree on (ADR-0029 decision 3).
	harnessIssuer  = "http://spire-oidc:8080"
	harnessGitsign = "v0.17.1"
	harnessAdmin   = "/run/spire/admin/api.sock"

	postgresImageDefault = "postgres:16"
	postgresUser         = "innsegl"
	postgresPassword     = "innsegl-test"
	postgresDB           = "innsegl"
)

var (
	sharedPG   *pgContainer
	dockerSkip string
	dbSeq      atomic.Int64
)

// ---------------------------------------------------------------------------
// Docker.
// ---------------------------------------------------------------------------

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

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return errors.New("INNSEGL_TEST_NO_DOCKER is set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return err
	}
	_, err := docker(ctx, "version", "--format", "{{.Server.Version}}")
	return err
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

// ---------------------------------------------------------------------------
// Postgres.
// ---------------------------------------------------------------------------

type pgContainer struct {
	id   string
	port string
}

func (c *pgContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, c.port, database)
}

func postgresImage() string {
	if v := os.Getenv("INNSEGL_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return postgresImageDefault
}

func startPG(ctx context.Context) (*pgContainer, error) {
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, err
	}
	id, err := docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		postgresImage(), "-c", "fsync=on")
	if err != nil {
		return nil, err
	}
	c := &pgContainer{id: id, port: port}
	if werr := c.waitReady(ctx, 90*time.Second); werr != nil {
		return nil, errors.Join(werr, c.remove())
	}
	return c, nil
}

func (c *pgContainer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pgx.Connect(attempt, c.dsn(postgresDB))
		if err == nil {
			err = conn.Ping(attempt)
			_ = conn.Close(attempt)
		}
		cancel()
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("postgres in %s never became ready: %w", c.id, last)
}

func (c *pgContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := docker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

// TestMain brings up the shared Postgres once for the whole package.
func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if err := dockerUsable(ctx); err != nil {
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		dockerSkip = fmt.Sprintf("could not start %s: %v", postgresImage(), err)
	} else {
		sharedPG = pg
	}
	cancel()

	code := m.Run()

	if sharedPG != nil {
		if err := sharedPG.remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing the postgres container: %v\n", err)
		}
	}
	os.Exit(code)
}

// freshStore creates an empty database, migrates it and opens a ledger on it.
// One database per test: ADR-0005 scopes a chain to a database.
func freshStore(t *testing.T) (*ledger.Store, string) {
	t.Helper()
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s). A hash chain in a map is not the "+
			"state REC-002 is a claim about.", dockerSkip)
	}
	name := fmt.Sprintf("rec_%d_%d", os.Getpid()%100000, dbSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, sharedPG.dsn(postgresDB))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, cerr := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); cerr != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database %s: %v", name, cerr)
	}
	_ = admin.Close(ctx)

	dsn := sharedPG.dsn(name)
	store, oerr := ledger.Open(ctx, dsn)
	if oerr != nil {
		t.Fatalf("ledger.Open: %v", oerr)
	}
	t.Cleanup(store.Close)
	if merr := store.Migrate(ctx); merr != nil {
		t.Fatalf("ledger.Migrate: %v", merr)
	}
	return store, dsn
}

// ---------------------------------------------------------------------------
// SPIRE and Sigstore, from deploy/compose/.
// ---------------------------------------------------------------------------

type stack struct {
	project     string
	spireFiles  []string
	sigFiles    []string
	env         []string
	fulcioURL   string
	rekorURL    string
	oidcURL     string
	gitsignPath string
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
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (s *stack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", harnessAdmin)
	return s.compose(ctx, s.spireFiles, full...)
}

// findGitsign locates the released binary. It never builds one: IP §7 uses
// Sigstore as a released upstream component.
func findGitsign(ctx context.Context) (string, error) {
	if p := os.Getenv("INNSEGL_GITSIGN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("INNSEGL_GITSIGN=%s: %w", p, err)
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
		"`go install github.com/sigstore/gitsign@%s` or set INNSEGL_GITSIGN", harnessGitsign)
}

// sigstoreOverlay finds the per-process Sigstore overlay. ADR-0031 records that
// the file starts beside its only caller and moves to deploy/compose/ the
// moment a second suite needs it; both places are looked in and neither is
// created here.
func sigstoreOverlay(root string) (string, error) {
	for _, candidate := range []string{
		filepath.Join(root, "deploy", "compose", "sigstore-testscope.yml"),
		filepath.Join(root, "internal", "signing", "testdata", "sigstore-testscope.yml"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("no sigstore-testscope.yml in deploy/compose/ or internal/signing/testdata/")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

func startStack(ctx context.Context, root string) (*stack, error) {
	gitsignPath, err := findGitsign(ctx)
	if err != nil {
		return nil, err
	}
	overlay, err := sigstoreOverlay(root)
	if err != nil {
		return nil, err
	}
	ports := make([]string, 3)
	for i := range ports {
		if ports[i], err = freeHostPort(ctx); err != nil {
			return nil, err
		}
	}
	oidcPort, fulcioPort, rekorPort := ports[0], ports[1], ports[2]

	// A compose project of this process's own (RM-065, #81): both compose
	// files pin a project name and a container_name per service, so every
	// process that brings one up would otherwise select the SAME stack.
	project := fmt.Sprintf("innsegl-recon-%d", os.Getpid())
	s := &stack{
		project: project,
		spireFiles: []string{
			filepath.Join(root, "deploy", "compose", "spire.yml"),
			filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		},
		sigFiles: []string{filepath.Join(root, "deploy", "compose", "sigstore.yml"), overlay},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
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

// registerOIDCProvider is deploy/compose/spire/register.sh's five selectors,
// derived from the running container, for a per-process stack. Without the
// entry the provider holds no SVID, GET /keys answers HTTP 500, and Fulcio
// refuses every token.
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
	dir, err := os.MkdirTemp("", "innsegl-recon-oidc-")
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
		body, err := httpGET(ctx, s.oidcURL+"/keys")
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

// awaitTrustMaterial waits for ADR-0024's definition of "Sigstore is
// reachable": bytes that PARSE, never a status code. It is the harness's own
// probe and not the production one, so a case cannot pass because the thing
// under test agrees with itself.
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
	return fmt.Errorf("Sigstore never served parseable trust material: %w", last)
}

func (s *stack) probeTrustMaterial(ctx context.Context) error {
	root, err := httpGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("fulcio: /api/v1/rootCert is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("fulcio: /api/v1/rootCert does not parse: %w", err)
	}
	if !cert.IsCA {
		return errors.New("fulcio: /api/v1/rootCert is not a CA certificate")
	}
	key, err := httpGET(ctx, s.rekorURL+"/api/v1/log/publicKey")
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	kb, _ := pem.Decode(key)
	if kb == nil {
		return errors.New("rekor: /api/v1/log/publicKey is not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(kb.Bytes); err != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", err)
	}
	return nil
}

func (s *stack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return body, nil
}

// rekorEntryOf reads one entry straight off the log, with the harness's own
// reader. The production reader agreeing with itself would prove nothing.
func rekorEntryOf(ctx context.Context, base, uuid string) (int64, error) {
	body, err := httpGET(ctx, base+"/api/v1/log/entries/"+uuid)
	if err != nil {
		return 0, err
	}
	var entries map[string]struct {
		LogIndex int64 `json:"logIndex"`
	}
	if jerr := json.Unmarshal(body, &entries); jerr != nil {
		return 0, jerr
	}
	entry, present := entries[uuid]
	if !present {
		return 0, fmt.Errorf("rekor returned no entry keyed %s: %s", uuid, body)
	}
	return entry.LogIndex, nil
}
