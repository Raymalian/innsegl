// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// A real SPIRE, a real self-hosted Sigstore, and a real gitsign, for #134
// (RM-089): `spireSignVerifier.Run` and `createVerificationCommit` in
// initsign.go are the ONE part of `innsegl init` #117 exists to guarantee —
// "Setup is not finished because files were written; it is finished because
// the chain held" — and until this file, no test measured it. IP §2: "a
// mocked Fulcio proves nothing about I5."
//
// internal/signing/sigstoreharness_test.go is the model this harness is
// built from, combined with internal/mcp's admin-proxy-over-socat (to reach
// spire.Dial's admin gRPC API from the host process, which internal/signing's
// own harness never needs to do) and test/smoke's PEM-file admin credential
// (to exercise initsign.go's own "bootstrapping a trust domain" branch of
// openInitCredentialSource, which is exactly this test's situation: there is
// no attested innsegl-init workload for the Workload API to hand a credential
// to). ADR-0022 calls the three existing copies of this shape a cost it
// accepted rather than a mistake, and says a fourth means extracting an
// internal test-support package. That extraction is out of this issue's
// scope (internal/signing/** and internal/spire/** are read-only per #134's
// instructions), so a fourth copy is what this is, named as a known
// trade-off rather than silently absorbed.
//
// # Why this harness is OPT-IN and every other one in this repository is not
//
// Every other container harness here runs automatically whenever Docker is
// reachable. This one does not, and that is a deliberate departure from the
// house style, for one reason: #100 measured this machine's Docker address
// pool ceiling at roughly 29 networks, and a combined SPIRE+Sigstore stack —
// spire-testscope.yml's three networks plus sigstore-testscope.yml's five —
// costs eight of them per run, the same eight
// internal/signing's own SIG-* suite already spends. #134 is explicit that
// several suites already hold eight each and that agents run containers in
// parallel on this machine; standing up an eighth network cost unconditionally,
// inside `go test ./cmd/innsegl/...`, on every invocation, for every
// developer and every CI job from now on, is how the ceiling gets hit by
// someone doing unrelated work. So this suite is gated behind
// INNSEGL_RUN_INIT_E2E: unset, it costs nothing and touches no container;
// set, it is meant to run ALONE (INNSEGL_TEST_FLAGS="-p 1", per #134's own
// hazard note), not folded into the default matrix.
//
// This is the "make the test schedulable" branch #134 offers, chosen over
// "reuse an existing stack" because cmd/innsegl has no existing SPIRE or
// Sigstore stack to reuse (confirmed: apiharness_test.go's own harness is a
// bare postgres:16 container, unrelated), and because ADR-0022 already
// rejected sharing one compose stack across processes/packages as the source
// of RM-018's and RM-065's false accusations — a shared stack was the
// mechanism that produced those bugs, not a workaround for this one.
const (
	signE2EEnv = "INNSEGL_RUN_INIT_E2E"

	// Protected strings (IP §1), spelled out rather than derived — same
	// reasoning as every other harness here: a silent change to
	// deploy/compose/spire/server.conf should fail this test, not agree with
	// it silently.
	signE2ETrustDomain = "innsegl.dev"
	// signE2EAdminID is the ONLY SPIFFE ID deploy/compose/spire/server.conf's
	// admin_ids authorizes. It is not a special "init" identity: in the
	// deployment, `innsegl init`'s own admin credential is resolved exactly
	// like `innsegl serve`'s (openInitCredentialSource mirrors
	// servewiring.go's openCredentialSource), so bootstrapping under the same
	// admin ID every other harness mints is the right impersonation, not a
	// shortcut.
	signE2EAdminID  = "spiffe://" + signE2ETrustDomain + "/innsegl/mcp"
	signE2EServerID = "spiffe://" + signE2ETrustDomain + "/spire/server"

	// signE2EIssuer is the OIDC issuer BOTH stacks must agree on (ADR-0029
	// decision 3): three files read INNSEGL_SPIRE_JWT_ISSUER and Fulcio
	// refuses every token if they disagree. `spire-oidc` is the service name
	// on the shared network — a compose-managed DNS alias present regardless
	// of this process's project prefix.
	signE2EIssuer = "http://spire-oidc:8080"

	// signE2EGitsignVersion is the release this suite pins, matching
	// internal/signing's own harness and initsign.go's defaultGitsignVersion.
	signE2EGitsignVersion = "v0.17.1"

	signE2EAdminSocket = "/run/spire/admin/api.sock"
	signE2EProxyImage  = "alpine/socat:1.8.0.3"
)

// errSignE2EDependencyAbsent marks the only conditions under which skipping
// this suite is honest: no Docker daemon, or no gitsign binary. Everything
// else — an image that will not pull, a network Docker refuses to create
// because the address pool is exhausted, a container that never becomes
// healthy — is a FAILURE (#101): reporting it as a skip is how a suite exits
// zero, reports ok, and proves nothing.
var errSignE2EDependencyAbsent = errors.New("a required dependency is absent")

// signE2EStackPrefix names this process's stack and everything in it,
// following ADR-0022 exactly: innsegl-<suite>test-<pid>, distinct from
// innsegl-spiretest-*, innsegl-mcptest-*, innsegl-signtest-* and
// innsegl-failure-*, so this suite cannot collide with any of them even if
// it were ever run alongside them by mistake.
func signE2EStackPrefix() string {
	return fmt.Sprintf("innsegl-inittest-%d", os.Getpid())
}

// signE2EStack is this process's SPIRE+Sigstore stack plus the admin proxy
// and minted credential files that let spireSignVerifier.Run — running in
// THIS process, on the host — reach the SPIRE admin API and Fulcio/Rekor.
type signE2EStack struct {
	project    string
	spireFiles []string
	sigFiles   []string
	env        []string

	fulcioURL, rekorURL, oidcURL string
	gitsignPath                  string

	adminNetwork, proxyName, adminAddr string

	// svidPath, keyPath and bundlePath are the three PEM files initsign.go's
	// openInitCredentialSource loads when SVIDFile is set — the
	// "bootstrapping a trust domain" branch, since there is no attested
	// innsegl-init workload here for the Workload API to answer.
	svidPath, keyPath, bundlePath string
	credDir                       string
}

func (s *signE2EStack) compose(ctx context.Context, files []string, args ...string) (string, error) {
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
			strings.Join(full, " "), err, signE2EOneLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// spireServer runs one spire-server CLI command on the local, unauthenticated
// admin socket inside the container — the same operator path ADR-0011
// documents, and the same one every other harness in this repository mints
// its own admin credential through.
func (s *signE2EStack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", signE2EAdminSocket)
	return s.compose(ctx, s.spireFiles, full...)
}

// signE2EOneLine collapses a multi-line subprocess error into one line — #101's
// own diagnostic lesson: `docker compose`'s progress lines on stderr can bury
// the actual fault under "Network ... Creating".
func signE2EOneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func signE2EDockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errSignE2EDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errSignE2EDependencyAbsent)
	}
	if _, err := dockerCLI(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errSignE2EDependencyAbsent)
	}
	return nil
}

// signE2EFindGitsign locates the released gitsign binary. Never built from
// source (IP §7: Sigstore is a released upstream component).
func signE2EFindGitsign(ctx context.Context) (string, error) {
	if p := os.Getenv("INNSEGL_GITSIGN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("INNSEGL_GITSIGN=%s: %w: %w", p, err, errSignE2EDependencyAbsent)
		}
		return p, nil
	}
	if p, err := exec.LookPath("gitsign"); err == nil {
		return p, nil
	}
	out, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(strings.TrimSpace(string(out)), "bin", "gitsign")
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no gitsign binary; install the pinned release with "+
		"`go install github.com/sigstore/gitsign@%s` or set INNSEGL_GITSIGN: %w",
		signE2EGitsignVersion, errSignE2EDependencyAbsent)
}

// registerOIDCProvider is deploy/compose/spire/register.sh's job, redone for
// a per-process stack under a project name register.sh does not know. Not
// optional: Fulcio refuses every JWT-SVID with "There was an error
// processing the identity token" until the discovery provider holds a
// registration entry and can serve /keys.
func (s *signE2EStack) registerOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://" + signE2ETrustDomain + "/innsegl/oidc-discovery-provider"
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

	imageConfigDigest, err := dockerCLI(ctx, "inspect", "--format", "{{.Image}}", container)
	if err != nil {
		return err
	}
	imageRef, err := dockerCLI(ctx, "inspect", "--format", "{{.Config.Image}}", container)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "innsegl-init-e2e-oidc-bin-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary := filepath.Join(dir, "oidc")
	if _, cpErr := dockerCLI(ctx, "cp", container+":/opt/spire/bin/oidc-discovery-provider", binary); cpErr != nil {
		return cpErr
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

func (s *signE2EStack) awaitJWKS(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := signE2EHTTPGet(ctx, s.oidcURL+"/keys")
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

// awaitTrustMaterial waits for bytes that PARSE as Fulcio's root certificate
// and Rekor's log key, not merely a 200 — a TCP dial or an unexamined status
// code passes against any listener, including a proxy in front of a dead
// Fulcio.
func (s *signE2EStack) awaitTrustMaterial(ctx context.Context) error {
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

func (s *signE2EStack) probeTrustMaterial(ctx context.Context) error {
	root, err := signE2EHTTPGet(ctx, s.fulcioURL+"/api/v1/rootCert")
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
	key, err := signE2EHTTPGet(ctx, s.rekorURL+"/api/v1/log/publicKey")
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, err := segment.ParseLogPublicKey(key); err != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", err)
	}
	return nil
}

func signE2EHTTPGet(ctx context.Context, url string) ([]byte, error) {
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

// mintAdminCredential writes the admin X509-SVID, its key and the trust
// bundle as three PEM files — initsign.go's own "bootstrapping a trust
// domain" branch (openInitCredentialSource, req.SVIDFile != ""), the one a
// fresh `innsegl init` uses on a deployment before init itself is an attested
// workload. `spire-server x509 mint` prints all three under fixed headings.
func (s *signE2EStack) mintAdminCredential(ctx context.Context) error {
	out, err := s.spireServer(ctx, "x509", "mint", "-spiffeID", signE2EAdminID, "-ttl", "1h")
	if err != nil {
		return fmt.Errorf("minting the admin X509-SVID: %w", err)
	}
	dir, err := os.MkdirTemp("", "innsegl-init-e2e-cred-")
	if err != nil {
		return err
	}
	s.credDir = dir

	sections := map[string]string{
		"svid.pem":   signE2ESection(out, "X509-SVID:", "Private key:"),
		"key.pem":    signE2ESection(out, "Private key:", "Root CAs:"),
		"bundle.pem": signE2ESection(out, "Root CAs:", ""),
	}
	paths := make(map[string]string, len(sections))
	for name, body := range sections {
		if !strings.Contains(body, "-----BEGIN") {
			return fmt.Errorf("`x509 mint` produced no %s:\n%s", name, out)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
		paths[name] = p
	}
	s.svidPath, s.keyPath, s.bundlePath = paths["svid.pem"], paths["key.pem"], paths["bundle.pem"]
	return nil
}

// signE2ESection returns the lines strictly between two headings in
// `x509 mint`'s output. An empty `until` runs to the end. The container is
// distroless and has no shell to split the three sections with, so this does
// it in the test process instead (copying test/smoke's sectionOf, which
// cannot be imported across packages).
func signE2ESection(text, from, until string) string {
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

// startSignE2EStack brings up the combined SPIRE+Sigstore stack and the admin
// proxy, and mints the admin credential files. It is the ONLY entry point:
// unset INNSEGL_RUN_INIT_E2E skips before touching Docker at all; an absent
// Docker or gitsign skips with a named reason; anything else is a FAILURE
// (#101) — Docker present and working and the stack still not coming up is
// not the same fact as "no Docker", and conflating them is how a suite
// reports ok while nothing ran.
func startSignE2EStack(ctx context.Context, t *testing.T) *signE2EStack {
	t.Helper()

	if os.Getenv(signE2EEnv) == "" {
		t.Skipf("skipping: %s is not set. This test drives `innsegl init`'s signing path "+
			"against a real containerised SPIRE+Fulcio+Rekor stack, costing roughly eight "+
			"Docker networks (matching internal/signing's own harness) for the run. #100/#134: "+
			"this machine's Docker address-pool ceiling is roughly 29 and several suites already "+
			"hold eight each, so this suite does not run inside the default `go test ./...` or CI "+
			"matrix. Set %s=1 and run this package ALONE (INNSEGL_TEST_FLAGS=\"-p 1\") to opt in.",
			signE2EEnv, signE2EEnv)
	}

	if err := signE2EDockerUsable(ctx); err != nil {
		if errors.Is(err, errSignE2EDependencyAbsent) {
			t.Skipf("skipping: %v", err)
		}
		t.Fatalf("docker is present and not working (FAILURE, not a skip — #101): %v", err)
	}
	gitsignPath, err := signE2EFindGitsign(ctx)
	if err != nil {
		if errors.Is(err, errSignE2EDependencyAbsent) {
			t.Skipf("skipping: %v", err)
		}
		t.Fatalf("%v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	oidcPort, err := apiFreeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserving a host port: %v", err)
	}
	fulcioPort, err := apiFreeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserving a host port: %v", err)
	}
	rekorPort, err := apiFreeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserving a host port: %v", err)
	}
	adminPort, err := apiFreeHostPort(ctx)
	if err != nil {
		t.Fatalf("reserving a host port: %v", err)
	}

	project := signE2EStackPrefix()
	s := &signE2EStack{
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
			"INNSEGL_SPIRE_JWT_ISSUER=" + signE2EIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
			"INNSEGL_REKOR_PORT=" + rekorPort,
		},
		fulcioURL:    "http://127.0.0.1:" + fulcioPort,
		rekorURL:     "http://127.0.0.1:" + rekorPort,
		oidcURL:      "http://127.0.0.1:" + oidcPort,
		gitsignPath:  gitsignPath,
		adminNetwork: project + "-spire-admin",
		proxyName:    project + "-adminproxy",
		adminAddr:    "127.0.0.1:" + adminPort,
	}
	// Registered before anything is brought up, so a partial failure at any
	// step below still tears down whatever did start. stop() is unconditional
	// (INNSEGL_TEST_KEEP_STACK aside): this project is this process's own.
	t.Cleanup(s.stop)

	if _, err := s.compose(ctx, s.spireFiles, "up", "-d", "--wait",
		"spire-server", "spire-agent", "spire-oidc"); err != nil {
		t.Fatalf("bringing up the SPIRE stack (Docker present and working — FAILURE, not a "+
			"skip, #101): %v", err)
	}

	if _, err := dockerCLI(ctx, "run", "--detach", "--name", s.proxyName,
		"--publish", "127.0.0.1:"+adminPort+":8081",
		signE2EProxyImage, "TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081"); err != nil {
		t.Fatalf("starting the admin proxy: %v", err)
	}
	// ADR-0011: the admin network is internal, no published port, whose only
	// member the deployment names is innsegl-mcp. Joining the proxy to it is
	// this test process standing in for exactly that membership so spire.Dial
	// (called by spireSignVerifier.Run, in this same process) has a route at
	// all — a Docker Desktop VM gives the host no route to a container
	// address by itself.
	if _, err := dockerCLI(ctx, "network", "connect", s.adminNetwork, s.proxyName); err != nil {
		t.Fatalf("joining the admin proxy to %s: %v", s.adminNetwork, err)
	}

	if err := s.mintAdminCredential(ctx); err != nil {
		t.Fatalf("minting the admin credential: %v", err)
	}

	if err := s.registerOIDCProvider(ctx); err != nil {
		t.Fatalf("registering the OIDC discovery provider: %v", err)
	}

	if _, err := s.compose(ctx, s.sigFiles, "up", "-d"); err != nil {
		t.Fatalf("bringing up the Sigstore stack: %v", err)
	}
	if err := s.awaitTrustMaterial(ctx); err != nil {
		t.Fatalf("Sigstore never served parseable trust material: %v", err)
	}

	return s
}

func (s *signE2EStack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	if s.proxyName != "" {
		if _, err := dockerCLI(ctx, "rm", "--force", s.proxyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.proxyName, err)
		}
	}
	for _, files := range [][]string{s.sigFiles, s.spireFiles} {
		if len(files) == 0 {
			continue
		}
		if _, err := s.compose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
	if s.credDir != "" {
		if err := os.RemoveAll(s.credDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.credDir, err)
		}
	}
}
