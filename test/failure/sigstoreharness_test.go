// SPDX-License-Identifier: Apache-2.0

package failure

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
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
	"innsegl.dev/innsegl/internal/signing"
)

// A real SPIRE, a real self-hosted Sigstore and the released gitsign binary —
// so that TC-SIG's layer-F cases have something real to take away.
//
// # Why this harness exists beside two others
//
// internal/signing/sigstoreharness_test.go builds the same pair of stacks and
// is the right shape, but it is a _test.go file in package `signing`: not
// importable, by construction. test/failure/harness_test.go builds a SPIRE
// stack for SPI-006/SPI-007 and cannot be reused either, for a reason that is
// about configuration rather than about Go: it brings spire.yml up on its
// DEFAULT issuer, `https://oidc.innsegl.dev`, which ADR-0010 decided is never
// stood up. Fulcio performs OIDC discovery against the issuer named in the
// token, so a JWT-SVID minted by that server can buy no certificate from any
// Fulcio, and the `iss` claim is baked into the server's configuration at
// container start. The stack these cases need is therefore a different stack,
// not a subset of that one — and having its own also means SPI-006's SIGKILL
// of `spire-server` and SIG-002's `docker stop` of `fulcio` can never land on
// each other.
//
// # What is real here, and why every one of those is load bearing
//
// IP §2 draws the line in one sentence — "a mocked Fulcio proves nothing about
// I5" — and layer F is where the temptation to cross it is strongest, because
// a stub that returns an error is so much cheaper than an outage. It is also
// worthless: a test that injects its failure at the seam it is asserting about
// proves that our switch statement has the arm we wrote, and nothing about
// whether a commit object appears when a certificate authority goes away. So:
//
//   - Fulcio and Rekor are the shipped containers from deploy/compose/
//     sigstore.yml, and blocking one means STOPPING it (stopSigService), after
//     which the harness asserts the published port really refuses connections
//     before any case relies on the outage.
//   - Slow Sigstore is injected by a real HTTP proxy in front of a real,
//     healthy Fulcio or Rekor (sigFailProxy), which also counts the requests
//     that reach the wire. internal/segment's anchor test counts round trips in
//     an http.RoundTripper for exactly this reason: "the client tried N times"
//     has to be a measurement, not an inference from a duration.
//   - The credential is a JWT-SVID minted by a real SPIRE server, on the admin
//     socket, which is ADR-0019's `get_credential` path.
//   - The commit is made by the released `gitsign` through the shipped
//     internal/signing wrapper. Nothing in this package reimplements any part
//     of it.
//
// Without Docker or without gitsign every case skips, naming what went
// unproven. Nothing here passes without a real Sigstore.

const (
	// Protected strings (IP §1). Spelled out rather than derived, so a silent
	// change to deploy/compose/spire/server.conf fails these cases.
	sigTrustDomain = "innsegl.dev"

	// The issuer BOTH stacks must agree on. ADR-0029 decision 3: three files
	// read INNSEGL_SPIRE_JWT_ISSUER and Fulcio refuses every token when they
	// disagree — with a message that names neither the issuer nor the
	// mismatch, which is why it is pinned here rather than defaulted.
	sigIssuer = "http://spire-oidc:8080"

	// The gitsign release this suite pins, matching internal/signing's
	// harness. gitsign is used as a released upstream component (IP §7).
	sigGitsignVersion = "v0.17.1"

	sigSpireAdminSocket = "/run/spire/admin/api.sock"

	// The Sigstore endpoints these cases block, delay and count. Spelled out
	// rather than imported: internal/signing keeps them unexported, and a
	// harness that derived them from the code under test could not notice the
	// code changing which endpoint it probes.
	sigFulcioRootPath = "/api/v1/rootCert"
	sigRekorKeyPath   = "/api/v1/log/publicKey"
	sigRekorIndexPath = "/api/v1/index/retrieve"
	sigRekorEntryPath = "/api/v1/log/entries"
	// MEASURED against gitsign v0.17.1 in this stack: the certificate exchange
	// is one POST here, answered 201. Named so that SIG-003 can assert a
	// certificate was ISSUED during a Rekor outage rather than infer it.
	sigFulcioCertPath  = "/api/v1/signingCert"
	sigAuthorEmailAddr = "operator@innsegl.invalid"
	sigAuthorFullName  = "Innsegl Operator"
)

var (
	sigOnce   sync.Once
	sigShared *sigStack
	sigSkip   string
	sigSeq    atomic.Int64
)

// sigStack is one process's pair of compose projects: a SPIRE trio configured
// with an issuer Fulcio can reach, and the Sigstore stack that trusts it.
type sigStack struct {
	root       string
	project    string
	spireFiles []string
	sigFiles   []string
	env        []string

	// The published loopback endpoints. These are the addresses a case blocks
	// or proxies; nothing here reaches into a container network.
	fulcioURL string
	rekorURL  string
	oidcURL   string

	fulcioPort string
	rekorPort  string

	gitsignPath string
}

func sigStackPrefix() string { return fmt.Sprintf("innsegl-sigfail-%d", os.Getpid()) }

// findSigGitsign locates the released gitsign binary. It never builds one from
// source: IP §7 says Sigstore is used as a released upstream component.
func findSigGitsign(ctx context.Context) (string, error) {
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
		"`go install github.com/sigstore/gitsign@%s` or set INNSEGL_GITSIGN",
		sigGitsignVersion)
}

// sigCompose runs one docker compose command against one of this stack's two
// projects, with the per-process names in the environment.
func (s *sigStack) sigCompose(ctx context.Context, files []string, args ...string) (string, error) {
	full := []string{"compose", "-p", s.project}
	for _, f := range files {
		full = append(full, "-f", f)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	// Appended to os.Environ rather than replacing it: docker itself reads
	// DOCKER_HOST, HOME and the credential-helper variables from there.
	cmd.Env = append(os.Environ(), s.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func startSigStack(ctx context.Context, root string) (*sigStack, error) {
	gitsignPath, err := findSigGitsign(ctx)
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

	project := sigStackPrefix()
	s := &sigStack{
		root:    root,
		project: project,
		spireFiles: []string{
			filepath.Join(root, "deploy", "compose", "spire.yml"),
			filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		},
		sigFiles: []string{
			filepath.Join(root, "deploy", "compose", "sigstore.yml"),
			filepath.Join(root, "test", "failure", "sigstore-isolated.yml"),
		},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
			// ADR-0029 decision 2: Fulcio joins the network spire.yml declares
			// for the discovery provider. Per process, that is the renamed one.
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + sigIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
			"INNSEGL_REKOR_PORT=" + rekorPort,
		},
		fulcioURL:   "http://127.0.0.1:" + fulcioPort,
		rekorURL:    "http://127.0.0.1:" + rekorPort,
		oidcURL:     "http://127.0.0.1:" + oidcPort,
		fulcioPort:  fulcioPort,
		rekorPort:   rekorPort,
		gitsignPath: gitsignPath,
	}

	if _, err := s.sigCompose(ctx, s.spireFiles, "up", "-d", "--wait",
		"spire-server", "spire-agent", "spire-oidc"); err != nil {
		return s, fmt.Errorf("bringing up the SPIRE stack: %w", err)
	}
	if err := s.registerSigOIDCProvider(ctx); err != nil {
		return s, fmt.Errorf("registering the OIDC discovery provider: %w", err)
	}
	if _, err := s.sigCompose(ctx, s.sigFiles, "up", "-d"); err != nil {
		return s, fmt.Errorf("bringing up the Sigstore stack: %w", err)
	}
	if err := s.awaitSigTrustMaterial(ctx, 3*time.Minute); err != nil {
		return s, err
	}
	return s, nil
}

// registerSigOIDCProvider does what deploy/compose/spire/register.sh does, for
// a per-process stack.
//
// It is not optional and it is not setup noise. The discovery provider reads
// the trust domain's JWT keys through the WORKLOAD API (ADR-0011: it is the one
// SPIRE component with a public listener, so it is an ordinary attested
// workload rather than a holder of the admin socket). Until it has a
// registration entry it holds no SVID, `GET /keys` answers
//
//	HTTP 500  document not available
//
// and Fulcio then refuses every JWT-SVID with "There was an error processing
// the identity token" — an error that names neither the provider nor the
// missing entry, and which is INDISTINGUISHABLE from the message an expired
// token produces. RM-032 measured that and ADR-0031 recorded it; a
// failure-injection suite has to know it, because "Fulcio refused the token"
// is exactly what a mis-set-up harness looks like AND what SIG-002 is trying
// to cause on purpose.
//
// register.sh cannot be reused: it hardcodes the container name
// `innsegl-spire-oidc` and addresses `-f spire.yml` with no project, so it
// registers into whichever shared stack happens to be up. The selectors below
// are its five, derived from the running container the same way.
func (s *sigStack) registerSigOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://" + sigTrustDomain + "/innsegl/oidc-discovery-provider"
	container := s.project + "-spire-oidc"

	out, err := s.sigSpireServer(ctx, "agent", "list")
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
	dir, err := os.MkdirTemp("", "innsegl-sigfail-oidc-")
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

	if _, err := s.sigSpireServer(ctx, "entry", "create",
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
	return s.awaitSigJWKS(ctx)
}

// awaitSigJWKS waits for the provider to serve the trust domain's public JWT
// keys. Entries reach the agent through its cache, so this polls rather than
// sleeps.
func (s *sigStack) awaitSigJWKS(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := sigHarnessGET(ctx, s.oidcURL+"/keys")
		if err == nil && strings.Contains(string(body), `"keys"`) {
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

// sigSpireServer runs one spire-server CLI command on the admin socket.
func (s *sigStack) sigSpireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", sigSpireAdminSocket)
	return s.sigCompose(ctx, s.spireFiles, full...)
}

// ---------------------------------------------------------------------------
// Readiness, and its inverse.
// ---------------------------------------------------------------------------

// awaitSigTrustMaterial waits for ADR-0024's definition of "Sigstore is
// reachable": bytes that PARSE as the trust material, not a status code. A TCP
// dial or an unexamined 200 passes against any listening socket, including a
// proxy in front of a dead Fulcio — which is a distinction this suite cares
// about more than most, because it stands proxies in front of Fulcio on
// purpose.
//
// The probe is the harness's own and deliberately does not call the wrapper's.
// A readiness check written in production code would make every case depend on
// the thing it is meant to be testing, and would skip — silently green —
// whenever that code was broken.
func (s *sigStack) awaitSigTrustMaterial(ctx context.Context, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		last = s.probeSigTrustMaterial(ctx)
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

func (s *sigStack) probeSigTrustMaterial(ctx context.Context) error {
	if err := s.probeFulcio(ctx); err != nil {
		return err
	}
	return s.probeRekor(ctx)
}

// probeFulcio is ADR-0024's Fulcio half: a PEM CA certificate, parsed.
func (s *sigStack) probeFulcio(ctx context.Context) error {
	root, err := sigHarnessGET(ctx, s.fulcioURL+sigFulcioRootPath)
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("fulcio: %s is not a PEM certificate", sigFulcioRootPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("fulcio: %s does not parse: %w", sigFulcioRootPath, err)
	}
	if !cert.IsCA {
		return fmt.Errorf("fulcio: %s is not a CA certificate", sigFulcioRootPath)
	}
	return nil
}

// probeRekor is ADR-0024's Rekor half: a PKIX public key, parsed by
// internal/segment's own parser rather than by a second one written here.
func (s *sigStack) probeRekor(ctx context.Context) error {
	key, err := sigHarnessGET(ctx, s.rekorURL+sigRekorKeyPath)
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	if _, err := segment.ParseLogPublicKey(key); err != nil {
		return fmt.Errorf("rekor: %s does not parse: %w", sigRekorKeyPath, err)
	}
	return nil
}

// sigHarnessGET fetches one document, with no retry and no interpretation.
func sigHarnessGET(ctx context.Context, endpoint string) ([]byte, error) {
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

// ---------------------------------------------------------------------------
// Taking a dependency away, for real.
// ---------------------------------------------------------------------------

// stopSigService stops one shipped container and does not return until the
// published port genuinely refuses connections.
//
// The wait is the substance. `docker stop` returns when the container is gone,
// but a case that asserted an error before the port had actually closed would
// be asserting against a race, and a case that asserted one after the port
// closed for some OTHER reason would be asserting against nothing. So the
// outage is CONFIRMED before the test proceeds — the same discipline
// internal/ledger's LED-009 uses when it polls pg_locks until the writers it
// parked are provably waiting, rather than sleeping and hoping.
func (s *sigStack) stopSigService(t *testing.T, service, port string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := s.sigCompose(ctx, s.sigFiles, "stop", "--timeout", "20", service); err != nil {
		t.Fatalf("stopping %s: %v", service, err)
	}
	if !waitFor(60*time.Second, func() bool { return sigPortRefuses(port) }) {
		t.Fatalf("%s was stopped but 127.0.0.1:%s still accepts connections; "+
			"the outage this case depends on did not happen", service, port)
	}
}

// startSigService brings a stopped container back and waits for the trust
// material to parse again. Every case that stops something restores it, so the
// next case starts from a healthy stack rather than from the previous case's
// wreckage.
func (s *sigStack) startSigService(t *testing.T, service string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if _, err := s.sigCompose(ctx, s.sigFiles, "start", service); err != nil {
		t.Fatalf("starting %s: %v", service, err)
	}
	if err := s.awaitSigTrustMaterial(ctx, 3*time.Minute); err != nil {
		t.Fatalf("%s came back but Sigstore is not serving trust material: %v", service, err)
	}
}

// sigPortRefuses reports whether a loopback port refuses connections outright.
// A dial that succeeds — to anything — means the dependency is not blocked.
func sigPortRefuses(port string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+port)
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

func (s *sigStack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	// Always torn down, and both projects: this pair is this suite's own, and
	// leaving a stopped Fulcio behind would be leaving a trap for the next run.
	for _, files := range [][]string{s.sigFiles, s.spireFiles} {
		if _, err := s.sigCompose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Credentials — the ADR-0019 path get_credential uses.
// ---------------------------------------------------------------------------

// mintSigJWTSVID mints one audience-bound JWT-SVID through the SPIRE server's
// admin socket. Attestation is upstream of this, at register_agent, and is
// TC-SPI's subject.
func (s *sigStack) mintSigJWTSVID(ctx context.Context, spiffeID string, ttl time.Duration) (signing.Credential, error) {
	out, err := s.sigSpireServer(ctx, "jwt", "mint",
		"-spiffeID", spiffeID,
		"-audience", signing.AudienceSigstore,
		"-ttl", ttl.String(),
		"-output", "json")
	if err != nil {
		return signing.Credential{}, err
	}
	// The CLI prints a human note before the JSON when it caps the TTL.
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
	if got.SVID.Token == "" {
		return signing.Credential{}, fmt.Errorf("`jwt mint` returned no token: %s", out)
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

// sigCredential is a CredentialSource holding one real, minted token.
//
// It is not a fake Sigstore and fakes nothing about signing: the token it
// hands over was minted by the real SPIRE server in this stack, and Fulcio
// validates it against the real discovery provider. What stands in for
// `get_credential` is only the MCP wiring, which is RM-033's and not under
// test here.
type sigCredential struct {
	cred  signing.Credential
	calls atomic.Int64
}

func (c *sigCredential) Credential(context.Context) (signing.Credential, error) {
	c.calls.Add(1)
	return c.cred, nil
}

// ---------------------------------------------------------------------------
// The failure proxy — real latency in front of a real, healthy Sigstore.
// ---------------------------------------------------------------------------

// sigWireCall is one HTTP request that reached the network element in front of
// Sigstore. Recorded whether or not it was ever answered: "the client tried"
// is a fact about the wire, and a request the client abandoned mid-flight is
// still an attempt it made.
type sigWireCall struct {
	at     time.Time
	method string
	path   string
	// status is what the backend answered, or 0 when the client abandoned the
	// request before the proxy ever forwarded it. A 2xx here is the strongest
	// evidence this suite has that a dependency was genuinely REACHABLE: it is
	// not our inference from an error message, it is the byte the real service
	// put on the wire.
	status int
}

// sigFailProxy is an HTTP reverse proxy in front of one real Sigstore service.
//
// WHY A PROXY RATHER THAN A STUB. SIG-004's subject is "slow Sigstore", and a
// stub that sleeps and then returns an error tests the stub. This forwards
// every byte to the real Fulcio or the real Rekor and adds nothing but delay,
// so what the wrapper meets on the other side of the timeout is the genuine
// article: the real TLS-less HTTP framing, the real response bodies, the real
// certificate exchange. The only thing injected is time.
//
// WHY HTTP AND NOT TCP. test/failure/harness_test.go's countingProxy counts TCP
// connections, which is the right granularity for a gRPC channel that opens one
// per attempt. It is the wrong granularity here: Go's HTTP client keeps the
// connection alive, so five sequential POSTs to Rekor's search index are ONE
// TCP connection and five requests. Counting requests is what makes "bounded
// retries" measurable, and the path is what makes it possible to slow the
// wrapper's own lookup without also slowing gitsign's upload.
type sigFailProxy struct {
	ln  net.Listener
	srv *http.Server
	rp  *httputil.ReverseProxy
	// closed releases any request parked in an injected delay. Without it a
	// 120-second delay outlives the case that injected it: gitsign is a
	// GRANDCHILD of this process and survives the SIGKILL that
	// exec.CommandContext delivers to `git`, so its connection stays open and
	// http.Server.Shutdown waits for a handler that is sleeping for two
	// minutes. MEASURED as "shutting the failure proxy down: context deadline
	// exceeded" on the first run of the lock case.
	closed chan struct{}

	mu     sync.Mutex
	delay  time.Duration
	onPath string
	seen   []sigWireCall
}

func newSigFailProxy(t *testing.T, backend string) *sigFailProxy {
	t.Helper()
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatalf("parsing the proxy backend %q: %v", backend, err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the failure proxy: %v", err)
	}
	p := &sigFailProxy{
		ln:     ln,
		rp:     httputil.NewSingleHostReverseProxy(target),
		closed: make(chan struct{}),
	}
	// Silence: a client that walked away mid-request is the normal case here
	// and there is nobody to report it to.
	p.rp.ErrorLog = nopLogger()
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: nopLogger()}
	served := make(chan error, 1)
	go func() { served <- p.srv.Serve(ln) }()
	t.Cleanup(func() {
		close(p.closed)
		// Close, not Shutdown: Shutdown waits for handlers, and a handler
		// parked in an injected delay for a client that has already been
		// killed is exactly what these cases leave behind.
		if err := p.srv.Close(); err != nil {
			t.Errorf("closing the failure proxy: %v", err)
		}
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("the failure proxy stopped serving: %v", err)
		}
	})
	return p
}

func (p *sigFailProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.seen = append(p.seen, sigWireCall{at: time.Now(), method: r.Method, path: r.URL.Path})
	index := len(p.seen) - 1
	delay, onPath := p.delay, p.onPath
	p.mu.Unlock()

	if delay > 0 && (onPath == "" || strings.HasPrefix(r.URL.Path, onPath)) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			// The client gave up first, which is the whole point of the case.
			// The attempt is already recorded above, with status 0.
			return
		case <-p.closed:
			return
		}
	}
	rec := &sigStatusRecorder{ResponseWriter: w, status: http.StatusOK}
	p.rp.ServeHTTP(rec, r)
	p.mu.Lock()
	p.seen[index].status = rec.status
	p.mu.Unlock()
}

// sigStatusRecorder remembers the status the backend answered with.
type sigStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *sigStatusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (p *sigFailProxy) url() string { return "http://" + p.ln.Addr().String() }

// slow injects latency on every request whose path starts with prefix. An
// empty prefix slows everything.
func (p *sigFailProxy) slow(d time.Duration, prefix string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.delay, p.onPath = d, prefix
}

// describe renders every request seen, for a failure message that names what
// actually happened instead of what was expected.
func (p *sigFailProxy) describe() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	for _, c := range p.seen {
		fmt.Fprintf(&b, "\n    %s %s %s -> %d",
			c.at.Format("15:04:05.000"), c.method, c.path, c.status)
	}
	if b.Len() == 0 {
		return " (nothing reached the wire)"
	}
	return b.String()
}

// mark records how much has already reached the wire, so a case can count
// only what its own injection caused.
//
// The first version of SIG-004 counted from zero and reported SIX searches
// against a bound of five, because the healthy warm-up signature it needed in
// order to reach the retry loop at all had made one search of its own. A
// retry count that silently includes a successful earlier call is exactly the
// kind of number that looks like evidence and is not.
func (p *sigFailProxy) mark() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

// callsAfter returns every request to a path prefix that reached the wire
// after mark, in order.
func (p *sigFailProxy) callsAfter(mark int, prefix string) []sigWireCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []sigWireCall
	for i, c := range p.seen {
		if i >= mark && strings.HasPrefix(c.path, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// calls returns every request that reached the wire for a path prefix, in
// order.
func (p *sigFailProxy) calls(prefix string) []sigWireCall { return p.callsAfter(0, prefix) }

// gapsAfter returns the intervals between consecutive requests to a path
// prefix — the backoff, measured rather than assumed.
func (p *sigFailProxy) gapsAfter(mark int, prefix string) []time.Duration {
	calls := p.callsAfter(mark, prefix)
	var out []time.Duration
	for i := 1; i < len(calls); i++ {
		out = append(out, calls[i].at.Sub(calls[i-1].at))
	}
	return out
}

// nopLogger silences net/http's own logging of proxied requests the client
// abandoned mid-flight, which is the normal case in every SIG-004 arm.
func nopLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// ---------------------------------------------------------------------------
// Repositories, and what git plumbing says about them.
// ---------------------------------------------------------------------------

// newSigRepo makes a git repository with one staged file, ready to commit.
func newSigRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = sigGitEnv(dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"),
		[]byte("innsegl RM-034\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "work.txt")
	return dir
}

// sigGitEnv keeps the developer's ~/.gitconfig out of every git invocation the
// harness makes, for ADR-0028's reason: a repository whose configuration came
// partly from the machine is not the repository the assertion is about.
func sigGitEnv(dir string) []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "nonexistent-gitconfig"),
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
		"GIT_TERMINAL_PROMPT=0",
	)
}

// stageSigFile stages a change so a further commit has something to record.
func stageSigFile(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo, "add", name)
	cmd.Env = sigGitEnv(repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s: %v: %s", name, err, out)
	}
}

// sigGitOut runs one read-only git command in repo and returns its stdout.
func sigGitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = sigGitEnv(repo)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// sigCommitObjects returns every commit object the repository holds, ANYWHERE
// in the object database — reachable or not, referenced or not.
//
// This is IP §6.3's assertion, and the plumbing is not incidental to it.
// `git log` walks refs, so a commit object that exists but was never pointed
// at is invisible to it, and "the repo has no new commit object at all" would
// be satisfied by a signer that created a commit and then merely failed to
// move HEAD. `cat-file --batch-all-objects` enumerates the object database
// itself, so an orphaned commit is caught. The filter on `%(objecttype)` is
// deliberate too: `git add` writes blobs and `git commit` writes trees, and
// both may legitimately exist after a refused signature. What may not exist is
// a commit.
func sigCommitObjects(t *testing.T, repo string) []string {
	t.Helper()
	out := sigGitOut(t, repo, "cat-file", "--batch-all-objects",
		"--batch-check=%(objectname) %(objecttype)")
	var commits []string
	for _, line := range strings.Split(out, "\n") {
		name, kind, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && kind == "commit" {
			commits = append(commits, name)
		}
	}
	return commits
}

// sigHeadOr returns HEAD's commit, or fallback when the branch is unborn.
func sigHeadOr(t *testing.T, repo, fallback string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo, "rev-parse", "HEAD")
	cmd.Env = sigGitEnv(repo)
	out, err := cmd.Output()
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(out))
}

// sigIndexLock is the lock `git commit` holds while it builds the commit — and
// therefore while gitsign is talking to Fulcio and Rekor. IP §6.3: "No
// indefinite hangs holding repo locks."
func sigIndexLock(repo string) string { return filepath.Join(repo, ".git", "index.lock") }

// sigStaleLocks returns every `*.lock` file left inside .git.
//
// git's locking protocol is a file created with O_CREAT|O_EXCL beside the
// thing it protects — .git/index.lock for the index, refs/heads/main.lock for
// a branch — and released by renaming or unlinking it. A process killed while
// it holds one leaves the file behind, and every later writer refuses with
// "Unable to create ... File exists". So the whole of "did anything stay
// locked" is: is any of them still there.
func sigStaleLocks(t *testing.T, repo string) []string {
	t.Helper()
	var stale []string
	root := filepath.Join(repo, ".git")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".lock") {
			rel, rerr := filepath.Rel(repo, path)
			if rerr != nil {
				rel = path
			}
			stale = append(stale, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return stale
}

// sigIndexLockIsFree acquires the index lock the way git itself does —
// O_CREAT|O_EXCL — and releases it again.
//
// This is deliberately git's own protocol rather than an os.Stat: a stat is a
// question about a file, and the question that matters is whether the next
// writer can take the lock. It creates nothing that outlives the call, so it
// can be used in cases that are also asserting that the object database is
// unchanged.
func sigIndexLockIsFree(repo string) error {
	path := sigIndexLock(repo)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("the index lock cannot be taken: %w", err)
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return os.Remove(path)
}

// sigRepoAcceptsACommit is the operational form of "the lock was released":
// can somebody make an ordinary, unsigned commit in this repository right now?
//
// It MUTATES the repository — one new commit object — so it is used only where
// that is the last thing a case does, and never before an assertion about the
// object database.
func sigRepoAcceptsACommit(t *testing.T, repo string) error {
	t.Helper()
	stageSigFile(t, repo, "lock-probe.txt", "probe\n")
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo,
		"-c", "user.name="+sigAuthorFullName,
		"-c", "user.email="+sigAuthorEmailAddr,
		"commit", "--no-gpg-sign", "-q", "-m", "lock probe")
	cmd.Env = sigGitEnv(repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("an ordinary commit is refused: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Claims and configuration.
// ---------------------------------------------------------------------------

// newSigRunClaim returns a claim for a run unique to this test.
func newSigRunClaim(t *testing.T, taskID string) signing.Claim {
	t.Helper()
	runID := fmt.Sprintf("run-%d-%d", os.Getpid()%100000, sigSeq.Add(1))
	return signing.Claim{
		Identity: fmt.Sprintf("spiffe://%s/agent/demo/%s/%s", sigTrustDomain, taskID, runID),
		Run:      runID,
		Task:     taskID,
	}
}

// sigConfig is the wrapper's shipped configuration, pointed at this stack.
// Every case builds on it and changes only what it is injecting into.
func (s *sigStack) sigConfig() signing.Config {
	return signing.Config{
		FulcioURL:   s.fulcioURL,
		RekorURL:    s.rekorURL,
		Issuer:      sigIssuer,
		GitsignPath: s.gitsignPath,
		// ADR-0028 decision 6: a `.invalid` domain can never be delegated, so
		// no GitHub account can ever hold it and no contributor can appear (I6).
		Author: signing.AuthorPolicy{AllowUnlinked: true},
	}
}

func newSigSigner(t *testing.T, cfg signing.Config, src signing.CredentialSource) *signing.Signer {
	t.Helper()
	signer, err := signing.NewSigner(cfg, src)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() {
		if err := signer.Close(); err != nil {
			t.Errorf("Signer.Close: %v", err)
		}
	})
	return signer
}

// sigRequest is one commit to sign in repo, for claim.
func sigRequest(repo, message string, claim signing.Claim) signing.Request {
	return signing.Request{
		Repo:        repo,
		Message:     message,
		AuthorName:  sigAuthorFullName,
		AuthorEmail: sigAuthorEmailAddr,
		Claim:       claim,
	}
}

// ---------------------------------------------------------------------------
// Bring-up.
// ---------------------------------------------------------------------------

// requireSigStack starts the pair of stacks once and hands them to the caller,
// registering the teardown on the caller's own cleanup.
//
// The lifetime is the CALLER's, not the process's, and that is forced rather
// than chosen: TestMain belongs to test/failure/harness_test.go, which this
// issue does not own, so there is no process-exit hook to hang a `compose down`
// on. The consequence is recorded in ADR-0032 and shapes the suite above:
// TC-SIG's layer-F cases are subtests of one parent, which is also the natural
// shape for them, since they share one positive control.
func requireSigStack(t *testing.T) *sigStack {
	t.Helper()
	sigOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		wd, err := os.Getwd()
		if err != nil {
			sigSkip = err.Error()
			return
		}
		root := filepath.Dir(filepath.Dir(wd))
		if derr := dockerUsable(ctx); derr != nil {
			sigSkip = derr.Error()
			return
		}
		s, serr := startSigStack(ctx, root)
		if serr != nil {
			sigSkip = serr.Error()
			if s != nil {
				s.stop()
			}
			return
		}
		sigShared = s
	})
	if sigShared == nil {
		t.Skipf("skipping: no real SPIRE + Sigstore from deploy/compose/ and no gitsign (%s). "+
			"A failure-injection case with no dependency to remove proves nothing, and "+
			"IP §2 is explicit that \"a mocked Fulcio proves nothing about I5\". Start "+
			"Docker, `go install github.com/sigstore/gitsign@%s`, and re-run.",
			sigSkip, sigGitsignVersion)
	}
	t.Cleanup(func() {
		sigShared.stop()
		sigShared = nil
		sigOnce = sync.Once{}
	})
	return sigShared
}
