// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ---------------------------------------------------------------------------
// A real object store, never a mock — the harness OPS-025/026/027/030 measure
// the shipped object-store provisioning against.
//
// It is harness_test.go's ledger harness in the other medium, and for the same
// stated reasons: the scripts that run are the SHIPPED scripts at the paths
// deploy/compose/innsegl.yml mounts them, the container publishes on loopback
// and creates no docker network of its own (#100), and #101's outcome shape is
// kept — an ABSENT dependency is a skip, a dependency that is present and
// BROKE is a failure, and they never share a variable.
//
// A refusal is the thing being measured here, and a mock that returns an error
// when asked to set a bucket configuration proves only that the mock was
// written to return an error. The refusal has to come from a real server's own
// authorization, over the real protocol.
//
// THE STORE RUNS AS ONE CONTAINER HERE AND AS THREE IN THE DEPLOYMENT, and
// saying which difference that is matters. The deployment splits the S3
// gateway from the Filer because the Filer is a second door to the same bytes
// with no lock on it, and that split is about REACHABILITY — it is measured by
// OPS-029, against the compose file, where networks exist. What these cases
// measure is AUTHORIZATION, which is the gateway's alone: the same binary, the
// same identity file, the same bucket. One container costs three fewer on a
// machine #100 already has arithmetic about, and gives up nothing these cases
// look at. The Filer's HTTP port is not published here either way.
//
// THE SCRIPTS RUN IN TWO IMAGES because the deployment runs them in two: the
// identity file is written inside the store's own image by the one-shot that
// has no network, and the bucket init runs in the reference S3 client. The
// client container joins the store container's network namespace rather than a
// docker network of its own, which is #100's constraint met exactly.
// ---------------------------------------------------------------------------

const (
	// storeRootUser and storeRootPassword are the store's ROOT account: the
	// credential the compose file gives the server and the one-time init, and
	// the credential nothing long-running may hold. The tests below hand it to
	// object-init.sh and then never use it again except as the control that
	// proves a refusal is the scope.
	storeRootUser     = "innsegl"
	storeRootPassword = "innsegl-deploy-test-objects"

	// storeSegmentPrefix is deploy/compose/innsegl.yml's x-object-store-prefix
	// default. It is the prefix the scoped identity's write grant is scoped to,
	// so a case that wrote outside it would be measuring the wrong refusal.
	storeSegmentPrefix = "segments/"

	// composeJWTIssuer is the value deploy/compose/innsegl.yml requires before
	// it will interpolate at all. `config` reads no secrets and starts
	// nothing; this is the compose default the file's own error message names.
	composeJWTIssuer = "http://spire-oidc:8080"

	// storeIdentitiesFile is where the shipped one-shot writes the gateway's
	// identity file and where the gateway is told to read it, both taken from
	// deploy/compose/innsegl.yml's x-s3-identities-file anchor.
	storeIdentitiesFile = "/run/innsegl/s3/identities.json"
)

// shippedImagePin lifts an image out of the compose file rather than repeating
// it here.
//
// internal/segment pins its store literally and says why: "the whole subject of
// SEG-005 is one server's object-lock enforcement, so the version that
// enforcement was observed in is part of the evidence". The same argument
// applies to one server's AUTHORIZATION, and it applies harder — an action a
// server does not recognise is silently no rule at all. So this harness does
// not pin a second version: it measures the version the reference deployment
// runs, and a bump to the compose file moves this with it.
func shippedImagePin(t *testing.T, root, anchor string) string {
	t.Helper()
	body := readFile(t, root+"/deploy/compose/innsegl.yml")
	re := regexp.MustCompile(`(?m)^x-` + anchor + `:\s*&` + anchor + `\s*\r?\n\s*(\S+)\s*$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("deploy/compose/innsegl.yml no longer declares `x-%s: &%s` over a pinned "+
			"reference. This harness measures the object store the reference deployment "+
			"actually runs; pinning a second version here would let the two drift.", anchor, anchor)
	}
	return m[1]
}

func shippedObjectStoreImage(t *testing.T, root string) string {
	return shippedImagePin(t, root, "object-store-image")
}

func shippedS3ClientImage(t *testing.T, root string) string {
	return shippedImagePin(t, root, "s3-client-image")
}

// objectStoreContainer is one containerised object store carrying one test's
// bucket.
type objectStoreContainer struct {
	name     string
	endpoint string // host:port on loopback
	bucket   string
	client   string // the reference S3 client image, for the init one-shots
	root     string // the repository, whose deploy/compose/innsegl is mounted in
}

// startObjectStore launches the shipped store on a loopback port and waits
// until it answers an authenticated request.
//
// THE IDENTITY FILE IS WRITTEN BY THE SHIPPED SCRIPT, not by this harness.
// That is the whole reason the container is created, staged and then started
// rather than run in one call: this store has NO DEFAULT CREDENTIALS, so a
// gateway started without a config refuses every signed request with a message
// about authentication that arrives at the caller as AccessDenied on a write —
// which is exactly what object lock working looks like from the outside. A
// harness that provisioned its own identities could pass while the shipped
// s3-identities.sh produced a file the server would not accept.
//
// Every error it returns is a fault on a machine that has Docker; only
// dockerUsable's wrap an absent dependency.
func startObjectStore(ctx context.Context, t *testing.T, bucket string) (*objectStoreContainer, error) {
	t.Helper()
	if err := dockerUsable(ctx); err != nil {
		return nil, err
	}
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserving a host port: %w", err)
	}
	name := fmt.Sprintf("innsegl-deploy-obj-%d-%s", os.Getpid(), bucket)
	// A previous run that was killed rather than torn down leaves the name
	// taken; removing it is not an error worth reporting.
	discardError(docker(ctx, "rm", "--force", "--volumes", name))

	root := repoRoot(t)
	c := &objectStoreContainer{
		name: name, endpoint: "127.0.0.1:" + port, bucket: bucket,
		client: shippedS3ClientImage(t, root), root: root,
	}

	if _, err := docker(ctx, "create",
		"--name", name,
		"--publish", "127.0.0.1:"+port+":8333",
		// THE SHIPPED SCRIPTS AT THE PATH THE COMPOSE FILE MOUNTS THEM, and
		// mounted the way the compose file mounts them. What this test runs
		// must be the artifact an adopter runs, not a copy of it.
		"--volume", root+"/deploy/compose/innsegl:/innsegl/init:ro",
		"--env", "INNSEGL_S3_IDENTITIES_FILE="+storeIdentitiesFile,
		"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_BUCKET="+bucket,
		"--env", "INNSEGL_OBJECT_STORE_PREFIX="+storeSegmentPrefix,
		"--entrypoint", "sh",
		shippedObjectStoreImage(t, root), "-c",
		// The shipped one-shot, then the server, in the order the compose
		// stack runs them: nothing may answer a signed request before the
		// identity file exists.
		"/innsegl/init/s3-identities.sh && exec weed server -dir=/data -volume.max=100 -s3 "+
			"-s3.config="+storeIdentitiesFile+" -s3.port=8333 -s3.iam=false "+
			"-s3.port.iceberg=0 -s3.port.lance=0",
	); err != nil {
		return nil, fmt.Errorf("creating the object store container: %w", err)
	}
	if _, err := docker(ctx, "start", name); err != nil {
		return nil, fmt.Errorf("starting the object store: %w", err)
	}

	if err := waitForObjectStore(ctx, c); err != nil {
		logs, _ := docker(ctx, "logs", "--tail", "40", name) //nolint:errcheck // a best-effort diagnostic on a path that is already failing
		c.stop()
		// THIS STORE SHIPS NO DEFAULT CREDENTIALS, so "never answered" has one
		// failure mode that reads like a different problem entirely: without
		// an identity file every signed request is refused for want of
		// authentication. The logs are attached rather than summarised.
		return nil, fmt.Errorf("the object store never answered an authenticated request: %w\n%s", err, logs)
	}
	return c, nil
}

func (c *objectStoreContainer) stop() {
	if c == nil || c.name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	discardError(docker(ctx, "rm", "--force", "--volumes", c.name))
}

// clientAs is a client for this store under one identity. Every test below
// asks the same server the same question under two identities, which is the
// only way a refusal says anything about the scope.
func (c *objectStoreContainer) clientAs(access, secret string) (*minio.Client, error) {
	return minio.New(c.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(access, secret, ""),
		Secure: false,
	})
}

// runObjectInit runs the shipped object-store init with the environment
// deploy/compose/innsegl.yml gives it, and returns its combined output.
//
// IT RUNS IN THE REFERENCE S3 CLIENT, which is the image the compose file runs
// it in, and it joins the STORE CONTAINER'S NETWORK NAMESPACE rather than a
// docker network of its own — so `http://127.0.0.1:8333` is the store, and the
// harness still creates zero networks (#100).
//
// NOTHING SCOPED IS PASSED BY DEFAULT. That is the case an existing operator
// is in: they set a root credential once and never heard of #228. If the
// scoped credential has to be configured before the stack works, the change is
// not deployable, so the default path is the path under test.
func (c *objectStoreContainer) runObjectInit(ctx context.Context, extra ...string) (string, error) {
	return c.runObjectInitOn(ctx, "container:"+c.name, extra...)
}

// runObjectInitOn is runObjectInit against a named docker network, for the one
// case that has real networks to place the client on.
func (c *objectStoreContainer) runObjectInitOn(ctx context.Context, network string, extra ...string) (string, error) {
	args := []string{"run", "--rm",
		"--network", network,
		"--volume", c.root + "/deploy/compose/innsegl:/innsegl/init:ro",
		"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY=" + storeRootUser,
		"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY=" + storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_URL=http://127.0.0.1:8333",
		"--env", "INNSEGL_OBJECT_STORE_BUCKET=" + c.bucket,
		"--env", "INNSEGL_OBJECT_STORE_PREFIX=" + storeSegmentPrefix,
		"--env", "INNSEGL_OBJECT_LOCK_RETENTION=1d",
		"--env", "INNSEGL_OBJECT_STORE_RETENTION_MODE=COMPLIANCE",
	}
	args = append(args, extra...)
	args = append(args, "--entrypoint", "sh", c.client, "/innsegl/init/object-init.sh")

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// requireObjectStore hands the calling test a provisioned store, or ends the
// test the honest way (#101).
func requireObjectStore(ctx context.Context, t *testing.T, id, bucket string) *objectStoreContainer {
	t.Helper()

	store, err := startObjectStore(ctx, t, bucket)
	skip, failure := startupOutcome(err)
	if store != nil {
		t.Cleanup(store.stop)
	}
	switch containerRequirement(store != nil, skip, failure) {
	case failTest:
		t.Fatalf("the object store did not start on a machine that has Docker: %s\n\n"+
			"This is a FAILURE and not a skip (#101). %s measures an authorization "+
			"refusal, and reporting a broken dependency as a skip exits zero while "+
			"nothing asked the server anything.", failure, id)
	case skipTest:
		t.Skipf("skipping %s: %s. The scope of the store credential is measured against "+
			"a real object store — a mocked refusal proves only that the mock was written "+
			"to refuse. Start Docker and re-run.", id, skip)
	case proceed:
	}

	out, initErr := store.runObjectInit(ctx)
	t.Logf("--- deploy/compose/innsegl/object-init.sh ---\n%s", out)
	if initErr != nil {
		t.Fatalf("object-init.sh failed: %v", initErr)
	}
	return store
}

// ---------------------------------------------------------------------------
// The compose file's own answer to "which credential does this service hold?"
//
// Read by interpolating the shipped file rather than by matching its text. The
// defect RM-144 is about is not a misspelling, it is an ANCHOR that resolves to
// the root account, and a text match would have read the anchor's name and been
// satisfied. `docker compose config` resolves it the way the daemon does.
// ---------------------------------------------------------------------------

type interpolatedService struct {
	Environment map[string]*string `json:"environment"`
	Image       string             `json:"image"`
	Command     []string           `json:"command"`
	// Networks is a map of network name to its per-service options; the
	// options are never read, only the membership, which is the access-control
	// list doc 05 §1 asks for.
	Networks map[string]any `json:"networks"`
}

// networkNames is one service's membership, sorted, as the compose file
// resolves it.
func (s interpolatedService) networkNames() []string {
	names := make([]string, 0, len(s.Networks))
	for n := range s.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

type composeConfig struct {
	Services map[string]interpolatedService `json:"services"`
}

// service returns one interpolated service, failing the test if the shipped
// compose file no longer declares it.
func (c composeConfig) service(t *testing.T, name string) interpolatedService {
	t.Helper()
	s, ok := c.Services[name]
	if !ok {
		t.Fatalf("deploy/compose/innsegl.yml no longer declares a %q service", name)
	}
	return s
}

// env returns one service's value for a variable, and whether it sets it.
func (c composeConfig) env(service, key string) (string, bool) {
	s, ok := c.Services[service]
	if !ok {
		return "", false
	}
	v, ok := s.Environment[key]
	if !ok || v == nil {
		return "", false
	}
	return *v, true
}

// composeUsable reports whether `docker compose` can interpolate a file. It
// contacts no daemon, so it is a lighter requirement than dockerUsable, and
// its error is an absent dependency.
func composeUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errDependencyAbsent)
	}
	if _, err := docker(ctx, "compose", "version", "--short"); err != nil {
		return fmt.Errorf("no usable docker compose: %w: %w", err, errDependencyAbsent)
	}
	return nil
}

// interpolateCompose resolves the shipped compose files the way the daemon
// composeParentIDPlaceholder stands in for the attested node id. It is never
// dialled: interpolation needs a value, not a real parent.
const composeParentIDPlaceholder = "spiffe://innsegl.dev/spire/agent/placeholder/interpolation-only"

// would, with the object store's root credential as the deployment's, and
// returns what every service would actually be handed.
func interpolateCompose(ctx context.Context, t *testing.T, bucket string, files ...string) composeConfig {
	t.Helper()
	root := repoRoot(t)

	args := []string{"compose", "--profile", "canary"}
	for _, rel := range files {
		args = append(args, "-f", root+"/"+rel)
	}
	args = append(args, "config", "--format", "json")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(),
		"INNSEGL_SPIRE_JWT_ISSUER="+composeJWTIssuer,
		"INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"INNSEGL_OBJECT_STORE_BUCKET="+bucket,
		// The attested node id, which register.sh writes into
		// deploy/compose/.env when a stack is brought up. This reads the
		// CREDENTIAL WIRING out of the compose file and never starts SPIRE, so
		// the value is irrelevant and only its presence matters — but the file
		// refuses to interpolate without it, and that file does not exist on a
		// machine that has never run the stack. Which is every CI runner:
		// these tests passed locally and failed in CI for exactly this.
		"INNSEGL_SPIRE_PARENT_ID="+composeParentIDPlaceholder,
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("interpolating %v: %v: %s", files, err, strings.TrimSpace(stderr.String()))
	}

	var cfg composeConfig
	if jerr := json.Unmarshal(out, &cfg); jerr != nil {
		t.Fatalf("reading the interpolated compose configuration: %v", jerr)
	}
	return cfg
}
