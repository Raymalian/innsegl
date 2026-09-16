// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ---------------------------------------------------------------------------
// A real object store, never a mock — the harness OPS-025/026/027 measure the
// shipped object-store provisioning against.
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
// THE SCRIPTS RUN INSIDE THE MinIO SERVER CONTAINER, not in a second container
// running the mc image. The server image carries mc at the same release the
// compose file pins for the client image (measured: both are mc
// RELEASE.2025-08-13T08-35-41Z), and it carries the same minimal userland —
// a shell, `printf`, `cut`, `tr`, and no sed, grep or awk, which is the
// constraint object-init.sh is already written against. So the script under
// test meets the same tool set it meets in the deployment, and the harness
// costs one container and zero networks instead of two containers and one.
// ---------------------------------------------------------------------------

const (
	// storeRootUser and storeRootPassword are the store's ROOT account: the
	// credential the compose file gives the server and the one-time init, and
	// the credential nothing long-running may hold. The tests below hand it to
	// object-init.sh and then never use it again except as the control that
	// proves a refusal is the scope.
	storeRootUser     = "innsegl"
	storeRootPassword = "innsegl-deploy-test-objects"

	// composeJWTIssuer is the value deploy/compose/innsegl.yml requires before
	// it will interpolate at all. `config` reads no secrets and starts
	// nothing; this is the compose default the file's own error message names.
	composeJWTIssuer = "http://spire-oidc:8080"
)

// shippedMinIOImagePin lifts the object store's image out of the compose file
// rather than repeating it here.
//
// internal/segment pins its MinIO literally and says why: "the whole subject
// of SEG-005 is one server's object-lock enforcement, so the version that
// enforcement was observed in is part of the evidence". The same argument
// applies to one server's AUTHORIZATION, and it applies harder — a policy
// action a server does not recognise is silently no policy at all. So this
// harness does not pin a second version: it measures the version the reference
// deployment runs, and a bump to the compose file moves this with it.
var shippedMinIOImagePin = regexp.MustCompile(`(?m)^x-minio-image:\s*&minio-image\s*\r?\n\s*(\S+)\s*$`)

func shippedMinIOImage(t *testing.T, root string) string {
	t.Helper()
	body := readFile(t, root+"/deploy/compose/innsegl.yml")
	m := shippedMinIOImagePin.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("deploy/compose/innsegl.yml no longer declares `x-minio-image: &minio-image` " +
			"over a pinned reference. This harness measures the object store the reference " +
			"deployment actually runs; pinning a second version here would let the two drift.")
	}
	return m[1]
}

// objectStoreContainer is one containerised MinIO carrying one test's bucket.
type objectStoreContainer struct {
	name     string
	endpoint string // host:port on loopback
	bucket   string
}

// startObjectStore launches the shipped MinIO on a loopback port and waits
// until it answers an authenticated request.
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

	if _, err := docker(ctx, "run", "--detach",
		"--name", name,
		"--publish", "127.0.0.1:"+port+":9000",
		"--env", "MINIO_ROOT_USER="+storeRootUser,
		"--env", "MINIO_ROOT_PASSWORD="+storeRootPassword,
		shippedMinIOImage(t, repoRoot(t)), "server", "/data",
	); err != nil {
		return nil, fmt.Errorf("starting the object store: %w", err)
	}
	c := &objectStoreContainer{name: name, endpoint: "127.0.0.1:" + port, bucket: bucket}

	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		cl, cerr := c.clientAs(storeRootUser, storeRootPassword)
		if cerr == nil {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, cerr = cl.ListBuckets(attempt)
			cancel()
		}
		if cerr == nil {
			return c, nil
		}
		last = cerr
		select {
		case <-ctx.Done():
			c.stop()
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	c.stop()
	return nil, fmt.Errorf("the object store never answered: %w", last)
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

// stageDeployScripts puts the SHIPPED init scripts into the container at the
// path deploy/compose/innsegl.yml mounts them.
//
// The path matches the compose file on purpose, for harness_test.go's reason:
// what this test runs must be the artifact an adopter runs, not a second
// arrangement of the same files.
func (c *objectStoreContainer) stageDeployScripts(ctx context.Context, root string) error {
	if _, err := docker(ctx, "exec", c.name, "mkdir", "-p", "/innsegl/init"); err != nil {
		return err
	}
	if _, err := docker(ctx, "cp", root+"/deploy/compose/innsegl/.", c.name+":/innsegl/init"); err != nil {
		return fmt.Errorf("copying the shipped init scripts into the container: %w", err)
	}
	return nil
}

// runObjectInit runs the shipped object-store init inside the container with
// the environment deploy/compose/innsegl.yml gives it, and returns its
// combined output.
//
// NOTHING SCOPED IS PASSED BY DEFAULT. That is the case an existing operator
// is in: they set a root credential once and never heard of this issue. If the
// scoped credential has to be configured before the stack works, the change is
// not deployable, so the default path is the path under test.
func (c *objectStoreContainer) runObjectInit(ctx context.Context, extra ...string) (string, error) {
	args := []string{"exec",
		"--env", "MINIO_ROOT_USER=" + storeRootUser,
		"--env", "MINIO_ROOT_PASSWORD=" + storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_URL=http://127.0.0.1:9000",
		"--env", "INNSEGL_OBJECT_STORE_BUCKET=" + c.bucket,
		"--env", "INNSEGL_OBJECT_LOCK_RETENTION=1d",
		"--env", "INNSEGL_OBJECT_STORE_RETENTION_MODE=COMPLIANCE",
	}
	args = append(args, extra...)
	args = append(args, c.name, "sh", "/innsegl/init/object-init.sh")

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

	root := repoRoot(t)
	if stageErr := store.stageDeployScripts(ctx, root); stageErr != nil {
		t.Fatalf("staging the shipped deploy scripts: %v", stageErr)
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
}

type composeConfig struct {
	Services map[string]interpolatedService `json:"services"`
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
