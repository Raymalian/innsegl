// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// A real object store with object lock, never a mock.
//
// SEG-005 asserts that a storage layer *refuses* a deletion. A mock cannot
// establish that: a fake that returns an error when asked to delete proves
// only that the fake was written to return an error. The refusal has to come
// from S3 object lock in a real server, reached over the real protocol, or the
// test is a tautology. It is the same reason doc 01 §2 forbids a mocked Fulcio
// in the signing path and RM-009 runs the ledger tests against a containerised
// Postgres.
//
// Without Docker these tests skip with a message naming what was not proven,
// rather than passing quietly. With Docker present and MinIO refusing to
// start, they FAIL — see errDependencyAbsent.

const (
	// defaultMinIOImage is pinned to a release tag rather than `latest`.
	// RM-009 pins Postgres by major version because it asserts behaviour that
	// has been stable for a decade. This is the opposite case: the whole
	// subject of SEG-005 is one server's object-lock enforcement, so the
	// version that enforcement was observed in is part of the evidence.
	defaultMinIOImage = "minio/minio:RELEASE.2025-09-07T16-13-09Z"

	minioRootUser     = "innsegl"
	minioRootPassword = "innsegl-test-secret"
)

var bucketSeq atomic.Int64

// ---------------------------------------------------------------------------
// #126: a failed dependency is not a skip.
//
// errDependencyAbsent marks the ONLY conditions under which skipping this
// package's WORM cases is honest: there is no Docker daemon, or
// INNSEGL_TEST_NO_DOCKER asks for none. Nothing else wraps it, and that
// distinction is the point.
//
// Everything else that can go wrong bringing MinIO up — a port that cannot be
// reserved, an image that will not resolve, an exhausted Docker address pool,
// a server that never becomes ready — happens on a machine that HAS Docker,
// and is a FAILURE. Reporting one as a skip turns it into a pass-shaped
// outcome: `go test` exits zero, the package reports ok, and SEG-005's
// deletion canary — the control that proves WORM refuses deletion — never
// asked. #101 fixed this in nine harnesses; this package was outside that
// issue's ownership and kept it until #126.
//
// Both branches are exercised by
// TestHAR010AnAbsentDependencyIsASkipAndAFaultIsAFailure.
// ---------------------------------------------------------------------------
var errDependencyAbsent = errors.New("a required dependency is absent")

// startupOutcome routes a start-up error to exactly one of two outcomes.
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

// harnessRequirement is what requireMinIO must do for the calling test.
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
// docker writes progress and diagnostics across several lines, and Go's test
// JSON stream emits each line as its own event, so in a summary only the first
// survives. The CI failure that prompted #101 read "Network ... Creating"
// while the line naming the fault never appeared; a `docker run` against an
// unresolvable tag reads "Unable to find image ... locally" while "failed to
// resolve reference" is on the line after it.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func minioImage() string {
	if v := os.Getenv("INNSEGL_TEST_MINIO_IMAGE"); v != "" {
		return v
	}
	return defaultMinIOImage
}

// dockerCmd runs one docker command and returns its trimmed stdout.
func dockerCmd(ctx context.Context, args ...string) (string, error) {
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

// dockerUsable reports whether a docker daemon is reachable. Its errors are
// the ONLY ones here wrapped as an absent dependency.
func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errDependencyAbsent)
	}
	if _, err := dockerCmd(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errDependencyAbsent)
	}
	return nil
}

// freeHostPort reserves an ephemeral port and hands it back.
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

// minioContainer is one containerised MinIO.
type minioContainer struct {
	id       string
	image    string
	endpoint string
}

// startMinIO launches MinIO on a fixed host port and waits until it serves.
//
// Every error it returns is a fault on a machine that has Docker; none of them
// wrap errDependencyAbsent.
//
// There is no TestMain here on purpose. internal/segment already re-executes
// its own test binary as a child process for the SEG-002 crash matrix
// (crash_test.go), and a TestMain that started a container would start one in
// every one of those children. A container per test function is slower and
// unambiguous.
func startMinIO(ctx context.Context) (*minioContainer, error) {
	image := minioImage()
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := dockerCmd(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":9000",
		"--env", "MINIO_ROOT_USER="+minioRootUser,
		"--env", "MINIO_ROOT_PASSWORD="+minioRootPassword,
		image, "server", "/data",
	)
	if err != nil {
		return nil, fmt.Errorf("starting %s: %w", image, err)
	}
	c := &minioContainer{id: id, image: image, endpoint: "127.0.0.1:" + port}
	if err := c.waitReady(ctx, 90*time.Second); err != nil {
		if rerr := c.remove(); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		return nil, err
	}
	return c, nil
}

// client returns a MinIO client for the container, as the root account.
func (c *minioContainer) client() (*minio.Client, error) {
	return minio.New(c.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(minioRootUser, minioRootPassword, ""),
		Secure: false,
	})
}

// waitReady polls until the server answers an authenticated request.
func (c *minioContainer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		cl, err := c.client()
		if err == nil {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, err = cl.ListBuckets(attempt)
			cancel()
		}
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("minio in %s never became ready: %w", c.id, last)
}

func (c *minioContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := dockerCmd(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

// requireMinIO hands the calling test a real object store, or ends the test
// the honest way: a skip when there is no Docker, a FAILURE when Docker is
// there and MinIO is not. It never lets a WORM test pass without a server, and
// never reports an infrastructure fault as a skip (#126).
func requireMinIO(t *testing.T) *minioContainer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var c *minioContainer
	skip, failure := startupOutcome(dockerUsable(ctx))
	if skip == "" && failure == "" {
		var err error
		c, err = startMinIO(ctx)
		skip, failure = startupOutcome(err)
	}

	switch harnessNeed(c != nil, skip, failure) {
	case harnessFailTest:
		t.Fatalf("the WORM harness's object store did not come up, and Docker is "+
			"present and working: %s\n\nThis is a FAILURE and not a skip (#126): an "+
			"infrastructure fault reported as a skip exits zero and reports ok while "+
			"SEG-005's deletion canary — the control that proves WORM refuses a "+
			"deletion — never asked.", failure)
	case harnessSkipTest:
		t.Skipf("skipping: no real object store (%s). "+
			"This test proves nothing about WORM without one; "+
			"start Docker, or set INNSEGL_TEST_MINIO_IMAGE, and re-run.", skip)
	case harnessProceed:
	}

	t.Cleanup(func() {
		if rerr := c.remove(); rerr != nil {
			t.Logf("warning: removing test container: %v", rerr)
		}
	})
	return c
}

// freshBucket makes an empty bucket, with object lock on or off as asked.
//
// `locked` false is not a degenerate case to be tidied away later: it is the
// misconfigured deployment SEG-005 exists to catch, and the canary is pointed
// at one on purpose to prove the check can fail.
func freshBucket(t *testing.T, c *minioContainer, locked bool) string {
	t.Helper()

	name := fmt.Sprintf("seg-%d-%d", os.Getpid()%100000, bucketSeq.Add(1))
	cl, err := c.client()
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := cl.MakeBucket(ctx, name, minio.MakeBucketOptions{ObjectLocking: locked}); err != nil {
		t.Fatalf("create bucket %s (object lock %v): %v", name, locked, err)
	}
	return name
}

// setBucketRetention gives a bucket the default retention rule a production
// bucket has (doc 05 §2), so the canary's window check is exercised against a
// rule the store actually holds rather than one a test asserted about.
func setBucketRetention(t *testing.T, c *minioContainer, bucket string, mode RetentionMode, days uint) {
	t.Helper()

	cl, err := c.client()
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	minioMode := minio.RetentionMode(mode)
	unit := minio.Days
	if err := cl.SetBucketObjectLockConfig(ctx, bucket, &minioMode, &days, &unit); err != nil {
		t.Fatalf("set the default retention on %s: %v", bucket, err)
	}
}

// ---------------------------------------------------------------------------
// HAR-010 — #126. Both branches of the routing rule, exercised.
//
// #101 fixed nine harnesses and eleven secondary gates; this package was
// outside that issue's ownership and kept the defect. A routing rule nothing
// exercises is a routing rule nobody has checked, which is how the shape
// survived in nine harnesses at once. This case pins the two outcomes apart:
// an ABSENT dependency is a skip, and anything else is a failure that says so.
//
// It covers BOTH of this package's container gates — the WORM harness here and
// the Rekor harness in rekorharness_test.go — because a second gate nobody
// looked at is exactly how the first one survived.
// ---------------------------------------------------------------------------

func TestHAR010AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
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

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine, and the shape the CI
		// run in #101 produced: Docker is present, working, and refuses to
		// create the network because its address pools are used up.
		err := fmt.Errorf("could not start the WORM harness's minio: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, errDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errDependencyAbsent; it would " +
				"be reported as a skip and SEG-005's deletion canary would silently not run")
		}
		skip, failure := startupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("an image that does not exist is a failure", func(t *testing.T) {
		// The shape #126 was reported against, and the one the fix is
		// demonstrated with: Docker is present and the container did not start.
		err := fmt.Errorf("starting %s: %w: %s", "minio/minio:NO-SUCH-TAG",
			errors.New("exit status 125"),
			"docker: Error response from daemon: failed to resolve reference: not found")
		if errors.Is(err, errDependencyAbsent) {
			t.Fatal("an unresolvable image wraps errDependencyAbsent; it would be reported " +
				"as a skip and the package would report ok having proved nothing about WORM")
		}
		if _, failure := startupOutcome(err); failure == "" {
			t.Fatalf("startupOutcome(%v) routed an unresolvable image somewhere other than a failure", err)
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

	// The package's second container gate. requireRekor already fails rather
	// than skipping when the stack will not come up, and this pins that so it
	// cannot quietly regress to the shape #126 was filed about.
	t.Run("the rekor gate routes the same way", func(t *testing.T) {
		t.Run("no docker is a skip", func(t *testing.T) {
			t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
			err := rekorDockerUsable(t.Context())
			if err == nil {
				t.Fatal("rekorDockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
			}
			if !errors.Is(err, errRekorDockerAbsent) {
				t.Fatalf("%v does not wrap errRekorDockerAbsent, so a developer with no "+
					"Docker could not run this package", err)
			}
		})

		t.Run("a stack that did not come up is a failure", func(t *testing.T) {
			for _, err := range []error{
				fmt.Errorf("create network: %w", errors.New("Error response from daemon: "+
					"could not find an available, non-overlapping IPv4 address pool")),
				fmt.Errorf("start rekor: %w", errors.New("exit status 125")),
				fmt.Errorf("rekor never became ready: %w", errors.New("GET /api/v1/log: 500")),
			} {
				if errors.Is(err, errRekorDockerAbsent) {
					t.Errorf("%v wraps errRekorDockerAbsent; requireRekor would skip and "+
						"SEG-003 would silently not run", err)
				}
			}
		})
	})

	// #101's readability fix: docker writes progress across several lines and
	// only the first survives the test JSON stream, so the line naming the
	// fault has to be folded onto it.
	t.Run("a multi-line docker error is collapsed onto one line", func(t *testing.T) {
		raw := "Unable to find image 'minio/minio:NO-SUCH-TAG' locally\n" +
			"docker: Error response from daemon: failed to resolve reference\n\n" +
			"Run 'docker run --help' for more information.\n"
		got := oneLine(raw)
		if strings.Contains(got, "\n") {
			t.Fatalf("oneLine left a newline in %q", got)
		}
		if !strings.Contains(got, "failed to resolve reference") {
			t.Fatalf("oneLine dropped the line naming the fault: %q", got)
		}
	})
}
