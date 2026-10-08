// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"innsegl.dev/innsegl/internal/dockertest"
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
// rather than passing quietly. With Docker present and the object store
// refusing to start, they FAIL — see dockertest.ErrDependencyAbsent.

const (
	// defaultObjectStoreImage is pinned to a release digest rather than
	// `latest`. RM-009 pins Postgres by major version because it asserts
	// behaviour that has been stable for a decade. This is the opposite case:
	// the whole subject of SEG-005 is one server's object-lock enforcement, so
	// the version that enforcement was observed in is part of the evidence.
	//
	// The store itself changed in RM-143 (#227). The previous one was archived
	// upstream and delisted from the registry this file pulled it from, so the
	// pin stopped resolving at all. The replacement below was measured against
	// SEG-005 under the same configuration — the same buckets, compliance and
	// governance modes, the same canary — and that measurement is what this
	// version is pinned on.
	defaultObjectStoreImage = "chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"

	storeRootUser     = "innsegl"
	storeRootPassword = "innsegl-test-secret"

	// storeIdentities is the S3 identity file this harness's store is started
	// with. The store has no default account, so without this file there is no
	// credential that can do anything at all (see startObjectStore).
	//
	// The grant is deliberately whole-server admin. SEG-005 measures a refusal
	// by OBJECT LOCK, and a refusal for want of permission is the same
	// AccessDenied on the wire; the canary's own anti-vacuity guard — it
	// permanently deletes a version before it will call a refusal a refusal —
	// can only run if these credentials really could delete. Scoping an
	// identity down is a separate property of the shipped deployment, measured
	// against the shipped identity file in test/deploy; an under-privileged
	// identity here would manufacture a pass.
	storeIdentities = `{"identities":[{"name":"innsegl","credentials":[` +
		`{"accessKey":"` + storeRootUser + `","secretKey":"` + storeRootPassword + `"}],` +
		`"actions":["Admin","Read","Write","List","Tagging"]}]}`
)

var bucketSeq atomic.Int64

func objectStoreImage() string {
	if v := os.Getenv("INNSEGL_TEST_OBJECT_STORE_IMAGE"); v != "" {
		return v
	}
	return defaultObjectStoreImage
}

// objectStoreContainer is one containerised object store.
type objectStoreContainer struct {
	id       string
	image    string
	endpoint string
}

// startObjectStore launches the object store on a fixed host port and waits
// until it serves.
//
// THIS STORE SHIPS NO DEFAULT CREDENTIALS, and that is the trap here. Started
// without an identity file it refuses every signed request with "Signed
// request requires setting up SeaweedFS S3 authentication", which arrives at
// the caller as AccessDenied on a write — indistinguishable from object lock
// working. A harness that omitted the identity file would see SEG-005 report
// the same refusals while measuring authentication, not the lock. So the file
// is written into the container before the server is exec'd, and waitReady
// will not let a test start until a signed request has been answered.
//
// ONE CONTAINER HERE, THREE IN THE REFERENCE DEPLOYMENT (a store, a Filer and
// an S3 gateway across two networks), and which difference that is matters.
// What this package measures is the GATEWAY's object-lock enforcement, which
// is the gateway's alone: the same binary, the same identity file, the same
// bucket. The split is about REACHABILITY of the Filer's own API — a second
// door to the same bytes with no lock on it — and that is measured by OPS-029
// in test/deploy against the compose file, where networks exist. The Filer's
// port is not published here either way.
//
// Every error it returns is a fault on a machine that has Docker; none of them
// wrap dockertest.ErrDependencyAbsent.
//
// There is no TestMain here on purpose. internal/segment already re-executes
// its own test binary as a child process for the SEG-002 crash matrix
// (crash_test.go), and a TestMain that started a container would start one in
// every one of those children. A container per test function is slower and
// unambiguous.
func startObjectStore(ctx context.Context) (*objectStoreContainer, error) {
	image := objectStoreImage()
	port, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	// The identity file is written and then the server replaces the shell, so
	// nothing can answer a signed request before the credentials exist.
	//
	// THREE LISTENERS ARE TURNED OFF: -s3.iam=false is an IAM API served on
	// the S3 port itself, -s3.port.iceberg=0 an Iceberg REST catalog and
	// -s3.port.lance=0 a Lance namespace server. None of them is part of
	// storing a sealed segment, and each is an authenticated write surface on
	// a service whose entire job here is refusing writes to sealed objects.
	id, err := dockertest.Docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":8333",
		"--env", "INNSEGL_S3_IDENTITIES="+storeIdentities,
		"--entrypoint", "sh",
		image, "-c",
		"printf %s \"$INNSEGL_S3_IDENTITIES\" > /tmp/s3-identities.json && "+
			// -volume.max: EACH BUCKET IS A COLLECTION AND A NEW COLLECTION
			// IMMEDIATELY RESERVES SEVEN VOLUMES. The store's default cap is
			// EIGHT, so the second bucket in one container gets one volume and
			// the third gets none — and a write with nowhere to go comes back as
			// HTTP 500 "We encountered an internal error, please try again",
			// which in this package reads exactly like object lock refusing a
			// write. Measured. Volumes are sparse (eight of them were 256 KiB on
			// disk), so the cap is raised rather than the buckets reused.
			"exec weed server -dir=/data -volume.max=100 -s3 -s3.config=/tmp/s3-identities.json "+
			"-s3.port=8333 -s3.iam=false -s3.port.iceberg=0 -s3.port.lance=0",
	)
	if err != nil {
		return nil, fmt.Errorf("starting %s: %w", image, err)
	}
	c := &objectStoreContainer{id: id, image: image, endpoint: "127.0.0.1:" + port}
	if err := c.waitReady(ctx, 90*time.Second); err != nil {
		if rerr := c.remove(); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		return nil, err
	}
	return c, nil
}

// client returns an S3 client for the container, as the account declared in
// storeIdentities.
func (c *objectStoreContainer) client() (*minio.Client, error) {
	return minio.New(c.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(storeRootUser, storeRootPassword, ""),
		Secure: false,
	})
}

// waitReady polls until the server answers an authenticated request.
//
// Authenticated on purpose: an unauthenticated health probe would go green on
// a store that has no credentials at all, which is the state every later
// refusal would then be misread from.
func (c *objectStoreContainer) waitReady(ctx context.Context, timeout time.Duration) error {
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
	return fmt.Errorf("the object store in %s never became ready: %w", c.id, last)
}

func (c *objectStoreContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := dockertest.Docker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

// requireObjectStore hands the calling test a real object store, or ends the
// test the honest way: a skip when there is no Docker, a FAILURE when Docker is
// there and the store is not. It never lets a WORM test pass without a server,
// and never reports an infrastructure fault as a skip (#126).
func requireObjectStore(t *testing.T) *objectStoreContainer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var c *objectStoreContainer
	skip, failure := dockertest.StartupOutcome(dockertest.Usable(ctx))
	if skip == "" && failure == "" {
		var err error
		c, err = startObjectStore(ctx)
		skip, failure = dockertest.StartupOutcome(err)
	}

	switch dockertest.Need(c != nil, skip, failure) {
	case dockertest.FailTest:
		t.Fatalf("the WORM harness's object store did not come up, and Docker is "+
			"present and working: %s\n\nThis is a FAILURE and not a skip (#126): an "+
			"infrastructure fault reported as a skip exits zero and reports ok while "+
			"SEG-005's deletion canary — the control that proves WORM refuses a "+
			"deletion — never asked.", failure)
	case dockertest.SkipTest:
		t.Skipf("skipping: no real object store (%s). "+
			"This test proves nothing about WORM without one; "+
			"start Docker, or set INNSEGL_TEST_OBJECT_STORE_IMAGE, and re-run.", skip)
	case dockertest.Proceed:
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
func freshBucket(t *testing.T, c *objectStoreContainer, locked bool) string {
	t.Helper()

	name := fmt.Sprintf("seg-%d-%d", os.Getpid()%100000, bucketSeq.Add(1))
	cl, err := c.client()
	if err != nil {
		t.Fatalf("object store client: %v", err)
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
func setBucketRetention(t *testing.T, c *objectStoreContainer, bucket string, mode RetentionMode, days uint) {
	t.Helper()

	cl, err := c.client()
	if err != nil {
		t.Fatalf("object store client: %v", err)
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
		err := dockertest.Usable(t.Context())
		if err == nil {
			t.Fatal("dockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, dockertest.ErrDependencyAbsent) {
			t.Fatalf("%v does not wrap dockertest.ErrDependencyAbsent, so it would be routed to a "+
				"FAILURE and a developer with no Docker could not run this package", err)
		}
		skip, failure := dockertest.StartupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine, and the shape the CI
		// run in #101 produced: Docker is present, working, and refuses to
		// create the network because its address pools are used up.
		err := fmt.Errorf("could not start the WORM harness's object store: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, dockertest.ErrDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps dockertest.ErrDependencyAbsent; it would " +
				"be reported as a skip and SEG-005's deletion canary would silently not run")
		}
		skip, failure := dockertest.StartupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("an image that does not exist is a failure", func(t *testing.T) {
		// The shape #126 was reported against, and the one the fix is
		// demonstrated with: Docker is present and the container did not start.
		err := fmt.Errorf("starting %s: %w: %s", "chrislusf/seaweedfs:NO-SUCH-TAG",
			errors.New("exit status 125"),
			"docker: Error response from daemon: failed to resolve reference: not found")
		if errors.Is(err, dockertest.ErrDependencyAbsent) {
			t.Fatal("an unresolvable image wraps dockertest.ErrDependencyAbsent; it would be reported " +
				"as a skip and the package would report ok having proved nothing about WORM")
		}
		if _, failure := dockertest.StartupOutcome(err); failure == "" {
			t.Fatalf("startupOutcome(%v) routed an unresolvable image somewhere other than a failure", err)
		}
	})

	t.Run("a healthy start-up is neither", func(t *testing.T) {
		if skip, failure := dockertest.StartupOutcome(nil); skip != "" || failure != "" {
			t.Fatalf("startupOutcome(nil) = (%q, %q), want both empty", skip, failure)
		}
	})

	t.Run("a failure outranks a skip", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			up            bool
			skip, failure string
			want          dockertest.Requirement
		}{
			{"a failure outranks everything", false, "no docker", "boom", dockertest.FailTest},
			{"nothing up and no failure is a skip", false, "no docker", "", dockertest.SkipTest},
			{"a live dependency proceeds", true, "", "", dockertest.Proceed},
		} {
			if got := dockertest.Need(tc.up, tc.skip, tc.failure); got != tc.want {
				t.Errorf("%s: dockertest.Need(%v, %q, %q) = %d, want %d",
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
		raw := "Unable to find image 'chrislusf/seaweedfs:NO-SUCH-TAG' locally\n" +
			"docker: Error response from daemon: failed to resolve reference\n\n" +
			"Run 'docker run --help' for more information.\n"
		got := dockertest.OneLine(raw)
		if strings.Contains(got, "\n") {
			t.Fatalf("oneLine left a newline in %q", got)
		}
		if !strings.Contains(got, "failed to resolve reference") {
			t.Fatalf("oneLine dropped the line naming the fault: %q", got)
		}
	})
}
