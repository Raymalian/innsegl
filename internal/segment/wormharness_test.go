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
// rather than passing quietly.

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

var (
	bucketSeq        atomic.Int64
	errDockerMissing = errors.New("docker is not available")
)

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
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// dockerUsable reports whether a docker daemon is reachable.
func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDockerMissing)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errDockerMissing, err)
	}
	if _, err := dockerCmd(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errDockerMissing, err)
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
		return nil, err
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

// requireMinIO starts a MinIO for the calling test, or skips it with a message
// naming what went unproven. It never lets a WORM test pass without a server.
func requireMinIO(t *testing.T) *minioContainer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping: no real object store (%v). "+
			"This test proves nothing about WORM without one; "+
			"start Docker, or set INNSEGL_TEST_MINIO_IMAGE, and re-run.", err)
	}
	c, err := startMinIO(ctx)
	if err != nil {
		t.Skipf("skipping: could not start %s: %v. "+
			"This test proves nothing about WORM without a real object store.",
			minioImage(), err)
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
