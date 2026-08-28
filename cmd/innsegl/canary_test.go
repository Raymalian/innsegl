// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

	"innsegl.dev/innsegl/internal/segment"
)

// The command's contract is its exit status, so that is what is asserted.
// IP §6.4: "deployment fails if deletion succeeds". A deploy step and a cron
// job both consult the same number, and there is no outcome in which a
// permitted deletion exits zero.

// passingReport is a report in which every check the canary defines has held.
// It is built from segment.CanaryCheckNames() rather than a literal list so
// that a check added to the canary cannot quietly stop being required here.
func passingReport() *segment.CanaryReport {
	r := &segment.CanaryReport{Bucket: "bucket", Endpoint: "store:9000"}
	for _, name := range segment.CanaryCheckNames() {
		r.Checks = append(r.Checks, segment.CanaryCheck{Name: name, Passed: true, Detail: "held"})
	}
	return r
}

// failingReport is the same report with one check turned over — the shape a
// bucket without object lock produces.
func failingReport() *segment.CanaryReport {
	r := passingReport()
	for i := range r.Checks {
		if r.Checks[i].Name == segment.CheckVersionDeleteRefused {
			r.Checks[i] = segment.CanaryCheck{
				Name:   segment.CheckVersionDeleteRefused,
				Passed: false,
				Detail: "the object was deleted",
			}
		}
	}
	return r
}

func minimalCanaryArgs(extra ...string) []string {
	return append([]string{
		"-endpoint", "store:9000",
		"-bucket", "segments",
		"-access-key", "key",
		"-secret-key", "secret",
	}, extra...)
}

func TestCanaryExitStatusIsTheGate(t *testing.T) {
	errOpen := errors.New("dial: connection refused")
	errRun := errors.New("the canary could not write a probe")

	for _, tc := range []struct {
		name string
		deps canaryDeps
		want int
	}{
		{
			name: "every check held",
			deps: canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
				run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
					return passingReport(), nil
				},
			},
			want: exitOK,
		},
		{
			name: "a check failed",
			deps: canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
				run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
					return failingReport(), nil
				},
			},
			want: exitCanaryFailed,
		},
		{
			name: "the store could not be opened",
			deps: canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return nil, errOpen },
			},
			want: exitCanaryInconclusive,
		},
		{
			name: "the canary could not run",
			deps: canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
				run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
					return nil, errRun
				},
			},
			want: exitCanaryInconclusive,
		},
		{
			// Nothing may turn an absent report into a pass.
			name: "no report and no error",
			deps: canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
				run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
					return nil, nil
				},
			},
			want: exitCanaryInconclusive,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			got := runCanaryCommand(minimalCanaryArgs(), &stdout, &stderr, tc.deps)

			if got != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tc.want, stdout.String(), stderr.String())
			}
			if got != exitOK && stderr.Len() == 0 {
				t.Errorf("a failing run wrote nothing to stderr")
			}
		})
	}
}

// A failure has to be legible to whoever is looking at a red deploy step.
func TestCanaryFailureSaysWhatWentWrongOnStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runCanaryCommand(minimalCanaryArgs(), &stdout, &stderr, canaryDeps{
		open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
		run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
			return failingReport(), nil
		},
	})
	if code != exitCanaryFailed {
		t.Fatalf("exit = %d, want %d", code, exitCanaryFailed)
	}
	for _, want := range []string{"FAILED", segment.CheckVersionDeleteRefused, "Fail this deploy"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not mention %q:\n%s", want, stderr.String())
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("a failing run wrote to stdout: %q", stdout.String())
	}
}

func TestCanaryJSONReportIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runCanaryCommand(minimalCanaryArgs("-json"), &stdout, &stderr, canaryDeps{
		open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) { return &segment.WORM{}, nil },
		run: func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
			return passingReport(), nil
		},
	})
	if code != exitOK {
		t.Fatalf("exit = %d, want %d: %s", code, exitOK, stderr.String())
	}

	var decoded segment.CanaryReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, stdout.String())
	}
	if len(decoded.Checks) != len(segment.CanaryCheckNames()) {
		t.Errorf("the JSON report carries %d checks, want %d", len(decoded.Checks), len(segment.CanaryCheckNames()))
	}
}

func TestCanaryRefusesToRunWithoutItsConfiguration(t *testing.T) {
	// The environment fallbacks must not leak a real deployment's settings
	// into the test, nor the test's into a developer's shell.
	for _, name := range []string{envEndpoint, envBucket, envAccessKey, envSecretKey} {
		t.Setenv(name, "")
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no endpoint", []string{"-bucket", "b", "-access-key", "k", "-secret-key", "s"}, "-endpoint"},
		{"no bucket", []string{"-endpoint", "e", "-access-key", "k", "-secret-key", "s"}, "-bucket"},
		{"no access key", []string{"-endpoint", "e", "-bucket", "b", "-secret-key", "s"}, "-access-key"},
		{"no secret key", []string{"-endpoint", "e", "-bucket", "b", "-access-key", "k"}, "-secret-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			// The deps would panic if reached; not reaching them is the point.
			code := runCanaryCommand(tc.args, &stdout, &stderr, canaryDeps{
				open: func(context.Context, segment.WORMConfig) (*segment.WORM, error) {
					t.Error("the store was opened despite an incomplete configuration")
					return nil, errors.New("unreachable")
				},
			})
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d (exitUsage)", code, exitUsage)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %s", stderr.String(), tc.want)
			}
		})
	}
}

func TestCanaryRejectsUnknownFlagsAndStrayArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"unknown flag", minimalCanaryArgs("-frobnicate")},
		{"stray argument", minimalCanaryArgs("segments")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runCanaryCommand(tc.args, &stdout, &stderr, canaryDeps{}); code != exitUsage {
				t.Fatalf("exit = %d, want %d (exitUsage)", code, exitUsage)
			}
		})
	}
}

func TestCanaryHelpExplainsTheExitStatuses(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := runCanaryCommand([]string{"-h"}, &stdout, &stderr, canaryDeps{}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	for _, want := range []string{"fail the deploy", "fails closed", "-probe-retention"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help does not mention %q:\n%s", want, stderr.String())
		}
	}
}

// A store that cannot be reached is not a store that refused. It fails closed.
func TestCanaryIsInconclusiveWhenTheStoreIsUnreachable(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runCanaryCommand([]string{
		"-endpoint", "127.0.0.1:1", "-bucket", "segments",
		"-access-key", "k", "-secret-key", "s", "-tls=false", "-timeout", "3s",
	}, &stdout, &stderr, canaryDeps{})

	if code != exitCanaryInconclusive {
		t.Fatalf("exit = %d, want %d (exitCanaryInconclusive)\n%s", code, exitCanaryInconclusive, stderr.String())
	}
	if !strings.Contains(stderr.String(), "INCONCLUSIVE") {
		t.Errorf("stderr = %q, want it to say the run proved nothing", stderr.String())
	}
}

// SEG-005 end to end: the deploy gate, exercised as a deploy would exercise it
// — the real binary body, the real WORM writer, a real object store — against
// a bucket with object lock and a bucket without.
//
// internal/segment proves what the canary observes. This proves that what it
// observes reaches the exit status, which is the only thing a deploy step
// reads.
func TestSEG005CanarySubcommandIsADeployGate(t *testing.T) {
	c := requireMinIOForCLI(t)

	for _, tc := range []struct {
		name       string
		objectLock bool
		want       int
	}{
		{"bucket with object lock", true, exitOK},
		{"bucket without object lock", false, exitCanaryFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket := makeBucket(t, c, tc.objectLock)

			var stdout, stderr bytes.Buffer
			code := run([]string{
				"canary",
				"-endpoint", c.endpoint,
				"-bucket", bucket,
				"-access-key", cliMinIOUser,
				"-secret-key", cliMinIOPassword,
				"-tls=false",
				"-retention", "2m",
			}, &stdout, &stderr)

			if code != tc.want {
				t.Fatalf("innsegl canary exit = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					code, tc.want, stdout.String(), stderr.String())
			}
			t.Logf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
		})
	}
}

// A containerised MinIO for the command-level gate test. The plumbing is
// deliberately duplicated from internal/segment's harness rather than exported
// from it: test harnesses are not part of a package's API, and a seam opened
// between packages so that a test can reach through it is a seam production
// code can be written against by mistake.

const (
	cliMinIOImage    = "minio/minio:RELEASE.2025-09-07T16-13-09Z"
	cliMinIOUser     = "innsegl"
	cliMinIOPassword = "innsegl-test-secret"
)

type cliMinIO struct {
	id       string
	endpoint string
}

var cliBucketSeq atomic.Int64

func requireMinIOForCLI(t *testing.T) *cliMinIO {
	t.Helper()

	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		t.Skip("skipping: INNSEGL_TEST_NO_DOCKER is set. " +
			"The canary's exit status is unproven against a real object store.")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("skipping: no docker (%v). "+
			"The canary's exit status is unproven against a real object store.", err)
	}

	image := cliMinIOImage
	if v := os.Getenv("INNSEGL_TEST_MINIO_IMAGE"); v != "" {
		image = v
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: could not reserve a port: %v", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Skipf("skipping: could not read the reserved port: %v", err)
	}
	if cerr := l.Close(); cerr != nil {
		t.Skipf("skipping: could not release the reserved port: %v", cerr)
	}

	out, err := exec.CommandContext(ctx, "docker", "run", "--detach",
		"--publish", "127.0.0.1:"+port+":9000",
		"--env", "MINIO_ROOT_USER="+cliMinIOUser,
		"--env", "MINIO_ROOT_PASSWORD="+cliMinIOPassword,
		image, "server", "/data").Output()
	if err != nil {
		t.Skipf("skipping: could not start %s: %v. "+
			"The canary's exit status is unproven against a real object store.", image, err)
	}

	c := &cliMinIO{id: strings.TrimSpace(string(out)), endpoint: "127.0.0.1:" + port}
	t.Cleanup(func() {
		removeCtx, removeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer removeCancel()
		if rerr := exec.CommandContext(removeCtx, "docker", "rm", "--force", "--volumes", c.id).Run(); rerr != nil {
			t.Logf("warning: removing test container: %v", rerr)
		}
	})

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cl, cerr := c.client()
		if cerr == nil {
			attempt, attemptCancel := context.WithTimeout(ctx, 3*time.Second)
			_, cerr = cl.ListBuckets(attempt)
			attemptCancel()
		}
		if cerr == nil {
			return c
		}
		err = cerr
		time.Sleep(250 * time.Millisecond)
	}
	t.Skipf("skipping: minio never became ready: %v", err)
	return nil
}

func (c *cliMinIO) client() (*minio.Client, error) {
	return minio.New(c.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cliMinIOUser, cliMinIOPassword, ""),
		Secure: false,
	})
}

func makeBucket(t *testing.T, c *cliMinIO, objectLock bool) string {
	t.Helper()

	name := fmt.Sprintf("cli-%d-%d", os.Getpid()%100000, cliBucketSeq.Add(1))
	cl, err := c.client()
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := cl.MakeBucket(ctx, name, minio.MakeBucketOptions{ObjectLocking: objectLock}); err != nil {
		t.Fatalf("create bucket %s (object lock %v): %v", name, objectLock, err)
	}
	return name
}
