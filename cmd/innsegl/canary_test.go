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

// ---------------------------------------------------------------------------
// #101: a failed dependency is not a skip.
//
// errCLIDependencyAbsent marks the ONLY conditions under which skipping the
// canary's object-store cases is honest: there is no Docker daemon, or
// INNSEGL_TEST_NO_DOCKER asks for none. Nothing else wraps it.
//
// Every other thing this function used to report as a skip — a port that could
// not be reserved, an image that would not pull, a MinIO that never became
// ready — happens on a machine that HAS Docker, and is a FAILURE. Reporting
// one as a skip turns it into a pass-shaped outcome: `go test` exits zero, the
// package reports ok, and the canary's exit status went unmeasured against a
// real object store.
//
// Both branches are exercised by
// TestHAR009AnAbsentDependencyIsASkipAndAFaultIsAFailure.
// ---------------------------------------------------------------------------
var errCLIDependencyAbsent = errors.New("a required dependency is absent")

// cliStartupOutcome routes a start-up error to exactly one of two outcomes.
func cliStartupOutcome(err error) (skip, failure string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, errCLIDependencyAbsent):
		return err.Error(), ""
	default:
		return "", err.Error()
	}
}

// cliRequirement is what requireMinIOForCLI must do for the calling test.
type cliRequirement int

const (
	cliProceed cliRequirement = iota
	cliSkipTest
	cliFailTest
)

// cliNeed decides between the three. A failure outranks a skip: if the
// dependency broke, the reason it broke is what the developer needs to read.
func cliNeed(up bool, skip, failure string) cliRequirement {
	switch {
	case failure != "":
		return cliFailTest
	case !up:
		return cliSkipTest
	default:
		return cliProceed
	}
}

// cliDockerUsable reports whether a docker daemon is reachable. Its error is
// the ONLY one here wrapped as an absent dependency.
func cliDockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errCLIDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errCLIDependencyAbsent)
	}
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %s: %w",
			err, cliOneLine(stderr.String()), errCLIDependencyAbsent)
	}
	return nil
}

// cliOneLine collapses a multi-line subprocess error into a single line, so
// the line naming the fault survives the test JSON stream (#101).
func cliOneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// startCLIMinIO brings up one MinIO and waits for it. Every error it returns
// is a fault on a machine that has Docker; none of them wrap
// errCLIDependencyAbsent.
func startCLIMinIO(ctx context.Context, t *testing.T) (*cliMinIO, error) {
	t.Helper()
	image := cliMinIOImage
	if v := os.Getenv("INNSEGL_TEST_MINIO_IMAGE"); v != "" {
		image = v
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("reserving a host port: %w", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("reading the reserved port: %w", err)
	}
	if cerr := l.Close(); cerr != nil {
		return nil, fmt.Errorf("releasing the reserved port: %w", cerr)
	}

	run := exec.CommandContext(ctx, "docker", "run", "--detach",
		"--publish", "127.0.0.1:"+port+":9000",
		"--env", "MINIO_ROOT_USER="+cliMinIOUser,
		"--env", "MINIO_ROOT_PASSWORD="+cliMinIOPassword,
		image, "server", "/data")
	var stderr strings.Builder
	run.Stderr = &stderr
	out, err := run.Output()
	if err != nil {
		return nil, fmt.Errorf("starting %s: %w: %s", image, err, cliOneLine(stderr.String()))
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
	var last error
	for time.Now().Before(deadline) {
		cl, cerr := c.client()
		if cerr == nil {
			attempt, attemptCancel := context.WithTimeout(ctx, 3*time.Second)
			_, cerr = cl.ListBuckets(attempt)
			attemptCancel()
		}
		if cerr == nil {
			return c, nil
		}
		last = cerr
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("%s never became ready: %w", image, last)
}

// requireMinIOForCLI hands the calling test a real object store, or ends the
// test the honest way: a skip when there is no Docker, a FAILURE when Docker
// is there and MinIO is not.
func requireMinIOForCLI(t *testing.T) *cliMinIO {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var c *cliMinIO
	skip, failure := cliStartupOutcome(cliDockerUsable(ctx))
	if skip == "" && failure == "" {
		var err error
		c, err = startCLIMinIO(ctx, t)
		skip, failure = cliStartupOutcome(err)
	}

	switch cliNeed(c != nil, skip, failure) {
	case cliFailTest:
		t.Fatalf("the canary's object store did not come up, and Docker is present "+
			"and working: %s\n\nThis is a FAILURE and not a skip (#101): an "+
			"infrastructure fault reported as a skip exits zero and reports ok "+
			"while the canary's exit status went unmeasured against a real "+
			"object store.", failure)
	case cliSkipTest:
		t.Skipf("skipping: %s. "+
			"The canary's exit status is unproven against a real object store.", skip)
	case cliProceed:
	}
	return c
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

// ---------------------------------------------------------------------------
// HAR-009 — #101. Both branches of the routing rule, exercised.
//
// A routing rule nothing exercises is a routing rule nobody has checked, which
// is exactly how #101 survived in nine harnesses at once. This case pins the
// two outcomes apart: an ABSENT dependency is a skip, and anything else is a
// failure that says so.
// ---------------------------------------------------------------------------

func TestHAR009AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
	t.Run("no docker is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
		err := cliDockerUsable(t.Context())
		if err == nil {
			t.Fatal("cliDockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, errCLIDependencyAbsent) {
			t.Fatalf("%v does not wrap errCLIDependencyAbsent, so it would be routed to a "+
				"FAILURE and a developer with no Docker could not run this package", err)
		}
		skip, failure := cliStartupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("cliStartupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine, and the shape the CI
		// run in #101 produced: Docker is present, working, and refuses to
		// create the network because its address pools are used up.
		err := fmt.Errorf("could not start the canary's minio: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, errCLIDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errCLIDependencyAbsent; it would " +
				"be reported as a skip and the canary's exit-status cases would silently not run")
		}
		skip, failure := cliStartupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("cliStartupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("a healthy start-up is neither", func(t *testing.T) {
		if skip, failure := cliStartupOutcome(nil); skip != "" || failure != "" {
			t.Fatalf("cliStartupOutcome(nil) = (%q, %q), want both empty", skip, failure)
		}
	})

	t.Run("a failure outranks a skip", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			up            bool
			skip, failure string
			want          cliRequirement
		}{
			{"a failure outranks everything", false, "no docker", "boom", cliFailTest},
			{"nothing up and no failure is a skip", false, "no docker", "", cliSkipTest},
			{"a live dependency proceeds", true, "", "", cliProceed},
		} {
			if got := cliNeed(tc.up, tc.skip, tc.failure); got != tc.want {
				t.Errorf("%s: cliNeed(%v, %q, %q) = %d, want %d",
					tc.name, tc.up, tc.skip, tc.failure, got, tc.want)
			}
		}
	})
}
