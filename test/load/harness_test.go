// SPDX-License-Identifier: Apache-2.0

package load

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// The real stack, never a mock.
//
// OPS-002 is a measurement, and a measurement of a fake measures the fake. The
// three numbers doc 05 §4 asks for — bytes per event in the hot tier, bytes
// per event in an object, and how many events a second the append path
// sustains — are all properties of a real Postgres with the real triggers and
// the real advisory lock, a real S3 object store with object lock on, and a
// real transparency log that really integrates a leaf before it will issue an
// inclusion proof. Substituting an in-memory store for any of them would
// produce a number, and the number would be about Go's map implementation.
//
// # THE #101 DEFECT IS NOT REPEATED HERE
//
// Eight harnesses in this repository treat "Docker is absent" and "the
// container did not start" as the same outcome and skip for both. The second
// is an infrastructure fault, and reporting it as a skip makes `go test` exit
// zero and print `ok` while the case that carries the evidence never ran.
//
// So this harness routes them apart, in the shape internal/verify and
// internal/api corrected to: errDependencyAbsent is wrapped ONLY by the
// genuinely-absent conditions, everything else lands in stackFailure, and
// requireStack calls t.Fatalf on it. Both branches are exercised by
// harnesshonesty_test.go, because a routing rule nothing exercises is a
// routing rule nobody has checked — which is exactly how #101 survived.

const (
	// Pinned images. The versions are part of the evidence: a throughput
	// number and a bytes-per-event number are both properties of the server
	// that produced them, and ADR-0039 quotes these tags beside the numbers.
	defaultPostgresImage = "postgres:16"
	defaultMinIOImage    = "minio/minio:RELEASE.2025-09-07T16-13-09Z"
	// The Rekor stack, matching internal/segment/rekorharness_test.go so that
	// OPS-002 anchors against the same log SEG-003 does.
	defaultRekorImage             = "ghcr.io/sigstore/rekor/rekor-server:v1.3.10"
	defaultTrillianLogServerImage = "ghcr.io/sigstore/scaffolding/trillian_log_server:v1.7.1"
	defaultTrillianLogSignerImage = "ghcr.io/sigstore/scaffolding/trillian_log_signer:v1.7.1"
	defaultTrillianDBImage        = "gcr.io/trillian-opensource-ci/db_server:v1.4.0"
	defaultRekorRedisImage        = "redis:7-alpine"

	postgresUser     = "innsegl"
	postgresPassword = "innsegl-load-test"
	postgresDB       = "innsegl"

	minioRootUser     = "innsegl"
	minioRootPassword = "innsegl-load-test-secret"

	trillianDBName     = "test"
	trillianDBUser     = "test"
	trillianDBPassword = "zaphod"

	// rekorOrigin is the checkpoint origin the log signs under.
	rekorOrigin = "rekor.innsegl.test"
)

// errDependencyAbsent marks the only condition under which skipping OPS-002 is
// honest: there is no Docker daemon. On a developer's machine that is a
// legitimate reason not to run a test that needs eight containers.
//
// A container that would not start on a machine that HAS Docker is not one of
// them. See the file comment.
var errDependencyAbsent = errors.New("a required dependency is absent")

var (
	sharedStack  *stack
	stackSkip    string
	stackFailure string
	nameSeq      atomic.Int64
)

func envImage(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func postgresImage() string { return envImage("INNSEGL_TEST_POSTGRES_IMAGE", defaultPostgresImage) }
func minioImage() string    { return envImage("INNSEGL_TEST_MINIO_IMAGE", defaultMinIOImage) }
func rekorImage() string    { return envImage("INNSEGL_TEST_REKOR_IMAGE", defaultRekorImage) }

// docker runs one docker command and returns its trimmed stdout.
func docker(ctx context.Context, args ...string) (string, error) {
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

// oneLine collapses a multi-line subprocess error into a single line, so that
// Go's test JSON stream does not scatter the cause across events and show only
// the first progress line.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// dependenciesPresent reports the absence of a dependency, and nothing else.
// Every error it returns wraps errDependencyAbsent; no other function in this
// harness does.
func dependenciesPresent(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errDependencyAbsent)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errDependencyAbsent)
	}
	return nil
}

// startupOutcome routes a TestMain start-up error into exactly one of the two
// buckets. It is a named function rather than an inline `if` so that both of
// its branches can be exercised by a test — the #101 defect was a branch
// nothing measured.
func startupOutcome(err error) (skip, failure string) {
	if err == nil {
		return "", ""
	}
	if errors.Is(err, errDependencyAbsent) {
		return err.Error(), ""
	}
	return "", err.Error()
}

// requirement is what requireStack must do for the calling test.
type requirement int

const (
	proceed requirement = iota
	skipTest
	failTest
)

// stackRequirement decides between the three. Split out for the same reason
// startupOutcome is.
func stackRequirement(s *stack, skip, failure string) requirement {
	switch {
	case failure != "":
		return failTest
	case s == nil:
		return skipTest
	default:
		return proceed
	}
}

// stack is the whole OPS-002 deployment: one Postgres, one MinIO, and Rekor
// with everything under it.
type stack struct {
	network    string
	containers []string

	pgPort       string
	minioAddr    string
	rekorBaseURL string

	dockerVersion string
	dockerOS      string
	dockerCPUs    string
	dockerMemory  string
}

func (s *stack) adminDSN(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, s.pgPort, database)
}

func (s *stack) minioClient() (*minio.Client, error) {
	return minio.New(s.minioAddr, &minio.Options{
		Creds:  credentials.NewStaticV4(minioRootUser, minioRootPassword, ""),
		Secure: false,
	})
}

// run starts one detached container on the stack's network and remembers it.
func (s *stack) run(ctx context.Context, name string, args ...string) error {
	full := append([]string{"run", "--detach", "--name", name, "--network", s.network}, args...)
	id, err := docker(ctx, full...)
	if err != nil {
		return err
	}
	s.containers = append(s.containers, id)
	return nil
}

// stop removes every container and the network. Best effort: a leaked
// container is a nuisance, a failed teardown that masks a test failure is
// worse.
func (s *stack) stop() []error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var errs []error
	for i := len(s.containers) - 1; i >= 0; i-- {
		if _, err := docker(ctx, "rm", "--force", "--volumes", s.containers[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if s.network != "" {
		if _, err := docker(ctx, "network", "rm", s.network); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
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

// One network for the whole stack, not one per service.
//
// This machine refuses roughly the 29th Docker network (#100), and every
// package in this repository that stands a compose project up spends several.
// OPS-002 needs Trillian to reach MySQL and Rekor to reach Trillian, which is
// the only reason it needs a network at all; Postgres and MinIO are reached
// from the test process over published ports and are on it only because
// putting them there costs nothing.
func startStack(ctx context.Context) (*stack, error) {
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), nameSeq.Add(1))
	s := &stack{network: "innsegl-load-" + suffix}

	if _, err := docker(ctx, "network", "create", s.network); err != nil {
		return s, fmt.Errorf("create network: %w", err)
	}
	if err := s.recordHostFacts(ctx); err != nil {
		return s, err
	}
	if err := s.startPostgres(ctx, suffix); err != nil {
		return s, err
	}
	if err := s.startMinIO(ctx, suffix); err != nil {
		return s, err
	}
	if err := s.startRekor(ctx, suffix); err != nil {
		return s, err
	}
	return s, nil
}

// recordHostFacts reads the conditions every number in this package is
// reported with. A throughput figure without the machine it was taken on is
// not a measurement, so the machine is read from the daemon rather than
// assumed.
func (s *stack) recordHostFacts(ctx context.Context) error {
	out, err := docker(ctx, "info", "--format",
		"{{.ServerVersion}}\t{{.OperatingSystem}}\t{{.NCPU}}\t{{.MemTotal}}")
	if err != nil {
		return fmt.Errorf("read docker host facts: %w", err)
	}
	parts := strings.Split(out, "\t")
	if len(parts) != 4 {
		return fmt.Errorf("docker info returned %d fields, want 4: %q", len(parts), out)
	}
	s.dockerVersion, s.dockerOS, s.dockerCPUs, s.dockerMemory = parts[0], parts[1], parts[2], parts[3]
	return nil
}

func (s *stack) startPostgres(ctx context.Context, suffix string) error {
	port, err := freeHostPort(ctx)
	if err != nil {
		return fmt.Errorf("reserve a host port for postgres: %w", err)
	}
	s.pgPort = port
	if err := s.run(ctx, "innsegl-load-pg-"+suffix,
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		// fsync stays on. A throughput number taken with fsync off is a
		// number about a database that can lose an acknowledged append, which
		// is not the database this project ships and not the one doc 05 §4 is
		// being sized for.
		postgresImage(), "-c", "fsync=on",
	); err != nil {
		return fmt.Errorf("start %s: %w", postgresImage(), err)
	}
	return s.waitForPostgres(ctx, 2*time.Minute)
}

func (s *stack) waitForPostgres(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pgx.Connect(attempt, s.adminDSN(postgresDB))
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
	return fmt.Errorf("postgres never became ready: %w", last)
}

func (s *stack) startMinIO(ctx context.Context, suffix string) error {
	port, err := freeHostPort(ctx)
	if err != nil {
		return fmt.Errorf("reserve a host port for minio: %w", err)
	}
	s.minioAddr = "127.0.0.1:" + port
	if err := s.run(ctx, "innsegl-load-minio-"+suffix,
		"--publish", "127.0.0.1:"+port+":9000",
		"--env", "MINIO_ROOT_USER="+minioRootUser,
		"--env", "MINIO_ROOT_PASSWORD="+minioRootPassword,
		minioImage(), "server", "/data",
	); err != nil {
		return fmt.Errorf("start %s: %w", minioImage(), err)
	}
	return s.waitForMinIO(ctx, 2*time.Minute)
}

func (s *stack) waitForMinIO(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		cl, err := s.minioClient()
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
	return fmt.Errorf("minio never became ready: %w", last)
}

// startRekor brings up MySQL, the Trillian log server and sequencer, Redis and
// Rekor. The shape is internal/segment/rekorharness_test.go's, which is
// upstream Rekor's own compose reference; OPS-002 anchors against the same log
// SEG-003 does so that "the segment anchored" means the same thing in both.
func (s *stack) startRekor(ctx context.Context, suffix string) error {
	port, err := freeHostPort(ctx)
	if err != nil {
		return fmt.Errorf("reserve a host port for rekor: %w", err)
	}
	s.rekorBaseURL = "http://127.0.0.1:" + port

	db := "innsegl-load-tdb-" + suffix
	if err := s.run(ctx, db,
		"--env", "MYSQL_ROOT_PASSWORD="+trillianDBPassword,
		"--env", "MYSQL_DATABASE="+trillianDBName,
		"--env", "MYSQL_USER="+trillianDBUser,
		"--env", "MYSQL_PASSWORD="+trillianDBPassword,
		envImage("INNSEGL_TEST_TRILLIAN_DB_IMAGE", defaultTrillianDBImage),
	); err != nil {
		return fmt.Errorf("start trillian database: %w", err)
	}
	if err := s.waitForTrillianSchema(ctx, db, 4*time.Minute); err != nil {
		return err
	}

	redis := "innsegl-load-redis-" + suffix
	if err := s.run(ctx, redis,
		envImage("INNSEGL_TEST_REKOR_REDIS_IMAGE", defaultRekorRedisImage),
		"--bind", "0.0.0.0", "--appendonly", "no",
	); err != nil {
		return fmt.Errorf("start redis: %w", err)
	}

	mysqlURI := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s",
		trillianDBUser, trillianDBPassword, db, trillianDBName)

	logServer := "innsegl-load-tlog-" + suffix
	if err := s.run(ctx, logServer,
		"--restart", "on-failure:30",
		envImage("INNSEGL_TEST_TRILLIAN_LOG_SERVER_IMAGE", defaultTrillianLogServerImage),
		"--storage_system=mysql", "--mysql_uri="+mysqlURI,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
	); err != nil {
		return fmt.Errorf("start trillian log server: %w", err)
	}

	// Without the sequencer, leaves are queued and never integrated: the log
	// would accept every anchor OPS-002 submits and be unable to prove any of
	// them, and "all segments anchor" would be answered by a log that had
	// integrated nothing.
	signer := "innsegl-load-tsign-" + suffix
	if err := s.run(ctx, signer,
		"--restart", "on-failure:30",
		envImage("INNSEGL_TEST_TRILLIAN_LOG_SIGNER_IMAGE", defaultTrillianLogSignerImage),
		"--storage_system=mysql", "--mysql_uri="+mysqlURI,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
		"--force_master",
	); err != nil {
		return fmt.Errorf("start trillian log signer: %w", err)
	}

	if err := s.run(ctx, "innsegl-load-rekor-"+suffix,
		"--restart", "on-failure:30",
		"--publish", "127.0.0.1:"+port+":3000",
		rekorImage(),
		"serve",
		"--trillian_log_server.address="+logServer, "--trillian_log_server.port=8090",
		"--redis_server.address="+redis, "--redis_server.port=6379",
		"--host=0.0.0.0", "--port=3000", "--rekor_server.address=0.0.0.0",
		"--rekor_server.signer=memory",
		"--rekor_server.hostname="+rekorOrigin,
		"--enable_attestation_storage=false",
		"--enable_stable_checkpoint=false",
	); err != nil {
		return fmt.Errorf("start %s: %w", rekorImage(), err)
	}
	return s.waitForRekor(ctx, 4*time.Minute)
}

// waitForTrillianSchema polls until Trillian's tables are reachable over TCP.
// Over TCP, and that is the point: the MySQL image boots a socket-only server
// first to apply the schema, so a socket probe answers yes at a moment when
// nothing on the network can connect.
func (s *stack) waitForTrillianSchema(ctx context.Context, container string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := docker(attempt, "exec", container,
			"mysql", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
			"-u"+trillianDBUser, "-p"+trillianDBPassword,
			"-e", "SELECT 1 FROM "+trillianDBName+".Trees LIMIT 1")
		cancel()
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("trillian schema never became reachable over TCP: %w", last)
}

func (s *stack) waitForRekor(ctx context.Context, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.rekorBaseURL+"/api/v1/log", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("GET /api/v1/log: %s", resp.Status)
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("rekor never became ready: %w", last)
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	if err := dependenciesPresent(ctx); err != nil {
		stackSkip, stackFailure = startupOutcome(err)
	} else if s, err := startStack(ctx); err != nil {
		// Docker answered a moment ago and the stack still did not come up.
		// That is an infrastructure fault, and startupOutcome sends it to
		// stackFailure precisely because reporting it as a skip is what #101
		// was.
		stackSkip, stackFailure = startupOutcome(
			fmt.Errorf("the OPS-002 stack did not come up: %w", err))
		if s != nil {
			for _, serr := range s.stop() {
				fmt.Fprintf(os.Stderr, "warning: tearing down a partial stack: %v\n", serr)
			}
		}
	} else {
		sharedStack = s
	}
	cancel()

	code := m.Run()

	if sharedStack != nil {
		for _, err := range sharedStack.stop() {
			fmt.Fprintf(os.Stderr, "warning: tearing down the load stack: %v\n", err)
		}
	}
	os.Exit(code)
}

// requireStack hands the calling test the live stack, or ends it — as a SKIP
// when Docker is absent and as a FAILURE when the stack did not come up. The
// two are never the same outcome here.
func requireStack(t *testing.T) *stack {
	t.Helper()
	switch stackRequirement(sharedStack, stackSkip, stackFailure) {
	case failTest:
		t.Fatalf("the OPS-002 stack did not come up, and Docker is present: %s\n\n"+
			"This is a failure and not a skip. OPS-002 is the only measurement that "+
			"supersedes doc 05 §4's estimated sizing posture; reporting an "+
			"infrastructure fault as a skip exits zero and prints ok while the "+
			"estimates stay unmeasured and nobody is told (#101).", stackFailure)
	case skipTest:
		t.Skipf("skipping: no Docker (%s). OPS-002 measures a real Postgres, a real "+
			"object store and a real transparency log under sustained load; against "+
			"in-memory substitutes it would measure Go's map implementation and "+
			"report the answer as a deployment sizing. Start Docker and re-run.", stackSkip)
	case proceed:
	}
	return sharedStack
}

// freshDatabase creates an empty database inside the stack's Postgres and
// returns its owner DSN. ADR-0005 scopes a chain to a database, so a database
// per test is a chain per test.
func freshDatabase(t *testing.T, s *stack) string {
	t.Helper()
	name := fmt.Sprintf("load_%d_%d", os.Getpid()%100000, nameSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, s.adminDSN(postgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", postgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+strings.ReplaceAll(name, `"`, `""`)+`"`); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return s.adminDSN(name)
}

// freshLockedBucket makes an empty bucket with S3 object lock enabled, which
// is the only kind internal/segment's WORM writer will write to.
func freshLockedBucket(t *testing.T, s *stack) string {
	t.Helper()
	name := fmt.Sprintf("load-%d-%d", os.Getpid()%100000, nameSeq.Add(1))

	cl, err := s.minioClient()
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := cl.MakeBucket(ctx, name, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		t.Fatalf("create locked bucket %s: %v", name, err)
	}
	return name
}
