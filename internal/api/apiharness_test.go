// SPDX-License-Identifier: Apache-2.0

package api

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

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/ledger"
)

// A real Postgres, never a mock.
//
// TC-API's storage cases run against a containerised Postgres brought up once
// per test process. A mocked database would prove nothing about the one thing
// this package's read-only posture rests on: that the credential the API holds
// is REFUSED by the server when it tries to write. "The Go code contains no
// INSERT" is a property of today's code; "the role has no INSERT privilege" is
// a property of the deployment, and only a real server can be asked.
//
// # THE #101 DEFECT IS NOT REPEATED HERE
//
// Eight harnesses in this repository still treat "Docker is absent" and "the
// container failed to start" as the same outcome and skip for both. The second
// is an infrastructure fault: skipping it makes `go test` exit zero and print
// `ok` while the cases that carry the invariant never ran. It reached CI once
// and five I5 cases silently did not run.
//
// So this harness routes them apart. errDependencyAbsent is wrapped ONLY by the
// genuinely-absent conditions; everything else lands in pgFailure, and
// requirePG calls t.Fatalf on it. Both branches are exercised by
// TestTheHarnessSeparatesAnAbsentDockerFromAContainerThatDidNotStart, because a
// routing rule nothing exercises is a routing rule nobody has checked — which
// is exactly how #101 survived.

const (
	// defaultPostgresImage is pinned by major version, matching
	// internal/ledger: this package asserts privilege behaviour that has been
	// stable in Postgres for decades.
	defaultPostgresImage = "postgres:16"

	postgresUser     = "innsegl"
	postgresPassword = "innsegl-test"
	postgresDB       = "innsegl"

	// readerPassword is the password the read-only role gets in tests. It is a
	// test fixture and names itself as one.
	readerPassword = "reader-test-password"
)

// errDependencyAbsent marks the only conditions under which skipping TC-API's
// storage cases is honest: no Docker daemon, or no git. On a developer's
// machine either is a legitimate reason not to run them.
//
// A container that would not start on a machine that HAS Docker is not one of
// them. See the file comment.
var errDependencyAbsent = errors.New("a required dependency is absent")

var (
	sharedPG  *pgContainer
	pgSkip    string
	pgFailure string
	testDBSeq atomic.Int64
)

func postgresImage() string {
	if v := os.Getenv("INNSEGL_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return defaultPostgresImage
}

func docker(ctx context.Context, args ...string) (string, error) {
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
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not on PATH: %w: %w", err, errDependencyAbsent)
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

// requirement is what requirePG must do for the calling test.
type requirement int

const (
	proceed requirement = iota
	skipTest
	failTest
)

// pgRequirement decides between the three. Split out for the same reason
// startupOutcome is.
func pgRequirement(pg *pgContainer, skip, failure string) requirement {
	switch {
	case failure != "":
		return failTest
	case pg == nil:
		return skipTest
	default:
		return proceed
	}
}

type pgContainer struct {
	id    string
	image string
	port  string
}

func (c *pgContainer) dsn(database, user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		user, password, c.port, database)
}

// adminDSN is the owner credential. It is what the migrations and the role
// provisioning run as, and it is deliberately NOT what the API connects with.
func (c *pgContainer) adminDSN(database string) string {
	return c.dsn(database, postgresUser, postgresPassword)
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

func startPG(ctx context.Context) (*pgContainer, error) {
	image := postgresImage()
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := docker(ctx, "run", "--detach",
		"--name", fmt.Sprintf("innsegl-apitest-%d", os.Getpid()),
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		image,
	)
	if err != nil {
		return nil, err
	}
	c := &pgContainer{id: id, image: image, port: port}
	if err := c.waitReady(ctx, 90*time.Second); err != nil {
		if rerr := c.remove(); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		return nil, err
	}
	return c, nil
}

func (c *pgContainer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pgx.Connect(attempt, c.adminDSN(postgresDB))
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
	return fmt.Errorf("postgres in %s never became ready: %w", c.id, last)
}

func (c *pgContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := docker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	if err := dependenciesPresent(ctx); err != nil {
		pgSkip, pgFailure = startupOutcome(err)
	} else if pg, err := startPG(ctx); err != nil {
		// Docker answered a moment ago and the container still did not come
		// up. That is an infrastructure fault, and startupOutcome sends it to
		// pgFailure precisely because reporting it as a skip is what #101 was.
		pgSkip, pgFailure = startupOutcome(fmt.Errorf("could not start %s: %w", postgresImage(), err))
	} else {
		sharedPG = pg
	}
	cancel()

	code := m.Run()

	if sharedPG != nil {
		if err := sharedPG.remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing test container: %v\n", err)
		}
	}
	os.Exit(code)
}

// requirePG hands the calling test a live Postgres, or ends it — as a SKIP
// when a dependency is absent and as a FAILURE when the container did not come
// up. The two are never the same outcome here.
func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	switch pgRequirement(sharedPG, pgSkip, pgFailure) {
	case failTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present: %s\n\n"+
			"This is a failure and not a skip. TC-API's storage cases are what "+
			"demonstrate that the API's credential cannot write; reporting an "+
			"infrastructure fault as a skip exits zero and prints ok while "+
			"API-001, API-002 and API-003 did not run (#101).", pgFailure)
	case skipTest:
		t.Skipf("skipping: no real Postgres (%s). These cases prove nothing about "+
			"a read-only database role without one; start Docker and re-run.", pgSkip)
	case proceed:
	}
	return sharedPG
}

// pgQuoteIdent quotes an SQL identifier. Test-local.
func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// freshDB creates an empty database, migrates it, and returns the OWNER dsn.
// One database per test: ADR-0005 scopes a chain to a database.
func freshDB(t *testing.T) (c *pgContainer, database, adminDSN string) {
	t.Helper()
	c = requirePG(t)
	name := fmt.Sprintf("api_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, c.adminDSN(postgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", postgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgQuoteIdent(name)); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return c, name, c.adminDSN(name)
}

// migrated returns a fresh database with the ledger schema applied, the
// read-only role provisioned, and both DSNs.
//
// The owner credential runs the migrations and appends the fixture events; the
// API is never given it. That split is the whole point of TC-API's read-only
// cases, so the harness models it rather than papering over it.
func migrated(t *testing.T) (owner *ledger.Store, ownerDSN, readerDSN string) {
	t.Helper()
	c, database, ownerDSN := freshDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	if err := EnsureReadOnlyRole(ctx, ownerDSN, ReadOnlyRole, readerPassword); err != nil {
		t.Fatalf("EnsureReadOnlyRole: %v", err)
	}
	return s, ownerDSN, c.dsn(database, ReadOnlyRole, readerPassword)
}
