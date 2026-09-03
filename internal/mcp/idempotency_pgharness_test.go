// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
)

// A real Postgres, never a mock.
//
// Doc 05 §2 is the whole reason this store exists: "MCP replicas are stateless
// (idempotency store lives in Postgres) — MCP-011's crash/replay property is
// what makes horizontal scaling safe." A mocked or in-memory store would pass
// every assertion below while proving none of them, because the claims are
// about what two processes see, what survives a SIGKILL, and what one UNIQUE
// index does under sixteen concurrent writers.
//
// Without Docker the tests skip with a message naming what went unproven,
// rather than passing quietly.
//
// SUPERVISOR NOTE (RM-021/RM-020 merge): TestMain is per test binary, so this
// file's TestMain and any TestMain added by RM-020's server tests collide at
// merge. Whichever survives must keep the container lifecycle below.

const (
	defaultPostgresImage = "postgres:16"

	postgresUser     = "innsegl"
	postgresPassword = "innsegl-test"
	postgresDB       = "innsegl"
)

// dockerSkip is set when there is no Docker daemon to ask; dockerFailure when
// Docker is present and the container still did not start. Two outcomes, two
// verdicts (#101).
var (
	sharedPG      *pgContainer
	dockerSkip    string
	dockerFailure string
	testDBSeq     atomic.Int64
)

// ---------------------------------------------------------------------------
// #101: a failed dependency is not a skip.
//
// errDependencyAbsent marks the ONLY conditions under which skipping is
// honest: there is no Docker daemon (or INNSEGL_TEST_NO_DOCKER asks for none),
// or there is no gitsign binary. Nothing else wraps it.
//
// Everything else that can go wrong while standing a dependency up — an image
// that cannot be pulled, a port that cannot be bound, a network Docker refuses
// to create because its predefined address pools are used up, a container that
// never becomes healthy — is a FAILURE. Reporting one of those as a skip turns
// it into a pass-shaped outcome: `go test` exits zero, the package reports ok,
// and the idempotency store, SIG-001, MCP-012 and the get_credential
// authorization case did not run. That is what CI produced on a runner whose
// "Require Docker" step had already passed.
//
// internal/verify/verifyharness_test.go carries the reference shape; both
// branches here are exercised by
// TestHAR002AnAbsentDependencyIsASkipAndAFaultIsAFailure.
// ---------------------------------------------------------------------------
var errDependencyAbsent = errors.New("a required dependency is absent")

// startupOutcome routes a start-up error to exactly one of the two variables.
// An absent dependency is a skip; anything else is a failure. There is no
// third answer, and the third answer is how this package came to report ok
// with nothing having run.
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

// harnessRequirement is what a require-function must do for the calling test.
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

// requireStartup ends the calling test the honest way when a per-test stack
// did not come up. The lazily-built stacks in this package (get_credential's,
// sign_commit's, health's) cannot use TestMain — it belongs to the idempotency
// harness — so they route through here instead.
func requireStartup(t *testing.T, err error, unproven string) {
	t.Helper()
	skip, failure := startupOutcome(err)
	if failure != "" {
		t.Fatalf("a dependency this case needs did not come up, and Docker is "+
			"present and working: %s\n\nThis is a FAILURE and not a skip "+
			"(#101). %s", failure, unproven)
	}
	if skip != "" {
		t.Skipf("skipping: %s. %s", skip, unproven)
	}
}

// oneLine collapses a multi-line subprocess error into a single line.
//
// docker and `docker compose` report progress on stderr, so a failure arrives
// as several lines of which only the last usually names the cause. Go's test
// JSON stream emits each line as its own event, and the CI failure behind #101
// read "Network innsegl-verifytest-40427-spire-admin  Creating" — compose's
// first progress line, with the fault itself on a line the summary never showed.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

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
			strings.Join(args, " "), err, oneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errDependencyAbsent, err)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errDependencyAbsent, err)
	}
	return nil
}

type pgContainer struct {
	id   string
	port string
}

func (c *pgContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, c.port, database)
}

// freeHostPort reserves an ephemeral port. The container publishes on a fixed
// host port because the crash test restarts it, and a docker-assigned port
// changes on every start — which would look like recovery failing when it is
// the test moving the goal.
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
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		// fsync stays on: the crash test asserts that a recorded response
		// survives a SIGKILL, and that assertion is meaningless with fsync off.
		postgresImage(), "-c", "fsync=on",
	)
	if err != nil {
		return nil, err
	}
	c := &pgContainer{id: id, port: port}
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
		conn, err := pgx.Connect(attempt, c.dsn(postgresDB))
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

// kill stops the container the hard way: SIGKILL, no shutdown checkpoint, so
// the restart goes through WAL crash recovery.
func (c *pgContainer) kill(ctx context.Context) error {
	_, err := docker(ctx, "kill", "--signal", "SIGKILL", c.id)
	return err
}

func (c *pgContainer) restart(ctx context.Context) error {
	if _, err := docker(ctx, "start", c.id); err != nil {
		return err
	}
	return c.waitReady(ctx, 90*time.Second)
}

func (c *pgContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := docker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

// TestMain brings up the shared Postgres once for the whole package.
func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if err := dockerUsable(ctx); err != nil {
		// The only honest skip: there is no daemon to ask.
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		// Docker is present and working and the container still did not come
		// up. That is an infrastructure FAILURE, not an absent dependency, and
		// conflating the two is #101.
		dockerSkip, dockerFailure = startupOutcome(
			fmt.Errorf("could not start %s: %w", postgresImage(), err))
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

// requirePG skips the calling test when no real Postgres is available, naming
// what went unproven. It never lets a storage test pass without a database.
func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	switch harnessNeed(sharedPG != nil, dockerSkip, dockerFailure) {
	case harnessFailTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present and "+
			"working: %s\n\nThis is a FAILURE and not a skip (#101): an "+
			"infrastructure fault reported as a skip exits zero and reports ok "+
			"while the idempotency store, SIG-001 and MCP-012 did not run.",
			dockerFailure)
	case harnessSkipTest:
		t.Skipf("skipping: no real Postgres (%s). "+
			"This test proves nothing about the idempotency store without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
	case harnessProceed:
	}
	return sharedPG
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// freshDSN creates an empty database inside c and returns its DSN. One
// database per test: ADR-0005 scopes a ledger chain to a database, and this
// store is scoped to the same database, so a database per test is a chain and
// a key space per test.
func freshDSN(t *testing.T, c *pgContainer) string {
	t.Helper()
	name := fmt.Sprintf("mcp_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, c.dsn(postgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", postgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return c.dsn(name)
}

// migrate applies the embedded migrations to dsn, through the ledger's own
// runner. There is one migration set and one runner: the idempotency table
// ships in it (0002), so a deployment cannot have the ledger schema without
// the store's, nor drift between them.
func migrate(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
}

// newPool opens a pgx pool the caller owns, exactly as an MCP replica would.
func newPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newStore migrates a fresh database and returns a store on it, plus the DSN
// so a test can open a second "replica" against the same database.
func newStore(t *testing.T, opts ...IdempotencyOption) (*IdempotencyStore, string) {
	t.Helper()
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrate(t, dsn)
	return NewIdempotencyStore(newPool(t, dsn), opts...), dsn
}

// rawConn opens a plain pgx connection, bypassing the store entirely. The
// schema-guard tests need one: the point is what direct SQL is refused, not
// what the Go API declines to offer.
func rawConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("raw connect: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = conn.Close(closeCtx)
	})
	return conn
}

// mcpError extracts the *Error an operation must have returned. A failure
// with no error_class is a failure the contract tests cannot check (IP §4),
// and errors.go is where that vocabulary lives — this store reports through
// it rather than inventing a second error type for one package.
func mcpError(t *testing.T, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v (%T) is not an *Error; there is no error_class to report (IP §4)", err, err)
	}
	return e
}

// ---------------------------------------------------------------------------
// HAR-002 — #101. Both branches of the routing rule, exercised.
//
// A routing rule nothing exercises is a routing rule nobody has checked, which
// is exactly how #101 survived in nine harnesses at once. This case pins the
// two outcomes apart: an ABSENT dependency is a skip, and anything else is a
// failure that says so.
// ---------------------------------------------------------------------------

func TestHAR002AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
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

	t.Run("no gitsign is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_GITSIGN", filepath.Join(t.TempDir(), "no-such-gitsign"))
		_, err := scFindGitsign(t.Context())
		if err == nil {
			t.Fatal("scFindGitsign accepted a path that does not exist")
		}
		if !errors.Is(err, errDependencyAbsent) {
			t.Fatalf("%v does not wrap errDependencyAbsent; a machine without gitsign "+
				"would be told the suite FAILED", err)
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
		err := fmt.Errorf("could not start the idempotency store's postgres: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, errDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errDependencyAbsent; it would " +
				"be reported as a skip and the idempotency, SIG-001 and MCP-012 cases would silently not run")
		}
		skip, failure := startupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
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
}
