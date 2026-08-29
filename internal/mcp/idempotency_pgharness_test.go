// SPDX-License-Identifier: Apache-2.0

package mcp

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

var (
	sharedPG        *pgContainer
	dockerSkip      string
	testDBSeq       atomic.Int64
	errDockerAbsent = errors.New("docker is not available")
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

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDockerAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errDockerAbsent, err)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errDockerAbsent, err)
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
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		dockerSkip = fmt.Sprintf("could not start %s: %v", postgresImage(), err)
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
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s). "+
			"This test proves nothing about the idempotency store without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
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
