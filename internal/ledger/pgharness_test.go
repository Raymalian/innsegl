// SPDX-License-Identifier: Apache-2.0

package ledger

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
)

// A real Postgres, never a mock.
//
// Every LED test in this package that touches storage runs against a
// containerised Postgres brought up in TestMain. A mocked database would prove
// nothing about an append-only guarantee that is enforced by a trigger, about
// position assignment that is serialized by an advisory lock, or about what
// survives a crash — the three things RM-009 exists to establish. It is the
// same reason doc 01 §2 forbids a mocked Fulcio in the signing path.
//
// Without Docker the tests skip with a message naming what was not proven,
// rather than passing quietly.

const (
	// defaultPostgresImage is pinned by major version, not by digest: the
	// tests assert Postgres behaviour that has been stable for a decade
	// (triggers, advisory locks, crash recovery), and pinning a digest here
	// would rot without buying anything.
	defaultPostgresImage = "postgres:16"

	postgresUser     = "innsegl"
	postgresPassword = "innsegl-test"
	postgresDB       = "innsegl"
)

// dockerSkipReason is set once by TestMain when the container could not be
// started. Empty means the shared container is up.
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

// docker runs one docker command and returns its trimmed stdout.
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

// dockerUsable reports whether a docker daemon is reachable.
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

// pgContainer is one containerised Postgres.
type pgContainer struct {
	id    string
	image string
	port  string
}

// dsn is the connection string for one database inside the container.
func (c *pgContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, c.port, database)
}

// freeHostPort reserves an ephemeral port and hands it back. The container is
// published on a fixed host port rather than a docker-assigned one because
// LED-009 restarts it, and a docker-assigned port changes on every start —
// which would look like recovery failing when it is the test moving the goal.
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

// startPG launches a Postgres container on a fixed host port and waits until
// it accepts connections.
func startPG(ctx context.Context) (*pgContainer, error) {
	image := postgresImage()
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		// A ledger that loses a committed event is not a ledger. fsync stays
		// on: LED-009 asserts that an acknowledged append survives a SIGKILL,
		// and that assertion is meaningless with fsync off.
		image, "-c", "fsync=on",
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

// waitReady polls until a connection succeeds.
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
// the restart goes through WAL crash recovery (LED-009).
func (c *pgContainer) kill(ctx context.Context) error {
	_, err := docker(ctx, "kill", "--signal", "SIGKILL", c.id)
	return err
}

// restart brings a killed container back and waits for it to accept
// connections. The host port is stable across a start of the same container.
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
			"This test proves nothing about the store without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
	}
	return sharedPG
}

// freshDSN creates an empty database inside c and returns its DSN.
//
// One database per test is not tidiness. ADR-0005 scopes a chain to a
// database, so a database per test is a chain per test — the isolation the
// design already implies.
func freshDSN(t *testing.T, c *pgContainer) string {
	t.Helper()
	name := fmt.Sprintf("led_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, c.dsn(postgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", postgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgQuoteIdent(name)); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return c.dsn(name)
}

// pgQuoteIdent quotes an SQL identifier. Test-local: the store itself never
// interpolates an identifier into SQL.
func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// newStore opens a migrated store on a database of its own.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	c := requirePG(t)
	dsn := freshDSN(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, dsn
}

// rawConn opens a plain pgx connection, bypassing the store entirely. LED-003
// needs one: the point is what direct SQL is refused, not what the Go API
// declines to offer.
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
