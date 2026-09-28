// SPDX-License-Identifier: Apache-2.0

package gateway

// gwpgharness_test.go — RM-231 (#376): a real, throwaway Postgres for
// registrar_test.go. MCPRegistrar.Register and Restore call straight into
// internal/mcp.RegisterRunForGateway, which runs register_agent's own mint
// path — and that path's idempotency claim (ADR-0017) is a real
// *mcp.IdempotencyStore backed by a real pgxpool.Pool, a concrete type this
// package cannot fake. internal/mcp's own test suite
// (idempotency_pgharness_test.go) faces the identical requirement and
// solves it the identical way: one throwaway container, standed up once for
// the package's test binary, never the running deployment's own
// innsegl-postgres (doc 05's; touching it would not be a throwaway
// database). #101, from that file, is the reason this is a FAILURE and not
// a SKIP when Docker is present and the container still does not start —
// only an absent Docker daemon is honestly a skip.

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

const (
	gwPostgresImage    = "postgres:16"
	gwPostgresUser     = "innsegl"
	gwPostgresPassword = "innsegl-gateway-test"
	gwPostgresDB       = "innsegl"
)

var (
	gwSharedPG      *gwPGContainer
	gwDockerSkip    string
	gwDockerFailure string
	gwTestDBSeq     atomic.Int64
)

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	switch {
	case os.Getenv("INNSEGL_TEST_NO_DOCKER") != "":
		gwDockerSkip = "INNSEGL_TEST_NO_DOCKER is set"
	default:
		if _, err := exec.LookPath("docker"); err != nil {
			gwDockerSkip = fmt.Sprintf("no docker binary: %v", err)
		} else if _, verr := gwDocker(ctx, "version", "--format", "{{.Server.Version}}"); verr != nil {
			gwDockerSkip = fmt.Sprintf("no reachable docker daemon: %v", verr)
		} else if pg, serr := gwStartPG(ctx); serr != nil {
			// Docker answered and the container still did not come up: a
			// FAILURE, not a skip (#101) — an infrastructure fault reported
			// as a skip exits zero while GID-002's restore-path composition
			// through MCPRegistrar never ran.
			gwDockerFailure = serr.Error()
		} else {
			gwSharedPG = pg
		}
	}
	cancel()

	code := m.Run()

	if gwSharedPG != nil {
		if err := gwSharedPG.remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing gateway test postgres: %v\n", err)
		}
	}
	os.Exit(code)
}

// requireGWPG skips the calling test when no real Postgres came up, and
// fails it outright when Docker is present and working but the container
// still did not start (#101).
func requireGWPG(t *testing.T) *gwPGContainer {
	t.Helper()
	switch {
	case gwDockerFailure != "":
		t.Fatalf("the gateway test Postgres did not come up, and Docker is present and "+
			"working: %s\n\nThis is a FAILURE and not a skip: MCPRegistrar's Register and "+
			"Restore did not run.", gwDockerFailure)
	case gwSharedPG == nil:
		t.Skipf("skipping: no real Postgres (%s). MCPRegistrar's composition through "+
			"internal/mcp proves nothing without one; start Docker and re-run.", gwDockerSkip)
	}
	return gwSharedPG
}

func gwDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, strings.Join(strings.Fields(stderr.String()), " "))
	}
	return strings.TrimSpace(string(out)), nil
}

type gwPGContainer struct {
	id   string
	port string
}

func (c *gwPGContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		gwPostgresUser, gwPostgresPassword, c.port, database)
}

func (c *gwPGContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := gwDocker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

func gwFreeHostPort(ctx context.Context) (string, error) {
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

func gwStartPG(ctx context.Context) (*gwPGContainer, error) {
	port, err := gwFreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := gwDocker(ctx, "run", "--detach",
		// Labelled the same way internal/mcp's own throwaway containers are,
		// so a leaked one is findable by the same `make test-clean`.
		"--label", "dev.innsegl.test=1",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+gwPostgresUser,
		"--env", "POSTGRES_PASSWORD="+gwPostgresPassword,
		"--env", "POSTGRES_DB="+gwPostgresDB,
		gwPostgresImage,
	)
	if err != nil {
		return nil, err
	}
	c := &gwPGContainer{id: id, port: port}
	if err := c.waitReady(ctx, 90*time.Second); err != nil {
		if rerr := c.remove(); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		return nil, err
	}
	return c, nil
}

func (c *gwPGContainer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pgx.Connect(attempt, c.dsn(gwPostgresDB))
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

// gwFreshDSN creates an empty database inside c and returns its DSN: one
// database per test, exactly as internal/mcp's own freshDSN does, and for
// the identical reason — the idempotency store is scoped to a database, so
// a database per test is a key space per test.
func gwFreshDSN(t *testing.T, c *gwPGContainer) string {
	t.Helper()
	name := fmt.Sprintf("gw_%d_%d", os.Getpid()%100000, gwTestDBSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, c.dsn(gwPostgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", gwPostgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()

	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return c.dsn(name)
}

// gwMigrate applies the shipped migrations through the ledger's own runner —
// the idempotency table ships in migration 0002, so a database that has run
// this has the idempotency store's schema too.
func gwMigrate(t *testing.T, dsn string) {
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

// gwPool opens a pgx pool the caller owns, exactly as an MCP replica would.
func gwPool(t *testing.T, dsn string) *pgxpool.Pool {
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
