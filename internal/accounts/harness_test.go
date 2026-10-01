// SPDX-License-Identifier: Apache-2.0

package accounts

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

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/migrations"
)

// A real Postgres, never a mock — the same shape as internal/api's harness.
// Docker absent is a skip; a container that will not start is a failure,
// never a skip (#101).

const (
	pgUser     = "innsegl"
	pgPassword = "innsegl-test"
	pgDatabase = "innsegl"
	pgImage    = "postgres:16"

	writerPassword = "authwriter-test-password"
)

var (
	sharedPG  *pgContainer
	pgSkip    string
	pgFailure string
	dbSeq     atomic.Int64
)

type pgContainer struct{ id, port string }

func (c *pgContainer) dsn(database, user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", user, password, c.port, database)
}

func dockerRun(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// removeContainer is best-effort cleanup; a failure is worth a line on
// stderr and nothing more.
func removeContainer(ctx context.Context, id string) {
	if _, err := dockerRun(ctx, "rm", "--force", "--volumes", id); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removing test container: %v\n", err)
	}
}

func startPG(ctx context.Context) (*pgContainer, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	_, port, splitErr := net.SplitHostPort(l.Addr().String())
	if closeErr := l.Close(); closeErr != nil || splitErr != nil {
		return nil, fmt.Errorf("reserve a port: %w", errors.Join(splitErr, closeErr))
	}
	id, err := dockerRun(ctx, "run", "--detach",
		"--name", fmt.Sprintf("innsegl-accttest-%d", os.Getpid()),
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+pgUser, "--env", "POSTGRES_PASSWORD="+pgPassword,
		"--env", "POSTGRES_DB="+pgDatabase, pgImage)
	if err != nil {
		return nil, err
	}
	c := &pgContainer{id: id, port: port}
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, cerr := pgx.Connect(attempt, c.dsn(pgDatabase, pgUser, pgPassword))
		if cerr == nil {
			cerr = conn.Ping(attempt)
			_ = conn.Close(attempt)
		}
		cancel()
		if cerr == nil {
			return c, nil
		}
		last = cerr
		time.Sleep(250 * time.Millisecond)
	}
	removeContainer(ctx, id)
	return nil, fmt.Errorf("postgres never became ready: %w", last)
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	switch {
	case os.Getenv("INNSEGL_TEST_NO_DOCKER") != "":
		pgSkip = "INNSEGL_TEST_NO_DOCKER is set"
	case func() bool { _, err := exec.LookPath("docker"); return err != nil }():
		pgSkip = "docker is not on PATH"
	default:
		if _, err := dockerRun(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
			pgSkip = "no reachable docker daemon: " + err.Error()
		} else if pg, err := startPG(ctx); err != nil {
			pgFailure = err.Error()
		} else {
			sharedPG = pg
		}
	}
	cancel()
	code := m.Run()
	if sharedPG != nil {
		rctx, rcancel := context.WithTimeout(context.Background(), time.Minute)
		removeContainer(rctx, sharedPG.id)
		rcancel()
	}
	os.Exit(code)
}

func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	if pgFailure != "" {
		t.Fatalf("the test Postgres did not come up and Docker is present: %s", pgFailure)
	}
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s)", pgSkip)
	}
	return sharedPG
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// env is one fresh database.
type env struct {
	pg       *pgContainer
	database string
	ownerDSN string
	writer   string
}

func freshDB(t *testing.T) *env {
	t.Helper()
	c := requirePG(t)
	name := fmt.Sprintf("acct_%d_%d", os.Getpid()%100000, dbSeq.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, c.dsn(pgDatabase, pgUser, pgPassword))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoteIdent(name)); err != nil {
		t.Fatalf("create database: %v", err)
	}
	return &env{pg: c, database: name, ownerDSN: c.dsn(name, pgUser, pgPassword)}
}

// migrated applies every migration, provisions the auth-writer role and
// returns a Store connected as it.
func migrated(t *testing.T) (*env, *Store) {
	t.Helper()
	e := freshDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	l, err := ledger.Open(ctx, e.ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(l.Close)
	if err := l.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return e, e.openStore(t)
}

func (e *env) openStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := api.EnsureAuthWriterRole(ctx, e.ownerDSN, api.AuthWriterRole, writerPassword); err != nil {
		t.Fatalf("EnsureAuthWriterRole: %v", err)
	}
	e.writer = e.pg.dsn(e.database, api.AuthWriterRole, writerPassword)
	s, err := Open(ctx, e.writer)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// premigration applies every migration BEFORE version `before`, the way the
// ledger runner would, so a test can put data in the old schema first.
func premigration(t *testing.T, before string) (*env, *ledger.Store) {
	t.Helper()
	e := freshDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, e.ownerDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, bootErr := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS innsegl;
		CREATE TABLE IF NOT EXISTS innsegl.schema_migrations (
			version text PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); bootErr != nil {
		t.Fatalf("bootstrap: %v", bootErr)
	}
	all, err := migrations.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.Version >= before {
			continue
		}
		if _, applyErr := conn.Exec(ctx, m.SQL); applyErr != nil {
			t.Fatalf("apply %s: %v", m.Name, applyErr)
		}
		if _, recErr := conn.Exec(ctx, `INSERT INTO innsegl.schema_migrations (version, name) VALUES ($1, $2)`,
			m.Version, m.Name); recErr != nil {
			t.Fatalf("record %s: %v", m.Name, recErr)
		}
	}
	l, err := ledger.Open(ctx, e.ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(l.Close)
	return e, l
}

func eventBody(n int) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      "tool_call",
		event.FieldTS:             "2026-08-28T09:14:03.201Z",
		event.FieldRunID:          "run-42",
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("idem-%d", n),
		"tool_name":               "git-commit",
	}
}
