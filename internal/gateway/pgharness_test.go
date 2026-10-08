// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/dockertest"
	"innsegl.dev/innsegl/internal/ledger"
)

// A real Postgres, never a mock.
//
// GID-007 through GID-009 are claims about a trigger the database enforces
// and a lookup that has to survive a process restart intact. A mocked
// database would prove nothing about either: whether UPDATE, DELETE and
// TRUNCATE are actually refused by migrations/0007's trigger, and whether a
// second PostgresMappingStore opened against the same DSN sees what the
// first wrote, are both claims about real Postgres and not about this
// package's own Go code.
//
// Without Docker these skip, naming what went unproven -- the same #101
// distinction internal/ledger, internal/rundir and every other
// Postgres-backed package's harness makes.

const (
	postgresUser     = "innsegl"
	postgresPassword = "innsegl-test"
	postgresDB       = "innsegl"
)

var (
	sharedPG      *pgContainer
	dockerSkip    string
	dockerFailure string
	testDBSeq     atomic.Int64
)

type pgContainer struct {
	id   string
	port string
}

func (c *pgContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, c.port, database)
}

func startPG(ctx context.Context) (*pgContainer, error) {
	port, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := dockertest.Docker(ctx, "run", "--detach",
		"--label", "dev.innsegl.test=1",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		dockertest.PostgresImage(),
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

func (c *pgContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := dockertest.Docker(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if err := dockertest.Usable(ctx); err != nil {
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		dockerSkip, dockerFailure = dockertest.StartupOutcome(
			fmt.Errorf("could not start %s: %w", dockertest.PostgresImage(), err))
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

// requirePG hands the calling test the shared Postgres, or ends the test the
// honest way: a skip when there is no Docker, a FAILURE when Docker is there
// and the database is not (#101).
func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	switch dockertest.Need(sharedPG != nil, dockerSkip, dockerFailure) {
	case dockertest.FailTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present and "+
			"working: %s\n\nThis is a FAILURE and not a skip (#101). GID-007 "+
			"through GID-009 are claims about migrations/0007's trigger and about "+
			"a lookup surviving a restart, both against a real database; "+
			"reporting an infrastructure fault as a skip exits zero and reports "+
			"ok while neither ran.", dockerFailure)
	case dockertest.SkipTest:
		t.Skipf("skipping: no real Postgres (%s). "+
			"This test proves nothing about the store without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
	case dockertest.Proceed:
	}
	return sharedPG
}

// freshDatabase creates an empty database inside c and returns its DSN. One
// database per test is not tidiness: ADR-0005 scopes a chain to a database,
// so a database per test is a chain per test, and this table lives inside
// that same chain's database.
func freshDatabase(t *testing.T, c *pgContainer) string {
	t.Helper()
	name := fmt.Sprintf("gw_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))

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

// newMigratedMappingStore opens a PostgresMappingStore on a freshly migrated
// database of its own, and returns the DSN alongside it so a test can also
// open a second store (GID-009: a restarted gateway) or a raw connection
// (GID-007: what direct SQL is refused).
//
// Migration runs through internal/ledger.Store.Migrate -- the one applier
// this project has for any migration, migrations/0007 included -- exactly as
// production brings this table up, never through a second path invented for
// the test.
func newMigratedMappingStore(t *testing.T) (*PostgresMappingStore, string) {
	t.Helper()
	c := requirePG(t)
	dsn := freshDatabase(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	led, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	defer led.Close()
	if merr := led.Migrate(ctx); merr != nil {
		t.Fatalf("ledger.Migrate: %v", merr)
	}

	store, err := OpenPostgresMappingStore(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPostgresMappingStore: %v", err)
	}
	t.Cleanup(store.Close)
	return store, dsn
}

// rawMappingConn opens a plain pgx connection, bypassing PostgresMappingStore
// entirely. GID-007 needs one: the point is what direct SQL is refused, not
// what the Go API declines to offer.
func rawMappingConn(t *testing.T, dsn string) *pgx.Conn {
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

// ---------------------------------------------------------------------------
// The skip-versus-failure rule (#101), exercised for this package's own
// harness -- the same case every other Postgres-backed package's harness
// carries (internal/ledger's TestHAR001, internal/dockertest's TestHAR003, and
// so on). Not itself cataloged under a HAR id: this package's harness is new
// with this issue, and #101's rule is what every one of them already proves,
// not a new claim about the gateway.
// ---------------------------------------------------------------------------

func TestGatewayPostgresHarnessSkipVersusFailure(t *testing.T) {
	t.Run("no docker is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
		err := dockertest.Usable(t.Context())
		if err == nil {
			t.Fatal("dockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, dockertest.ErrDependencyAbsent) {
			t.Fatalf("%v does not wrap dockertest.ErrDependencyAbsent, so it would be routed to a "+
				"FAILURE and a developer with no Docker could not run this package", err)
		}
		skip, failure := dockertest.StartupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		err := fmt.Errorf("could not start the run mapping's postgres: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, dockertest.ErrDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps dockertest.ErrDependencyAbsent; it would " +
				"be reported as a skip and GID-007 through GID-009 would silently not run")
		}
		skip, failure := dockertest.StartupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("startupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("a healthy start-up is neither", func(t *testing.T) {
		if skip, failure := dockertest.StartupOutcome(nil); skip != "" || failure != "" {
			t.Fatalf("startupOutcome(nil) = (%q, %q), want both empty", skip, failure)
		}
	})

	t.Run("a failure outranks a skip", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			up            bool
			skip, failure string
			want          dockertest.Requirement
		}{
			{"a failure outranks everything", false, "no docker", "boom", dockertest.FailTest},
			{"nothing up and no failure is a skip", false, "no docker", "", dockertest.SkipTest},
			{"a live dependency proceeds", true, "", "", dockertest.Proceed},
		} {
			if got := dockertest.Need(tc.up, tc.skip, tc.failure); got != tc.want {
				t.Errorf("%s: dockertest.Need(%v, %q, %q) = %d, want %d",
					tc.name, tc.up, tc.skip, tc.failure, got, tc.want)
			}
		}
	})
}
