// SPDX-License-Identifier: Apache-2.0

package rundir

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
// The fake-chain cases in directory_test.go decide what this reader does with
// a set of events. They cannot decide whether it reads the right set: that is
// a claim about a SQL predicate, an index and the bytes the ledger stored, and
// only a real database can answer it. ADR-0020 §5's contract in particular is
// about a chain that really carries several `run_retired` events for one run,
// so this file puts several there.
//
// Without Docker these skip, naming what went unproven.

const (
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
		// The only honest skip: there is no daemon to ask.
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		// Docker is present and working and the container still did not come
		// up. That is an infrastructure FAILURE, not an absent dependency, and
		// conflating the two is #101.
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

// newLedger opens a migrated store on a database of its own. ADR-0005 scopes a
// chain to a database, so a database per test is a chain per test.
func newLedger(t *testing.T) *ledger.Store {
	t.Helper()
	switch dockertest.Need(sharedPG != nil, dockerSkip, dockerFailure) {
	case dockertest.FailTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present and "+
			"working: %s\n\nThis is a FAILURE and not a skip (#101): an "+
			"infrastructure fault reported as a skip exits zero and reports ok "+
			"while the run-directory cases did not run.", dockerFailure)
	case dockertest.SkipTest:
		t.Skipf("skipping: no real Postgres (%s). This case is about what the reader "+
			"pulls out of a real chain; without one it would prove nothing. "+
			"Start Docker and re-run.", dockerSkip)
	case dockertest.Proceed:
	}

	name := fmt.Sprintf("rundir_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, sharedPG.dsn(postgresDB))
	if err != nil {
		t.Fatalf("connect to %s: %v", postgresDB, err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, cerr := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); cerr != nil {
		t.Fatalf("create database %s: %v", name, cerr)
	}

	store, err := ledger.Open(ctx, sharedPG.dsn(name))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	return store
}
