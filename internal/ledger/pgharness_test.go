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

// dockerSkip is set once by TestMain when there is no Docker daemon to ask.
// dockerFailure is set when Docker is present and the container still did not
// start — a different outcome with a different verdict (#101). Both empty
// means the shared container is up.
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
// honest: there is no Docker daemon, or INNSEGL_TEST_NO_DOCKER asks for none. Nothing else wraps it.
//
// Everything else that can go wrong while standing the dependency up — an
// image that cannot be pulled, a port that cannot be bound, a network Docker
// refuses to create because its predefined address pools are used up, a server
// that never becomes ready — is a FAILURE. Reporting one of those as a skip
// turns it into a pass-shaped outcome: `go test` exits zero, the package
// reports ok, and LED-001 through LED-009 — the append-only chain, I1 and I2 — did not run. That is what CI produced on a runner
// whose "Require Docker" step had already passed, and what
// internal/reconciler's drift case produced locally on the same day.
//
// internal/verify/verifyharness_test.go carries the reference shape; both
// branches here are exercised by
// TestHAR001AnAbsentDependencyIsASkipAndAFaultIsAFailure.
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

// dockerUsable reports whether a docker daemon is reachable.
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

// requirePG hands the calling test the shared Postgres, or ends the test the
// honest way: a skip when there is no Docker, a FAILURE when Docker is there
// and the database is not.
func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	switch harnessNeed(sharedPG != nil, dockerSkip, dockerFailure) {
	case harnessFailTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present and "+
			"working: %s\n\nThis is a FAILURE and not a skip (#101). LED-001 "+
			"through LED-009 are claims about an append-only chain enforced by a "+
			"trigger in a real database; reporting an infrastructure fault as a "+
			"skip exits zero and reports ok while not one of them ran.",
			dockerFailure)
	case harnessSkipTest:
		t.Skipf("skipping: no real Postgres (%s). "+
			"This test proves nothing about the store without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
	case harnessProceed:
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

// ---------------------------------------------------------------------------
// HAR-001 — #101. Both branches of the routing rule, exercised.
//
// A routing rule nothing exercises is a routing rule nobody has checked, which
// is exactly how #101 survived in nine harnesses at once. This case pins the
// two outcomes apart: an ABSENT dependency is a skip, and anything else is a
// failure that says so.
// ---------------------------------------------------------------------------

func TestHAR001AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
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

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine, and the shape the CI
		// run in #101 produced: Docker is present, working, and refuses to
		// create the network because its address pools are used up.
		err := fmt.Errorf("could not start the ledger's postgres: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, errDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errDependencyAbsent; it would " +
				"be reported as a skip and LED-001 through LED-009 would silently not run")
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
