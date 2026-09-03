// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A real Postgres, never a mock — and #101's corrected outcome shape.
//
// #101: eight harnesses sent "no Docker" and "the container did not start" to
// the same variable, and the second silently became a skip. `go test` exits
// zero, the package reports ok, and the case that proves the invariant did not
// run. internal/verify/verifyharness_test.go carries the corrected shape and
// test/smoke copied it; this is the third copy, deliberately identical.
//
// The rule: an ABSENT dependency is a skip. A dependency that is present and
// BROKE is a failure. They never share a variable.
// ---------------------------------------------------------------------------

const (
	// postgresImage is pinned by major version. The behaviour these tests
	// measure — ACL checks, statement triggers, ALTER DEFAULT PRIVILEGES —
	// has been stable for a decade, and the compose stack pins the digest.
	postgresImage = "postgres:16"

	ownerRole     = "innsegl"
	ownerPassword = "innsegl-deploy-test"
	ownerDatabase = "innsegl"

	// appenderRole is doc 05 §1's append-only role. It is a default and not a
	// protected string; deploy/compose/innsegl/db-init.sh takes it as a
	// parameter, exactly as api.EnsureReadOnlyRole takes the reader's name.
	appenderRole     = "innsegl_appender"
	appenderPassword = "innsegl-deploy-test-appender"

	// readerRole is the role `innsegl api` connects as — api.ReadOnlyRole,
	// spelled here rather than imported for the same reason appenderRole is
	// spelled: the deployment takes it as a parameter and a test that read its
	// expectation out of the code under test would agree with it by
	// construction.
	readerRole     = "innsegl_reader"
	readerPassword = "innsegl-deploy-test-reader"
)

var errDependencyAbsent = errors.New("a required dependency is absent")

// startupOutcome routes a start-up error to exactly one of the two variables.
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

// requirement is what a harness must do for the calling test.
type requirement int

const (
	proceed requirement = iota
	skipTest
	failTest
)

// containerRequirement decides between the three. A failure outranks a skip:
// if the dependency broke, the reason it broke is what the developer needs.
func containerRequirement(up bool, skip, failure string) requirement {
	switch {
	case failure != "":
		return failTest
	case !up:
		return skipTest
	default:
		return proceed
	}
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

// dockerUsable reports whether a docker daemon is reachable. Its error is the
// ONLY one in this package wrapped as an absent dependency.
func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errDependencyAbsent)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errDependencyAbsent)
	}
	return nil
}

// freeHostPort reserves an ephemeral port and hands it back.
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

// ledgerContainer is one containerised Postgres carrying the shipped ledger
// schema, provisioned by the shipped deploy scripts and nothing else.
//
// It creates NO docker network of its own: it publishes on loopback and every
// script runs inside it through `docker exec`. #100 — this machine tops out at
// roughly twenty-nine networks and two chaos harnesses already hold several —
// so a harness that can cost zero networks costs zero.
type ledgerContainer struct {
	name string
	port string
}

// ownerDSN is the administrative connection: the role that owns the schema.
func (c *ledgerContainer) ownerDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		ownerRole, ownerPassword, c.port, ownerDatabase)
}

// appenderDSN is the credential doc 05 §1 runs the MCP on.
func (c *ledgerContainer) appenderDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		appenderRole, appenderPassword, c.port, ownerDatabase)
}

// readerDSN is the credential doc 05 §1 mounts on the dashboard — $INNSEGL_API_DSN
// and never $INNSEGL_LEDGER_DSN.
func (c *ledgerContainer) readerDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		readerRole, readerPassword, c.port, ownerDatabase)
}

func startLedger(ctx context.Context, t *testing.T) (*ledgerContainer, error) {
	t.Helper()
	if err := dockerUsable(ctx); err != nil {
		return nil, err
	}
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserving a host port: %w", err)
	}
	name := fmt.Sprintf("innsegl-deploy-pg-%d", os.Getpid())
	// A previous run that was killed rather than torn down leaves the name
	// taken; removing it is not an error worth reporting.
	discardError(docker(ctx, "rm", "--force", "--volumes", name))

	if _, err := docker(ctx, "run", "--detach",
		"--name", name,
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+ownerRole,
		"--env", "POSTGRES_PASSWORD="+ownerPassword,
		"--env", "POSTGRES_DB="+ownerDatabase,
		postgresImage,
	); err != nil {
		return nil, fmt.Errorf("starting the ledger's postgres: %w", err)
	}
	c := &ledgerContainer{name: name, port: port}

	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		if _, last = docker(ctx, "exec", name,
			"pg_isready", "-U", ownerRole, "-d", ownerDatabase); last == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			c.stop()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	c.stop()
	return nil, fmt.Errorf("the ledger never accepted a connection: %w", last)
}

func (c *ledgerContainer) stop() {
	if c == nil || c.name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	discardError(docker(ctx, "rm", "--force", "--volumes", c.name))
}

// discardError swallows an error a caller genuinely cannot act on. errcheck
// runs with check-blank in this repository, so the discard is a NAMED function
// rather than a blank assignment — internal/api/readonly.go's idiom, and for
// its stated reason: a discard should be visible and explained, not invisible.
func discardError(string, error) {}

// copyDeployScripts puts the SHIPPED migrations and the SHIPPED init scripts
// into the container at the paths deploy/compose/innsegl.yml mounts them.
//
// The paths match the compose file on purpose: what this test runs must be the
// artifact an adopter runs, not a second arrangement of the same files.
func (c *ledgerContainer) copyDeployScripts(ctx context.Context, root string) error {
	if _, err := docker(ctx, "exec", c.name, "mkdir", "-p", "/innsegl"); err != nil {
		return err
	}
	for _, cp := range [][2]string{
		{root + "/migrations/.", "/innsegl/migrations"},
		{root + "/deploy/compose/innsegl/.", "/innsegl/init"},
		// internal/api/readonly.sql, at the path deploy/compose/innsegl.yml
		// mounts it. NOT A COPY, for the reason the migrations are not a copy:
		// api.EnsureReadOnlyRole embeds this exact file, and a second set of
		// GRANTs in deploy/ would be a read-only posture that could drift from
		// the one the API's own start-up assertion measures against.
		{root + "/internal/api/readonly.sql", "/innsegl/api/readonly.sql"},
	} {
		dir := cp[1]
		if strings.HasSuffix(dir, ".sql") {
			dir = dir[:strings.LastIndexByte(dir, '/')]
		}
		if _, err := docker(ctx, "exec", c.name, "mkdir", "-p", dir); err != nil {
			return err
		}
		if _, err := docker(ctx, "cp", cp[0], c.name+":"+cp[1]); err != nil {
			return fmt.Errorf("copying %s into the container: %w", cp[0], err)
		}
	}
	return nil
}

// runInit runs one shipped script inside the container, with the environment
// deploy/compose/innsegl.yml gives it, and returns its combined output.
func (c *ledgerContainer) runInit(ctx context.Context, script string, extra ...string) (string, error) {
	args := []string{"exec",
		"--env", "PGHOST=127.0.0.1",
		"--env", "PGPORT=5432",
		"--env", "PGUSER=" + ownerRole,
		"--env", "PGPASSWORD=" + ownerPassword,
		"--env", "PGDATABASE=" + ownerDatabase,
		"--env", "INNSEGL_APPENDER_ROLE=" + appenderRole,
		"--env", "INNSEGL_APPENDER_PASSWORD=" + appenderPassword,
		"--env", "INNSEGL_READER_ROLE=" + readerRole,
		"--env", "INNSEGL_READER_PASSWORD=" + readerPassword,
		"--env", "INNSEGL_READONLY_SQL=/innsegl/api/readonly.sql",
	}
	args = append(args, extra...)
	args = append(args, c.name, "sh", "/innsegl/init/"+script)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// psqlAsOwner runs one statement as the schema owner, for the tests that have
// to widen the role in order to prove the check bites.
func (c *ledgerContainer) psqlAsOwner(ctx context.Context, sql string) error {
	_, err := docker(ctx, "exec",
		"--env", "PGPASSWORD="+ownerPassword,
		c.name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
		"-U", ownerRole, "-d", ownerDatabase, "-c", sql)
	return err
}
