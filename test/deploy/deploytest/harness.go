// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
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

	OwnerRole     = "innsegl"
	ownerPassword = "innsegl-deploy-test"
	OwnerDatabase = "innsegl"

	// AppenderRole is doc 05 §1's append-only role. It is a default and not a
	// protected string; deploy/compose/innsegl/db-init.sh takes it as a
	// parameter, exactly as api.EnsureReadOnlyRole takes the reader's name.
	AppenderRole     = "innsegl_appender"
	appenderPassword = "innsegl-deploy-test-appender"

	// ReaderRole is the role `innsegl api` connects as — api.ReadOnlyRole,
	// spelled here rather than imported for the same reason appenderRole is
	// spelled: the deployment takes it as a parameter and a test that read its
	// expectation out of the code under test would agree with it by
	// construction.
	ReaderRole     = "innsegl_reader"
	readerPassword = "innsegl-deploy-test-reader"

	// BackupRole is the role the backup service connects as (RM-146, #237):
	// the reader's grants over the ledger plus CREATEDB, because the backup
	// proves a dump restores by restoring it into a throwaway database of its
	// own. Spelled here for the same reason the other two are.
	BackupRole     = "innsegl_backup"
	backupPassword = "innsegl-deploy-test-backup"
	// The sign-in store's writer (RM-260/RM-261): its own schema, no grant
	// on the ledger; db-init.sh provisions it beside the other three.
	AuthwriterRole     = "innsegl_authwriter"
	authwriterPassword = "innsegl-deploy-test-authwriter"
	// The alert resolver (RM-330): may insert an alert resolution and
	// nothing else; db-init.sh provisions it beside the other four.
	ResolverRole     = "innsegl_resolver"
	resolverPassword = "innsegl-deploy-test-resolver"
)

// Requirement is what a harness must do for the calling test.
type Requirement int

const (
	Proceed Requirement = iota
	SkipTest
	FailTest
)

// ContainerRequirement decides between the three. A failure outranks a skip:
// if the dependency broke, the reason it broke is what the developer needs.
func ContainerRequirement(up bool, skip, failure string) Requirement {
	switch {
	case failure != "":
		return FailTest
	case !up:
		return SkipTest
	default:
		return Proceed
	}
}

// LedgerContainer is one containerised Postgres carrying the shipped ledger
// schema, provisioned by the shipped deploy scripts and nothing else.
//
// It creates NO docker network of its own: it publishes on loopback and every
// script runs inside it through `docker exec`. #100 — this machine tops out at
// roughly twenty-nine networks and two chaos harnesses already hold several —
// so a harness that can cost zero networks costs zero.
type LedgerContainer struct {
	Name string
	port string
}

// OwnerDSN is the administrative connection: the role that owns the schema.
func (c *LedgerContainer) OwnerDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		OwnerRole, ownerPassword, c.port, OwnerDatabase)
}

// AppenderDSN is the credential doc 05 §1 runs the MCP on.
func (c *LedgerContainer) AppenderDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		AppenderRole, appenderPassword, c.port, OwnerDatabase)
}

// ReaderDSN is the credential doc 05 §1 mounts on the dashboard — $INNSEGL_API_DSN
// and never $INNSEGL_LEDGER_DSN.
func (c *LedgerContainer) ReaderDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		ReaderRole, readerPassword, c.port, OwnerDatabase)
}

// AuthwriterDSN is the sign-in store's credential (RM-260/RM-261), the one
// `innsegl api` checks sessions with; it holds no grant on the ledger.
func (c *LedgerContainer) AuthwriterDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		AuthwriterRole, authwriterPassword, c.port, OwnerDatabase)
}

// ResolverDSN is the alert resolver's credential (RM-330).
func (c *LedgerContainer) ResolverDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		ResolverRole, resolverPassword, c.port, OwnerDatabase)
}

func StartLedger(ctx context.Context, t *testing.T) (*LedgerContainer, error) {
	t.Helper()
	return StartLedgerOwner(ctx, t, ownerPassword)
}

// StartLedgerOwner is startLedger with the owner's password chosen by the
// caller, the way POSTGRES_PASSWORD_FILE chooses it on a first start.
func StartLedgerOwner(ctx context.Context, t *testing.T, owner string) (*LedgerContainer, error) {
	t.Helper()
	if err := dockertest.Usable(ctx); err != nil {
		return nil, err
	}
	port, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserving a host port: %w", err)
	}
	name := fmt.Sprintf("innsegl-deploy-pg-%d", os.Getpid())
	// A previous run that was killed rather than torn down leaves the name
	// taken; removing it is not an error worth reporting.
	DiscardError(dockertest.Docker(ctx, "rm", "--force", "--volumes", name))

	if _, err := dockertest.Docker(ctx, "run", "--detach",
		"--name", name,
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+OwnerRole,
		"--env", "POSTGRES_PASSWORD="+owner,
		"--env", "POSTGRES_DB="+OwnerDatabase,
		postgresImage,
	); err != nil {
		return nil, fmt.Errorf("starting the ledger's postgres: %w", err)
	}
	c := &LedgerContainer{Name: name, port: port}

	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		if _, last = dockertest.Docker(ctx, "exec", name,
			"pg_isready", "-U", OwnerRole, "-d", OwnerDatabase); last == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			c.Stop()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	c.Stop()
	return nil, fmt.Errorf("the ledger never accepted a connection: %w", last)
}

func (c *LedgerContainer) Stop() {
	if c == nil || c.Name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	DiscardError(dockertest.Docker(ctx, "rm", "--force", "--volumes", c.Name))
}

// DiscardError swallows an error a caller genuinely cannot act on. errcheck
// runs with check-blank in this repository, so the discard is a NAMED function
// rather than a blank assignment — internal/api/readonly.go's idiom, and for
// its stated reason: a discard should be visible and explained, not invisible.
func DiscardError(string, error) {}

// CopyDeployScripts puts the SHIPPED migrations and the SHIPPED init scripts
// into the container at the paths deploy/compose/innsegl.yml mounts them.
//
// The paths match the compose file on purpose: what this test runs must be the
// artifact an adopter runs, not a second arrangement of the same files.
func (c *LedgerContainer) CopyDeployScripts(ctx context.Context, root string) error {
	if _, err := dockertest.Docker(ctx, "exec", c.Name, "mkdir", "-p", "/innsegl"); err != nil {
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
		{root + "/internal/api/authwriter.sql", "/innsegl/api/authwriter.sql"},
		{root + "/internal/api/resolver.sql", "/innsegl/api/resolver.sql"},
	} {
		dir := cp[1]
		if strings.HasSuffix(dir, ".sql") {
			dir = dir[:strings.LastIndexByte(dir, '/')]
		}
		if _, err := dockertest.Docker(ctx, "exec", c.Name, "mkdir", "-p", dir); err != nil {
			return err
		}
		if _, err := dockertest.Docker(ctx, "cp", cp[0], c.Name+":"+cp[1]); err != nil {
			return fmt.Errorf("copying %s into the container: %w", cp[0], err)
		}
	}
	return nil
}

// RunInit runs one shipped script inside the container, with the environment
// deploy/compose/innsegl.yml gives it, and returns its combined output.
func (c *LedgerContainer) RunInit(ctx context.Context, script string, extra ...string) (string, error) {
	args := []string{"exec",
		"--env", "PGHOST=127.0.0.1",
		"--env", "PGPORT=5432",
		"--env", "PGUSER=" + OwnerRole,
		"--env", "PGPASSWORD=" + ownerPassword,
		"--env", "PGDATABASE=" + OwnerDatabase,
		"--env", "INNSEGL_APPENDER_ROLE=" + AppenderRole,
		"--env", "INNSEGL_APPENDER_PASSWORD=" + appenderPassword,
		"--env", "INNSEGL_READER_ROLE=" + ReaderRole,
		"--env", "INNSEGL_READER_PASSWORD=" + readerPassword,
		"--env", "INNSEGL_BACKUP_ROLE=" + BackupRole,
		"--env", "INNSEGL_BACKUP_PASSWORD=" + backupPassword,
		"--env", "INNSEGL_READONLY_SQL=/innsegl/api/readonly.sql",
		"--env", "INNSEGL_AUTHWRITER_ROLE=" + AuthwriterRole,
		"--env", "INNSEGL_AUTHWRITER_PASSWORD=" + authwriterPassword,
		"--env", "INNSEGL_AUTHWRITER_SQL=/innsegl/api/authwriter.sql",
		"--env", "INNSEGL_RESOLVER_ROLE=" + ResolverRole,
		"--env", "INNSEGL_RESOLVER_PASSWORD=" + resolverPassword,
		"--env", "INNSEGL_RESOLVER_SQL=/innsegl/api/resolver.sql",
	}
	args = append(args, extra...)
	args = append(args, c.Name, "sh", "/innsegl/init/"+script)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// PsqlAsOwner runs one statement as the schema owner, for the tests that have
// to widen the role in order to prove the check bites.
func (c *LedgerContainer) PsqlAsOwner(ctx context.Context, sql string) error {
	_, err := dockertest.Docker(ctx, "exec",
		"--env", "PGPASSWORD="+ownerPassword,
		c.Name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
		"-U", OwnerRole, "-d", OwnerDatabase, "-c", sql)
	return err
}
