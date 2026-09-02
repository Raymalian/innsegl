// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/ledger"
)

// A real Postgres, never a mock — and the #101 routing rule, not repeated.
//
// API-009 is about what a database credential is ALLOWED to do. "The Go code
// contains no INSERT" is a property of today's source; "the role has no INSERT
// privilege" is a property of a deployment, and only a real server can be
// asked. So the cases below run against postgres:16, and the command under
// test is given the same two credentials a deployment has: the owner the
// migrations run as, and the reader doc 05 §1 mounts on the dashboard.
//
// # THE #101 DEFECT IS NOT REPEATED HERE
//
// Eight harnesses in this repository treat "Docker is absent" and "the
// container failed to start" as the same outcome and skip for both — including
// `requireMinIOForCLI` in this very package, which is one of the eight. The
// second is an infrastructure fault: skipping it makes `go test` exit zero and
// print `ok` while the cases that carry the guarantee never ran.
//
// So this harness routes them apart, the way internal/verify's and
// internal/api's do. errAPIDependencyAbsent is wrapped ONLY by the genuinely
// absent conditions; everything else lands in apiPGFailure, and requireAPIPG
// calls t.Fatalf on it. Both branches are exercised by
// TestTheAPIHarnessSeparatesAnAbsentDockerFromAContainerThatDidNotStart,
// because a routing rule nothing exercises is a routing rule nobody has
// checked — which is exactly how #101 survived.
//
// # It starts nothing until a case asks for one
//
// The container is started lazily rather than from TestMain, so the unit half
// of this package — API-008, and every other subcommand's cases — still runs
// in under a second on a machine with no Docker at all. TestMain exists only
// to remove the container afterwards.

const (
	// apiPGImage is pinned by major version, matching internal/api and
	// internal/ledger: what these cases assert about GRANTs has been stable in
	// Postgres for decades.
	apiPGImage = "postgres:16"

	apiPGUser     = "innsegl"
	apiPGPassword = "innsegl-test"
	apiPGDatabase = "innsegl"

	// apiReaderRole and apiReaderPassword are the read-only credential the
	// command is meant to run on. The password names itself a test fixture.
	apiReaderRole     = api.ReadOnlyRole
	apiReaderPassword = "api-cli-reader-password"
)

// errAPIDependencyAbsent marks the only conditions under which skipping these
// cases is honest: no Docker daemon, or no git. A container that would not
// start on a machine that HAS Docker is not one of them.
var errAPIDependencyAbsent = errors.New("a required dependency is absent")

var (
	apiPGOnce    sync.Once
	apiPGShared  *apiPGContainer
	apiPGSkip    string
	apiPGFailure string
	apiDBSeq     atomic.Int64
)

func TestMain(m *testing.M) {
	code := m.Run()
	if apiPGShared != nil {
		if err := apiPGShared.remove(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing the test Postgres: %v\n", err)
		}
	}
	os.Exit(code)
}

type apiPGContainer struct {
	id   string
	port string
}

func (c *apiPGContainer) dsn(database, user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		user, password, c.port, database)
}

// ownerDSN is the credential the migrations run as. It is deliberately NOT
// what `innsegl api` is meant to be given, and API-009 hands it over on
// purpose.
func (c *apiPGContainer) ownerDSN(database string) string {
	return c.dsn(database, apiPGUser, apiPGPassword)
}

func (c *apiPGContainer) readerDSN(database string) string {
	return c.dsn(database, apiReaderRole, apiReaderPassword)
}

func dockerCLI(ctx context.Context, args ...string) (string, error) {
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

// apiDependenciesPresent reports the ABSENCE of a dependency and nothing else.
// Every error it returns wraps errAPIDependencyAbsent; no other function here
// does.
func apiDependenciesPresent(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errAPIDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errAPIDependencyAbsent)
	}
	if _, err := dockerCLI(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errAPIDependencyAbsent)
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not on PATH: %w: %w", err, errAPIDependencyAbsent)
	}
	return nil
}

// apiStartupOutcome routes a start-up error into exactly one of the two
// buckets. Split out so both of its branches can be exercised by a test.
func apiStartupOutcome(err error) (skip, failure string) {
	if err == nil {
		return "", ""
	}
	if errors.Is(err, errAPIDependencyAbsent) {
		return err.Error(), ""
	}
	return "", err.Error()
}

// apiRequirement is what requireAPIPG must do for the calling test.
type apiRequirement int

const (
	apiProceed apiRequirement = iota
	apiSkipTest
	apiFailTest
)

func apiPGRequirement(pg *apiPGContainer, skip, failure string) apiRequirement {
	switch {
	case failure != "":
		return apiFailTest
	case pg == nil:
		return apiSkipTest
	default:
		return apiProceed
	}
}

func apiFreeHostPort(ctx context.Context) (string, error) {
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

func startAPIPG(ctx context.Context) (*apiPGContainer, error) {
	image := apiPGImage
	if v := os.Getenv("INNSEGL_TEST_POSTGRES_IMAGE"); v != "" {
		image = v
	}
	port, err := apiFreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := dockerCLI(ctx, "run", "--detach",
		"--name", fmt.Sprintf("innsegl-apicli-%d", os.Getpid()),
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+apiPGUser,
		"--env", "POSTGRES_PASSWORD="+apiPGPassword,
		"--env", "POSTGRES_DB="+apiPGDatabase,
		image,
	)
	if err != nil {
		return nil, err
	}
	c := &apiPGContainer{id: id, port: port}
	if rerr := c.waitReady(ctx, 90*time.Second); rerr != nil {
		if remErr := c.remove(); remErr != nil {
			return nil, errors.Join(rerr, remErr)
		}
		return nil, rerr
	}
	return c, nil
}

func (c *apiPGContainer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := pgx.Connect(attempt, c.ownerDSN(apiPGDatabase))
		if err == nil {
			err = conn.Ping(attempt)
			discardAPIError(conn.Close(attempt))
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

func (c *apiPGContainer) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := dockerCLI(ctx, "rm", "--force", "--volumes", c.id)
	return err
}

// requireAPIPG hands the calling test a live Postgres, or ends it — as a SKIP
// when a dependency is absent and as a FAILURE when the container did not come
// up. The two are never the same outcome here.
func requireAPIPG(t *testing.T) *apiPGContainer {
	t.Helper()
	apiPGOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := apiDependenciesPresent(ctx); err != nil {
			apiPGSkip, apiPGFailure = apiStartupOutcome(err)
			return
		}
		pg, err := startAPIPG(ctx)
		if err != nil {
			// Docker answered a moment ago and the container still did not
			// come up. That is an infrastructure fault, and it is reported as
			// one — which is precisely what #101 was not.
			apiPGSkip, apiPGFailure = apiStartupOutcome(
				fmt.Errorf("could not start %s: %w", apiPGImage, err))
			return
		}
		apiPGShared = pg
	})

	switch apiPGRequirement(apiPGShared, apiPGSkip, apiPGFailure) {
	case apiFailTest:
		t.Fatalf("the test Postgres did not come up, and Docker is present: %s\n\n"+
			"This is a failure and not a skip. API-009 is what demonstrates that "+
			"`innsegl api` refuses a credential that can write; reporting an "+
			"infrastructure fault as a skip exits zero and prints ok while nothing "+
			"measured it (#101).", apiPGFailure)
	case apiSkipTest:
		t.Skipf("skipping: no real Postgres (%s). What a GRANT actually permits cannot "+
			"be established without one; start Docker and re-run.", apiPGSkip)
	case apiProceed:
	}
	return apiPGShared
}

func apiQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// freshLedgerDB creates an empty database, migrates it as the OWNER, and
// provisions the read-only role beside it. It returns both DSNs, because the
// difference between them is what API-009 is about.
func freshLedgerDB(t *testing.T) (ownerDSN, readerDSN string) {
	t.Helper()
	c := requireAPIPG(t)
	name := fmt.Sprintf("apicli_%d_%d", os.Getpid()%100000, apiDBSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, c.ownerDSN(apiPGDatabase))
	if err != nil {
		t.Fatalf("connect to %s: %v", apiPGDatabase, err)
	}
	defer func() { discardAPIError(admin.Close(ctx)) }()

	if _, cerr := admin.Exec(ctx, "CREATE DATABASE "+apiQuoteIdent(name)); cerr != nil {
		t.Fatalf("create database %s: %v", name, cerr)
	}

	ownerDSN = c.ownerDSN(name)
	store, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open as the owner: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}

	// The shipped provisioning, not a hand-written GRANT: what API-009 must
	// exercise is the role a deployment actually gets.
	if err := api.EnsureReadOnlyRole(ctx, ownerDSN, apiReaderRole, apiReaderPassword); err != nil {
		t.Fatalf("api.EnsureReadOnlyRole: %v", err)
	}
	return ownerDSN, c.readerDSN(name)
}

// discardAPIError swallows an error a caller genuinely cannot act on. errcheck
// runs with check-blank, so the discard is a named function rather than a blank
// assignment.
func discardAPIError(error) {}

// ---------------------------------------------------------------------------
// The routing rule, exercised in both directions.
// ---------------------------------------------------------------------------

// A skip and a failure are different outcomes and the code that tells them
// apart is checked, not assumed. #101 was a branch nothing measured.
func TestTheAPIHarnessSeparatesAnAbsentDockerFromAContainerThatDidNotStart(t *testing.T) {
	absent := fmt.Errorf("docker is not on PATH: %w", errAPIDependencyAbsent)
	if skip, failure := apiStartupOutcome(absent); skip == "" || failure != "" {
		t.Errorf("an absent dependency routed to (skip=%q, failure=%q), want a skip",
			skip, failure)
	}

	broken := errors.New("could not start postgres:16: exit status 125")
	if skip, failure := apiStartupOutcome(broken); failure == "" || skip != "" {
		t.Errorf("a container that would not start routed to (skip=%q, failure=%q), "+
			"want a failure — this is #101", skip, failure)
	}

	if skip, failure := apiStartupOutcome(nil); skip != "" || failure != "" {
		t.Errorf("a clean start-up routed to (skip=%q, failure=%q), want neither",
			skip, failure)
	}

	for _, tc := range []struct {
		name          string
		pg            *apiPGContainer
		skip, failure string
		want          apiRequirement
	}{
		{"a failure outranks everything", nil, "", "boom", apiFailTest},
		{"no container and no failure is a skip", nil, "no docker", "", apiSkipTest},
		{"a live container proceeds", &apiPGContainer{}, "", "", apiProceed},
	} {
		if got := apiPGRequirement(tc.pg, tc.skip, tc.failure); got != tc.want {
			t.Errorf("%s: requirement = %d, want %d", tc.name, got, tc.want)
		}
	}
}
