// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/spire"
)

// OPS-003's world: every component of the identity-and-ledger core, running for
// real, and every one of them a thing this file is allowed to SIGKILL.
//
//	postgres          the chain (ADR-0005), in its own container
//	spire-server      the identity plane, from deploy/compose/spire.yml
//	spire-agent       the attested node the run entries hang off
//	innsegl serve     the SHIPPED binary, as a local process
//
// Plus a real Rekor — five containers, the shape internal/segment's SEG-003
// harness established — because the reconciler's convergence is asked of a
// transparency log and a log that answers from a fake answers about nothing.
//
// # What is NOT killed, and why that is stated rather than hidden
//
// Fulcio. There is no Fulcio in this stack, so `sign_commit` is not part of the
// soak's workload: ADR-0033 gate 7 probes Sigstore BEFORE Phase A, so with the
// signer unreachable the tool refuses before it writes anything and the A → B
// window cannot be reached from the outside at all. The crash windows inside
// `sign_commit` are REC-002's subject (internal/reconciler, against a real
// Fulcio, a real Rekor and the released gitsign) and MCP-011's; duplicating
// them here would double this suite's container budget to re-prove somebody
// else's case. What OPS-003 adds is the soak: many components, many kills,
// concurrent work, and one sweep over everything afterwards.
//
// # Why there is no TestMain
//
// A package gets one, and #59 is writing test/chaos/partition_test.go in this
// same directory during this same wave. A TestMain here would be a land grab
// that stops that file compiling. internal/segment made the same call for the
// same reason ("A TestMain here would be a land grab"), and the consequence is
// the same: the one case that needs the stack starts it and tears it down
// through t.Cleanup. Every identifier in this file is prefixed `k9` or `OPS003`
// so that two harnesses in one package cannot collide on a name.
//
// # Docker's address pools
//
// Issue #100: roughly the 29th network is refused on a developer machine, and
// this suite's stacks take about four (three for the SPIRE project, one for
// Rekor). Run the whole suite with INNSEGL_TEST_FLAGS="-p 2".

const (
	// PROTECTED STRINGS (doc 01 §1). Spelled out rather than derived, so a
	// silent change to deploy/compose/spire/server.conf fails this test.
	k9TrustDomain = "innsegl.dev"
	k9AdminID     = "spiffe://innsegl.dev/innsegl/mcp"
	k9ServerID    = "spiffe://innsegl.dev/spire/server"

	// k9StackEnv is the variable test/chaos/kill-spire.yml interpolates into
	// the compose project, every container_name and every network name.
	k9StackEnv = "INNSEGL_CHAOS_KILL_STACK"

	k9AdminSocket = "/run/spire/admin/api.sock"

	// The soak's own agent type and task. Held to doc 02 §5's identifier
	// grammar, because they become components of a SPIFFE ID.
	k9AgentType = "chaos-soak"
	k9TaskID    = "ops-003"

	// k9RunTTL is the identity lifetime every run in the soak is registered
	// with. Short on purpose and well under spire.MaxRunTTL: IP §6.7's orphan
	// is a run whose entry outlived its TTL, and a five-minute default would
	// mean the soak had to run for five minutes before one existed.
	k9RunTTL = 20 * time.Second

	// k9Lease is the idempotency lease the server runs with. The shipped
	// default is a minute (ADR-0017 §5), which is right for a deployment and
	// wrong here: a replay of a claim whose owner was SIGKILLed waits out the
	// remainder of the lease, and this campaign COUNTS those takeovers as its
	// durable proof that a kill landed inside a call. A short lease makes the
	// takeover path ordinary rather than rare.
	k9Lease = 750 * time.Millisecond

	// k9KillsDefault is the CI budget: enough kills for every component to be
	// hit and for the anti-vacuity gates to have something to measure, small
	// enough to keep the case inside a few minutes. INNSEGL_CHAOS_KILLS raises
	// it.
	k9KillsDefault = 8
	// k9WorkersDefault is how many agents drive work concurrently.
	// INNSEGL_CHAOS_WORKERS raises it.
	k9WorkersDefault = 3

	// k9StrikeWindow bounds the seeded delay a strike waits BEFORE it starts
	// looking for work. It is what makes the arrival point random rather than
	// "wherever the last restore happened to leave the workload", so a seed
	// changes which of the running calls the kill lands on. The delay comes
	// before the parking and not after: applied after, it is a delay the
	// claimed call can finish inside, and measured it usually did.
	k9StrikeWindow = 40 * time.Millisecond
	// k9PollInterval is how often the killer re-reads the state it is waiting
	// for. Tight on purpose: the interval is the width of the window the kill
	// can overshoot by.
	k9PollInterval = 2 * time.Millisecond
	// k9BusyBudget bounds the killer's wait for work to be in flight. Generous,
	// because a loaded machine starves the workload rather than stopping it and
	// a strike that cannot find work must WAIT rather than fire: a kill into an
	// idle system is the one thing this campaign must never do.
	k9BusyBudget = 90 * time.Second
	// k9AimAttempts bounds how many extra shots the campaign takes at the one
	// window it refuses to leave to luck. See aimAtAClaimedCall.
	k9AimAttempts = 6
	// k9FreshClaim is how recently a claim must have been taken for the killer
	// to treat it as a call that is still running.
	//
	// The bound is what keeps "park on evidence" honest. A row is left
	// `in_progress` by a replica that died holding it, and it stays that way
	// until somebody replays the key — so a killer that parked on "any
	// in_progress row" could be satisfied by the WRECKAGE OF AN EARLIER KILL
	// and fire into an idle system while believing it had found work. A claim
	// taken inside the last quarter second is a call that is still running: the
	// slowest tool here is register_agent, which is a SPIRE round trip and
	// completes in tens of milliseconds.
	k9FreshClaim = 250 * time.Millisecond

	// Images. Pinned, doc 05 §1: "pin versions".
	k9PostgresImage = "postgres:16"
	k9ProxyImage    = "alpine/socat:1.8.0.3"

	k9PGUser     = "innsegl"
	k9PGPassword = "innsegl-test"
	k9PGDatabase = "innsegl"

	// The repository identifier the reconciler's planted intents name, and the
	// tree they claim. doc 02 §5's `host/org/name`, and a git object id.
	k9Repo = "example.test/innsegl/chaos"
	k9Tree = "1111111111111111111111111111111111111111"
)

// The four components a kill can land on. Doc 07 OPS-003 says "across all
// components"; these are all of them that the soak's workload depends on.
const (
	k9TargetMCP         = "innsegl serve"
	k9TargetPostgres    = "postgres"
	k9TargetSPIREServer = "spire-server"
	k9TargetSPIREAgent  = "spire-agent"
)

var k9Targets = []string{k9TargetMCP, k9TargetPostgres, k9TargetSPIREServer, k9TargetSPIREAgent}

// errK9DependencyAbsent marks the ONLY condition under which OPS-003 may skip:
// there is no Docker daemon. On a developer's machine that is a legitimate
// reason not to run a four-container chaos campaign.
//
// Everything else that can go wrong while standing the stack up — a compose
// network that cannot be created, a port that cannot be bound, a container that
// never becomes healthy, Docker's address pools exhausted — is a FAILURE, and
// this distinction is issue #101. Eight harnesses in this repository report a
// failed dependency as a skip; `go test` then exits zero, the package reports
// ok, and the case did not run. internal/verify/verifyharness_test.go carries
// the corrected shape and this is it. k9Classify is the decision, and
// TestOPS003ADependencyThatIsAbsentIsNotAStackThatFailed exercises both of its
// branches without needing Docker at all.
var errK9DependencyAbsent = errors.New("a required dependency is absent")

// k9Classify splits a bring-up error into the message OPS-003 may skip with and
// the message it must fail with. Exactly one is ever non-empty.
func k9Classify(err error) (skip, fail string) {
	if err == nil {
		return "", ""
	}
	if errors.Is(err, errK9DependencyAbsent) {
		return err.Error(), ""
	}
	return "", err.Error()
}

// ---------------------------------------------------------------------------
// The seeded generator.
//
// Written out rather than taken from math/rand so that a seed reproduces the
// same campaign on every Go release, which is the whole point of printing one.
// splitmix64, the same generator test/failure/crashharness_test.go uses.
// ---------------------------------------------------------------------------

type k9RNG struct {
	mu    sync.Mutex
	state uint64
}

func newK9RNG(seed uint64) *k9RNG { return &k9RNG{state: seed} }

func (r *k9RNG) next() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0, n).
func (r *k9RNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

// duration returns a value in [lo, hi).
func (r *k9RNG) duration(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(r.next()%uint64(hi-lo))
}

// shuffle permutes n items with the campaign's own generator.
func (r *k9RNG) shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.intn(i+1))
	}
}

func k9Seed(t *testing.T) uint64 {
	t.Helper()
	if raw := os.Getenv("INNSEGL_CHAOS_SEED"); raw != "" {
		seed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("INNSEGL_CHAOS_SEED=%q is not a uint64: %v", raw, err)
		}
		return seed
	}
	return uint64(time.Now().UnixNano())
}

func k9EnvInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func k9EnvOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Docker.
// ---------------------------------------------------------------------------

func k9Docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, k9OneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// k9OneLine collapses a multi-line subprocess error into a single line, so the
// cause is not lost in compose's progress output.
func k9OneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func k9DockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("INNSEGL_TEST_NO_DOCKER is set: %w", errK9DependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not on PATH: %w: %w", err, errK9DependencyAbsent)
	}
	if _, err := k9Docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("no reachable docker daemon: %w: %w", err, errK9DependencyAbsent)
	}
	return nil
}

func k9FreePort(ctx context.Context) (string, error) {
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

func k9WaitFor(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return cond()
}

// ---------------------------------------------------------------------------
// The stack.
// ---------------------------------------------------------------------------

type k9Stack struct {
	root   string
	prefix string

	composeFile string
	overlayFile string

	serverContainer string
	agentContainer  string
	adminNetwork    string
	proxyName       string
	socatAddr       string
	parentID        string

	pgContainer string
	pgPort      string

	rekor *k9RekorStack
}

func k9Prefix() string { return fmt.Sprintf("innsegl-kill9-%d", os.Getpid()) }

func (s *k9Stack) compose(ctx context.Context, args ...string) (string, error) {
	full := []string{"compose", "-p", s.prefix, "-f", s.composeFile, "-f", s.overlayFile}
	return k9Docker(ctx, append(full, args...)...)
}

// spireLocal runs the SPIRE server CLI inside the server container against the
// container-private admin socket (ADR-0011's operator path). It is the ground
// truth for what the datastore holds.
func (s *k9Stack) spireLocal(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", k9AdminSocket)
	return s.compose(ctx, full...)
}

func k9PGDSN(port, database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		k9PGUser, k9PGPassword, port, database)
}

func (s *k9Stack) dsn() string { return k9PGDSN(s.pgPort, k9PGDatabase) }

// startK9Stack brings every component up. Postgres, SPIRE and Rekor are
// independent of one another, so they are started concurrently: three serial
// bring-ups is most of this case's wall clock.
func startK9Stack(ctx context.Context, root string) (*k9Stack, error) {
	prefix := k9Prefix()
	if err := os.Setenv(k9StackEnv, prefix); err != nil {
		return nil, fmt.Errorf("set %s: %w", k9StackEnv, err)
	}
	s := &k9Stack{
		root:            root,
		prefix:          prefix,
		composeFile:     filepath.Join(root, "deploy", "compose", "spire.yml"),
		overlayFile:     filepath.Join(root, "test", "chaos", "kill-spire.yml"),
		serverContainer: prefix + "-spire-server",
		agentContainer:  prefix + "-spire-agent",
		adminNetwork:    prefix + "-spire-admin",
	}

	var (
		wg                  sync.WaitGroup
		pgErr, spErr, rkErr error
	)
	wg.Add(3)
	go func() { defer wg.Done(); pgErr = s.startPostgres(ctx) }()
	go func() { defer wg.Done(); spErr = s.startSPIRE(ctx) }()
	go func() {
		defer wg.Done()
		s.rekor, rkErr = startK9Rekor(ctx)
	}()
	wg.Wait()

	if err := errors.Join(pgErr, spErr, rkErr); err != nil {
		return s, err
	}
	return s, nil
}

func (s *k9Stack) startPostgres(ctx context.Context) error {
	port, err := k9FreePort(ctx)
	if err != nil {
		return fmt.Errorf("reserve a host port for postgres: %w", err)
	}
	id, err := k9Docker(ctx, "run", "--detach",
		"--name", s.prefix+"-postgres",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+k9PGUser,
		"--env", "POSTGRES_PASSWORD="+k9PGPassword,
		"--env", "POSTGRES_DB="+k9PGDatabase,
		k9EnvOr("INNSEGL_TEST_POSTGRES_IMAGE", k9PostgresImage),
	)
	if err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}
	s.pgContainer, s.pgPort = id, port
	if !k9WaitFor(150*time.Second, func() bool { return k9PGReady(ctx, port) }) {
		return fmt.Errorf("postgres on 127.0.0.1:%s never accepted a connection", port)
	}
	return nil
}

func k9PGReady(ctx context.Context, port string) bool {
	attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := pgx.Connect(attempt, k9PGDSN(port, k9PGDatabase))
	if err != nil {
		return false
	}
	err = conn.Ping(attempt)
	_ = conn.Close(attempt)
	return err == nil
}

func (s *k9Stack) startSPIRE(ctx context.Context) error {
	if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server", "spire-agent"); err != nil {
		return fmt.Errorf("compose up spire: %w", err)
	}
	if err := s.awaitAttestedNode(ctx, 150*time.Second); err != nil {
		return err
	}

	// The admin proxy. Created on the default bridge so the port can be
	// published — docker skips port publishing for a container whose only
	// network is `internal: true` — then joined to the admin network, which is
	// the membership that grants admin reachability (ADR-0011).
	port, err := k9FreePort(ctx)
	if err != nil {
		return fmt.Errorf("reserve a host port for the admin proxy: %w", err)
	}
	s.proxyName = s.prefix + "-adminproxy"
	if _, err = k9Docker(ctx, "run", "--detach", "--name", s.proxyName,
		"--publish", "127.0.0.1:"+port+":8081",
		k9EnvOr("INNSEGL_TEST_PROXY_IMAGE", k9ProxyImage),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		return fmt.Errorf("start the admin proxy: %w", err)
	}
	if _, err = k9Docker(ctx, "network", "connect", s.adminNetwork, s.proxyName); err != nil {
		return fmt.Errorf("join %s: %w", s.adminNetwork, err)
	}
	s.socatAddr = "127.0.0.1:" + port
	return nil
}

// awaitAttestedNode polls until the agent has attested and the server names the
// node every run entry will be parented to.
func (s *k9Stack) awaitAttestedNode(ctx context.Context, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		// Derived fresh on every pass, and that is not tidiness. Reusing a
		// parentID left over from an earlier call made this function return
		// immediately while spire-server was still refusing connections after a
		// kill, so the campaign carried on against a component it had not
		// waited for. MEASURED: a soak with eight kills "finished in 3.18s".
		found := ""
		out, err := s.spireLocal(ctx, "agent", "list")
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
					found = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
					break
				}
			}
		}
		last = err
		if found != "" {
			s.parentID = found
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("no attested agent within %s, last error: %w", budget, last)
}

func (s *k9Stack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if s.rekor != nil {
		for _, err := range s.rekor.stop() {
			fmt.Fprintf(os.Stderr, "warning: tearing down rekor: %v\n", err)
		}
	}
	for _, name := range []string{s.proxyName, s.pgContainer} {
		if name == "" {
			continue
		}
		if _, err := k9Docker(ctx, "rm", "--force", "--volumes", name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", name, err)
		}
	}
	if os.Getenv("INNSEGL_TEST_KEEP_SPIRE") != "" {
		return
	}
	if _, err := s.compose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
	}
}

// ---------------------------------------------------------------------------
// Rekor.
//
// The shape internal/segment/rekorharness_test.go established for SEG-003, and
// the reasoning is the same one: Rekor is a front end over a Trillian log,
// Trillian is a log over MySQL whose sequencer is a separate process, and
// Rekor's search index needs Redis. The reconciler's convergence is a question
// put to a transparency log, and a log that answers from a map answers about
// nothing (IP §2).
// ---------------------------------------------------------------------------

const (
	k9RekorImage      = "ghcr.io/sigstore/rekor/rekor-server:v1.3.10"
	k9TLogServerImage = "ghcr.io/sigstore/scaffolding/trillian_log_server:v1.7.1"
	k9TLogSignerImage = "ghcr.io/sigstore/scaffolding/trillian_log_signer:v1.7.1"
	k9TrillianDBImage = "gcr.io/trillian-opensource-ci/db_server:v1.4.0"
	k9RedisImage      = "redis:7-alpine"

	k9TrillianDB       = "test"
	k9TrillianDBUser   = "test"
	k9TrillianPassword = "zaphod"
	k9RekorOrigin      = "rekor.innsegl.test"
)

type k9RekorStack struct {
	network    string
	containers []string
	port       string
}

func (s *k9RekorStack) baseURL() string { return "http://127.0.0.1:" + s.port }

func (s *k9RekorStack) run(ctx context.Context, name string, args ...string) error {
	full := append([]string{"run", "--detach", "--name", name, "--network", s.network}, args...)
	id, err := k9Docker(ctx, full...)
	if err != nil {
		return err
	}
	s.containers = append(s.containers, id)
	return nil
}

func (s *k9RekorStack) stop() []error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var errs []error
	for i := len(s.containers) - 1; i >= 0; i-- {
		if _, err := k9Docker(ctx, "rm", "--force", "--volumes", s.containers[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if s.network != "" {
		if _, err := k9Docker(ctx, "network", "rm", s.network); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func startK9Rekor(ctx context.Context) (*k9RekorStack, error) {
	port, err := k9FreePort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port for rekor: %w", err)
	}
	suffix := strconv.Itoa(os.Getpid())
	s := &k9RekorStack{network: "innsegl-kill9-rekor-" + suffix, port: port}

	if _, err := k9Docker(ctx, "network", "create", s.network); err != nil {
		return s, fmt.Errorf("create the rekor network: %w", err)
	}

	db := "innsegl-kill9-rekordb-" + suffix
	if err := s.run(ctx, db,
		"--env", "MYSQL_ROOT_PASSWORD="+k9TrillianPassword,
		"--env", "MYSQL_DATABASE="+k9TrillianDB,
		"--env", "MYSQL_USER="+k9TrillianDBUser,
		"--env", "MYSQL_PASSWORD="+k9TrillianPassword,
		k9EnvOr("INNSEGL_TEST_TRILLIAN_DB_IMAGE", k9TrillianDBImage),
	); err != nil {
		return s, fmt.Errorf("start the trillian database: %w", err)
	}
	if err := s.awaitSchema(ctx, db, 3*time.Minute); err != nil {
		return s, err
	}

	redis := "innsegl-kill9-rekorredis-" + suffix
	if err := s.run(ctx, redis,
		k9EnvOr("INNSEGL_TEST_REKOR_REDIS_IMAGE", k9RedisImage),
		"--bind", "0.0.0.0", "--appendonly", "no",
	); err != nil {
		return s, fmt.Errorf("start redis: %w", err)
	}

	uri := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s",
		k9TrillianDBUser, k9TrillianPassword, db, k9TrillianDB)

	logServer := "innsegl-kill9-tlog-" + suffix
	if err := s.run(ctx, logServer,
		"--restart", "on-failure:30",
		k9EnvOr("INNSEGL_TEST_TRILLIAN_LOG_SERVER_IMAGE", k9TLogServerImage),
		"--storage_system=mysql", "--mysql_uri="+uri,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
	); err != nil {
		return s, fmt.Errorf("start the trillian log server: %w", err)
	}
	signer := "innsegl-kill9-tsign-" + suffix
	if err := s.run(ctx, signer,
		"--restart", "on-failure:30",
		k9EnvOr("INNSEGL_TEST_TRILLIAN_LOG_SIGNER_IMAGE", k9TLogSignerImage),
		"--storage_system=mysql", "--mysql_uri="+uri,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
		"--force_master",
	); err != nil {
		return s, fmt.Errorf("start the trillian log signer: %w", err)
	}

	rekor := "innsegl-kill9-rekor-" + suffix
	if err := s.run(ctx, rekor,
		"--restart", "on-failure:30",
		"--publish", "127.0.0.1:"+port+":3000",
		k9EnvOr("INNSEGL_TEST_REKOR_IMAGE", k9RekorImage),
		"serve",
		"--trillian_log_server.address="+logServer, "--trillian_log_server.port=8090",
		"--redis_server.address="+redis, "--redis_server.port=6379",
		"--host=0.0.0.0", "--port=3000", "--rekor_server.address=0.0.0.0",
		"--rekor_server.signer=memory",
		"--rekor_server.hostname="+k9RekorOrigin,
		"--enable_attestation_storage=false",
		"--enable_stable_checkpoint=false",
	); err != nil {
		return s, fmt.Errorf("start rekor: %w", err)
	}
	return s, s.awaitRekor(ctx, 3*time.Minute)
}

// awaitSchema polls until Trillian's tables are reachable OVER TCP. The MySQL
// image boots twice and a probe over the container's unix socket succeeds
// during the first boot, when nothing on the network can connect yet.
func (s *k9RekorStack) awaitSchema(ctx context.Context, container string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := k9Docker(attempt, "exec", container,
			"mysql", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
			"-u"+k9TrillianDBUser, "-p"+k9TrillianPassword,
			"-e", "SELECT 1 FROM "+k9TrillianDB+".Trees LIMIT 1")
		cancel()
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the trillian schema never became reachable over TCP: %w", last)
}

func (s *k9RekorStack) awaitRekor(ctx context.Context, budget time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			s.baseURL()+"/api/v1/log", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("GET /api/v1/log answered %d", code)
		} else {
			last = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("rekor never answered: %w", last)
}

// ---------------------------------------------------------------------------
// Admin credentials for the shipped binary.
// ---------------------------------------------------------------------------

type k9MintedSVID struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (m k9MintedSVID) GetX509SVID() (*x509svid.SVID, error) { return m.svid, nil }

func (m k9MintedSVID) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, m.roots), nil
}

// k9ParseMint splits `spire-server x509 mint` output into its three PEM
// sections.
func k9ParseMint(out string) (svidPEM, keyPEM, rootsPEM string, err error) {
	const (
		hSVID  = "X509-SVID:"
		hKey   = "Private key:"
		hRoots = "Root CAs:"
	)
	i, j, k := strings.Index(out, hSVID), strings.Index(out, hKey), strings.Index(out, hRoots)
	if i < 0 || j < i || k < j {
		return "", "", "", fmt.Errorf("unrecognised `x509 mint` output: %.200q", out)
	}
	return out[i+len(hSVID) : j], out[j+len(hKey) : k], out[k+len(hRoots):], nil
}

func k9ParseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			if len(out) == 0 {
				return nil, errors.New("no PEM certificate found")
			}
			return out, nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

// ---------------------------------------------------------------------------
// The campaign.
// ---------------------------------------------------------------------------

type k9Campaign struct {
	stack   *k9Stack
	store   *ledger.Store
	pool    *pgxpool.Pool
	idem    *mcp.IdempotencyStore
	admin   *spire.Client
	binary  string
	pemDir  string
	workDir string
	repos   string

	// mcpAddr is fixed for the life of the campaign. `-listen 127.0.0.1:0`
	// would hand out a new port on every restart, and the workers would then
	// have to be told the new one after every kill — turning a reconnect into
	// a rendezvous.
	mcpAddr string

	seed    uint64
	rng     *k9RNG
	kills   int
	workers int

	dispatched  atomic.Int64
	inFlight    atomic.Int64
	interrupted atomic.Int64

	mu             sync.Mutex
	daemon         *k9Daemon
	killCount      int
	byTarget       map[string]int
	idleKills      int
	invariants     int
	firstInvariant string
	// runs is every run id the workload registered, and whether the workload
	// meant to retire it.
	runs map[string]bool
	// outstanding is every keyed call the workload has dispatched and not yet
	// had an answer to, by idempotency key. It is how settle knows what the
	// soak's deadline cut off; see settle for why finishing them is part of
	// what IP §6.6 asks and not a way of hiding anything.
	outstanding map[string]k9Call
}

// k9Call is one tool call, as the workload issued it.
type k9Call struct {
	tool mcp.ToolName
	args map[string]any
}

type k9Evidence struct {
	kills               int
	byTarget            map[string]int
	idleKills           int
	dispatched          int64
	interrupted         int64
	invariantViolations int
	firstInvariant      string
	claims              k9Claims
}

// requireK9Campaign brings up everything OPS-003 needs, or says exactly which
// of the two things happened: a dependency is absent (skip) or the stack did
// not come up (fail). See errK9DependencyAbsent.
func requireK9Campaign(t *testing.T) *k9Campaign {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	root := filepath.Dir(filepath.Dir(wd))

	if derr := k9DockerUsable(ctx); derr != nil {
		skip, fail := k9Classify(derr)
		if fail != "" {
			t.Fatalf("OPS-003 could not ask whether Docker is usable: %s", fail)
		}
		t.Skipf("skipping OPS-003: %s. A kill campaign with no component to kill "+
			"proves nothing — IP §2, \"a mocked Fulcio proves nothing about I5\", and a "+
			"SPIRE that was never running proves exactly as little. Start Docker and "+
			"re-run.", skip)
	}

	stack, serr := startK9Stack(ctx, root)
	if serr != nil {
		if stack != nil {
			stack.stop()
		}
		skip, fail := k9Classify(serr)
		if skip != "" {
			t.Skipf("skipping OPS-003: %s", skip)
		}
		t.Fatalf("the OPS-003 stack did not come up, and Docker is present: %s\n\n"+
			"This is a failure and not a skip (issue #101). Reporting an "+
			"infrastructure fault as a skip exits zero and reports ok while the "+
			"kill campaign did not run. If the cause is Docker's address pools, "+
			"run the suite with INNSEGL_TEST_FLAGS=\"-p 2\" (issue #100).", fail)
	}
	t.Cleanup(stack.stop)

	c := &k9Campaign{
		stack:       stack,
		workDir:     t.TempDir(),
		byTarget:    map[string]int{},
		runs:        map[string]bool{},
		outstanding: map[string]k9Call{},
		kills:       k9EnvInt("INNSEGL_CHAOS_KILLS", k9KillsDefault),
		workers:     k9EnvInt("INNSEGL_CHAOS_WORKERS", k9WorkersDefault),
	}
	c.seed = k9Seed(t)
	c.rng = newK9RNG(c.seed)
	t.Logf("OPS-003 seed %d — re-run this exact campaign with INNSEGL_CHAOS_SEED=%d "+
		"(%d kills across %d components, %d concurrent agents; raise with "+
		"INNSEGL_CHAOS_KILLS / INNSEGL_CHAOS_WORKERS)",
		c.seed, c.seed, c.kills, len(k9Targets), c.workers)

	c.store = k9OpenLedger(t, stack.dsn())
	c.pool = k9OpenPool(t, stack.dsn())
	c.idem = mcp.NewIdempotencyStore(c.pool, mcp.WithIdempotencyLease(k9Lease))
	c.admin = k9AdminClient(t, stack)
	c.binary = k9BuildServer(t, root)
	c.pemDir = c.writeAdminPEMs(t)
	c.repos = c.makeWorkspace(t)

	port, err := k9FreePort(ctx)
	if err != nil {
		t.Fatalf("reserve the MCP's listening port: %v", err)
	}
	c.mcpAddr = "127.0.0.1:" + port

	c.startDaemon(t)
	return c
}

func k9OpenLedger(t *testing.T, dsn string) *ledger.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	return s
}

func k9OpenPool(t *testing.T, dsn string) *pgxpool.Pool {
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

func k9AdminClient(t *testing.T, s *k9Stack) *spire.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	src, err := k9MintAdmin(ctx, s, k9AdminID)
	if err != nil {
		t.Fatalf("mint the admin SVID: %v", err)
	}
	c, err := spire.Dial(ctx, spire.Config{
		Address:     s.socatAddr,
		TrustDomain: k9TrustDomain,
		ServerID:    k9ServerID,
		Source:      src,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial(%s): %v", s.socatAddr, err)
	}
	t.Cleanup(func() {
		if cerr := c.Close(); cerr != nil {
			t.Logf("warning: closing the admin client: %v", cerr)
		}
	})
	return c
}

func k9MintAdmin(ctx context.Context, s *k9Stack, id string) (k9MintedSVID, error) {
	out, err := s.spireLocal(ctx, "x509", "mint", "-spiffeID", id, "-ttl", "2h")
	if err != nil {
		return k9MintedSVID{}, fmt.Errorf("mint %s: %w", id, err)
	}
	svidPEM, keyPEM, rootsPEM, err := k9ParseMint(out)
	if err != nil {
		return k9MintedSVID{}, err
	}
	svid, err := x509svid.Parse([]byte(svidPEM), []byte(keyPEM))
	if err != nil {
		return k9MintedSVID{}, fmt.Errorf("parse the minted SVID: %w", err)
	}
	roots, err := k9ParseCerts([]byte(rootsPEM))
	if err != nil {
		return k9MintedSVID{}, fmt.Errorf("parse the trust bundle: %w", err)
	}
	return k9MintedSVID{svid: svid, roots: roots}, nil
}

// k9BuildServer compiles the SHIPPED binary. ./cmd/innsegl, not a purpose-built
// daemon: the whole value of a kill campaign is that the process it kills is
// the process a deployment runs.
func k9BuildServer(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "innsegl")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/innsegl")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("OPS-003 needs a process to kill: build ./cmd/innsegl: %v: %s", err, b)
	}
	return out
}

// writeAdminPEMs mints the admin SVID and puts it where a subprocess can read
// it. In a deployment the MCP is an attested workload and holds no files; there
// is no attested innsegl-mcp workload on this host and the containerised
// agent's Workload API socket is inside the container.
func (c *k9Campaign) writeAdminPEMs(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	out, err := c.stack.spireLocal(ctx, "x509", "mint", "-spiffeID", k9AdminID, "-ttl", "2h")
	if err != nil {
		t.Fatalf("mint the admin SVID for the server: %v", err)
	}
	svidPEM, keyPEM, rootsPEM, err := k9ParseMint(out)
	if err != nil {
		t.Fatalf("parse `x509 mint` output: %v", err)
	}
	dir := filepath.Join(c.workDir, "admin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for name, body := range map[string]string{
		"svid.pem": svidPEM, "key.pem": keyPEM, "bundle.pem": rootsPEM,
	} {
		if werr := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); werr != nil {
			t.Fatalf("write %s: %v", name, werr)
		}
	}
	return dir
}

// makeWorkspace creates the repository root the reconciler resolves `repo`
// under, with one real (empty) git repository in it. Empty is the point: the
// dangling intent the reconciler is asked to converge on names a tree that no
// signed commit holds, and `git cat-file --batch-all-objects` in a repository
// with no objects is the honest way to establish that.
func (c *k9Campaign) makeWorkspace(t *testing.T) string {
	t.Helper()
	root := filepath.Join(c.workDir, "repos")
	dir := filepath.Join(root, filepath.FromSlash(k9Repo))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "init", "--quiet", dir)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v: %s", dir, err, b)
	}
	return root
}

// ---------------------------------------------------------------------------
// The process under test.
// ---------------------------------------------------------------------------

type k9Daemon struct {
	cmd    *exec.Cmd
	stderr *k9Buffer
	dead   bool
}

type k9Buffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *k9Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > 1<<20 {
		b.buf = b.buf[len(b.buf)-(1<<20):]
	}
	return len(p), nil
}

func (b *k9Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// startDaemon launches one `innsegl serve` on the campaign's fixed address and
// waits until it accepts a connection.
func (c *k9Campaign) startDaemon(t *testing.T) {
	t.Helper()

	// context.Background rather than the test's: CommandContext kills the
	// child when the context ends, and the one thing that may kill this child
	// is the SIGKILL below, whose wait status is then read back.
	cmd := exec.CommandContext(context.Background(), c.binary, "serve",
		"-dsn", c.stack.dsn(),
		"-spire-address", c.stack.socatAddr,
		"-trust-domain", k9TrustDomain,
		"-spire-server-id", k9ServerID,
		"-parent-id", c.stack.parentID,
		"-svid", filepath.Join(c.pemDir, "svid.pem"),
		"-key", filepath.Join(c.pemDir, "key.pem"),
		"-bundle", filepath.Join(c.pemDir, "bundle.pem"),
		"-listen", c.mcpAddr,
		"-health-listen", "127.0.0.1:0",
		"-idempotency-lease", k9Lease.String(),
		"-run-ttl", k9RunTTL.String(),
		// Required configuration this campaign does not exercise: they are read
		// only by /readyz, which nothing here calls, and there is no Sigstore in
		// this stack for the MCP to reach. A closed port is the honest value.
		"-fulcio-url", "http://127.0.0.1:1",
		"-rekor-url", "http://127.0.0.1:1",
		// register_agent floods are MCP-013's subject; an unmetered tool is
		// what the soak's throughput is measured against.
		"-register-rate-calls", "0",
	)
	stderr := &k9Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting `innsegl serve`: %v", err)
	}
	d := &k9Daemon{cmd: cmd, stderr: stderr}

	c.mu.Lock()
	c.daemon = d
	c.mu.Unlock()
	t.Cleanup(func() { d.reap() })

	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(90 * time.Second)
	for {
		dial, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialer.DialContext(dial, "tcp", c.mcpAddr)
		cancel()
		if err == nil {
			if cerr := conn.Close(); cerr != nil {
				t.Fatalf("closing the readiness probe's connection: %v", cerr)
			}
			return
		}
		if cmd.ProcessState != nil {
			t.Fatalf("`innsegl serve` exited before it served: %s", stderr.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("`innsegl serve` never accepted a connection on %s; stderr:\n%s",
				c.mcpAddr, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// kill sends SIGKILL and proves the process died of it.
//
// The proof matters. "The test called kill" and "the process was killed" are
// different claims, and only the second is OPS-003's: a daemon that had already
// exited on its own would leave state this harness would then attribute to a
// crash it did not cause.
func (d *k9Daemon) kill(t *testing.T) {
	t.Helper()
	if d.dead {
		t.Fatalf("`innsegl serve` was already dead before this kill; the campaign lost "+
			"track of the process it is measuring. stderr:\n%s", d.stderr.String())
	}
	if err := d.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	err := d.cmd.Wait()
	d.dead = true

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("`innsegl serve` exited with %v, not by a signal; OPS-003 is about a "+
			"process the operating system removed and this one left on its own. If the "+
			"previous kill landed on Postgres or SPIRE, an MCP that exits when a "+
			"dependency goes away is itself the finding: IP §6.4 has the ledger "+
			"failing operations closed, not the server exiting. stderr:\n%s",
			err, d.stderr.String())
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("no wait status for `innsegl serve`: %T", exitErr.Sys())
	}
	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("`innsegl serve` exited with %v; OPS-003 requires SIGKILL. stderr:\n%s",
			exitErr.ProcessState, d.stderr.String())
	}
}

func (d *k9Daemon) reap() {
	if d == nil || d.dead || d.cmd.Process == nil {
		return
	}
	d.dead = true
	if err := d.cmd.Process.Kill(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: killing the server: %v\n", err)
		return
	}
	var exitErr *exec.ExitError
	if err := d.cmd.Wait(); err != nil && !errors.As(err, &exitErr) {
		fmt.Fprintf(os.Stderr, "warning: reaping the server: %v\n", err)
	}
}

// ---------------------------------------------------------------------------
// The workload.
//
// Real work, driven over the shipped MCP transport against the shipped binary.
// One "agent" per worker goroutine, each running the lifecycle IP §1 describes:
// register, take a credential, record what it did, and — two times in three —
// retire. The third case is IP §6.7's agent that crashed without retiring, and
// it is what gives the reaper an orphan to find.
// ---------------------------------------------------------------------------

type k9Worker struct {
	index   int
	session *sdk.ClientSession
}

func (c *k9Campaign) soak(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for w := range c.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.work(ctx, w)
		}()
	}

	started := time.Now()
	for i, target := range c.schedule() {
		c.strike(t, i+1, target)
	}
	// The workers are still running here, deliberately: the aimed shot needs a
	// keyed call in flight to aim at, and after cancel() there are none.
	c.aimAtAClaimedCall(t)
	cancel()
	wg.Wait()
	t.Logf("seed %d: soak finished in %s", c.seed, time.Since(started).Truncate(time.Millisecond))
}

// schedule draws the kill order.
//
// STRATIFIED, not independent draws, and for the reason the crash campaign
// stratifies its delays: doc 07 OPS-003 says "across all components", and four
// independent draws over eight kills leave a better-than-one-in-ten chance that
// some component is never hit at all — which would fail the coverage gate for
// no reason but luck. So the budget is dealt round-robin first and the
// remainder drawn, and only then is the whole sequence shuffled by the
// campaign's own generator. What is random is the ORDER and the timing; what is
// guaranteed is the coverage.
func (c *k9Campaign) schedule() []string {
	out := make([]string, 0, c.kills)
	for len(out)+len(k9Targets) <= c.kills {
		out = append(out, k9Targets...)
	}
	for len(out) < c.kills {
		out = append(out, k9Targets[c.rng.intn(len(k9Targets))])
	}
	c.rng.shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// work is one agent, looping until the soak ends.
func (c *k9Campaign) work(ctx context.Context, index int) {
	w := &k9Worker{index: index}
	defer w.close()
	for step := 1; ctx.Err() == nil; step++ {
		c.oneRun(ctx, w, step)
	}
}

func (c *k9Campaign) oneRun(ctx context.Context, w *k9Worker, step int) {
	base := fmt.Sprintf("ops003-%d-w%d-s%d", c.seed%1_000_000, w.index, step)

	reply, ok := c.call(ctx, w, mcp.ToolRegisterAgent, map[string]any{
		"agent_type": k9AgentType, "task_id": k9TaskID, "idempotency_key": base + "/reg",
	})
	if !ok {
		return
	}
	var reg struct {
		SPIFFEID string `json:"spiffe_id"`
		RunID    string `json:"run_id"`
	}
	if !k9Decode(reply, &reg) || reg.RunID == "" {
		return
	}

	if _, ok = c.call(ctx, w, mcp.ToolGetCredential, map[string]any{
		"run_id": reg.RunID, "audience": mcp.AudienceSigstore,
	}); !ok {
		return
	}
	for i := range 2 {
		key := fmt.Sprintf("%s/rec%d", base, i)
		if _, ok = c.call(ctx, w, mcp.ToolRecordEvent, map[string]any{
			"run_id":          reg.RunID,
			"event_type":      "shell.exec",
			"payload_digest":  event.Digest([]byte(key)),
			"idempotency_key": key,
		}); !ok {
			return
		}
	}

	// One run in three is abandoned, unretired, exactly as IP §6.7 describes.
	// The choice is derived from the step so a seed reproduces which runs were
	// abandoned; it does not draw from the shared generator, because the
	// killer's draws must stay reproducible independently of how many runs the
	// workers happened to complete.
	//
	// The intent is recorded BEFORE the call, not after: the soak ends by
	// cancelling this context, and a retirement the deadline cut off is a call
	// that has to be finished before the sweep, not a run that was abandoned.
	retire := (step+w.index)%3 != 0
	c.mu.Lock()
	c.runs[reg.RunID] = retire
	c.mu.Unlock()
	if retire {
		c.call(ctx, w, mcp.ToolRetireAgent, map[string]any{"run_id": reg.RunID})
	}
}

// call dispatches one tool call, retrying until it succeeds or the soak ends.
//
// Retrying with the SAME idempotency key is not a convenience: it is IP §6.6's
// contract being exercised on every kill. A call the workload reissues after
// the server died is a replay, and the server is required to return the
// original result rather than a second identity, a second event or a second
// commit.
func (c *k9Campaign) call(ctx context.Context, w *k9Worker,
	tool mcp.ToolName, args map[string]any,
) (any, bool) {
	key, keyed := args["idempotency_key"].(string)
	if keyed {
		c.mu.Lock()
		c.outstanding[key] = k9Call{tool: tool, args: args}
		c.mu.Unlock()
	}

	backoff := 20 * time.Millisecond
	for ctx.Err() == nil {
		session, err := c.session(ctx, w)
		if err != nil {
			if ctx.Err() == nil {
				c.interrupted.Add(1)
			}
			k9Backoff(ctx, &backoff)
			continue
		}

		c.dispatched.Add(1)
		c.inFlight.Add(1)
		callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		res, cerr := session.CallTool(callCtx, &sdk.CallToolParams{
			Name: string(tool), Arguments: args,
		})
		cancel()
		c.inFlight.Add(-1)

		switch {
		case cerr != nil:
			// The ordinary outcome of a kill landing inside a call: the
			// transport went away under it.
			//
			// The ctx.Err() guard is what keeps this counter honest. The soak
			// ends by cancelling this context, which interrupts one call per
			// worker; counting those would satisfy the "something was
			// interrupted" gate with the campaign's own shutdown and the gate
			// would then be unfalsifiable. Measured: with the kill step removed
			// entirely, three calls were still reported interrupted — one per
			// worker, all of them the cancellation.
			if ctx.Err() == nil {
				c.interrupted.Add(1)
			}
			w.close()
			k9Backoff(ctx, &backoff)
		case res.IsError:
			// A dependency outage the server classified, which is the other
			// ordinary outcome: IDENTITY_UNAVAILABLE while SPIRE is down,
			// LEDGER_UNAVAILABLE while Postgres is. Both are retryable and both
			// are evidence the kill was noticed.
			c.noteToolError(tool, res)
			if ctx.Err() == nil {
				c.interrupted.Add(1)
			}
			k9Backoff(ctx, &backoff)
		default:
			if keyed {
				c.mu.Lock()
				delete(c.outstanding, key)
				c.mu.Unlock()
			}
			return res.StructuredContent, true
		}
	}
	return nil, false
}

func k9Backoff(ctx context.Context, d *time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(*d):
	}
	if *d < 500*time.Millisecond {
		*d *= 2
	}
}

// noteToolError records the classified refusals. INVARIANT_VIOLATION is the one
// that is never acceptable: IP §6.2 makes it alert-level, meaning either this
// code has a defect or something is using a credential it should not have.
func (c *k9Campaign) noteToolError(tool mcp.ToolName, res *sdk.CallToolResult) {
	body, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return
	}
	var wire struct {
		Class   string `json:"error_class"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &wire) != nil {
		return
	}
	if wire.Class != string(mcp.ClassInvariantViolation) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invariants++
	if c.firstInvariant == "" {
		c.firstInvariant = fmt.Sprintf("%s: %s", tool, wire.Message)
	}
}

func (c *k9Campaign) session(ctx context.Context, w *k9Worker) (*sdk.ClientSession, error) {
	if w.session != nil {
		return w.session, nil
	}
	dial, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-ops-003", Version: "v0"}, nil)
	session, err := client.Connect(dial,
		&sdk.StreamableClientTransport{Endpoint: "http://" + c.mcpAddr}, nil)
	if err != nil {
		return nil, err
	}
	w.session = session
	return session, nil
}

func (w *k9Worker) close() {
	if w.session == nil {
		return
	}
	_ = w.session.Close()
	w.session = nil
}

func k9Decode(v any, out any) bool {
	body, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(body, out) == nil
}

// ---------------------------------------------------------------------------
// The kills.
// ---------------------------------------------------------------------------

// strike lands one kill on one component.
//
// It never sleeps and then fires blind. The seeded delay decides WHEN this
// strike starts looking; the signal then goes out on EVIDENCE, the instant
// awaitBusy sees both witnesses that a tool call is running — a claim Postgres
// says was taken inside the last k9FreshClaim with no reply recorded, and a
// call this process dispatched and has not had back. That is RM-066's standard,
// park on evidence rather than on a sleep, and it is the whole difference
// between a soak that killed a busy process and one that killed an idle process
// and then found that nothing had broken.
//
// A strike that fires without both witnesses is counted as an idle kill and the
// campaign fails on it, so the discipline cannot quietly stop applying.
func (c *k9Campaign) strike(t *testing.T, n int, target string) {
	t.Helper()

	// The seeded delay comes FIRST and the parking second, so the signal goes
	// out the moment a fresh claim is seen rather than a random interval after
	// one — a delay applied after parking is a delay the call can finish
	// inside, and MEASURED it usually did.
	delay := c.rng.duration(0, k9StrikeWindow)
	time.Sleep(delay)
	if !c.awaitBusy(t, k9BusyBudget) {
		t.Fatalf("no tool call was provably in flight at any point in %s, so kill %d/%d "+
			"was never fired (seed %d). The workload has stalled — the last restore "+
			"left a component the workers cannot reach — and killing an idle system "+
			"would measure nothing, so the campaign stops here instead of certifying "+
			"a soak over a system that was not working.", k9BusyBudget, n, c.kills, c.seed)
	}

	inFlight := c.inFlight.Load()
	claimed := c.freshClaims(t, false)
	if inFlight == 0 || claimed == 0 {
		c.mu.Lock()
		c.idleKills++
		c.mu.Unlock()
	}
	t.Logf("kill %d/%d: %s, %s into the soak's own rhythm, with %d call(s) dispatched "+
		"and unreturned and %d claim(s) taken inside the last %s and not yet answered",
		n, c.kills, target, delay, inFlight, claimed, k9FreshClaim)

	c.killTarget(t, target)
	c.mu.Lock()
	c.killCount++
	c.byTarget[target]++
	c.mu.Unlock()

	c.restoreTarget(t, target)
}

// awaitBusy polls until the system is provably mid-call: a claim taken inside
// the last k9FreshClaim with no reply recorded, AND a call this process
// dispatched and has not had back.
//
// Two witnesses because each covers the other's blind spot. The Postgres row is
// DURABLE and is the shipped server's own statement that a tool call is between
// its claim and its reply; the in-process counter is LIVE and cannot be
// satisfied by a row somebody else left behind.
func (c *k9Campaign) awaitBusy(t *testing.T, budget time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if c.inFlight.Load() > 0 && c.freshClaims(t, false) > 0 {
			return true
		}
		time.Sleep(k9PollInterval)
	}
	return false
}

// freshClaims counts the claims taken inside the last k9FreshClaim that have
// not recorded a reply.
//
// The window is applied by Postgres against its own clock_timestamp(), never
// against this process's clock: doc 04 residual risk #4 is a skewed clock being
// able to move another party's lease, and the same reasoning says a test may
// not decide from its own clock how old a row the server wrote is.
//
// A read failure is not fatal here. Postgres is one of the things this campaign
// kills, and asking it a question while it is down is not an error in the
// campaign — it is an answer of "nothing is provably in flight", which is what
// returning zero says.
// keyedOnly restricts the count to the two tools that take an idempotency_key.
// get_credential and retire_agent are intrinsically idempotent and claim
// nothing, so a kill landing inside one of them leaves no claim behind and no
// durable trace of having interrupted anything.
func (c *k9Campaign) freshClaims(t *testing.T, keyedOnly bool) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tools := []string{
		string(mcp.ToolRegisterAgent), string(mcp.ToolGetCredential),
		string(mcp.ToolRecordEvent), string(mcp.ToolRetireAgent), string(mcp.ToolSignCommit),
	}
	if keyedOnly {
		tools = []string{string(mcp.ToolRegisterAgent), string(mcp.ToolRecordEvent)}
	}
	var n int
	err := c.pool.QueryRow(ctx, `
		SELECT count(*) FROM innsegl.idempotency
		 WHERE status = 'in_progress'
		   AND tool = ANY($2)
		   AND claimed_at > clock_timestamp() - ($1::bigint * interval '1 millisecond')`,
		k9FreshClaim.Milliseconds(), tools).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// aimAtAClaimedCall guarantees the campaign's one durable witness rather than
// leaving it to luck.
//
// The witness is a key in innsegl.idempotency that was claimed and unanswered
// when its holder stopped existing (ADR-0017 §5), and only a kill on the MCP
// while it is inside register_agent or record_event produces one:
// get_credential and retire_agent are intrinsically idempotent and claim
// nothing, and a kill on Postgres or SPIRE leaves the server alive to finish or
// fail the call. The soak's schedule guarantees the MCP is killed, but not that
// those two kills land inside a KEYED call — MEASURED, a full-suite run under
// four concurrent agents produced eight well-aimed kills and no takeover, and
// the campaign correctly refused to certify it.
//
// So the window is aimed at, and the shot repeated until it lands, which is
// test/failure/crashharness_test.go's `aim` discipline: park until a keyed call
// has a fresh claim, fire, let the workers replay, and look. What is asserted
// is unchanged; what is removed is the dependence on which of five tools three
// workers happened to be inside at two arbitrary moments.
func (c *k9Campaign) aimAtAClaimedCall(t *testing.T) {
	t.Helper()
	for attempt := 1; attempt <= k9AimAttempts; attempt++ {
		if got := c.claims(t); got.takeovers+got.stranded > 0 {
			if attempt > 1 {
				t.Logf("the durable witness took %d aimed shot(s)", attempt-1)
			}
			return
		}
		deadline := time.Now().Add(k9BusyBudget)
		for c.freshClaims(t, true) == 0 || c.inFlight.Load() == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("no keyed tool call was in flight at any point in %s, so the "+
					"campaign could not aim at the window that leaves a durable trace "+
					"(seed %d)", k9BusyBudget, c.seed)
			}
			time.Sleep(k9PollInterval)
		}
		t.Logf("aimed shot %d/%d: SIGKILL on %s while a keyed call holds a fresh claim",
			attempt, k9AimAttempts, k9TargetMCP)
		c.killTarget(t, k9TargetMCP)
		c.mu.Lock()
		c.killCount++
		c.byTarget[k9TargetMCP]++
		c.mu.Unlock()
		c.restoreTarget(t, k9TargetMCP)

		// The takeover appears when a worker replays the key it lost. They
		// retry on their own; this only waits for one of them to get there.
		until := time.Now().Add(20 * time.Second)
		for time.Now().Before(until) {
			if got := c.claims(t); got.takeovers+got.stranded > 0 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Errorf("%d aimed SIGKILLs on `innsegl serve`, every one of them fired while a "+
		"register_agent or record_event held a claim taken inside the last %s, and not "+
		"one of them left a reclaimed or stranded key behind (seed %d). Either the "+
		"claim is not written before the tool runs or it is not durable across the "+
		"process that wrote it.", k9AimAttempts, k9FreshClaim, c.seed)
}

// k9Claims is what innsegl.idempotency holds after the soak, which is the
// campaign's durable record of what the kills interrupted.
type k9Claims struct {
	rows int
	// takeovers is the number of keys claimed more than once. ADR-0017 §5: a
	// second claim means a lease ran out and another caller took it over, and
	// the only thing that leaves a claim behind is a replica that stopped
	// existing while holding it.
	takeovers int
	// stranded is the number of claims still in flight with nobody running.
	// After the soak and the settle there is no caller left, so a row still
	// in_progress is a claim whose holder died and never came back.
	stranded  int
	maxClaims int
}

func (c *k9Campaign) claims(t *testing.T) k9Claims {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out k9Claims
	err := c.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE claim_count > 1),
		       count(*) FILTER (WHERE status = 'in_progress'),
		       coalesce(max(claim_count), 0)
		  FROM innsegl.idempotency`).
		Scan(&out.rows, &out.takeovers, &out.stranded, &out.maxClaims)
	if err != nil {
		t.Fatalf("reading innsegl.idempotency: %v", err)
	}
	return out
}

func (c *k9Campaign) killTarget(t *testing.T, target string) {
	t.Helper()
	if target == k9TargetMCP {
		c.mu.Lock()
		d := c.daemon
		c.mu.Unlock()
		d.kill(t)
		return
	}
	name := c.containerFor(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := k9Docker(ctx, "kill", "--signal", "KILL", name); err != nil {
		t.Fatalf("SIGKILL %s: %v", name, err)
	}
	// Proved dead, not assumed dead: `docker kill` returning is not the same
	// claim as the process being gone.
	if !k9WaitFor(30*time.Second, func() bool { return !k9Running(name) }) {
		t.Fatalf("%s was still running after SIGKILL", name)
	}
}

func (c *k9Campaign) restoreTarget(t *testing.T, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch target {
	case k9TargetMCP:
		c.startDaemon(t)
	case k9TargetPostgres:
		c.startContainer(t, c.stack.pgContainer)
		if !k9WaitFor(150*time.Second, func() bool { return k9PGReady(ctx, c.stack.pgPort) }) {
			t.Fatalf("postgres never came back after the kill (seed %d)", c.seed)
		}
	case k9TargetSPIREServer:
		c.startContainer(t, c.stack.serverContainer)
		c.awaitHealthy(t, c.stack.serverContainer)
		if !k9WaitFor(150*time.Second, func() bool {
			_, err := c.stack.spireLocal(ctx, "entry", "count")
			return err == nil
		}) {
			t.Fatalf("spire-server never answered again after the kill (seed %d)", c.seed)
		}
	case k9TargetSPIREAgent:
		c.startContainer(t, c.stack.agentContainer)
		// The container's own healthcheck, which is `spire-agent healthcheck`
		// against the Workload API socket — the agent answering, not merely a
		// process existing.
		//
		// `agent list` is NOT the readiness signal here and that is worth
		// saying, because it looks like one: it reads the SERVER's datastore,
		// which still holds the node's attestation record while the agent is
		// dead, so it answers immediately after a kill and would wait for
		// nothing.
		c.awaitHealthy(t, c.stack.agentContainer)
		if err := c.stack.awaitAttestedNode(ctx, 150*time.Second); err != nil {
			t.Fatalf("the server names no attested node after the agent was killed "+
				"(seed %d): %v", c.seed, err)
		}
	default:
		t.Fatalf("no restore path for %q", target)
	}
}

func (c *k9Campaign) containerFor(t *testing.T, target string) string {
	t.Helper()
	switch target {
	case k9TargetPostgres:
		return c.stack.pgContainer
	case k9TargetSPIREServer:
		return c.stack.serverContainer
	case k9TargetSPIREAgent:
		return c.stack.agentContainer
	default:
		t.Fatalf("no container for %q", target)
		return ""
	}
}

func (c *k9Campaign) startContainer(t *testing.T, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := k9Docker(ctx, "start", name); err != nil {
		t.Fatalf("restarting %s: %v", name, err)
	}
	if !k9WaitFor(60*time.Second, func() bool { return k9Running(name) }) {
		t.Fatalf("%s did not come back up", name)
	}
}

// awaitHealthy waits for a container's own healthcheck to pass.
//
// deploy/compose/spire.yml gives spire-server and spire-agent a healthcheck
// that runs SPIRE's own probe, which asks the question a client asks: can the
// API be reached, and does it answer. A restore that waited only for
// `{{.State.Running}}` would hand the workload a container whose process had
// not opened its socket yet, and the outage the soak thinks it closed would
// still be open.
func (c *k9Campaign) awaitHealthy(t *testing.T, name string) {
	t.Helper()
	if !k9WaitFor(150*time.Second, func() bool { return k9Health(name) == "healthy" }) {
		t.Fatalf("%s never became healthy after the kill (seed %d); its healthcheck "+
			"reports %q", name, c.seed, k9Health(name))
	}
}

func k9Health(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := k9Docker(ctx, "inspect", "--format", "{{.State.Health.Status}}", name)
	if err != nil {
		return ""
	}
	return out
}

func k9Running(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := k9Docker(ctx, "inspect", "--format", "{{.State.Running}}", name)
	return err == nil && out == "true"
}

// restoreEverything puts every component back and waits for it, so the sweep
// reads a system that is up rather than one that is still recovering.
func (c *k9Campaign) restoreEverything(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, name := range []string{c.stack.pgContainer, c.stack.serverContainer, c.stack.agentContainer} {
		if !k9Running(name) {
			c.startContainer(t, name)
		}
	}
	c.awaitHealthy(t, c.stack.serverContainer)
	c.awaitHealthy(t, c.stack.agentContainer)
	if !k9WaitFor(150*time.Second, func() bool { return k9PGReady(ctx, c.stack.pgPort) }) {
		t.Fatalf("postgres is not reachable at the end of the soak (seed %d)", c.seed)
	}
	if !k9WaitFor(150*time.Second, func() bool {
		_, err := c.stack.spireLocal(ctx, "entry", "count")
		return err == nil
	}) {
		t.Fatalf("spire-server is not answering at the end of the soak (seed %d)", c.seed)
	}
	if err := c.stack.awaitAttestedNode(ctx, 150*time.Second); err != nil {
		t.Fatalf("no attested node at the end of the soak (seed %d): %v", c.seed, err)
	}

	c.mu.Lock()
	dead := c.daemon == nil || c.daemon.dead
	c.mu.Unlock()
	if dead {
		c.startDaemon(t)
	}
	c.settle(t)
}

// settle finishes the retirements the soak's deadline cut off.
//
// IP §6.6's claim is about the state reached "after restart + reconciliation",
// not about the instant the power came back, and a worker whose retire_agent
// was interrupted by the end of the soak is a call that a real agent would have
// retried. Replaying it here is that retry, through the shipped tool, and every
// replay is required to SUCCEED: retirement is idempotent (IP §4), so a run
// that was already retired must answer the same way as one that was not, and a
// refusal here would itself be the finding.
//
// It settles only the runs the workload decided to retire. The ones it decided
// to abandon stay abandoned — they are IP §6.7's crashed agent and the reaper's
// reason to exist.
func (c *k9Campaign) settle(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	w := &k9Worker{index: -1}
	defer w.close()

	// The keyed calls first, in key order so a seed replays them identically.
	//
	// An interrupted register_agent is the one that matters, and it is ADR-0018's
	// window: `run_registered` is appended BEFORE the SPIRE entry is created,
	// so a SIGKILL between the two leaves a chain that claims an identity SPIRE
	// does not hold. Nothing in the deployment closes that window on its own —
	// the reaper reaps ENTRIES, and there is no entry to reap — so the only
	// thing that closes it is the caller replaying its key, which is exactly
	// what IP §6.6 promises: "replaying any request after a crash returns the
	// original result". This is that replay, and every one is required to
	// SUCCEED. MEASURED before it existed: three runs were left registered on
	// the chain with no entry and no retirement, one per worker, all of them
	// calls the soak's own deadline had cut off.
	c.mu.Lock()
	keys := make([]string, 0, len(c.outstanding))
	for key := range c.outstanding {
		keys = append(keys, key)
	}
	c.mu.Unlock()
	slices.Sort(keys)

	for _, key := range keys {
		c.mu.Lock()
		call := c.outstanding[key]
		c.mu.Unlock()
		if _, ok := c.call(ctx, w, call.tool, call.args); !ok {
			t.Fatalf("%s under idempotency_key %q never succeeded after the soak "+
				"(seed %d); IP §6.6 requires a replay after a crash to return the "+
				"original result, and this one never returned at all",
				call.tool, key, c.seed)
		}
	}

	// Then the retirements the workload meant to make.
	c.mu.Lock()
	pending := make([]string, 0, len(c.runs))
	for runID, retire := range c.runs {
		if retire {
			pending = append(pending, runID)
		}
	}
	c.mu.Unlock()
	slices.Sort(pending)

	for _, runID := range pending {
		if _, ok := c.call(ctx, w, mcp.ToolRetireAgent, map[string]any{"run_id": runID}); !ok {
			t.Fatalf("retire_agent(%s) never succeeded after the soak (seed %d); IP §4 "+
				"makes retirement idempotent, so a replay of one is required to answer "+
				"the same way as the first call", runID, c.seed)
		}
	}
	t.Logf("seed %d: settled %d interrupted call(s) and %d retirement(s) the soak had begun",
		c.seed, len(keys), len(pending))
}

func (c *k9Campaign) evidence(t *testing.T) k9Evidence {
	t.Helper()
	c.mu.Lock()
	ev := k9Evidence{
		kills:               c.killCount,
		byTarget:            maps.Clone(c.byTarget),
		idleKills:           c.idleKills,
		dispatched:          c.dispatched.Load(),
		interrupted:         c.interrupted.Load(),
		invariantViolations: c.invariants,
		firstInvariant:      c.firstInvariant,
	}
	c.mu.Unlock()
	ev.claims = c.claims(t)
	for _, target := range k9Targets {
		if _, ok := ev.byTarget[target]; !ok {
			ev.byTarget[target] = 0
		}
	}
	return ev
}

// ---------------------------------------------------------------------------
// The reaper: IP §6.7's resolution step, run by the shipped component.
// ---------------------------------------------------------------------------

func (c *k9Campaign) reaper(t *testing.T) *spire.Reaper {
	t.Helper()
	r, err := spire.NewReaper(spire.ReaperConfig{
		Client: c.admin,
		Ledger: c.store,
		// Zero grace, deliberately. The operator surface applies
		// DefaultReapGrace — a second identity lifetime — and that is right for
		// a deployment; here it would double the wall clock of a bounded soak
		// for no assertion. The TTL itself is the bound being tested.
		Grace: 0,
	})
	if err != nil {
		t.Fatalf("spire.NewReaper: %v", err)
	}
	return r
}

// sweepUntilExpired runs the shipped reaper until it expires one named run.
//
// Polled rather than swept once, and the reason is a real property of the
// environment rather than of the system under test: the reaper computes a run's
// deadline from `created_at` AS THE SPIRE SERVER RECORDED IT, in the container's
// clock and truncated to a whole second, while this test derives its own
// deadline from the host clock at the instant it called RegisterRun. On a
// Docker VM whose clock has drifted ahead of the host — routine on macOS after
// a sleep — a one-second identity lifetime can be past by the host's reckoning
// and not yet past by SPIRE's. MEASURED: a planted orphan the sweep function
// convicted was still Live in the reaper's report on the same pass.
//
// Waiting for the two clocks to agree is not weakening the assertion. What is
// asserted is unchanged and is the whole of IP §6.7: the reaper finds the
// orphan, records the expiry, and deletes the entry. What is no longer asserted
// is that it does so on the first sweep after a deadline this process computed,
// which was never OPS-003's claim.
func (c *k9Campaign) sweepUntilExpired(t *testing.T, run spire.RunRef, budget time.Duration) spire.Expiry {
	t.Helper()
	started := time.Now()
	deadline := started.Add(budget)
	for {
		report := c.sweepOnce(t)
		if expiry, found := report.FindExpired(run.RunID); found {
			if waited := time.Since(started); waited > time.Second {
				t.Logf("the reaper needed %s longer than this test's own derivation of "+
					"the deadline; the SPIRE server's clock is ahead of the host's",
					waited.Truncate(10*time.Millisecond))
			}
			return expiry
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reaper never expired the planted orphan %s within %s (seed %d). "+
				"Its entry has a one-second identity lifetime and nobody retired it, "+
				"which is IP §6.7's orphan exactly; a reaper that does not find it is "+
				"the finding. Last report: %s", run.RunID, budget, c.seed, report)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (c *k9Campaign) sweepOnce(t *testing.T) *spire.SweepReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	report, err := c.reaper(t).Sweep(ctx)
	if err != nil {
		t.Fatalf("the reaper could not sweep (seed %d): %v", c.seed, err)
	}
	if !report.OK() {
		t.Errorf("the reaper failed on %d entr(ies) (seed %d): %s",
			len(report.Failures), c.seed, report)
	}
	return report
}

// reapUntilQuiet runs the shipped reaper until a sweep expires nothing, and
// returns how many runs were expired in total.
func (c *k9Campaign) reapUntilQuiet(t *testing.T) int {
	t.Helper()
	total, waited := 0, false
	for pass := 1; pass <= 10; pass++ {
		report := c.sweepOnce(t)
		total += len(report.Expired)
		if n := len(report.Expired); n > 0 {
			t.Logf("reaper pass %d expired %d run(s)", pass, n)
			continue
		}
		// Nothing was orphaned yet. Every run still holding an entry at this
		// point was abandoned — the workers are gone and the retirements have
		// been settled — so each becomes an orphan at its own deadline, and the
		// earliest is the shortest wait that gives the reaper something real to
		// find. Waiting is bounded by the identity lifetime the runs were
		// registered with, so it cannot become an unbounded sleep.
		if total == 0 && !waited && len(report.Live) > 0 {
			earliest := report.Live[0].Deadline
			for _, cand := range report.Live[1:] {
				if cand.Deadline.Before(earliest) {
					earliest = cand.Deadline
				}
			}
			wait := time.Until(earliest.Add(500 * time.Millisecond))
			if wait > 0 && wait <= k9RunTTL+10*time.Second {
				t.Logf("no run has outlived its %s identity lifetime yet; the earliest "+
					"does in %s", k9RunTTL, wait.Truncate(time.Millisecond))
				time.Sleep(wait)
				waited = true
				continue
			}
		}
		return total
	}
	t.Errorf("the reaper was still expiring runs after 10 passes (seed %d); it is not "+
		"converging", c.seed)
	return total
}

// ---------------------------------------------------------------------------
// Gathering the state the sweep reads.
// ---------------------------------------------------------------------------

type k9State struct {
	now     time.Time
	records []event.Fields
	tip     ledger.Head
	live    []spire.Candidate
	skipped []spire.Skipped
}

func (c *k9Campaign) gather(t *testing.T) k9State {
	t.Helper()
	// `now` is read BEFORE the sweep and not after, and that ordering is load
	// bearing. Every entry the reaper reports as Live had a deadline in the
	// future at the instant it swept; reading the clock afterwards could put
	// `now` past one of those deadlines and the sweep would then convict an
	// entry of outliving a TTL it had not yet outlived when it was observed.
	now := time.Now().UTC()
	report := c.sweepOnce(t)
	st := c.chainState(t)
	st.now = now
	st.live = report.Live
	st.skipped = report.Skipped
	return st
}

func (c *k9Campaign) chainState(t *testing.T) k9State {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	head, err := c.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger Head: %v", err)
	}
	st := k9State{now: time.Now().UTC(), tip: head}
	if head.IsEmpty() {
		return st
	}
	records, err := c.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("ledger Events: %v", err)
	}
	st.records = records
	return st
}

func k9Clone(st k9State) k9State {
	out := k9State{now: st.now, tip: st.tip}
	out.records = make([]event.Fields, 0, len(st.records))
	for _, r := range st.records {
		out.records = append(out.records, k9CloneFields(r))
	}
	out.live = slices.Clone(st.live)
	out.skipped = slices.Clone(st.skipped)
	return out
}

func k9CloneFields(f event.Fields) event.Fields {
	out := make(event.Fields, len(f))
	maps.Copy(out, f)
	return out
}

// ---------------------------------------------------------------------------
// The sweep.
//
// Every check is named, and the name is what a planted-violation subtest asks
// for. A sweep whose failures cannot be told apart is a sweep whose self-test
// cannot tell whether the right thing fired.
// ---------------------------------------------------------------------------

const (
	k9CheckChainLinks        = "the hash chain verifies from the genesis constant"
	k9CheckChainTip          = "the walk ends at the tip the store records"
	k9CheckPositions         = "chain positions are consecutive from 1, with no gap and no duplicate"
	k9CheckMonotonicTS       = "ts never goes backwards along the chain"
	k9CheckOneIdentityPerRun = "one run_registered per run, and one per idempotency_key"
	k9CheckOneExitPerRun     = "a run is retired or expired, never both and never twice"
	k9CheckRunIsRegistered   = "every event scoped to a run follows that run's run_registered"

	k9CheckNoOrphanPastTTL = "no registration entry outlives its TTL"
	k9CheckEntryIsRecorded = "every live entry has a run_registered and no retirement"
	k9CheckExitIsRecorded  = "every registered run with no entry has a run_retired or a run_expired"
	k9CheckEntryGrammar    = "every entry in the agent subtree is a classifiable run identity"
)

type k9Violation struct {
	check  string
	detail string
}

func (v k9Violation) String() string { return v.check + ": " + v.detail }

func k9Fire(vs *[]k9Violation, check, format string, args ...any) {
	*vs = append(*vs, k9Violation{check: check, detail: fmt.Sprintf(format, args...)})
}

// k9SweepChain is the ledger half: I3 and I4, and IP §6.6's "never a second
// identity".
func k9SweepChain(st k9State) []k9Violation {
	var vs []k9Violation

	// I4, and doc 02 §4.5. VerifyTip walks from the genesis constant and then
	// checks the walk ended where the store says it ends — the walk alone
	// cannot see a chain that has had its tail removed, because a prefix of a
	// valid chain is a valid chain.
	if _, err := ledger.Verify(st.records); err != nil {
		k9Fire(&vs, k9CheckChainLinks, "%v", err)
	} else if err := ledger.VerifyTip(st.records, st.tip); err != nil {
		k9Fire(&vs, k9CheckChainTip, "%v", err)
	}

	var (
		lastTS    string
		registrar = map[string]int{}  // run id → run_registered count
		regKeys   = map[string]int{}  // register idempotency key → count
		retired   = map[string]int{}  // run id → run_retired count
		expired   = map[string]int{}  // run id → run_expired count
		seenRun   = map[string]bool{} // run id → its run_registered has been passed
	)
	for i, rec := range st.records {
		want := int64(i + 1)
		got, _ := k9Int(rec[event.FieldChainPosition])
		if got != want {
			k9Fire(&vs, k9CheckPositions,
				"the %dth record carries chain_position %d", i+1, got)
		}

		// Compared as strings, which is sound and not a shortcut: doc 02 §2's
		// `ts` is RFC 3339 UTC at exactly millisecond precision with a literal
		// Z (internal/event/envelope.go says so and validates it), so every
		// value is the same width and lexicographic order is chronological
		// order. A format that allowed variable fractional digits would make
		// this comparison quietly wrong.
		ts := k9Str(rec, event.FieldTS)
		if lastTS != "" && ts < lastTS {
			k9Fire(&vs, k9CheckMonotonicTS,
				"position %d carries ts %s, after %s at the position before it "+
					"(IP §6.8: ledger ts values are server-assigned and monotonic per chain)",
				got, ts, lastTS)
		}
		if ts > lastTS {
			lastTS = ts
		}

		kind := k9Str(rec, event.FieldEventType)
		runID := k9Str(rec, event.FieldRunID)
		switch kind {
		case event.EventTypeRunRegistered:
			registrar[runID]++
			if key := k9Str(rec, event.FieldIdempotencyKey); key != "" {
				regKeys[key]++
			}
			seenRun[runID] = true
		case event.EventTypeRunRetired:
			retired[runID]++
		case event.EventTypeRunExpired:
			expired[runID]++
		}

		// I3, read forwards: nothing may be recorded against a run before the
		// run was registered. The soak's own event types are the ones with a
		// run scope; the reconciler's alerts carry one too and are appended
		// after the fact, so the check is "the registration came first", not
		// "the registration exists somewhere".
		if runID != "" && kind != event.EventTypeRunRegistered && !seenRun[runID] {
			k9Fire(&vs, k9CheckRunIsRegistered,
				"position %d is a %s for run %q and no run_registered for it comes "+
					"before it (I3)", got, kind, runID)
		}
	}

	for runID, n := range registrar {
		if n > 1 {
			k9Fire(&vs, k9CheckOneIdentityPerRun,
				"run %q has %d run_registered events; IP §6.6 forbids a replay ever "+
					"producing a second identity", runID, n)
		}
	}
	for key, n := range regKeys {
		if n > 1 {
			k9Fire(&vs, k9CheckOneIdentityPerRun,
				"idempotency_key %q registered %d runs", key, n)
		}
	}
	for runID, n := range retired {
		switch {
		case n > 1:
			k9Fire(&vs, k9CheckOneExitPerRun, "run %q was retired %d times", runID, n)
		case expired[runID] > 0:
			k9Fire(&vs, k9CheckOneExitPerRun,
				"run %q has both a run_retired and a run_expired; the two are "+
					"deliberately distinct (IP §6.7) and a run cannot be both",
				runID)
		}
	}
	for runID, n := range expired {
		if n > 1 {
			k9Fire(&vs, k9CheckOneExitPerRun, "run %q was expired %d times", runID, n)
		}
	}
	return vs
}

// k9SweepIdentities is the SPIRE half: IP §6.7's orphans, and I1/I3 across the
// boundary between the identity plane and the chain.
func k9SweepIdentities(st k9State) []k9Violation {
	var vs []k9Violation

	registered := map[string]bool{}
	gone := map[string]bool{}
	for _, rec := range st.records {
		kind := k9Str(rec, event.FieldEventType)
		runID := k9Str(rec, event.FieldRunID)
		if runID == "" {
			continue
		}
		switch kind {
		case event.EventTypeRunRegistered:
			registered[runID] = true
		case event.EventTypeRunRetired, event.EventTypeRunExpired:
			gone[runID] = true
		}
	}

	live := map[string]bool{}
	for _, cand := range st.live {
		live[cand.Run.RunID] = true

		if st.now.After(cand.Deadline) {
			k9Fire(&vs, k9CheckNoOrphanPastTTL,
				"%s was created at %s with a %s identity lifetime, so it was orphaned "+
					"at %s, and it is still in the datastore (IP §6.7)",
				cand.Entry.SPIFFEID, cand.CreatedAt.Format(time.RFC3339),
				cand.Entry.TTL, cand.Deadline.Format(time.RFC3339))
		}
		if err := event.ValidateSPIFFEID(cand.Entry.SPIFFEID); err != nil {
			k9Fire(&vs, k9CheckEntryGrammar, "%s: %v", cand.Entry.SPIFFEID, err)
		}
		if !registered[cand.Run.RunID] {
			k9Fire(&vs, k9CheckEntryIsRecorded,
				"%s exists in SPIRE and the chain holds no run_registered for run %q "+
					"(I1, I3)", cand.Entry.SPIFFEID, cand.Run.RunID)
		}
		if gone[cand.Run.RunID] {
			k9Fire(&vs, k9CheckEntryIsRecorded,
				"%s is still in SPIRE and the chain says run %q was retired or expired",
				cand.Entry.SPIFFEID, cand.Run.RunID)
		}
	}

	for _, sk := range st.skipped {
		k9Fire(&vs, k9CheckEntryGrammar,
			"the reaper could not classify %s (%s): %s", sk.SPIFFEID, sk.EntryID, sk.Reason)
	}

	for runID := range registered {
		if !live[runID] && !gone[runID] {
			k9Fire(&vs, k9CheckExitIsRecorded,
				"run %q was registered, has no entry in SPIRE, and the chain records "+
					"neither a run_retired nor a run_expired for it (I3, I4: the identity "+
					"went and nothing says why)", runID)
		}
	}
	return vs
}

func k9Int(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

func (c *k9Campaign) requireNoViolations(t *testing.T, what string, vs []k9Violation) {
	t.Helper()
	if len(vs) == 0 {
		return
	}
	var b strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&b, "\n  - %s", v)
	}
	t.Errorf("%d invariant violation(s) survived the sweep of %s (seed %d — replay with "+
		"INNSEGL_CHAOS_SEED=%d):%s", len(vs), what, c.seed, c.seed, b.String())
}

// requireViolation insists the sweep reported the named check, and — when
// `names` is given — that the finding is about the thing that was planted.
//
// The second half is not decoration. A soak leaves plenty of true findings
// lying around in a tampered snapshot, and a self-test that accepted any
// finding under the right name could be satisfied by one the plant had nothing
// to do with. That is the same class of mistake as the sweep itself passing
// vacuously.
func (c *k9Campaign) requireViolation(t *testing.T, check string, vs []k9Violation, names ...string) {
	t.Helper()
	for _, v := range vs {
		if v.check != check {
			continue
		}
		if len(names) > 0 && !strings.Contains(v.detail, names[0]) {
			continue
		}
		t.Logf("the planted violation was caught: %s", v)
		return
	}
	subject := ""
	if len(names) > 0 {
		subject = fmt.Sprintf(" naming %q", names[0])
	}
	t.Errorf("the sweep did not report %q%s against state with that very violation "+
		"planted in it (seed %d). It reported %d other finding(s): %v. A sweep nobody "+
		"has seen fail proves nothing.", check, subject, c.seed, len(vs), vs)
}

// ---------------------------------------------------------------------------
// Planting.
// ---------------------------------------------------------------------------

// plantOrphan creates a real registration entry, in the real SPIRE, with a
// one-second identity lifetime and nobody to retire it. IP §6.7's agent that
// crashed.
//
// The Candidate it returns is the entry as SPIRE now holds it, with the
// deadline re-derived here — created-at plus the entry's own TTL — rather than
// read back from the component under test. That re-derivation is deliberate:
// internal/spire.entryDeadline computes the same sum, and a sweep that took the
// deadline from the reaper would be asking the reaper whether the reaper is
// right. The reaper's independent verdict is asserted separately, by reaping
// this entry.
func (c *k9Campaign) plantOrphan(t *testing.T) (spire.RunRef, spire.Candidate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	run := spire.RunRef{
		AgentType: k9AgentType,
		TaskID:    k9TaskID,
		RunID:     fmt.Sprintf("orphan-%d", c.seed%1_000_000),
	}
	spiffeID := k9SPIFFEIDFor(t, run)

	// I3 first: an identity with no record would itself be a violation, and
	// planting one would make the sweep fire for the wrong reason.
	if _, err := c.store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldAgentType:      run.AgentType,
		event.FieldTaskRef:        run.TaskID,
		event.FieldIdempotencyKey: "ops-003/orphan/" + run.RunID,
	}); err != nil {
		t.Fatalf("recording the planted orphan's registration: %v", err)
	}

	createdAt := time.Now().UTC()
	entry, err := c.admin.RegisterRun(ctx, spire.Registration{
		Run:       run,
		ParentID:  c.stack.parentID,
		Selectors: []spire.Selector{{Type: "docker", Value: "label:dev.innsegl.run-id:" + run.RunID}},
		TTL:       time.Second,
	})
	if err != nil {
		t.Fatalf("registering the planted orphan: %v", err)
	}
	return run, spire.Candidate{
		Entry:     entry,
		Run:       run,
		CreatedAt: createdAt,
		Deadline:  createdAt.Add(entry.TTL),
	}
}

// awaitOrphaned waits until the planted entry is past its deadline and returns
// the state a sweep would see with it in the datastore.
func (c *k9Campaign) awaitOrphaned(t *testing.T, base k9State, cand spire.Candidate) k9State {
	t.Helper()
	if wait := time.Until(cand.Deadline.Add(250 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	st := c.chainState(t)
	st.live = append(slices.Clone(base.live), cand)
	st.skipped = slices.Clone(base.skipped)
	return st
}

func k9SPIFFEIDFor(t *testing.T, run spire.RunRef) string {
	t.Helper()
	id, err := run.SPIFFEID(k9TrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID(%+v): %v", run, err)
	}
	return id
}

// plantIntent appends a `commit_intent` with no signature behind it — the
// durable residue of IP §6.5's crash between Phase A and Phase B.
func (c *k9Campaign) plantIntent(t *testing.T, runID, spiffeID, key string) event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rec, err := c.store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: key,
		event.FieldRepo:           k9Repo,
		event.FieldTreeHash:       k9Tree,
	})
	if err != nil {
		t.Fatalf("planting a commit_intent: %v", err)
	}
	return rec
}

// plantFabricatedRecord appends a `commit_recorded` naming a Rekor entry that
// the real Rekor does not hold. IP §6.10, verbatim: "inject a fabricated
// `commit_recorded` with no Rekor entry, assert drift detection fires".
func (c *k9Campaign) plantFabricatedRecord(t *testing.T, intent event.Fields) event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rec, err := c.store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          member(t, intent, event.FieldRunID),
		event.FieldSpiffeID:       member(t, intent, event.FieldSpiffeID),
		event.FieldIdempotencyKey: "ops-003/fabricated/" + member(t, intent, event.FieldEventID),
		event.FieldRepo:           k9Repo,
		event.FieldTreeHash:       k9Tree,
		event.FieldCommitSHA:      "2222222222222222222222222222222222222222",
		event.FieldIntentEventID:  member(t, intent, event.FieldEventID),
		event.FieldRekorEntryUUID: strings.Repeat("3", 64),
		event.FieldRekorLogIndex:  int64(999_999),
	})
	if err != nil {
		t.Fatalf("planting a fabricated commit_recorded: %v", err)
	}
	return rec
}

// ---------------------------------------------------------------------------
// The reconciler.
// ---------------------------------------------------------------------------

func (c *k9Campaign) reconcile(t *testing.T, at time.Time) reconciler.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log, err := reconciler.NewRekorLog(c.stack.rekor.baseURL(), &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("reconciler.NewRekorLog: %v", err)
	}
	repos, err := reconciler.NewGitWorkspace(c.repos)
	if err != nil {
		t.Fatalf("reconciler.NewGitWorkspace: %v", err)
	}
	r, err := reconciler.New(reconciler.Config{
		Ledger:      c.store,
		Appender:    c.store,
		Repos:       repos,
		Log:         log,
		TrustDomain: k9TrustDomain,
		Now:         func() time.Time { return at },
		Drift:       &reconciler.DriftConfig{Sweep: log},
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(ctx)
	if err != nil {
		t.Fatalf("the reconciler could not run a cycle (seed %d): %v", c.seed, err)
	}
	return result
}

// aRegisteredRun picks a run the soak registered, so the planted events below
// carry an identity this deployment really issued.
func (c *k9Campaign) aRegisteredRun(t *testing.T, st k9State) (runID, spiffeID string) {
	t.Helper()
	for _, rec := range st.records {
		if k9Str(rec, event.FieldEventType) != event.EventTypeRunRegistered {
			continue
		}
		id := k9Str(rec, event.FieldRunID)
		sid := k9Str(rec, event.FieldSpiffeID)
		if id != "" && sid != "" {
			return id, sid
		}
	}
	t.Fatalf("the soak registered no run at all (seed %d); there is no identity to plant "+
		"against", c.seed)
	return "", ""
}

func (c *k9Campaign) requireEventType(t *testing.T, eventID, want string) {
	t.Helper()
	st := c.chainState(t)
	for _, rec := range st.records {
		if k9Str(rec, event.FieldEventID) != eventID {
			continue
		}
		if got := k9Str(rec, event.FieldEventType); got != want {
			t.Errorf("event %s is a %q, expected a %q (seed %d)", eventID, got, want, c.seed)
		}
		return
	}
	t.Errorf("event %s is not on the chain (seed %d)", eventID, c.seed)
}

// ---------------------------------------------------------------------------
// Small helpers the test file uses.
// ---------------------------------------------------------------------------

// k9Str reads a string member, or "" when the record does not carry one.
//
// One accessor rather than a blank type assertion at every use: errcheck's
// check-type-assertions is on, and a `v, _ := x.(string)` is exactly the
// silently-wrong read it exists to catch.
func k9Str(f event.Fields, name string) string {
	s, ok := f[name].(string)
	if !ok {
		return ""
	}
	return s
}

func member(t *testing.T, f event.Fields, name string) string {
	t.Helper()
	s, ok := f[name].(string)
	if !ok {
		t.Fatalf("the record carries no %s: %v", name, f)
	}
	return s
}

func k9FindEvent(t *testing.T, records []event.Fields, eventType string) event.Fields {
	t.Helper()
	for _, rec := range records {
		if k9Str(rec, event.FieldEventType) == eventType {
			return rec
		}
	}
	t.Fatalf("no %s on the chain", eventType)
	return nil
}

// k9FlipDigest changes one hex digit of a digest, leaving it well-formed. A
// malformed value would be caught by the envelope validator and would prove
// something weaker than a broken link.
func k9FlipDigest(s string) string {
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		switch {
		case b[i] >= '0' && b[i] <= '8', b[i] >= 'a' && b[i] <= 'e':
			b[i]++
			return string(b)
		case b[i] == '9':
			b[i] = 'a'
			return string(b)
		case b[i] == 'f':
			b[i] = '0'
			return string(b)
		}
	}
	return s
}
