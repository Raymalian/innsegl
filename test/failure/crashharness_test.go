// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// ---------------------------------------------------------------------------
// MCP-011's world: a real Postgres holding one chain, a real containerised
// SPIRE, and the SHIPPED `innsegl serve` as a process this file is allowed to
// SIGKILL.
//
// This used to build test/failure/crashd — a binary written for this campaign
// because nothing in the repository wired the tools onto a listener. RM-068
// (#89) built the real entry point, so the campaign now kills the binary a
// deployment runs. Nothing that is ASSERTED below changed with the swap: crashd
// called the same exported Configure* seams over the same real dependencies,
// which is why it could be replaced by a change to which binary is built.
//
// Two things about the process are still the harness's and not a deployment's,
// and both are flags the shipped binary takes rather than code written here.
// The admin SVID arrives as PEM files, because there is no attested innsegl-mcp
// workload on this host and the containerised agent's Workload API socket is
// inside the container. And -fulcio-url / -rekor-url point at a closed port:
// they are required configuration, they are read only by /readyz, and MCP-011
// is a claim about what a SIGKILL leaves in Postgres and in SPIRE.
//
// HOW THE KILL TIMING IS FUZZED — IP §6.6 says "fuzz the kill timing", so a
// hand-picked list of three points is not what is being asked for.
//
// Two mechanisms, and they answer two different questions.
//
//  1. A BLIND, SEEDED, STRATIFIED DELAY. Each tool's uninterrupted call is
//     first timed for real (calibrate), and the campaign then draws kill
//     delays across [0, 1.25 x that duration) at nanosecond resolution: the
//     window is cut into strata, one delay is drawn uniformly inside each, and
//     the strata are visited in a seeded random order. Stratifying rather than
//     drawing 12 independent uniforms is what makes a short campaign cover the
//     whole call instead of clumping; drawing INSIDE each stratum is what
//     keeps the points unchosen. This is the half that hits windows nobody
//     thought to name, and every landing is CLASSIFIED FROM DURABLE STATE
//     afterwards rather than assumed from the delay.
//
//  2. AN OBSERVED TRIGGER. For each window this project has actually reasoned
//     about — ADR-0018's "the event is on the chain and the SPIRE entry is
//     not", ADR-0017's "the reply is recorded and the caller has not got it",
//     ADR-0020's mirror of the first — the kill is fired by POLLING POSTGRES
//     OR SPIRE and sending the signal the moment the state appears, and is
//     then verified against durable state after the fact. That is RM-066's
//     waitForLockWaiters standard: park on evidence, not on a sleep. A blind
//     campaign alone could not promise to reach these, and a test that only
//     reached them by luck would be green for reasons nobody could reproduce.
//
// REPRODUCING A FAILURE. The seed is printed at the head of every run and
// again with every failure. INNSEGL_CRASH_SEED=<seed> replays the identical
// sequence of tool choices, strata orders and delays; INNSEGL_CRASH_BLIND
// sets the number of blind strata per tool.
//
// WHY EVERY ITERATION IS SUSPECTED OF BEING VACUOUS. A crash harness that
// kills too early proves nothing and passes anyway: a call that never started
// cannot leave a second identity. So no iteration is allowed to assert on its
// own say-so. Each one reads back, from Postgres and from SPIRE, what state
// the process was actually in when it died, names the window it landed in, and
// the campaign then FAILS unless every named window was reached at least once
// and the blind half landed on both sides of "something durable happened".
// ---------------------------------------------------------------------------

const (
	// The campaign's own agent type and task. Held to doc 02 §5's identifier
	// grammar, because they become components of a SPIFFE ID.
	crashAgentType = "crash-replay"
	crashTaskID    = "mcp-011"

	// crashLease is the idempotency lease the server runs with. The shipped
	// default is a minute (ADR-0017 §5), which is the right number for a
	// deployment and the wrong one for a test: a replay of a claim whose owner
	// was SIGKILLed waits out the remainder of the lease before taking it
	// over, so a minute would make every crash-mid-claim iteration take a
	// minute. Shortening it does not weaken anything — it makes the TAKEOVER
	// path, which is where a second identity would appear if the run id were
	// minted rather than derived, the ordinary case here rather than the rare
	// one.
	crashLease = 750 * time.Millisecond

	// crashPollInterval is how often an observed trigger re-reads the state it
	// is waiting for. Tight on purpose: the interval is the width of the
	// window the kill can overshoot by.
	crashPollInterval = time.Millisecond

	// crashTriggerBudget bounds an observed trigger's wait.
	crashTriggerBudget = 20 * time.Second

	// crashBlindDefault is how many strata each tool's blind campaign uses.
	crashBlindDefault = 10

	// crashTargetAttempts is how many times a targeted window is attempted
	// before the campaign gives up and says so.
	crashTargetAttempts = 8
)

// ---------------------------------------------------------------------------
// Windows. Every kill lands in exactly one of these, decided by what Postgres
// and SPIRE hold afterwards.
// ---------------------------------------------------------------------------

const (
	winBeforeClaim   = "before the claim: no idempotency row"
	winClaimedNoWork = "claimed, nothing durable yet"
	winEventNoEntry  = "run_registered on the chain, no SPIRE entry (ADR-0018's window)"
	winEntryNoReply  = "SPIRE entry created, reply not recorded"
	winReplyUnseen   = "reply recorded, the caller never saw it (ADR-0017's window)"
	winReplySeen     = "reply recorded and delivered"

	winRecEventNoReply = "tool_call on the chain, reply not recorded"

	winRetireNoRecord = "no run_retired yet"
	winRetireNoDelete = "run_retired on the chain, the SPIRE entry still there (ADR-0020's window)"
	winRetireNoReply  = "run_retired on the chain, entry deleted, reply not delivered"
	winRetireSeen     = "retirement delivered"

	winCredNoRecord = "no credential_issued: the token, if minted, was dropped"
	winCredNoReply  = "credential_issued on the chain, the token not delivered"
	winCredSeen     = "credential delivered"
)

// ---------------------------------------------------------------------------
// The campaign.
// ---------------------------------------------------------------------------

type campaign struct {
	stack *stack
	// dsn names the one database this campaign's chain lives in (ADR-0005).
	dsn string
	// store and pool are the TEST's own readers. The server opens its own.
	store *ledger.Store
	pool  *pgxpool.Pool
	idem  *mcp.IdempotencyStore
	admin *spire.Client

	binary  string
	pemDir  string
	workDir string

	// proxy is the response-holding proxy in front of the current shot, when
	// one is in play. See holdingProxy.
	proxy *holdingProxy

	seed  uint64
	rng   *deterministicRNG
	blind int

	// entriesAtStart is the whole SPIRE datastore before the campaign ran, so
	// "no second identity" can be asked of the datastore and not only of the
	// runs this file happens to know about.
	entriesAtStart []string
	// expectLive and expectGone are the identities the campaign deliberately
	// created and deliberately retired.
	expectLive []string
	expectGone []string

	mu            sync.Mutex
	landings      map[string]int
	blindLandings map[string]int
	nameSeq       int
	killCount     int
	// originals counts how many times the headline comparison was actually
	// made: a replay's bytes against the bytes recorded before the crash. It
	// is a gate, not a statistic — see census.
	originals int
}

// requireCrashCampaign brings up everything MCP-011 needs, or skips naming
// what goes unproven. Nothing here passes without a real Postgres, a real
// SPIRE and a real process to kill.
func requireCrashCampaign(t *testing.T) *campaign {
	t.Helper()

	ctx := context.Background()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping MCP-011: %v. Crash-and-replay is a claim about what a SIGKILLed "+
			"process leaves in Postgres and in SPIRE; with neither running there is nothing "+
			"to leave anything in, and a green test here would mean nothing. Start Docker "+
			"and re-run.", err)
	}
	s := requireStack(t)

	// requireLedger owns the shared Postgres container (pgOnce). Calling it is
	// how this file brings that container up without a second copy of its
	// lifecycle; the store it returns is on a database of its own and is not
	// used here.
	_ = requireLedger(t)

	c := &campaign{
		stack:         s,
		landings:      map[string]int{},
		blindLandings: map[string]int{},
		blind:         envInt("INNSEGL_CRASH_BLIND", crashBlindDefault),
		workDir:       t.TempDir(),
	}
	c.seed = crashSeed(t)
	c.rng = newDeterministicRNG(c.seed)
	t.Logf("MCP-011 seed %d — re-run this exact campaign with INNSEGL_CRASH_SEED=%d", c.seed, c.seed)

	c.dsn = c.freshDatabase(t)
	c.store = openCrashLedger(t, c.dsn)
	c.pool = openCrashPool(t, c.dsn)
	c.idem = mcp.NewIdempotencyStore(c.pool, mcp.WithIdempotencyLease(crashLease))
	c.admin = s.adminClient(t)
	c.binary = buildServer(t)
	c.pemDir = c.writeAdminPEMs(t)

	before, err := s.allEntrySPIFFEIDs(context.Background())
	if err != nil {
		t.Fatalf("reading the SPIRE datastore before the campaign: %v", err)
	}
	c.entriesAtStart = before
	return c
}

// crashSeed reads the campaign seed, or draws one and prints it.
func crashSeed(t *testing.T) uint64 {
	t.Helper()
	if raw := os.Getenv("INNSEGL_CRASH_SEED"); raw != "" {
		seed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("INNSEGL_CRASH_SEED=%q is not a uint64: %v", raw, err)
		}
		return seed
	}
	return uint64(time.Now().UnixNano())
}

func envInt(name string, fallback int) int {
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

// deterministicRNG is a splitmix64. Written out rather than taken from
// math/rand so that a seed reproduces the same campaign on every Go release,
// which is the whole point of printing one.
type deterministicRNG struct {
	mu    sync.Mutex
	state uint64
}

func newDeterministicRNG(seed uint64) *deterministicRNG { return &deterministicRNG{state: seed} }

func (r *deterministicRNG) next() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0, n).
func (r *deterministicRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

// duration returns a value in [lo, hi).
func (r *deterministicRNG) duration(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(r.next()%uint64(hi-lo))
}

// shuffle permutes xs with the campaign's own generator.
func (r *deterministicRNG) shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.intn(i+1))
	}
}

// requireOriginalReply is IP §6.6's headline, asserted: "replaying any request
// after a crash returns the original result".
//
// It runs only when the reply was recorded BEFORE the kill, because only then
// is there an original to return; the campaign counts the times it ran and
// fails if that is ever zero, so the assertion cannot quietly stop applying.
func (c *campaign) requireOriginalReply(t *testing.T, why string, replayed any, recorded []byte) {
	t.Helper()
	got, want := canonical(t, replayed), canonicalBytes(t, recorded)
	// A comparison of two empty things is not a comparison. The shortest reply
	// any of IP §4's tools can produce has two members.
	if len(want) < 16 {
		t.Fatalf("%s: the reply recorded before the crash canonicalizes to %q, which is too "+
			"short to be any of IP §4's result shapes; comparing against it would prove nothing",
			why, want)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: the replay returned %s; the reply recorded before the crash was %s. "+
			"IP §6.6: replaying any request after a crash returns the original result. (seed %d)",
			why, got, want, c.seed)
	}
	c.mu.Lock()
	c.originals++
	c.mu.Unlock()
}

func (c *campaign) countKill() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killCount++
}

func (c *campaign) name(prefix string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nameSeq++
	return fmt.Sprintf("%s-%d-%d", prefix, c.seed%1_000_000, c.nameSeq)
}

// landed credits one kill to the window it was OBSERVED to land in. target is
// what the shot was aiming at — empty for a blind stratum — and is never what
// is credited: an observed trigger that overshot lands where it landed.
func (c *campaign) landed(target, window string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.landings[window]++
	if target == "" {
		c.blindLandings[window]++
	}
}

func (c *campaign) kills() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.killCount
}

// live and gone remember the identities the campaign deliberately created and
// deliberately retired, for the datastore-wide census at the end.
func (c *campaign) live(spiffeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.expectLive, spiffeID) {
		c.expectLive = append(c.expectLive, spiffeID)
	}
}

func (c *campaign) gone(spiffeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expectLive = slices.DeleteFunc(c.expectLive, func(id string) bool { return id == spiffeID })
	if !slices.Contains(c.expectGone, spiffeID) {
		c.expectGone = append(c.expectGone, spiffeID)
	}
}

// aim fires shots at one named window until one of them lands in it.
//
// A targeted shot can overshoot: between the poll seeing the state and the
// signal arriving, the process may have moved on. That is a property of a real
// kill against a running process and is not smoothed over — the shot is
// credited with where it ACTUALLY landed, and aim simply tries again. What
// fails is the budget running out, which means the trigger cannot reach the
// state it names.
func (c *campaign) aim(t *testing.T, target string, shoot func(*testing.T) string) {
	t.Helper()
	for attempt := 1; attempt <= crashTargetAttempts; attempt++ {
		got := shoot(t)
		if got == target {
			t.Logf("attempt %d landed in %q", attempt, target)
			return
		}
		t.Logf("attempt %d aimed at %q and landed in %q; the process moved on between the "+
			"poll and the signal, so this is retried", attempt, target, got)
	}
	t.Errorf("%d attempts to interrupt the server in %q all overshot (seed %d). The window "+
		"exists — the poll saw the state every time — but the signal never arrived inside it.",
		crashTargetAttempts, target, c.seed)
}

// sameReply insists two replies are the same reply, byte for byte in the
// project's one canonical form (RFC 8785, doc 02 §4.2).
func (c *campaign) sameReply(t *testing.T, why, what string, a, b any) {
	t.Helper()
	ca, cb := canonical(t, a), canonical(t, b)
	if !bytes.Equal(ca, cb) {
		t.Fatalf("%s: %s differ.\n  %s\n  %s\nIP §6.6: replaying any request after a crash "+
			"returns the original result. (seed %d)", why, what, ca, cb, c.seed)
	}
}

// ---------------------------------------------------------------------------
// Bring-up.
// ---------------------------------------------------------------------------

// freshDatabaseSeq numbers databases within this process. The pid separates
// processes; this separates callers inside one. It replaced UnixNano()%100000,
// which wraps every 100 microseconds — two databases created in the same tenth
// of a millisecond collided with "database already exists", which is what
// TestServeRunsUnderAnAppendOnlyDatabaseRole hit.
var freshDatabaseSeq atomic.Uint64

func (c *campaign) freshDatabase(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("crash_%d_%d", os.Getpid()%100000, freshDatabaseSeq.Add(1))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, pgDSN(pgPort, pgDatabase))
	if err != nil {
		t.Fatalf("connect to %s: %v", pgDatabase, err)
	}
	_, err = admin.Exec(ctx, `CREATE DATABASE "`+name+`"`)
	closeErr := admin.Close(ctx)
	if err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	if closeErr != nil {
		t.Fatalf("close admin connection: %v", closeErr)
	}
	return pgDSN(pgPort, name)
}

func openCrashLedger(t *testing.T, dsn string) *ledger.Store {
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

func openCrashPool(t *testing.T, dsn string) *pgxpool.Pool {
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

var (
	serverOnce   sync.Once
	serverPath   string
	serverErr    error
	serverOutDir string
)

// buildServer compiles the SHIPPED binary once per test process.
//
// ./cmd/innsegl, not a purpose-built daemon: the whole value of MCP-011 is
// that the process it kills is the process a deployment runs, so the windows
// it lands in are the deployment's windows.
func buildServer(t *testing.T) string {
	t.Helper()
	serverOnce.Do(func() {
		dir, err := os.MkdirTemp("", "innsegl-serve-")
		if err != nil {
			serverErr = err
			return
		}
		serverOutDir = dir
		out := filepath.Join(dir, "innsegl")
		wd, err := os.Getwd()
		if err != nil {
			serverErr = err
			return
		}
		root := filepath.Dir(filepath.Dir(wd))
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/innsegl")
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			serverErr = fmt.Errorf("build ./cmd/innsegl: %w: %s", err, b)
			return
		}
		serverPath = out
	})
	if serverErr != nil {
		t.Fatalf("MCP-011 needs a process to kill: %v", serverErr)
	}
	t.Cleanup(func() {
		// Left until the process exits: every campaign in this binary shares it.
	})
	return serverPath
}

// writeAdminPEMs mints the admin SVID and puts it where a subprocess can read
// it. In a deployment the MCP is an attested workload and holds no files and
// takes none of the three flags below; the note at the head of this file says so.
func (c *campaign) writeAdminPEMs(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	out, err := c.stack.spireLocal(ctx, "x509", "mint", "-spiffeID", failureAdminID, "-ttl", "2h")
	if err != nil {
		t.Fatalf("mint the admin SVID for the server: %v", err)
	}
	svidPEM, keyPEM, rootsPEM, err := parseMint(out)
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
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
// The process.
// ---------------------------------------------------------------------------

type daemon struct {
	cmd     *exec.Cmd
	addr    string
	stderr  *lockedBuffer
	session *sdk.ClientSession
	dead    bool
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// start launches one `innsegl serve` and waits for it to publish its address.
func (c *campaign) start(t *testing.T) *daemon {
	t.Helper()
	return c.startWith(t)
}

// startWith launches one `innsegl serve` with extra flags appended, so a case
// that needs a different configuration — RM-068's metered register_agent, for
// one — starts the same binary the same way rather than duplicating this.
func (c *campaign) startWith(t *testing.T, extra ...string) *daemon {
	t.Helper()
	addrFile := filepath.Join(c.workDir, c.name("addr"))

	// context.Background rather than the test's: CommandContext kills the
	// child when the context ends, and the ONE thing that may kill this child
	// is the SIGKILL below, whose wait status the harness then reads back.
	cmd := exec.CommandContext(context.Background(), c.binary, "serve",
		"-dsn", c.dsn,
		"-spire-address", c.stack.socatAddr,
		"-trust-domain", failureTrustDomain,
		"-spire-server-id", failureServerID,
		"-parent-id", c.stack.parentID,
		"-svid", filepath.Join(c.pemDir, "svid.pem"),
		"-key", filepath.Join(c.pemDir, "key.pem"),
		"-bundle", filepath.Join(c.pemDir, "bundle.pem"),
		"-listen", "127.0.0.1:0",
		"-health-listen", "127.0.0.1:0",
		"-addr-file", addrFile,
		"-idempotency-lease", crashLease.String(),
		// Required configuration that this campaign does not exercise: they
		// are read only by /readyz, which nothing here calls. A closed port is
		// the honest value — there is no Sigstore in this stack, and pointing
		// them at a real one would be the only untrue thing in this command.
		"-fulcio-url", "http://127.0.0.1:1",
		"-rekor-url", "http://127.0.0.1:1",
		// register_agent floods are MCP-013's subject, not this campaign's;
		// an unmetered tool is what the crash windows are measured against.
		"-register-rate-calls", "0",
	)
	cmd.Args = append(cmd.Args, extra...)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting `innsegl serve`: %v", err)
	}
	d := &daemon{cmd: cmd, stderr: stderr}
	t.Cleanup(func() { d.reap() })

	deadline := time.Now().Add(60 * time.Second)
	for {
		raw, err := os.ReadFile(addrFile)
		if err == nil && len(raw) > 0 {
			d.addr = string(raw)
			return d
		}
		if cmd.ProcessState != nil {
			t.Fatalf("`innsegl serve` exited before it served: %s", stderr.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("`innsegl serve` never published its address; stderr:\n%s", stderr.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// connect opens an MCP session over the transport the server is serving.
func (c *campaign) connect(t *testing.T, d *daemon, endpoint string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-mcp-011", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "http://" + endpoint}, nil)
	if err != nil {
		t.Fatalf("connecting to `innsegl serve` at %s: %v\nserver stderr:\n%s", endpoint, err, d.stderr.String())
	}
	d.session = session
	return session
}

// kill sends SIGKILL and proves the process died of it.
//
// The proof matters. "The test called kill" and "the process was killed" are
// different claims, and only the second one is MCP-011's: a daemon that had
// already exited on its own — a panic, a lost database — would leave a state
// this harness would then attribute to a crash it did not cause.
func (d *daemon) kill(t *testing.T) {
	t.Helper()
	if d.dead {
		return
	}
	if err := d.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	err := d.cmd.Wait()
	d.dead = true

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("`innsegl serve` exited with %v, not by a signal; MCP-011 is about a process the "+
			"operating system removed, and this one left on its own. stderr:\n%s",
			err, d.stderr.String())
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("no wait status for `innsegl serve`: %T", exitErr.Sys())
	}
	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("`innsegl serve` exited with %v; MCP-011 requires SIGKILL. stderr:\n%s",
			exitErr.ProcessState, d.stderr.String())
	}
}

// reap is the cleanup path for a daemon a test finished with without killing.
// A failure here is not worth failing a test over — the process is on its way
// out either way — but it is not swallowed silently.
func (d *daemon) reap() {
	if d.dead || d.cmd.Process == nil {
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
// Reading back what actually happened.
// ---------------------------------------------------------------------------

// chain returns every event on the chain, oldest first.
func (c *campaign) chain(t *testing.T) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	head, err := c.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger Head: %v", err)
	}
	if head.IsEmpty() {
		return nil
	}
	records, err := c.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("ledger Events: %v", err)
	}
	return records
}

// countEvents counts the events of one type carrying one run_id.
func countEvents(records []event.Fields, eventType, runID string) int {
	n := 0
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != eventType {
			continue
		}
		if id, ok := rec[event.FieldRunID].(string); !ok || id != runID {
			continue
		}
		n++
	}
	return n
}

// eventByKey finds the single event an idempotency key names, if it is there.
func (c *campaign) eventByKey(t *testing.T, key string) (event.Fields, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, found, err := c.store.EventByIdempotencyKey(ctx, key)
	if err != nil {
		t.Fatalf("EventByIdempotencyKey(%q): %v", key, err)
	}
	return rec, found
}

// idemRecord reads the idempotency store's row for a key, through the shipped
// Lookup — the operator's view ADR-0017 describes.
func (c *campaign) idemRecord(t *testing.T, key string) (mcp.Record, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, found, err := c.idem.Lookup(ctx, key)
	if err != nil {
		t.Fatalf("idempotency Lookup(%q): %v", key, err)
	}
	return rec, found
}

// hasEntry asks the SPIRE SERVER, over the admin API, whether the run still
// has a registration entry.
func (c *campaign) hasEntry(t *testing.T, run spire.RunRef) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, found, err := c.admin.LookupRun(ctx, run)
	if err != nil {
		t.Fatalf("LookupRun(%+v): %v", run, err)
	}
	return found
}

// runRef rebuilds the reference internal/spire takes from a run id this
// campaign registered.
func crashRunRef(runID string) spire.RunRef {
	return spire.RunRef{AgentType: crashAgentType, TaskID: crashTaskID, RunID: runID}
}

// canonical renders any reply — one decoded off the wire, or one read out of
// the idempotency store — through the same normalisation, so that comparing
// them compares the reply and not the route it arrived by.
func canonical(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encoding a reply: %v", err)
	}
	var generic any
	if derr := json.Unmarshal(body, &generic); derr != nil {
		t.Fatalf("decoding a reply: %v", derr)
	}
	out, err := event.Canonicalize(generic)
	if err != nil {
		t.Fatalf("canonicalizing a reply: %v", err)
	}
	return out
}

// canonicalBytes normalises the bytes the idempotency store recorded.
func canonicalBytes(t *testing.T, recorded []byte) []byte {
	t.Helper()
	var generic any
	if err := json.Unmarshal(recorded, &generic); err != nil {
		t.Fatalf("the recorded reply %q is not JSON: %v", recorded, err)
	}
	out, err := event.Canonicalize(generic)
	if err != nil {
		t.Fatalf("canonicalizing the recorded reply: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Firing one shot: dispatch a tool call, kill the process under it, and report
// what the caller got.
// ---------------------------------------------------------------------------

// killWhen says when the SIGKILL goes.
type killWhen struct {
	// label names the intent, for a failure message. It is NOT the window the
	// iteration is credited with: that is decided afterwards from durable
	// state.
	label string
	// after is a delay from the instant the tool call was dispatched. Used by
	// the blind campaign.
	after time.Duration
	// trigger, when non-nil, replaces the delay: it is polled, and the signal
	// goes the first time it reports the state is there.
	trigger func(context.Context) (bool, error)
	// release undoes whatever the trigger did to hold the window open. It is
	// called the instant the process is dead and BEFORE anything replays: a
	// row lock still held would block the replay's own recording statement for
	// the whole of its context.
	release func()
	// hold puts a proxy between the caller and the server which stops
	// forwarding the server's bytes once the tool call is dispatched, so the
	// caller provably cannot receive the reply. See holdingProxy.
	hold bool
}

// shot is what one dispatch-and-kill produced.
type shot struct {
	// delivered is the reply the caller received before the process died, or
	// nil when it received none.
	delivered any
	// callErr is what the transport reported. Non-nil is the ordinary outcome
	// of a kill landing inside the call.
	callErr error
	// triggerFired says whether an observed trigger saw its state. False means
	// the signal went on the budget expiring, which is not a kill point.
	triggerFired bool
	// killedAfter is how long after dispatch the signal went.
	killedAfter time.Duration
}

func (c *campaign) fire(t *testing.T, tool mcp.ToolName, args map[string]any, when killWhen) shot {
	t.Helper()

	d := c.start(t)
	endpoint := d.addr
	if when.hold {
		endpoint = c.holdingProxyTo(t, d.addr)
	}
	session := c.connect(t, d, endpoint)
	if when.hold {
		c.holdNow()
	}

	type outcome struct {
		res *sdk.CallToolResult
		err error
	}
	done := make(chan outcome, 1)
	callCtx, cancelCall := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelCall()

	dispatched := time.Now()
	go func() {
		res, err := session.CallTool(callCtx, &sdk.CallToolParams{
			Name: string(tool), Arguments: args,
		})
		done <- outcome{res, err}
	}()

	s := shot{}
	if when.trigger != nil {
		s.triggerFired = c.waitForState(t, when.trigger)
	} else {
		remaining := when.after - time.Since(dispatched)
		if remaining > 0 {
			time.Sleep(remaining)
		}
		s.triggerFired = true
	}
	s.killedAfter = time.Since(dispatched)
	d.kill(t)
	c.countKill()
	if when.release != nil {
		when.release()
	}

	out := <-done
	s.callErr = out.err
	if out.err == nil && out.res != nil {
		if out.res.IsError {
			t.Fatalf("%s(%v) failed on the wire: %v\n(kill was %s after dispatch, intent %q)",
				tool, args, out.res.StructuredContent, s.killedAfter, when.label)
		}
		s.delivered = out.res.StructuredContent
	}
	return s
}

// waitForState polls durable state until it is there, or the budget runs out.
//
// This is the device RM-066 used for pg_stat_activity, generalised: the signal
// goes because a query said the state exists, never because a sleep elapsed.
func (c *campaign) waitForState(t *testing.T, trigger func(context.Context) (bool, error)) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), crashTriggerBudget)
	defer cancel()
	for {
		ok, err := trigger(ctx)
		if err != nil {
			t.Fatalf("polling for the state to interrupt: %v", err)
		}
		if ok {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(crashPollInterval):
		}
	}
}

// ---------------------------------------------------------------------------
// Replaying, after the restart.
// ---------------------------------------------------------------------------

// replay restarts the server and calls the same tool with the same arguments,
// twice. The second call is not decoration: the first replay may be the call's
// first COMPLETED execution — ADR-0017 §5's takeover, when the crash landed
// inside the claim — and only from the second onwards is "the recorded reply"
// a thing that exists to be returned.
func (c *campaign) replay(t *testing.T, tool mcp.ToolName, args map[string]any) (first, second any) {
	t.Helper()
	d := c.start(t)
	session := c.connect(t, d, d.addr)
	defer d.reap()

	first = c.callOnce(t, session, tool, args)
	second = c.callOnce(t, session, tool, args)
	return first, second
}

func (c *campaign) callOnce(t *testing.T, session *sdk.ClientSession, tool mcp.ToolName, args map[string]any) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{Name: string(tool), Arguments: args})
	if err != nil {
		t.Fatalf("replaying %s(%v): transport failure %v", tool, args, err)
	}
	if res.IsError {
		t.Fatalf("replaying %s(%v) failed: %v", tool, args, res.StructuredContent)
	}
	return res.StructuredContent
}

// callSucceeds runs one tool call to completion on a server of its own, for
// the set-up a fuzzed iteration needs and does not interrupt.
func (c *campaign) callSucceeds(t *testing.T, tool mcp.ToolName, args map[string]any) (any, time.Duration) {
	t.Helper()
	d := c.start(t)
	session := c.connect(t, d, d.addr)
	defer d.reap()
	started := time.Now()
	out := c.callOnce(t, session, tool, args)
	return out, time.Since(started)
}

// decodeInto re-decodes a structured reply into its documented shape.
func decodeInto(t *testing.T, v any, out any) {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encoding a reply: %v", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("reply %s is not the documented shape: %v", body, err)
	}
}

type registerReply struct {
	SPIFFEID  string `json:"spiffe_id"`
	RunID     string `json:"run_id"`
	ExpiresAt string `json:"expires_at"`
}

type recordReply struct {
	EventID       string `json:"event_id"`
	ChainPosition int64  `json:"chain_position"`
}

type retireReply struct {
	RetiredAt string `json:"retired_at"`
}

type credentialReply struct {
	JWTSVID   string `json:"jwt_svid"`
	ExpiresAt string `json:"expires_at"`
}

// strata cuts [0, window) into n pieces and draws one delay inside each, then
// shuffles the order. Both halves are the campaign's seeded generator, so a
// seed reproduces the sequence exactly.
func (c *campaign) strata(window time.Duration, n int) []time.Duration {
	if n < 1 {
		n = 1
	}
	width := window / time.Duration(n)
	out := make([]time.Duration, 0, n)
	for i := range n {
		lo := time.Duration(i) * width
		out = append(out, c.rng.duration(lo, lo+width))
	}
	c.rng.shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// crashInProgress and crashCompleted are the idempotency store's own status
// spellings. They are unexported constants in internal/mcp, so they are
// transcribed here rather than imported; a rename there fails these switches
// loudly rather than silently classifying every row as "unknown".
const (
	crashInProgress = "in_progress"
	crashCompleted  = "completed"
)

// countKeyed counts the events carrying one idempotency_key. The ledger's
// UNIQUE index makes the answer 0 or 1; asking is how LED-008 is checked
// rather than assumed.
func countKeyed(records []event.Fields, key string) int {
	n := 0
	for _, rec := range records {
		if k, ok := rec[event.FieldIdempotencyKey].(string); ok && k == key {
			n++
		}
	}
	return n
}

// countEventsAt counts the events of one type for one run at one position.
func countEventsAt(records []event.Fields, position int64, eventType, runID string) int {
	n := 0
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != eventType {
			continue
		}
		if id, ok := rec[event.FieldRunID].(string); !ok || id != runID {
			continue
		}
		switch at := rec[event.FieldChainPosition].(type) {
		case int64:
			if at == position {
				n++
			}
		case float64:
			if int64(at) == position {
				n++
			}
		}
	}
	return n
}

// retiredAt returns the ts the ledger stamped on a run's `run_retired`.
func (c *campaign) retiredAt(t *testing.T, records []event.Fields, runID string) string {
	t.Helper()
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != event.EventTypeRunRetired {
			continue
		}
		if id, ok := rec[event.FieldRunID].(string); !ok || id != runID {
			continue
		}
		ts, ok := rec[event.FieldTS].(string)
		if !ok {
			t.Fatalf("the `run_retired` for run %q carries no ts", runID)
		}
		return ts
	}
	t.Fatalf("no `run_retired` on the chain for run %q", runID)
	return ""
}

func (c *campaign) headPosition(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	head, err := c.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger Head: %v", err)
	}
	return head.Position
}

// freshRun registers one run to completion, on a server nothing interrupts.
// It is set-up, not a measurement, and it is the only way retire_agent can be
// fuzzed at all: a run retires once (ADR-0004), so each shot needs its own.
func (c *campaign) freshRun(t *testing.T, prefix string) registerReply {
	t.Helper()
	out, _ := c.callSucceeds(t, mcp.ToolRegisterAgent, c.registerArgs(c.name(prefix)))
	var reply registerReply
	decodeInto(t, out, &reply)
	if reply.RunID == "" || reply.SPIFFEID == "" {
		t.Fatalf("register_agent returned %+v; IP §4 requires all three members", reply)
	}
	c.live(reply.SPIFFEID)
	return reply
}

// ---------------------------------------------------------------------------
// The observed triggers. Each one is a query against Postgres or SPIRE, and
// the SIGKILL goes the first time it answers yes — never after a sleep.
// ---------------------------------------------------------------------------

// eventKeyed waits for the event an idempotency key names to be ON THE CHAIN.
func (c *campaign) eventKeyed(key string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		_, found, err := c.store.EventByIdempotencyKey(ctx, key)
		return found, err
	}
}

// replyRecorded waits for the idempotency store to hold a COMPLETED reply.
func (c *campaign) replyRecorded(key string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		rec, found, err := c.idem.Lookup(ctx, key)
		if err != nil || !found {
			return false, err
		}
		return rec.Status == crashCompleted, nil
	}
}

// eventAppendedAfter waits for one event type to appear for one run beyond a
// chain position the caller read before the call was dispatched.
func (c *campaign) eventAppendedAfter(from int64, eventType, runID string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		head, err := c.store.Head(ctx)
		if err != nil || head.Position <= from {
			return false, err
		}
		records, err := c.store.Events(ctx, from+1, head.Position)
		if err != nil {
			return false, err
		}
		return countEvents(records, eventType, runID) > 0, nil
	}
}

// ---------------------------------------------------------------------------
// Device 1: a Postgres row lock, so the server can be caught inside the one
// statement that records its reply.
//
// The window between "the SPIRE entry exists" and "the reply is recorded" is
// one Postgres round trip wide. Polling for the entry and then signalling
// loses that race every time — MEASURED: 8 attempts out of 8 overshot into
// "reply recorded and delivered" before this device existed. So the window is
// held open instead of chased.
//
// ADR-0023 made the recording statement open with `SELECT … FOR UPDATE` on the
// claim's row. A transaction of this test's own holding that row therefore
// parks the server inside `complete`, after the ledger append and after
// RegisterRun, and before anything is recorded. That the server is genuinely
// parked — rather than merely presumed slow — is read out of pg_stat_activity,
// which is the standard RM-066 set with waitForLockWaiters: never a sleep, and
// never an assumption about where another process has got to.
// ---------------------------------------------------------------------------

// lockWaiterSQL counts backends other than this one that are blocked on a lock
// while running the statement that records a reply. `SET status = 'completed'`
// appears in completeSQL and in nothing else.
const lockWaiterSQL = `
SELECT count(*)
  FROM pg_stat_activity
 WHERE datname = current_database()
   AND pid <> pg_backend_pid()
   AND state = 'active'
   AND wait_event_type = 'Lock'
   AND query ILIKE '%status = ''completed''%'`

// parkedOnTheReply returns a trigger that fires once the server is provably
// blocked recording its reply, and the release its caller must defer.
func (c *campaign) parkedOnTheReply(t *testing.T, key string) (func(context.Context) (bool, error), func()) {
	t.Helper()
	var (
		conn   *pgxpool.Conn
		tx     pgx.Tx
		locked bool
		spent  bool
	)
	release := func() {
		if tx != nil {
			rollBack(tx)
			tx = nil
		}
		if conn != nil {
			conn.Release()
			conn = nil
		}
	}

	trigger := func(ctx context.Context) (bool, error) {
		if spent {
			return true, nil
		}
		if !locked {
			rec, found, err := c.idem.Lookup(ctx, key)
			if err != nil || !found {
				return false, err
			}
			acquired, status, err := c.lockRow(ctx, key, &conn, &tx)
			if err != nil {
				return false, err
			}
			if !acquired {
				return false, nil
			}
			locked = true
			if status == crashCompleted || rec.Status == crashCompleted {
				// The server got there first. Signal now: the shot lands
				// where it lands and aim tries again.
				spent = true
				return true, nil
			}
			return false, nil
		}
		var waiters int
		if err := c.pool.QueryRow(ctx, lockWaiterSQL).Scan(&waiters); err != nil {
			return false, err
		}
		return waiters > 0, nil
	}
	return trigger, release
}

// rollBack ends a transaction this test opened only to hold a lock. There is
// nothing to commit and nothing a rollback failure could cost, but a failure
// that is not the transaction already being closed is worth saying out loud.
func rollBack(tx pgx.Tx) {
	if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		fmt.Fprintf(os.Stderr, "warning: rolling back the lock-holding transaction: %v\n", err)
	}
}

// lockRow opens a transaction and takes the claim row's lock, or reports that
// somebody else holds it.
func (c *campaign) lockRow(ctx context.Context, key string, conn **pgxpool.Conn, tx *pgx.Tx) (bool, string, error) {
	acquire, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	got, err := c.pool.Acquire(acquire)
	if err != nil {
		return false, "", err
	}
	opened, err := got.Begin(acquire)
	if err != nil {
		got.Release()
		return false, "", err
	}
	var status string
	err = opened.QueryRow(acquire,
		`SELECT status FROM innsegl.idempotency WHERE idempotency_key = $1 FOR UPDATE`, key).Scan(&status)
	if err != nil {
		rollBack(opened)
		got.Release()
		if errors.Is(err, context.DeadlineExceeded) {
			// Somebody else has the row. Try again on the next poll.
			return false, "", nil
		}
		return false, "", err
	}
	*conn, *tx = got, opened
	return true, status, nil
}

// ---------------------------------------------------------------------------
// Device 2: a proxy that stops forwarding the server's bytes.
//
// "The reply was recorded and the caller never saw it" is ADR-0017's
// motivating window, and it is likewise narrower than the poll that would
// chase it: after `complete` commits, the server writes an HTTP response in
// well under the time one SELECT takes to come back.
//
// So non-delivery is made certain rather than hoped for. The proxy forwards
// the MCP handshake, and from the moment the tool call is dispatched it drops
// everything the server sends back. The kill is still a real SIGKILL of the
// real process at a point read out of Postgres.
//
// STATED PLAINLY, BECAUSE IT IS THE ONE PLACE THIS HARNESS SUBSTITUTES: in a
// real crash the reply is lost BECAUSE the process died; here it is lost
// because the harness cut the response, and the process is then killed. The
// durable state at the instant of the kill — a completed row, the event on the
// chain, the entry in SPIRE — is identical, and that state is the whole of
// what MCP-011 asserts on. What is NOT demonstrated by this device is anything
// about the network path itself.
// ---------------------------------------------------------------------------

type holdingProxy struct {
	ln     net.Listener
	target string
	hold   atomic.Bool
	closed atomic.Bool
}

func (c *campaign) holdingProxyTo(t *testing.T, target string) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the holding proxy: %v", err)
	}
	p := &holdingProxy{ln: ln, target: target}
	c.mu.Lock()
	c.proxy = p
	c.mu.Unlock()
	go p.accept()
	t.Cleanup(p.close)
	return ln.Addr().String()
}

func (c *campaign) holdNow() {
	c.mu.Lock()
	p := c.proxy
	c.mu.Unlock()
	if p != nil {
		p.hold.Store(true)
	}
}

func (p *holdingProxy) accept() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serve(client)
	}
}

func (p *holdingProxy) serve(client net.Conn) {
	var dialer net.Dialer
	server, err := dialer.DialContext(context.Background(), "tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}
	var once sync.Once
	shut := func() {
		once.Do(func() {
			_ = client.Close()
			_ = server.Close()
		})
	}
	go func() {
		p.pipe(server, client, false)
		shut()
	}()
	p.pipe(client, server, true)
	shut()
}

// pipe copies src to dst. When honourHold is set and the proxy is holding, the
// bytes are read and dropped: the server believes it replied and the caller
// never hears it.
func (p *holdingProxy) pipe(dst io.Writer, src io.Reader, honourHold bool) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 && (!honourHold || !p.hold.Load()) {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (p *holdingProxy) close() {
	if p.closed.Swap(true) {
		return
	}
	_ = p.ln.Close()
}

// spiffeIDOf renders a run id as the SPIFFE ID this campaign's runs carry,
// through internal/spire's own grammar rather than by string concatenation.
func (c *campaign) spiffeIDOf(t *testing.T, runID string) string {
	t.Helper()
	id, err := crashRunRef(runID).SPIFFEID(failureTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID for run %q: %v", runID, err)
	}
	return id
}

// pruneIdempotency deletes a completed row from the idempotency store.
//
// It is not vandalism: ADR-0017 §7 makes this table prunable on purpose —
// "unlike innsegl.events this is a bounded record of recent calls, not the
// ledger, so an operator must be able to delete from it" — and migration
// 0002's IN003 guard permits deleting a COMPLETED row while refusing an
// in-flight one. The delete going through is therefore itself a check that the
// guard says what ADR-0017 says it says.
func (c *campaign) pruneIdempotency(t *testing.T, key string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tag, err := c.pool.Exec(ctx, `DELETE FROM innsegl.idempotency WHERE idempotency_key = $1`, key)
	if err != nil {
		t.Fatalf("pruning the completed row for %q: %v", key, err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("pruning the completed row for %q removed %d rows, want 1", key, tag.RowsAffected())
	}
}
