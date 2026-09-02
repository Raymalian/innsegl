// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// ---------------------------------------------------------------------------
// A real Postgres, never a mock.
//
// Three of the eleven classes are states of a real database and nothing else:
// DUPLICATE_REQUEST is a UNIQUE index answering a second claim on one
// idempotency key, RUN_ALREADY_RETIRED is a `run_retired` row on the chain,
// and LEDGER_UNAVAILABLE is IP §6.4's "Postgres down". A fake store would
// return each of them on request and prove nothing about any of them, which is
// the failure mode this issue was written against.
//
// Without Docker the tests skip with a message naming what went unproven,
// rather than passing quietly.
// ---------------------------------------------------------------------------

const (
	defaultPostgresImage = "postgres:16"

	postgresUser     = "innsegl"
	postgresPassword = "innsegl-contract"
	postgresDB       = "innsegl"
)

var (
	sharedPG        *pgContainer
	dockerSkip      string
	testDBSeq       atomic.Int64
	errDockerAbsent = errors.New("docker is not available")
)

func postgresImage() string {
	if v := os.Getenv("INNSEGL_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return defaultPostgresImage
}

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

func dockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errDockerAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errDockerAbsent, err)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errDockerAbsent, err)
	}
	return nil
}

type pgContainer struct {
	id   string
	port string
}

func (c *pgContainer) dsn(database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		postgresUser, postgresPassword, c.port, database)
}

// freeHostPort reserves an ephemeral port. Each container publishes on a fixed
// host port of its own, so two test processes never collide (#81's rule for a
// shared compose project, applied to a plain container).
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

func startPG(ctx context.Context) (*pgContainer, error) {
	port, err := freeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}
	id, err := docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+postgresUser,
		"--env", "POSTGRES_PASSWORD="+postgresPassword,
		"--env", "POSTGRES_DB="+postgresDB,
		postgresImage(), "-c", "fsync=off",
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

// kill stops the container the hard way. IP §6.4's "Postgres down at any
// record_event" is a process that went away, not a connection that was closed
// politely, and the two do not necessarily classify the same.
func (c *pgContainer) kill(ctx context.Context) error {
	_, err := docker(ctx, "kill", "--signal", "SIGKILL", c.id)
	return err
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
		dockerSkip = err.Error()
	} else if pg, err := startPG(ctx); err != nil {
		dockerSkip = fmt.Sprintf("could not start %s: %v", postgresImage(), err)
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

// requirePG skips the calling test when no real Postgres is available, naming
// what went unproven. It never lets a reachability claim pass without one.
func requirePG(t *testing.T) *pgContainer {
	t.Helper()
	if sharedPG == nil {
		t.Skipf("skipping: no real Postgres (%s). "+
			"Reachability of DUPLICATE_REQUEST, RUN_ALREADY_RETIRED and LEDGER_UNAVAILABLE "+
			"is a claim about a real database and is unproven without one; "+
			"start Docker, or set INNSEGL_TEST_POSTGRES_IMAGE, and re-run.",
			dockerSkip)
	}
	return sharedPG
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// freshDSN creates an empty database inside c. One database per stack:
// ADR-0005 scopes a chain to a database, so this is a chain and an idempotency
// key space per test.
func freshDSN(t *testing.T, c *pgContainer) string {
	t.Helper()
	name := fmt.Sprintf("contract_%d_%d", os.Getpid()%100000, testDBSeq.Add(1))

	ctx := testCtx(t, 30*time.Second)
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

// openLedger migrates a fresh database and returns the real store on it.
// The idempotency table ships in the same embedded migration set (0002), so
// one runner gives both.
func openLedger(t *testing.T, dsn string) *ledger.Store {
	t.Helper()
	ctx := testCtx(t, 60*time.Second)
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

func newPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(testCtx(t, 30*time.Second), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ---------------------------------------------------------------------------
// The run directory, over the real chain.
//
// internal/mcp declares CredentialRuns and ships no implementation of it — the
// component that reads `run_registered` and `run_retired` back out of the
// ledger has not been written yet (see the report for RM-028). This is that
// reader, kept deliberately dumb: it scans the chain and believes nothing it
// did not read there. RUN_NOT_FOUND and RUN_ALREADY_RETIRED therefore come
// from what register_agent and retire_agent actually wrote, not from a switch
// in a double.
// ---------------------------------------------------------------------------

type ledgerRuns struct{ store *ledger.Store }

func (d ledgerRuns) CredentialRun(ctx context.Context, runID string) (mcp.CredentialRun, bool, error) {
	head, err := d.store.Head(ctx)
	if err != nil {
		return mcp.CredentialRun{}, false, err
	}
	if head.IsEmpty() {
		return mcp.CredentialRun{}, false, nil
	}
	records, err := d.store.Events(ctx, 1, head.Position)
	if err != nil {
		return mcp.CredentialRun{}, false, err
	}

	var (
		run   mcp.CredentialRun
		found bool
	)
	for _, rec := range records {
		if id, ok := rec[event.FieldRunID].(string); !ok || id != runID {
			continue
		}
		kind, isString := rec[event.FieldEventType].(string)
		if !isString {
			return mcp.CredentialRun{}, false, fmt.Errorf("an event for %q carries no event_type", runID)
		}
		switch kind {
		case event.EventTypeRunRegistered:
			spiffeID, isString := rec[event.FieldSpiffeID].(string)
			if !isString {
				return mcp.CredentialRun{}, false,
					fmt.Errorf("run_registered for %q carries no spiffe_id", runID)
			}
			agentType, taskID, ok := splitRunIdentity(spiffeID, runID)
			if !ok {
				return mcp.CredentialRun{}, false,
					fmt.Errorf("run_registered for %q carries the unusable spiffe_id %q", runID, spiffeID)
			}
			run.RunID, run.SPIFFEID, run.AgentType, run.TaskID = runID, spiffeID, agentType, taskID
			found = true
		case event.EventTypeRunRetired:
			raw, ok := rec[event.FieldTS].(string)
			if !ok {
				return mcp.CredentialRun{}, false, fmt.Errorf("run_retired for %q carries no ts", runID)
			}
			ts, perr := event.ParseTimestamp(raw)
			if perr != nil {
				return mcp.CredentialRun{}, false, perr
			}
			// IP §4 requires every later call to be answered with the
			// ORIGINAL instant, so the earliest wins.
			if run.RetiredAt.IsZero() || ts.Time().Before(run.RetiredAt) {
				run.RetiredAt = ts.Time()
			}
		}
	}
	if !found {
		return mcp.CredentialRun{}, false, nil
	}
	return run, true, nil
}

// splitRunIdentity reads {agent-type} and {task-id} out of a run's SPIFFE ID.
// The grammar is doc 01 §1's:
// spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}.
func splitRunIdentity(spiffeID, runID string) (agentType, taskID string, ok bool) {
	_, rest, found := strings.Cut(spiffeID, "/agent/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[2] != runID {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ---------------------------------------------------------------------------
// A stand-in SPIRE server, one type behind all three SPIRE seams.
//
// It is not a mock that answers a class on request. It holds entries, and the
// tools' SPIRE-shaped outcomes fall out of whether an entry is there: a second
// RegisterRun for one run is DUPLICATE_REQUEST because the entry exists, and
// RequireActiveRun is RUN_NOT_FOUND because it does not. Both mirror
// internal/spire exactly — spire/client.go's classifyAdmin maps
// codes.AlreadyExists to DUPLICATE_REQUEST and codes.NotFound to
// RUN_NOT_FOUND, and spire/entries.go:296 is the RUN_NOT_FOUND
// RequireActiveRun raises when the server holds no entry.
//
// `fail` injects a transport outcome the shipped client would classify. Its
// values are drawn from adminClassifierRange, which is transcribed from
// classifyAdmin rather than read from it.
// ---------------------------------------------------------------------------

type fakeSPIRE struct {
	mu          sync.Mutex
	trustDomain string
	entries     map[string]spire.Entry
	ttl         time.Duration

	// failRegister, failLookup, failRequire and failRetire are returned in
	// place of the operation when non-nil.
	failRegister error
	failLookup   error
	failRequire  error
	failRetire   error

	// vanishOnLookup makes LookupRun report no entry immediately after
	// RegisterRun reported one: the "SPIRE said the entry exists and then said
	// it does not" window register_agent fails closed on.
	vanishOnLookup bool

	// duplicateOnRegister makes the first RegisterRun of a run report
	// DUPLICATE_REQUEST, which is what SPIRE answers when an EARLIER
	// EXECUTION of this same call already created the entry — ADR-0017 §5's
	// claim whose lease ran out and was taken over. It is the only way to
	// reach that branch without crashing a replica, which is MCP-011's job.
	duplicateOnRegister bool
}

func newFakeSPIRE(trustDomain string) *fakeSPIRE {
	return &fakeSPIRE{
		trustDomain: trustDomain,
		entries:     map[string]spire.Entry{},
		ttl:         time.Hour,
	}
}

func (f *fakeSPIRE) TrustDomain() string { return f.trustDomain }

func (f *fakeSPIRE) RegisterRun(_ context.Context, reg spire.Registration) (spire.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRegister != nil {
		return spire.Entry{}, stampRun(f.failRegister, reg.Run.RunID)
	}
	id, err := reg.Run.SPIFFEID(f.trustDomain)
	if err != nil {
		return spire.Entry{}, err
	}
	if _, exists := f.entries[reg.Run.RunID]; exists || f.duplicateOnRegister {
		return spire.Entry{}, &spire.Error{
			Class: spire.ClassDuplicateRequest, Op: "register_agent", RunID: reg.Run.RunID,
			Message: "entry already exists", Retryable: false,
		}
	}
	entry := spire.Entry{
		ID: "entry-" + reg.Run.RunID, SPIFFEID: id, ParentID: reg.ParentID,
		Selectors: reg.Selectors, TTL: f.ttl,
	}
	f.entries[reg.Run.RunID] = entry
	return entry, nil
}

func (f *fakeSPIRE) LookupRun(_ context.Context, run spire.RunRef) (spire.Entry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLookup != nil {
		return spire.Entry{}, false, f.failLookup
	}
	if f.vanishOnLookup {
		return spire.Entry{}, false, nil
	}
	entry, ok := f.entries[run.RunID]
	return entry, ok, nil
}

func (f *fakeSPIRE) RequireActiveRun(_ context.Context, run spire.RunRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRequire != nil {
		return f.failRequire
	}
	if _, ok := f.entries[run.RunID]; !ok {
		// spire/entries.go:296, verbatim in class and flag.
		return &spire.Error{
			Class: spire.ClassRunNotFound, Op: "require_active_run", RunID: run.RunID,
			Message: "SPIRE holds no registration entry for " + run.RunID, Retryable: false,
		}
	}
	return nil
}

func (f *fakeSPIRE) RetireRun(_ context.Context, run spire.RunRef) (spire.Retirement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRetire != nil {
		return spire.Retirement{}, stampRun(f.failRetire, run.RunID)
	}
	entry, ok := f.entries[run.RunID]
	delete(f.entries, run.RunID)
	return spire.Retirement{EntryID: entry.ID, Deleted: ok}, nil
}

// stampRun mirrors spire/entries.go's withRun: a classified error raised
// before the run was known is stamped with it on the way out, so an injected
// failure carries the run id a real one would.
func stampRun(err error, runID string) error {
	var e *spire.Error
	if !errors.As(err, &e) || e.RunID != "" {
		return err
	}
	stamped := *e
	stamped.RunID = runID
	return &stamped
}

// deleteEntry removes a run's entry behind the MCP's back — a reaper, an
// operator, or the deletion half of a retirement whose record never landed.
func (f *fakeSPIRE) deleteEntry(runID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, runID)
}

func (f *fakeSPIRE) hasEntry(runID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.entries[runID]
	return ok
}

// ---------------------------------------------------------------------------
// The minter: the SHIPPED mcp.NewSPIREMinter over a fake gRPC connection.
//
// This is the one SPIRE path a test can drive through the production
// classifier without a container, because NewSPIREMinter takes a
// grpc.ClientConnInterface. Everything mcp's credentialMintError decides — the
// code-to-class map, the narrowing of `retryable`, the refusal of a token with
// no expiry — is exercised for real; only the wire underneath is a double.
// ---------------------------------------------------------------------------

type fakeConn struct {
	mu     sync.Mutex
	err    error
	token  string
	id     string
	expiry time.Time
}

func (c *fakeConn) Invoke(_ context.Context, _ string, _, reply any, _ ...grpc.CallOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	resp, ok := reply.(*svidv1.MintJWTSVIDResponse)
	if !ok {
		return fmt.Errorf("contract harness: unexpected reply type %T", reply)
	}
	trustDomain, path, found := strings.Cut(strings.TrimPrefix(c.id, "spiffe://"), "/")
	if !found {
		return fmt.Errorf("contract harness: %q is not a SPIFFE ID", c.id)
	}
	var expiresAt int64
	if !c.expiry.IsZero() {
		expiresAt = c.expiry.Unix()
	}
	resp.Svid = &types.JWTSVID{
		Token:     c.token,
		Id:        &types.SPIFFEID{TrustDomain: trustDomain, Path: "/" + path},
		ExpiresAt: expiresAt,
	}
	return nil
}

func (c *fakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("contract harness: streaming is not part of the MintJWTSVID surface")
}

func (c *fakeConn) set(mutate func(*fakeConn)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mutate(c)
}

// failWith makes the next mint fail with a gRPC status code.
func (c *fakeConn) failWith(code codes.Code, msg string) {
	c.set(func(f *fakeConn) { f.err = status.Error(code, msg) })
}

// ---------------------------------------------------------------------------
// The stack: four real tools, one real ledger, one real idempotency store, and
// the real HTTP transport with a real SDK client on the other end.
// ---------------------------------------------------------------------------

const (
	testTrustDomain = "innsegl.dev"
	testParentID    = "spiffe://innsegl.dev/spire/agent/x509pop/contract"
	// testIdentitySecret keys the pseudonyms. A fixture, not a credential:
	// nothing outside this test binary ever sees an identity keyed with it.
	testIdentitySecret = "contract-fixture-secret-0123456"
	testAgentType      = "fix-ci"
	testTaskID         = "jira-118"
)

type stack struct {
	store   *ledger.Store
	idem    *mcp.IdempotencyStore
	spire   *fakeSPIRE
	conn    *fakeConn
	server  *mcp.Server
	session *sdk.ClientSession
	dsn     string
}

// newStack wires the four shipped tools onto a fresh chain and serves them.
func newStack(t *testing.T) *stack {
	t.Helper()
	return newStackOn(t, freshDSN(t, requirePG(t)))
}

func newStackOn(t *testing.T, dsn string) *stack {
	t.Helper()

	store := openLedger(t, dsn)
	idem := mcp.NewIdempotencyStore(newPool(t, dsn))
	fake := newFakeSPIRE(testTrustDomain)
	conn := &fakeConn{token: "contract.jwt.svid", expiry: time.Now().Add(5 * time.Minute)}
	runs := ledgerRuns{store: store}

	s := &stack{store: store, idem: idem, spire: fake, conn: conn, dsn: dsn}

	// The SHIPPED default: pseudonymous identity (RM-079, #116). The contract
	// matrix is where a tool's observable behaviour is pinned, so it is pinned
	// under the mode a deployment gets when it configures nothing. Nothing in
	// this package asserts the CONTENT of a SPIFFE ID's first two segments —
	// ledgerRuns reads them back off the ID itself, which is what every
	// consumer must now do.
	pseudonyms, err := identity.New(identity.ModePseudonymous, testIdentitySecret)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	restoreRegister, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities: fake, Ledger: store, Idempotency: idem, ParentID: testParentID,
		Pseudonyms: pseudonyms,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreRegister)

	if cerr := mcp.ConfigureGetCredential(mcp.CredentialConfig{
		Runs: runs, Entries: fake, Minter: mcp.NewSPIREMinter(conn), Ledger: store,
	}); cerr != nil {
		t.Fatalf("ConfigureGetCredential: %v", cerr)
	}

	restoreRecord, err := mcp.ConfigureRecordEvent(mcp.RecordEventConfig{
		Runs: runs, Ledger: store, Idempotency: idem,
	})
	if err != nil {
		t.Fatalf("ConfigureRecordEvent: %v", err)
	}
	t.Cleanup(restoreRecord)

	restoreRetire, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: runs, Entries: fake, Ledger: store,
	})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRetire)

	srv, err := mcp.New(mcp.Config{Version: "v0.0.0-contract"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	s.server = srv

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-contract", Version: "v0"}, nil)
	session, err := client.Connect(testCtx(t, 30*time.Second),
		&sdk.StreamableClientTransport{Endpoint: httpSrv.URL}, nil)
	if err != nil {
		t.Fatalf("connecting to %s: %v", httpSrv.URL, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	s.session = session
	return s
}

// call invokes one tool over the transport and returns the raw result.
func (s *stack) call(t *testing.T, tool mcp.ToolName, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	res, err := s.session.CallTool(testCtx(t, 60*time.Second), &sdk.CallToolParams{
		Name: string(tool), Arguments: args,
	})
	if err != nil {
		t.Fatalf("tools/call %s: transport failure %v", tool, err)
	}
	return res
}

// wireError is IP §4's structured error as it arrived on the wire.
type wireError struct {
	Class     string
	Message   string
	Retryable bool
	RunID     string
	RunIDSeen bool
	Extra     []string
}

// callExpectingError invokes a tool and insists it failed with an IP §4 error.
func (s *stack) callExpectingError(t *testing.T, tool mcp.ToolName, args map[string]any) wireError {
	t.Helper()
	res := s.call(t, tool, args)
	if !res.IsError {
		t.Fatalf("%s(%v) succeeded; this case exists to reach an error class", tool, args)
	}
	return decodeWireError(t, tool, res)
}

func decodeWireError(t *testing.T, tool mcp.ToolName, res *sdk.CallToolResult) wireError {
	t.Helper()
	raw, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("%s: structuredContent is %T, want the IP §4 error object", tool, res.StructuredContent)
	}
	// Every member's TYPE is part of IP §4's shape, so a member of the wrong
	// type is a failure here rather than a zero value carried on silently.
	str := func(key string, v any) string {
		t.Helper()
		s, isString := v.(string)
		if !isString {
			t.Fatalf("%s: wire error member %q is %T, IP §4 makes it a string", tool, key, v)
		}
		return s
	}
	out := wireError{}
	for k, v := range raw {
		switch k {
		case "error_class":
			out.Class = str(k, v)
		case "message":
			out.Message = str(k, v)
		case "retryable":
			flag, isBool := v.(bool)
			if !isBool {
				t.Fatalf("%s: wire error member \"retryable\" is %T, IP §4 makes it a bool", tool, v)
			}
			out.Retryable = flag
		case "run_id":
			out.RunID = str(k, v)
			out.RunIDSeen = true
		default:
			out.Extra = append(out.Extra, k)
		}
	}
	return out
}

// callExpectingSuccess invokes a tool and decodes its documented result shape.
func (s *stack) callExpectingSuccess(t *testing.T, tool mcp.ToolName, args map[string]any, out any) {
	t.Helper()
	res := s.call(t, tool, args)
	if res.IsError {
		t.Fatalf("%s(%v) failed: %v", tool, args, decodeWireError(t, tool, res))
	}
	body, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: re-encoding the result: %v", tool, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("%s: result %s is not the documented shape: %v", tool, body, err)
	}
}

// registerAgentResult is IP §4's register_agent reply.
type registerAgentResult struct {
	SPIFFEID  string `json:"spiffe_id"`
	RunID     string `json:"run_id"`
	ExpiresAt string `json:"expires_at"`
}

// retireAgentResult is IP §4's retire_agent reply.
type retireAgentResult struct {
	RetiredAt string `json:"retired_at"`
}

// registerRun registers one run for real and returns it.
func (s *stack) registerRun(t *testing.T, key string) registerAgentResult {
	t.Helper()
	var out registerAgentResult
	s.callExpectingSuccess(t, mcp.ToolRegisterAgent, map[string]any{
		"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": key,
	}, &out)
	if out.RunID == "" || out.SPIFFEID == "" || out.ExpiresAt == "" {
		t.Fatalf("register_agent returned %+v; IP §4 requires all three members", out)
	}
	s.conn.set(func(f *fakeConn) { f.id = out.SPIFFEID })
	return out
}

// retireRun retires a run for real.
func (s *stack) retireRun(t *testing.T, runID string) retireAgentResult {
	t.Helper()
	var out retireAgentResult
	s.callExpectingSuccess(t, mcp.ToolRetireAgent, map[string]any{"run_id": runID}, &out)
	return out
}

// appendRaw writes one event straight to the chain, bypassing the tools.
//
// It is how a run directory comes to hold an answer no tool would have written
// — the case the tools' "the directory's answer is checked, not trusted" gate
// exists for. Nothing else in this package writes to the ledger directly.
func (s *stack) appendRaw(t *testing.T, body event.Fields) {
	t.Helper()
	if _, err := s.store.Append(testCtx(t, 30*time.Second), body); err != nil {
		t.Fatalf("appending %v: %v", body[event.FieldEventType], err)
	}
}

// unknownRunID is a syntactically valid run id no chain has ever seen. It is
// spelled the way register_agent derives one, so nothing can refuse it for its
// shape rather than for its absence.
const unknownRunID = "run-00000000000000000000000000000000"
