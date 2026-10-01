// SPDX-License-Identifier: Apache-2.0

package main

// gatewayidentity_test.go — RM-235 (#380): the identity Guard through the
// REAL, production openGateway -- a real listener, real HTTP round trips,
// and register_agent/retire_agent/describe_workspace configured with a real
// *ledger.Store on a real, throwaway Postgres (requireAPIPG,
// apiharness_test.go), a fake SPIRE (RM-015's own SVID-issuing side is
// proven against a real containerised SPIRE elsewhere; what this file
// proves is the traffic-driven identity path end to end, not SPIRE), and a
// real git repository under a real projects mount for describe_workspace.
//
// GID-012, a three-level tree's parent_run_id, GID-009's resume across a
// simulated restart, and a fork's forked_from_run_id are each end-to-end
// claims through this same stack, per #380's own acceptance criteria.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/spire"
)

const (
	gwIdentityTrustDomain = "innsegl.dev"
	gwIdentityParentID    = "spiffe://innsegl.dev/spire/agent/x509pop/node-gwidentity-test"
	gwIdentityRemote      = "git@github.com:Example-Org/Example-Repo.git"
)

// ---------------------------------------------------------------------------
// A fake SPIRE, satisfying mcp.RegisterAgentIdentities and
// mcp.RetireAgentEntries -- the identical shape
// internal/gateway/registrar_test.go's gwIdentities uses one package over,
// restated here because cmd/innsegl cannot import a sibling package's own
// test-only types.
// ---------------------------------------------------------------------------

type gwIdentityFakeSPIRE struct {
	mu      sync.Mutex
	trust   string
	entries map[string]spire.Entry
	seq     int
}

func newGWIdentityFakeSPIRE() *gwIdentityFakeSPIRE {
	return &gwIdentityFakeSPIRE{trust: gwIdentityTrustDomain, entries: map[string]spire.Entry{}}
}

func (f *gwIdentityFakeSPIRE) TrustDomain() string { return f.trust }

func (f *gwIdentityFakeSPIRE) RegisterRun(_ context.Context, reg spire.Registration) (spire.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := reg.Run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Entry{}, err
	}
	if _, dup := f.entries[id]; dup {
		return spire.Entry{}, &spire.Error{
			Class: spire.ClassDuplicateRequest, Op: "register_agent", RunID: reg.Run.RunID,
			Message: "entry already exists",
		}
	}
	f.seq++
	ttl := reg.TTL
	if ttl == 0 {
		ttl = spire.DefaultRunTTL
	}
	e := spire.Entry{
		ID: fmt.Sprintf("entry-%d", f.seq), SPIFFEID: id, ParentID: reg.ParentID,
		Selectors: reg.Selectors, TTL: ttl,
	}
	f.entries[id] = e
	return e, nil
}

func (f *gwIdentityFakeSPIRE) LookupRun(_ context.Context, run spire.RunRef) (spire.Entry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Entry{}, false, err
	}
	e, ok := f.entries[id]
	return e, ok, nil
}

func (f *gwIdentityFakeSPIRE) RetireRun(_ context.Context, run spire.RunRef) (spire.Retirement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, err := run.SPIFFEID(f.trust)
	if err != nil {
		return spire.Retirement{}, err
	}
	e, ok := f.entries[id]
	if !ok {
		return spire.Retirement{}, nil
	}
	delete(f.entries, id)
	return spire.Retirement{EntryID: e.ID, Deleted: true}, nil
}

func (f *gwIdentityFakeSPIRE) entryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// ---------------------------------------------------------------------------
// The real projects mount: one git repository, host path == container path
// (the same simplification internal/mcp/workspace_test.go's own fixture
// makes: the tree has to exist for git to read it, and a container path
// does not exist on the host).
// ---------------------------------------------------------------------------

func gwIdentityGitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// configureGWIdentityWorkspace builds a projects root with one repository
// under it (main branch, one commit), and configures describe_workspace to
// read it -- host and container path identical, exactly as
// internal/mcp/workspace_test.go's configureWorkspace does. A test that
// wants workspace resolution to SUCCEED calls this; GID-012's own test
// deliberately does not, so registration fails at exactly this step.
func configureGWIdentityWorkspace(t *testing.T) (projects, repo string) {
	t.Helper()
	projects = t.TempDir()
	repo = filepath.Join(projects, "example-repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	gwIdentityGitRun(t, repo, "init", "-q", "-b", "main")
	gwIdentityGitRun(t, repo, "config", "user.email", "t@t")
	gwIdentityGitRun(t, repo, "config", "user.name", "t")
	gwIdentityGitRun(t, repo, "remote", "add", "origin", gwIdentityRemote)
	if err := os.WriteFile(filepath.Join(repo, "seed"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	gwIdentityGitRun(t, repo, "add", "seed")
	gwIdentityGitRun(t, repo, "commit", "-q", "-m", "seed", "--no-gpg-sign")

	restore, err := mcp.ConfigureDescribeWorkspace(mcp.DescribeWorkspaceConfig{
		HostProjects: projects, Projects: projects,
	})
	if err != nil {
		t.Fatalf("ConfigureDescribeWorkspace: %v", err)
	}
	t.Cleanup(restore)
	return projects, repo
}

// ---------------------------------------------------------------------------
// The fixture: register_agent, retire_agent and describe_workspace, all
// wired onto a real, throwaway Postgres, a real *ledger.Store and a fake
// SPIRE -- exactly what a `serve`-configured process hands the gateway
// companion in production (this file's own header).
// ---------------------------------------------------------------------------

// gwIdentityFixture wires register_agent and retire_agent for the duration
// of a test; it does NOT configure describe_workspace -- see
// configureGWIdentityWorkspace, called by every test but GID-012's own.
type gwIdentityFixture struct {
	dsn   string
	store *ledger.Store
	ids   *gwIdentityFakeSPIRE
}

func newGWIdentityFixture(t *testing.T) *gwIdentityFixture {
	t.Helper()
	ownerDSN, _, _ := freshLedgerDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)

	pool := gwIdentityPool(t, ownerDSN)
	idem := mcp.NewIdempotencyStore(pool)
	ids := newGWIdentityFakeSPIRE()
	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatalf("rundir.New: %v", err)
	}
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	restoreReg, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities:  ids,
		Runs:        dir,
		Ledger:      store,
		Idempotency: idem,
		ParentID:    gwIdentityParentID,
		Pseudonyms:  literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreReg)

	restoreRet, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: dir, Entries: ids, Ledger: store,
	})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRet)

	return &gwIdentityFixture{dsn: ownerDSN, store: store, ids: ids}
}

func gwIdentityPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open a pool on %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ---------------------------------------------------------------------------
// Driving the REAL openGateway over HTTP.
// ---------------------------------------------------------------------------

// startGWIdentityGateway runs the production openGateway (via runGateway,
// the same seam TestGatewayCommandRelaysRealTrafficEndToEnd already uses)
// against dsn and upstream, and returns its bound address and a stop
// function. Calling stop and then calling this again against the SAME dsn
// is GID-009's own scenario: a fresh process, an empty in-memory cache and
// an empty tree-linker table, the mapping store's own row the only thing
// that survives.
func startGWIdentityGateway(t *testing.T, dsn, upstreamURL string, upstreamClient *http.Client) (addr string, client *http.Client, stop func()) {
	t.Helper()
	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstreamClient
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstreamURL, "-dsn", dsn,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() { done <- runGateway(ctx, args, io.Discard, io.Discard, deps) }()

	select {
	case addr = <-addrCh:
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway never announced a bound address")
	}
	client = gatewayTrustingClient(t, certDir)

	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case code := <-done:
			if code != exitOK {
				t.Errorf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the gateway did not stop within 10s of its context being cancelled")
		}
	}
	return addr, client, stop
}

// gwIdentityMessage mirrors one Anthropic Messages API message, the shape
// internal/gateway/facts.go's own ExtractRequestFacts reads.
type gwIdentityMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// gwIdentityMessageBody builds a request body whose first user message
// states workdir inside a system-reminder (facts.go's own recognised
// label, "Primary working directory:") and carries brief as everything
// else -- byte for byte what a spawning Agent tool_use's own "prompt" must
// equal for ADR-0058 decision 3's exact-equality parent link. assistant,
// when non-empty, adds a second message, which is what makes
// ComputeFingerprint non-empty (facts.go: "empty until the conversation has
// a first assistant turn") -- Claude Code resends the whole history on
// every request, fork included, so a fork's own first request already
// carries the assistant turn its origin's did.
func gwIdentityMessageBody(t *testing.T, workdir, brief, assistant string) string {
	t.Helper()
	content := "<system-reminder>\n# Environment\nPrimary working directory: " + workdir + "\n</system-reminder>\n\n" + brief
	messages := []gwIdentityMessage{{Role: "user", Content: content}}
	if assistant != "" {
		messages = append(messages, gwIdentityMessage{Role: "assistant", Content: assistant})
	}
	b, err := json.Marshal(struct {
		Messages []gwIdentityMessage `json:"messages"`
	}{Messages: messages})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return string(b)
}

// sendGWIdentityMessage sends one /v1/messages request through the gateway
// at addr, over https, using client -- gatewayTrustingClient's own return
// from startGWIdentityGateway, the one client in each test that trusts THAT
// gateway's own CA (RM-246, #391). agentID empty means the root agent (no
// header, harness.go's own rule).
func sendGWIdentityMessage(t *testing.T, addr string, client *http.Client, sessionID, agentID, workdir, brief, assistant string) *http.Response {
	t.Helper()
	stateGatewayDirectory(t, addr, client, sessionID, agentID, workdir)
	body := gwIdentityMessageBody(t, workdir, brief, assistant)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+addr+"/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("X-Claude-Code-Session-Id", sessionID)
	if agentID != "" {
		req.Header.Set("X-Claude-Code-Agent-Id", agentID)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	return resp
}

// stateGatewayDirectory states workdir for sessionID (and agentID, when a
// subagent) to the gateway's session-workspace endpoint, exactly as `innsegl
// hook session` does before every user turn and subagent. The gateway
// registers a new run from this statement and from nothing else.
func stateGatewayDirectory(t *testing.T, addr string, client *http.Client, sessionID, agentID, workdir string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"session_id": sessionID, "agent_id": agentID, "cwd": workdir})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+addr+gatewaySessionWorkspacePath, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("stating the directory: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("stating the directory: status %d, want 204", resp.StatusCode)
	}
}

// sendAndDrainGWIdentityMessage sends one message and reads its reply to
// completion (so a streamed reply's own content_block_stop events have
// already been processed by the server side, synchronously, before this
// call returns -- Proxy.stream's own doc comment), closing the body itself
// rather than handing it back -- every test here that does not need the
// response's own status or bytes (GID-012's own test is the one that does)
// calls this instead of sendGWIdentityMessage directly.
func sendAndDrainGWIdentityMessage(t *testing.T, addr string, client *http.Client, sessionID, agentID, workdir, brief, assistant string) {
	t.Helper()
	resp := sendGWIdentityMessage(t, addr, client, sessionID, agentID, workdir, brief, assistant)
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain response: %v", err)
	}
}

// writeGWIdentitySSEToolUse writes one complete Agent tool_use block whose
// input is exactly {"prompt": prompt, "subagent_type": subagentType},
// flushing after every event -- the minimal recorded shape sse.go's own
// messagesInterpreter reads. subagentType may be empty, which marshals as
// an empty "subagent_type" field -- RM-263 (#416) reads that the same as a
// field that was never sent at all.
func writeGWIdentitySSEToolUse(t *testing.T, w http.ResponseWriter, prompt, subagentType string) {
	t.Helper()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("upstream: ResponseWriter is not a Flusher")
	}
	write := func(event, data string) {
		if _, err := io.WriteString(w, "event: "+event+"\ndata: "+data+"\n\n"); err != nil {
			t.Errorf("write SSE event %q: %v", event, err)
		}
		flusher.Flush()
	}
	write("content_block_start",
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Agent","input":{}}}`)
	inputJSON, err := json.Marshal(map[string]string{"prompt": prompt, "subagent_type": subagentType})
	if err != nil {
		t.Fatalf("marshal tool_use input: %v", err)
	}
	partialJSON, err := json.Marshal(string(inputJSON))
	if err != nil {
		t.Fatalf("marshal partial_json: %v", err)
	}
	write("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+string(partialJSON)+`}}`)
	write("content_block_stop", `{"type":"content_block_stop","index":0}`)
}

// ---------------------------------------------------------------------------
// Reading the gateway's own state back: the mapping table and the chain.
// ---------------------------------------------------------------------------

// gwIdentityMapping is one row of innsegl.gateway_run_mapping, read back
// directly -- the same table internal/gateway/mapping_postgres.go writes,
// queried here rather than through it, so this file's own claims are
// independent of that package's Go API.
type gwIdentityMapping struct {
	runID, parentRunID, forkedFromRunID string
	found                               bool
}

func queryGWIdentityMapping(t *testing.T, dsn, sessionID, agentID string) gwIdentityMapping {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := gwIdentityPool(t, dsn)

	var runID string
	var parentRunID, forkedFromRunID *string
	err := pool.QueryRow(ctx,
		`SELECT run_id, parent_run_id, forked_from_run_id
		   FROM innsegl.gateway_run_mapping
		  WHERE session_id = $1 AND agent_id = $2
		  ORDER BY recorded_at DESC, id DESC
		  LIMIT 1`, sessionID, agentID,
	).Scan(&runID, &parentRunID, &forkedFromRunID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return gwIdentityMapping{}
		}
		t.Fatalf("query the mapping table for session %s agent %s: %v", sessionID, agentID, err)
	}
	m := gwIdentityMapping{runID: runID, found: true}
	if parentRunID != nil {
		m.parentRunID = *parentRunID
	}
	if forkedFromRunID != nil {
		m.forkedFromRunID = *forkedFromRunID
	}
	return m
}

func countGWIdentityMappingRows(t *testing.T, dsn, sessionID, agentID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := gwIdentityPool(t, dsn)
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND agent_id = $2`,
		sessionID, agentID,
	).Scan(&n); err != nil {
		t.Fatalf("count mapping rows: %v", err)
	}
	return n
}

// runRegisteredForkedFrom reads runID's own run_registered event straight
// off the real chain and answers its forked_from_run_id, and whether the
// event was found at all.
func runRegisteredForkedFrom(t *testing.T, store *ledger.Store, runID string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	recs, err := store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%q): %v", runID, err)
	}
	for _, rec := range recs {
		if rec["event_type"] != "run_registered" {
			continue
		}
		forked, ok := rec["forked_from_run_id"].(string)
		if !ok {
			forked = "" // absent: not set, never a value to fake
		}
		return forked, true
	}
	return "", false
}

// runRegisteredAgentType reads runID's own run_registered event straight off
// the real chain and answers its agent_type (RM-263, #416) -- the real,
// unpseudonymised value (this file's own fixture configures
// identity.ModeLiteral), and whether the event was found at all.
func runRegisteredAgentType(t *testing.T, store *ledger.Store, runID string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	recs, err := store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%q): %v", runID, err)
	}
	for _, rec := range recs {
		if rec["event_type"] != "run_registered" {
			continue
		}
		agentType, ok := rec["agent_type"].(string)
		if !ok {
			t.Fatalf("run_registered for %q carries no agent_type", runID)
		}
		return agentType, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// GID-012: identity cannot be issued, end to end through the real
// openGateway. describe_workspace is deliberately left unconfigured (no
// call to configureGWIdentityWorkspace), so registration fails at
// workspace resolution -- a real, deterministic "identity cannot be
// issued" (ADR-0058 decision 11): 403, nothing forwarded.
// ---------------------------------------------------------------------------

func TestGID012IdentityCannotBeIssuedRefusesEndToEndThroughRealOpenGateway(t *testing.T) {
	f := newGWIdentityFixture(t)

	var upstreamHits int
	var mu sync.Mutex
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	const session = "d5a6a1a0-0000-4000-8000-000000000001"
	resp := sendGWIdentityMessage(t, addr, client, session, "", "/no-such-projects-mount/example-repo", "hello, world", "")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (GID-012). body:\n%s", resp.StatusCode, http.StatusForbidden, body)
	}
	if !strings.Contains(string(body), "innsegl") {
		t.Errorf("body %q does not name innsegl", body)
	}
	mu.Lock()
	hits := upstreamHits
	mu.Unlock()
	if hits != 0 {
		t.Errorf("upstream received %d requests, want 0 -- nothing should be forwarded", hits)
	}
	if m := queryGWIdentityMapping(t, f.dsn, session, "main"); m.found {
		t.Errorf("a mapping row was recorded for a refused request: %+v", m)
	}
}

// ---------------------------------------------------------------------------
// A three-level tree, registered end to end with correct parent_run_id.
// ---------------------------------------------------------------------------

const (
	gwTreeSession     = "d5a6a1a0-0000-4000-8000-000000000002"
	gwTreeLeadAgent   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	gwTreeWorkerAgent = "11111111-2222-3333-4444-555555555555"
	// gwTreeLeadType and gwTreeWorkerType are the subagent_type each spawn
	// asks for (RM-263, #416) -- deliberately distinct from each other and
	// from gwTreeLeadAgent/gwTreeWorkerAgent's own UUIDs, so a run recorded
	// with the wrong one (its agent id, or its sibling's type) is caught.
	gwTreeLeadType   = "wave-lead"
	gwTreeWorkerType = "widget-worker"
)

func TestThreeLevelTreeRegistersEndToEndWithCorrectParentRunID(t *testing.T) {
	f := newGWIdentityFixture(t)
	_, repo := configureGWIdentityWorkspace(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		switch r.Header.Get("X-Claude-Code-Agent-Id") {
		case "":
			writeGWIdentitySSEToolUse(t, w, "lead brief", gwTreeLeadType)
		case gwTreeLeadAgent:
			writeGWIdentitySSEToolUse(t, w, "worker brief", gwTreeWorkerType)
		default:
			// The worker spawns nothing further.
		}
	}))
	defer upstream.Close()

	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	sendAndDrainGWIdentityMessage(t, addr, client, gwTreeSession, "", repo, "root brief", "")
	sendAndDrainGWIdentityMessage(t, addr, client, gwTreeSession, gwTreeLeadAgent, repo, "lead brief", "")
	sendAndDrainGWIdentityMessage(t, addr, client, gwTreeSession, gwTreeWorkerAgent, repo, "worker brief", "")

	// mainAgentID's own value is harness.go's "main" (internal/gateway),
	// restated here as a literal because it is what is actually persisted.
	main := queryGWIdentityMapping(t, f.dsn, gwTreeSession, "main")
	lead := queryGWIdentityMapping(t, f.dsn, gwTreeSession, gwTreeLeadAgent)
	worker := queryGWIdentityMapping(t, f.dsn, gwTreeSession, gwTreeWorkerAgent)

	if !main.found || !lead.found || !worker.found {
		t.Fatalf("main.found=%v lead.found=%v worker.found=%v, want all true", main.found, lead.found, worker.found)
	}
	if main.parentRunID != "" {
		t.Errorf("main's parent_run_id = %q, want empty (the root)", main.parentRunID)
	}
	if lead.parentRunID != main.runID {
		t.Errorf("lead's parent_run_id = %q, want main's run id %q", lead.parentRunID, main.runID)
	}
	if worker.parentRunID != lead.runID {
		t.Errorf("worker's parent_run_id = %q, want lead's run id %q", worker.parentRunID, lead.runID)
	}
	if main.runID == lead.runID || lead.runID == worker.runID || main.runID == worker.runID {
		t.Errorf("the tree did not register three distinct runs: main=%s lead=%s worker=%s",
			main.runID, lead.runID, worker.runID)
	}
	if got := f.ids.entryCount(); got != 3 {
		t.Errorf("SPIRE holds %d entries after the tree registered, want 3 (one per run)", got)
	}

	// RM-263 (#416): each run's recorded agent_type is the type its OWN
	// spawn asked for -- never its harness-asserted agent id, and never
	// conflated with a sibling's type -- and the root's is the harness's
	// own fixed value.
	mainType, ok := runRegisteredAgentType(t, f.store, main.runID)
	if !ok {
		t.Fatalf("no run_registered event was appended to the real chain for main %q", main.runID)
	}
	if mainType != "main" {
		t.Errorf("main's agent_type = %q, want %q (the root's fixed type)", mainType, "main")
	}
	leadType, ok := runRegisteredAgentType(t, f.store, lead.runID)
	if !ok {
		t.Fatalf("no run_registered event was appended to the real chain for lead %q", lead.runID)
	}
	if leadType != gwTreeLeadType {
		t.Errorf("lead's agent_type = %q, want %q (the spawn's own type, not its agent id %q)",
			leadType, gwTreeLeadType, gwTreeLeadAgent)
	}
	workerType, ok := runRegisteredAgentType(t, f.store, worker.runID)
	if !ok {
		t.Fatalf("no run_registered event was appended to the real chain for worker %q", worker.runID)
	}
	if workerType != gwTreeWorkerType {
		t.Errorf("worker's agent_type = %q, want %q (the spawn's own type, not its agent id %q or lead's type %q)",
			workerType, gwTreeWorkerType, gwTreeWorkerAgent, gwTreeLeadType)
	}
}

// ---------------------------------------------------------------------------
// GID-009: resume after a gateway restart continues the run, end to end.
// ---------------------------------------------------------------------------

func TestGID009ResumeAfterGatewayRestartContinuesTheRunEndToEnd(t *testing.T) {
	f := newGWIdentityFixture(t)
	_, repo := configureGWIdentityWorkspace(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	const session = "d5a6a1a0-0000-4000-8000-000000000003"

	addr1, client1, stop1 := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	sendAndDrainGWIdentityMessage(t, addr1, client1, session, "", repo, "hello", "")
	stop1()

	before := queryGWIdentityMapping(t, f.dsn, session, "main")
	if !before.found {
		t.Fatal("no mapping row was recorded by the first gateway process")
	}

	// A fresh process against the SAME database: an empty in-memory cache,
	// an empty tree-linker table -- everything but the mapping row itself
	// is gone (ADR-0058 decision 9: "a gateway restart must find the same
	// mapping it left and continue the same runs").
	addr2, client2, stop2 := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop2()
	sendAndDrainGWIdentityMessage(t, addr2, client2, session, "", repo, "hello", "")

	after := queryGWIdentityMapping(t, f.dsn, session, "main")
	if !after.found {
		t.Fatal("no mapping row was found after the restart")
	}
	if after.runID != before.runID {
		t.Errorf("run id after the restart = %q, want the same run %q", after.runID, before.runID)
	}
	if got := countGWIdentityMappingRows(t, f.dsn, session, "main"); got != 1 {
		t.Errorf("mapping rows for this (session, agent) = %d, want 1 (no duplicate registration)", got)
	}
}

// ---------------------------------------------------------------------------
// A fork registers with forked_from_run_id, end to end -- on the mapping
// table AND on the real chain's own run_registered event.
// ---------------------------------------------------------------------------

func TestForkRegistersWithForkedFromRunIDEndToEnd(t *testing.T) {
	f := newGWIdentityFixture(t)
	_, repo := configureGWIdentityWorkspace(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	addr, client, stop := startGWIdentityGateway(t, f.dsn, upstream.URL, upstream.Client())
	defer stop()

	const (
		originSession = "d5a6a1a0-0000-4000-8000-000000000004"
		forkedSession = "d5a6a1a0-0000-4000-8000-000000000005"
		sharedBrief   = "a conversation that gets forked"
		sharedReply   = "the model's first reply, shared by the fork"
	)

	// The origin's first request already carries an assistant turn --
	// Claude Code resends the whole history on every request, so a
	// fingerprint is knowable from a conversation's very first message the
	// gateway ever sees exactly as readily as from its second.
	sendAndDrainGWIdentityMessage(t, addr, client, originSession, "", repo, sharedBrief, sharedReply)
	origin := queryGWIdentityMapping(t, f.dsn, originSession, "main")
	if !origin.found {
		t.Fatal("no mapping row was recorded for the origin")
	}

	// The fork: a DIFFERENT session, the IDENTICAL brief and first
	// assistant turn -- ADR-0058 decision 5, "a known fingerprint under a
	// new session".
	sendAndDrainGWIdentityMessage(t, addr, client, forkedSession, "", repo, sharedBrief, sharedReply)
	fork := queryGWIdentityMapping(t, f.dsn, forkedSession, "main")
	if !fork.found {
		t.Fatal("no mapping row was recorded for the fork")
	}

	if fork.runID == origin.runID {
		t.Fatalf("the fork registered as the same run as its origin (%s)", fork.runID)
	}
	if fork.forkedFromRunID != origin.runID {
		t.Errorf("the fork's mapping row forked_from_run_id = %q, want the origin's run id %q",
			fork.forkedFromRunID, origin.runID)
	}

	forkedFrom, found := runRegisteredForkedFrom(t, f.store, fork.runID)
	if !found {
		t.Fatalf("no run_registered event was appended to the real chain for the fork %q", fork.runID)
	}
	if forkedFrom != origin.runID {
		t.Errorf("the fork's run_registered forked_from_run_id = %q, want the origin's run id %q",
			forkedFrom, origin.runID)
	}

	originForkedFrom, originFound := runRegisteredForkedFrom(t, f.store, origin.runID)
	if !originFound {
		t.Fatalf("no run_registered event was appended to the real chain for the origin %q", origin.runID)
	}
	if originForkedFrom != "" {
		t.Errorf("the origin's own run_registered carries forked_from_run_id = %q, want empty: nothing forked it",
			originForkedFrom)
	}
}

// ---------------------------------------------------------------------------
// sessionEndHandler (#380 code review, 2026-09-28): review case (c) --
// the endpoint accepts only POST from loopback with a well-formed session
// id, and a flood of signals is rate-bounded. (The OTHER half of "bounded",
// SessionEndSignals' own table size, is internal/gateway's own
// TestSessionEndSignalsIsBoundedAndEvictsTheOldestMark.) These call the
// handler directly, bypassing any real listener, so RemoteAddr can be set
// to a non-loopback address deliberately -- something no real request to
// this gateway's own published port could ever carry (ADR-0060 decision 2),
// which is exactly why this handler's own belt-and-suspenders check is
// worth testing on its own.
// ---------------------------------------------------------------------------

// noopMappingStore and noopRegistrar satisfy gateway.MappingStore and
// gateway.Registrar with no behaviour at all -- these tests are about the
// HTTP handler's own checks (method, remote address, body shape, rate),
// never about what SessionEnder does once a signal gets past them.
type noopMappingStore struct{}

func (noopMappingStore) Insert(context.Context, gateway.RunMapping) error { return nil }

func (noopMappingStore) BySessionAgent(context.Context, string, string) (gateway.RunMapping, bool, error) {
	return gateway.RunMapping{}, false, nil
}

func (noopMappingStore) ByFingerprint(context.Context, gateway.Fingerprint) ([]gateway.RunMapping, error) {
	return nil, nil
}

type noopRegistrar struct{}

func (noopRegistrar) Register(context.Context, gateway.RegisterInput) (gateway.RegisteredRun, error) {
	return gateway.RegisteredRun{}, nil
}

func (noopRegistrar) Restore(context.Context, gateway.RunMapping, gateway.RegisterInput) (gateway.RegisteredRun, error) {
	return gateway.RegisteredRun{}, nil
}

func (noopRegistrar) Retire(context.Context, string) (string, error) { return "", nil }

func newTestSessionEndRateLimiter(t *testing.T) *gateway.SessionRateLimiter {
	t.Helper()
	l, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate: sessionEndRateLimitRate, Burst: sessionEndRateLimitBurst,
	})
	if err != nil {
		t.Fatalf("NewSessionRateLimiter: %v", err)
	}
	return l
}

// sessionEndTestHandler builds a handler over a fresh SessionEndSignals, so
// a test can read its Len() back directly.
func sessionEndTestHandler(t *testing.T) (http.HandlerFunc, *gateway.SessionEndSignals) {
	t.Helper()
	signals := gateway.NewSessionEndSignals(0)
	ender := gateway.NewSessionEnder(signals, noopMappingStore{}, noopRegistrar{}, time.Minute, nil)
	return sessionEndHandler(ender, newTestSessionEndRateLimiter(t), localCallers{}, newServeLog(io.Discard)), signals
}

func sessionEndTestRequest(t *testing.T, method, remoteAddr, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, "/_gateway/session-end", r)
	req.RemoteAddr = remoteAddr
	return req
}

func TestSessionEndHandlerRejectsNonPOST(t *testing.T) {
	h, _ := sessionEndTestHandler(t)
	rec := httptest.NewRecorder()
	h(rec, sessionEndTestRequest(t, http.MethodGet, "127.0.0.1:54321", ""))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestSessionEndHandlerRejectsANonLoopbackRemoteAddr(t *testing.T) {
	h, signals := sessionEndTestHandler(t)
	rec := httptest.NewRecorder()
	body := `{"session_id":"d5a6a1a0-0000-4000-8000-0000000000aa"}`
	h(rec, sessionEndTestRequest(t, http.MethodPost, "203.0.113.7:54321", body))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := signals.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0: a non-loopback caller must never be marked", got)
	}
}

func TestSessionEndHandlerRejectsAMalformedSessionID(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"not JSON at all", "not json"},
		{"no session_id field", `{}`},
		{"session_id is not a UUID", `{"session_id":"not-a-uuid"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, signals := sessionEndTestHandler(t)
			rec := httptest.NewRecorder()
			h(rec, sessionEndTestRequest(t, http.MethodPost, "127.0.0.1:54321", tc.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := signals.Len(); got != 0 {
				t.Errorf("Len() = %d, want 0: a malformed signal must never be marked", got)
			}
		})
	}
}

func TestSessionEndHandlerAcceptsAWellFormedLoopbackSignal(t *testing.T) {
	h, signals := sessionEndTestHandler(t)
	rec := httptest.NewRecorder()
	const sessionID = "d5a6a1a0-0000-4000-8000-0000000000aa"
	h(rec, sessionEndTestRequest(t, http.MethodPost, "127.0.0.1:54321", `{"session_id":"`+sessionID+`"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := signals.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1: a well-formed loopback signal must be marked", got)
	}
}

// IPv6 loopback (::1) is loopback too -- localCallers must not be a
// literal "127.0.0.1" string check.
func TestSessionEndHandlerAcceptsIPv6Loopback(t *testing.T) {
	h, signals := sessionEndTestHandler(t)
	rec := httptest.NewRecorder()
	const sessionID = "d5a6a1a0-0000-4000-8000-0000000000bb"
	req := sessionEndTestRequest(t, http.MethodPost, "[::1]:54321", `{"session_id":"`+sessionID+`"}`)
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := signals.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
}

// TestSessionEndHandlerBoundsAFloodByRate is review case (c)'s "rate" half:
// a flood of signals from the same (unauthenticated, unkeyable) caller is
// bounded by the endpoint's own rate limit, refused with 429 past its
// burst, well before it could grow SessionEndSignals' own table without
// bound.
func TestSessionEndHandlerBoundsAFloodByRate(t *testing.T) {
	h, signals := sessionEndTestHandler(t)

	var refused int
	for i := 0; i < sessionEndRateLimitBurst+10; i++ {
		rec := httptest.NewRecorder()
		sessionID := fmt.Sprintf("d5a6a1a0-0000-4000-8000-%012d", i)
		h(rec, sessionEndTestRequest(t, http.MethodPost, "127.0.0.1:54321", `{"session_id":"`+sessionID+`"}`))
		switch rec.Code {
		case http.StatusNoContent:
		case http.StatusTooManyRequests:
			refused++
			if rec.Header().Get("Retry-After") == "" {
				t.Errorf("request %d: 429 carries no Retry-After header", i)
			}
		default:
			t.Fatalf("request %d: status = %d, want 204 or 429", i, rec.Code)
		}
	}
	if refused == 0 {
		t.Error("no request was refused by the rate limit; the flood was not bounded at all")
	}
	// However many were admitted, the table itself never exceeded what was
	// admitted -- it is the rate limit, not the table's own cap, doing the
	// bounding here (the table's own cap is proven separately, at a small
	// size, by internal/gateway's own test).
	if got := signals.Len(); got > sessionEndRateLimitBurst+10-refused {
		t.Errorf("Len() = %d, more marks than requests the rate limit admitted", got)
	}
}
