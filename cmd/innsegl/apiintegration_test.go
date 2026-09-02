// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// API-009, API-010 and API-011 (PROPOSED for doc 07's TC-API) — `innsegl api`
// against a real Postgres.
//
// These are the cases API-008 cannot carry. What a database credential is
// ALLOWED to do is a property of a deployment's GRANTs, and the only thing
// that can be asked about it is a server.

// ---------------------------------------------------------------------------
// Running the shipped command.
// ---------------------------------------------------------------------------

// startAPICommand runs `innsegl api` exactly as the dispatch table does and
// returns the address it bound. The command is the subject; nothing here
// constructs an api.Server itself.
func startAPICommand(t *testing.T, args ...string) (addr string, stderr *syncBuffer) {
	t.Helper()
	var out syncBuffer
	errBuf := &syncBuffer{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- runAPI(ctx, args, &out, errBuf, apiDeps{}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("innsegl api did not stop when its context was cancelled")
		}
	})

	deadline := time.After(60 * time.Second)
	for {
		if line := strings.TrimSpace(out.String()); line != "" {
			return line, errBuf
		}
		select {
		case code := <-done:
			t.Fatalf("innsegl api exited %d before it published an address.\nstderr:\n%s",
				code, errBuf.String())
		case <-deadline:
			t.Fatalf("innsegl api never published an address.\nstderr:\n%s", errBuf.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// apiArgsFor is a command line pointed at one database and one repository.
func apiArgsFor(dsn, repoName, repoPath, fulcio, rekor string) []string {
	return []string{
		"-dsn", dsn,
		"-repos", repoName + "=" + repoPath,
		"-fulcio-url", fulcio,
		"-rekor-url", rekor,
		"-listen", "127.0.0.1:0",
		"-upstream-timeout", "3s",
		"-shutdown-timeout", "5s",
	}
}

func getJSON(t *testing.T, url string) (status int, body []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build a request for %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { discardAPIError(resp.Body.Close()) }()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the body of %s: %v", url, err)
	}
	return resp.StatusCode, body
}

// ---------------------------------------------------------------------------
// A git repository the proof route can be asked about.
// ---------------------------------------------------------------------------

func gitCLI(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-such-gitconfig"),
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
		"GIT_AUTHOR_NAME=Innsegl Operator",
		"GIT_AUTHOR_EMAIL=operator@innsegl.invalid",
		"GIT_COMMITTER_NAME=Innsegl Operator",
		"GIT_COMMITTER_EMAIL=operator@innsegl.invalid",
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// newProofRepo makes a repository with one ordinary, unsigned commit. It is
// unsigned on purpose: what these cases establish is that the route ANSWERS,
// and an unsigned commit's answer is a verdict like any other. Whether the
// three checks are right is internal/verify's, and VER-001's.
func newProofRepo(t *testing.T) (dir, sha string) {
	t.Helper()
	dir = t.TempDir()
	gitCLI(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("innsegl RM-083\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCLI(t, dir, "add", "work.txt")
	gitCLI(t, dir, "commit", "-q", "-m", "work")
	return dir, gitCLI(t, dir, "rev-parse", "HEAD")
}

// closedAddress is a URL nothing is listening on: a real connection refused,
// not a mocked failure.
func closedAddress(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := l.Addr().String()
	if cerr := l.Close(); cerr != nil {
		t.Fatalf("release the reserved port: %v", cerr)
	}
	return "http://" + addr
}

// ---------------------------------------------------------------------------
// API-009 — the refusal, and the distinction it rests on.
// ---------------------------------------------------------------------------

// The statements whose SQLSTATE tells the ACL's refusal apart from the
// trigger's. The owner reaches the trigger; the reader is stopped before it.
var aclProbes = []struct {
	name string
	sql  string
}{
	{"insert into innsegl.events", `INSERT INTO innsegl.events
		(chain_position, event_id, event_hash, prev_event_hash, event_type,
		 source, ts, canonical)
	 VALUES (1, '00000000-0000-7000-8000-000000000000',
		 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
		 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
		 'run_registered', 'mcp', now(), '\x7b7d'::bytea)`},
	{"update innsegl.events", `UPDATE innsegl.events SET run_id = 'x'`},
	{"delete from innsegl.events", `DELETE FROM innsegl.events WHERE false`},
	{"create a schema of its own", `CREATE SCHEMA api_cli_probe`},
}

// The two SQLSTATEs that are a refusal BY PRIVILEGE, spelled as
// internal/api/readonly.go spells them.
const (
	cliInsufficientPrivilege = "42501"
	cliReadOnlyTransaction   = "25006"
)

func cliSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// probeAs runs one statement in a transaction it always rolls back, and
// reports the SQLSTATE and whether the ACL let it through.
func probeAs(t *testing.T, dsn, sql string) (sqlstate string, aclAllowed bool, detail string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { discardAPIError(conn.Close(ctx)) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { discardAPIError(tx.Rollback(ctx)) }()

	// Defeat default_transaction_read_only so that a refusal below is the
	// ACL's and not a setting's — readonly.go's own precaution.
	if _, err := tx.Exec(ctx, "SET TRANSACTION READ WRITE"); err != nil {
		return cliSQLState(err), false, err.Error()
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		state := cliSQLState(err)
		allowed := state != cliInsufficientPrivilege && state != cliReadOnlyTransaction
		return state, allowed, strings.SplitN(err.Error(), "\n", 2)[0]
	}
	return "", true, "the statement succeeded and was rolled back"
}

// API-009 — `innsegl api` refuses a credential that can write, and the check
// that refuses it is the ACL rather than "did the write fail?".
//
// The distinction is the whole case. Both credentials below are refused every
// statement; only one of them is refused BY PRIVILEGE, and a gate that asked
// whether the statement failed would admit the database OWNER — which is the
// credential the gate exists to catch.
func TestAPI009AnOverPrivilegedCredentialIsRefused(t *testing.T) {
	ownerDSN, readerDSN := freshLedgerDB(t)
	repoDir, _ := newProofRepo(t)
	fulcio, rekor := closedAddress(t), closedAddress(t)

	// ---- the measurement the gate rests on --------------------------------
	t.Log("API-009  statement                       owner                       reader")
	for _, p := range aclProbes {
		ownerState, ownerAllowed, ownerDetail := probeAs(t, ownerDSN, p.sql)
		readerState, readerAllowed, readerDetail := probeAs(t, readerDSN, p.sql)

		t.Logf("API-009  %-32s owner sqlstate=%-6s acl_allowed=%-5v  %s",
			p.name, orNone(ownerState), ownerAllowed, ownerDetail)
		t.Logf("API-009  %-32s reader sqlstate=%-5s acl_allowed=%-5v  %s",
			"", orNone(readerState), readerAllowed, readerDetail)

		if !ownerAllowed {
			t.Errorf("the OWNER was refused %s by privilege (sqlstate %s). If the owner "+
				"is refused by the ACL, this case no longer demonstrates the distinction "+
				"the read-only gate depends on", p.name, ownerState)
		}
		if readerAllowed {
			t.Errorf("the READ-ONLY role was allowed %s (sqlstate %q): doc 05 §1 mounts no "+
				"write credentials on the dashboard.\n  %s",
				p.name, readerState, readerDetail)
		}
		if ownerState != "" && ownerState == cliInsufficientPrivilege {
			t.Errorf("the owner's refusal of %s is the ACL's (42501), so this probe cannot "+
				"tell the two credentials apart", p.name)
		}
	}

	// ---- the command, handed the owner ------------------------------------
	var stdout, stderr syncBuffer
	code := runAPI(context.Background(),
		apiArgsFor(ownerDSN, "github.com/innsegl/demo", repoDir, fulcio, rekor),
		&stdout, &stderr, apiDeps{})

	t.Logf("API-009 `innsegl api` on the OWNER credential exited %d\nstderr:\n%s",
		code, stderr.String())

	if code != exitAPIWritable {
		t.Fatalf("exit = %d, want %d (WRITABLE). A query API that starts on a credential "+
			"that can write has a read-only property that is a claim about its source "+
			"code rather than about its deployment (doc 06 §7).", code, exitAPIWritable)
	}
	if stdout.String() != "" {
		t.Errorf("the refused command published an address: %q", stdout.String())
	}
	for _, want := range []string{"is allowed to", "insert into innsegl.events"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the refusal does not name what the credential could do (%q):\n%s",
				want, stderr.String())
		}
	}

	// ---- the command, handed the reader -----------------------------------
	addr, readerStderr := startAPICommand(t,
		apiArgsFor(readerDSN, "github.com/innsegl/demo", repoDir, fulcio, rekor)...)
	t.Logf("API-009 `innsegl api` on the READ-ONLY credential bound %s", addr)
	if !strings.Contains(readerStderr.String(), apiReaderRole) {
		t.Errorf("the start-up report does not name the role it probed:\n%s",
			readerStderr.String())
	}
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------------------
// API-010 — the five routes answer.
// ---------------------------------------------------------------------------

// API-010 — every route internal/api serves is reachable through the shipped
// command, and /health reports the read-only evidence.
//
// RM-076 (#109) shipped the dashboard with no backend at all, so every one of
// these was a load-failure state in the UI. "It answers" is therefore the
// claim being made, and it is made about the command rather than about a
// handler wired up in a test.
func TestAPI010TheFiveRoutesAnswerThroughTheCommand(t *testing.T) {
	_, readerDSN := freshLedgerDB(t)
	repoDir, sha := newProofRepo(t)
	fulcio, rekor := closedAddress(t), closedAddress(t)

	addr, _ := startAPICommand(t,
		apiArgsFor(readerDSN, "github.com/innsegl/demo", repoDir, fulcio, rekor)...)
	base := "http://" + addr

	for _, tc := range []struct {
		route string
		url   string
		want  int
	}{
		{"GET /api/v1/runs", base + "/api/v1/runs", http.StatusOK},
		{"GET /api/v1/overview", base + "/api/v1/overview", http.StatusOK},
		{"GET /api/v1/health", base + "/api/v1/health", http.StatusOK},
		// An empty ledger holds no run, and "no such run" is an answer.
		{"GET /api/v1/runs/{run_id}", base + "/api/v1/runs/01234567-89ab-7def-8000-000000000000",
			http.StatusNotFound},
		// The upstreams are gone, and doc 06 P2 requires "we could not check"
		// to be a verdict rather than an HTTP error.
		{"GET /api/v1/proof/{commit_sha}", base + "/api/v1/proof/" + sha, http.StatusOK},
	} {
		t.Run(tc.route, func(t *testing.T) {
			status, body := getJSON(t, tc.url)
			t.Logf("API-010 %s -> %d %s", tc.route, status, firstLine(body))
			if status != tc.want {
				t.Fatalf("status = %d, want %d. body: %s", status, tc.want, body)
			}
		})
	}

	// /health carries the probe evidence, so "read-only" is a measured fact an
	// operator reads back rather than a claim in a README.
	status, body := getJSON(t, base+"/api/v1/health")
	if status != http.StatusOK {
		t.Fatalf("/api/v1/health = %d", status)
	}
	var health struct {
		Database struct {
			Role      string `json:"role"`
			Superuser bool   `json:"superuser"`
			Probes    []struct {
				Name     string `json:"name"`
				Allowed  bool   `json:"allowed"`
				SQLState string `json:"sqlstate"`
			} `json:"probes"`
		} `json:"database"`
		Repos []string `json:"repos"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode /api/v1/health: %v\n%s", err, body)
	}
	if health.Database.Role != apiReaderRole {
		t.Errorf("health reports role %q, want %q", health.Database.Role, apiReaderRole)
	}
	if health.Database.Superuser {
		t.Error("health reports the API's credential is a SUPERUSER, which no ACL binds")
	}
	if len(health.Database.Probes) == 0 {
		t.Error("health carries no probe evidence, so \"read-only\" is unmeasured")
	}
	for _, p := range health.Database.Probes {
		if p.Allowed {
			t.Errorf("health reports the credential is allowed to %s (sqlstate %q)",
				p.Name, p.SQLState)
		}
	}
	if len(health.Repos) != 1 || health.Repos[0] != "github.com/innsegl/demo" {
		t.Errorf("health reports repos %v, want the one this command was given", health.Repos)
	}
	t.Logf("API-010 /api/v1/health role=%s superuser=%v writes_refused=%d repos=%v",
		health.Database.Role, health.Database.Superuser,
		len(health.Database.Probes), health.Repos)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}

// ---------------------------------------------------------------------------
// API-011 — an unreachable ledger degrades honestly.
// ---------------------------------------------------------------------------

// tcpProxy is a stoppable route to Postgres. Closing it is how the ledger is
// taken away: a real connection refused rather than a mocked error, and
// without disturbing the container the other cases share.
type tcpProxy struct {
	ln       net.Listener
	upstream string

	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func newTCPProxy(t *testing.T, upstream string) *tcpProxy {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the proxy: %v", err)
	}
	p := &tcpProxy{ln: ln, upstream: upstream}
	go p.accept()
	t.Cleanup(p.stop)
	return p
}

func (p *tcpProxy) addr() string { return p.ln.Addr().String() }

func (p *tcpProxy) accept() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		dialer := net.Dialer{Timeout: 10 * time.Second}
		server, derr := dialer.DialContext(context.Background(), "tcp", p.upstream)
		if derr != nil {
			discardAPIError(client.Close())
			continue
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			discardAPIError(client.Close())
			discardAPIError(server.Close())
			return
		}
		p.conns = append(p.conns, client, server)
		p.mu.Unlock()

		go func() { discardAPIPipe(io.Copy(server, client)) }()
		go func() { discardAPIPipe(io.Copy(client, server)) }()
	}
}

// stop takes the ledger away: no new connection is accepted and every live one
// is severed.
func (p *tcpProxy) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	discardAPIError(p.ln.Close())
	for _, c := range p.conns {
		discardAPIError(c.Close())
	}
}

func discardAPIPipe(int64, error) {}

// API-011 — a route that needs the ledger says so when the ledger is gone.
//
// doc 06 anti-pattern 7 is silent staleness and P2 forbids collapsing "failed"
// into "unavailable". The failure mode this case exists to exclude is worse
// than either: an empty 200, which a runs table renders as "no runs" — a
// statement about the ledger's contents made when the ledger was not read at
// all.
func TestAPI011ARouteThatNeedsTheLedgerDegradesHonestly(t *testing.T) {
	_, readerDSN := freshLedgerDB(t)
	repoDir, sha := newProofRepo(t)
	fulcio, rekor := closedAddress(t), closedAddress(t)

	// Reach Postgres through a proxy this test can sever.
	direct, err := pgx.ParseConfig(readerDSN)
	if err != nil {
		t.Fatalf("parse the reader DSN: %v", err)
	}
	proxy := newTCPProxy(t, fmt.Sprintf("%s:%d", direct.Host, direct.Port))
	proxied := strings.Replace(readerDSN,
		fmt.Sprintf("@%s:%d/", direct.Host, direct.Port), "@"+proxy.addr()+"/", 1)
	if proxied == readerDSN {
		t.Fatalf("could not point the DSN at the proxy: %s", readerDSN)
	}

	addr, _ := startAPICommand(t,
		apiArgsFor(proxied, "github.com/innsegl/demo", repoDir, fulcio, rekor)...)
	base := "http://" + addr

	if status, body := getJSON(t, base+"/api/v1/runs"); status != http.StatusOK {
		t.Fatalf("with the ledger reachable, /api/v1/runs = %d: %s", status, body)
	}

	proxy.stop()

	for _, route := range []string{"/api/v1/runs", "/api/v1/overview"} {
		status, body := getJSON(t, base+route)
		t.Logf("API-011 ledger gone: GET %s -> %d %s", route, status, firstLine(body))

		if status == http.StatusOK {
			t.Errorf("GET %s answered 200 with the ledger unreachable. An empty success "+
				"is rendered as \"no runs\" — a statement about the ledger's contents made "+
				"without reading it (doc 06 anti-pattern 7).\n%s", route, body)
			continue
		}
		if status < 500 {
			t.Errorf("GET %s = %d with the ledger unreachable; a failure of this API's own "+
				"is a 5xx, not a statement about the request", route, status)
		}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Errorf("GET %s returned a body a client cannot read: %v\n%s", route, err, body)
			continue
		}
		if envelope.Error.Code == "" || envelope.Error.Message == "" {
			t.Errorf("GET %s failed without saying what failed: %s", route, body)
		}
	}

	// MEASURED, and reported rather than asserted: the proof route holds no
	// store and cannot reach a database (IP §6.11), so it keeps answering with
	// the ledger gone — and /health answers from the report Open gathered at
	// start-up, so it is a statement about this process rather than a
	// readiness probe on Postgres. Both are internal/api's design; this case
	// records what an operator will actually see.
	proofStatus, proofBody := getJSON(t, base+"/api/v1/proof/"+sha)
	t.Logf("API-011 ledger gone: GET /api/v1/proof/{sha} -> %d %s",
		proofStatus, firstLine(proofBody))
	if proofStatus != http.StatusOK {
		t.Errorf("the proof route stopped answering when the LEDGER went away; it holds "+
			"no store and must not depend on one (IP §6.11, doc 06 P2). status = %d: %s",
			proofStatus, proofBody)
	}

	healthStatus, healthBody := getJSON(t, base+"/api/v1/health")
	t.Logf("API-011 ledger gone: GET /api/v1/health -> %d %s",
		healthStatus, firstLine(healthBody))
}
