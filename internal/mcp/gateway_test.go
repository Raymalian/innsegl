// SPDX-License-Identifier: Apache-2.0

package mcp

// gateway_test.go — RM-231 (#376), E15 (#358), doc 07 TC-GID: GID-001..GID-004.
//
// GID-001..003 are unit tests (doc 07 type U): a fake SPIRE client (raSPIRE,
// register_agent_test.go / retireEntries, retire_agent_test.go) and an
// in-memory ledger built from the shipped chain primitives (retireLedger,
// retire_agent_test.go) stand in for the two external systems. Only the
// idempotency claim is real, on a real containerised Postgres via the
// package's shared TestMain (idempotency_pgharness_test.go): GID-001's
// "exactly one run" and GID-002's replay both rest on ADR-0017's claim
// mechanics, which an in-memory stand-in would assert rather than prove —
// see register_agent_test.go's own header for the identical reasoning.
// GID-004 is an integration test (type I): it runs against a real git
// repository on disk, reusing describe_workspace's own MCP-039..043
// fixtures (workspace_test.go).
//
// None of these tests re-proves register_agent, retire_agent or
// describe_workspace's own behaviour — TestMCP001, TestMCP007,
// TestRegisterAgentReplayRestoresAReapedEntry, TestMCP005-shaped retirement
// cases and TestMCP039..043 already do that. What is proved here is only
// that RegisterRunForGateway, RetireRunForGateway and
// ResolveWorkspaceForGateway reach that SAME configured path in process — a
// second implementation of any of it is exactly what ADR-0053 and this
// issue's "no rule duplicated" forbid.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
)

const gwAgentType = "gw-test"

// ---------------------------------------------------------------------------
// GID-001 — a new agent's first request registers through the MCP in
// process. Exactly one run registered; the run token is held in memory and
// appears in no store or log.
// ---------------------------------------------------------------------------

func TestGID001RegisterRunForGatewayRegistersExactlyOneRunAndHoldsTheTokenInMemoryOnly(t *testing.T) {
	idem, dsn := newStore(t, WithIdempotencyLease(DefaultIdempotencyLease))
	lg := newRetireLedger()
	ids := newRASPIRE(raTrustDomain)
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	const secret = "gid-001-run-token-secret"
	restore, err := ConfigureRegisterAgent(RegisterAgentConfig{
		Identities:     ids,
		Ledger:         lg,
		Idempotency:    idem,
		ParentID:       raParentID,
		Pseudonyms:     literal,
		RunTokenSecret: secret,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restore)

	const key = "gid-001-key"
	out, err := RegisterRunForGateway(t.Context(), GatewayRegistration{
		AgentType:      gwAgentType,
		TaskID:         "gid-001",
		IdempotencyKey: key,
		Repo:           raRepo,
		Branch:         raBranch,
	})
	if err != nil {
		t.Fatalf("RegisterRunForGateway: %v", err)
	}
	if out.RunID == "" || out.SPIFFEID == "" {
		t.Fatalf("RegisterRunForGateway returned %+v, want a run id and a SPIFFE id", out)
	}

	// Exactly one run registered: one ledger append, one run_registered
	// event for it, one SPIRE entry.
	if got := lg.calls(); got != 1 {
		t.Fatalf("the ledger recorded %d appends for one first-time registration, want 1", got)
	}
	regs := lg.of(event.EventTypeRunRegistered, out.RunID)
	if len(regs) != 1 {
		t.Fatalf("the ledger holds %d run_registered events for %s, want exactly 1", len(regs), out.RunID)
	}
	if got := ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after one registration, want 1", got)
	}

	// The run token is held in memory: correctly derived, and returned only
	// in this value.
	wantToken := RunToken(secret, out.RunID)
	if out.RunToken == "" || out.RunToken != wantToken {
		t.Fatalf("run token = %q, want the derived token %q", out.RunToken, wantToken)
	}

	// It appears in no store: not in the run_registered event just
	// appended...
	for field, value := range regs[0] {
		if s, ok := value.(string); ok && strings.Contains(s, out.RunToken) {
			t.Errorf("ledger event field %q carries the run token; the ledger must never hold it", field)
		}
	}
	// ...and not in the idempotency store's own recorded reply, which is
	// what a replay is answered from. register_agent.go's register method
	// recomputes RunToken AFTER outcome.Response is unmarshalled, precisely
	// so the recorded bytes never carry it — this reads those bytes back to
	// hold that claim to measurement rather than to the source comment.
	conn := rawConn(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var response []byte
	if err := conn.QueryRow(ctx,
		`SELECT response FROM innsegl.idempotency WHERE idempotency_key = $1`, key,
	).Scan(&response); err != nil {
		t.Fatalf("reading back the recorded reply: %v", err)
	}
	if strings.Contains(string(response), out.RunToken) {
		t.Errorf("the idempotency store's recorded reply contains the run token (%s); "+
			"it must never be at rest there", response)
	}
}

// ---------------------------------------------------------------------------
// RM-235 (#380) — a fork's registration carries forked_from_run_id on
// run_registered, reached through this same in-process seam. Never settable
// from the public MCP tool schema (register_agent_test.go's
// TestRegisterAgentEventCarriesForkedFromRunIDOnlyWhenSet already proves
// that at the unexported-field boundary); this proves GatewayRegistration's
// own exported member reaches it.
// ---------------------------------------------------------------------------

func TestGID005ForkedFromRunIDReachesRunRegisteredThroughTheGateway(t *testing.T) {
	idem, _ := newStore(t, WithIdempotencyLease(DefaultIdempotencyLease))
	lg := newRetireLedger()
	ids := newRASPIRE(raTrustDomain)
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	restore, err := ConfigureRegisterAgent(RegisterAgentConfig{
		Identities:  ids,
		Ledger:      lg,
		Idempotency: idem,
		ParentID:    raParentID,
		Pseudonyms:  literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restore)

	origin, err := RegisterRunForGateway(t.Context(), GatewayRegistration{
		AgentType:      gwAgentType,
		TaskID:         "gid-005-origin",
		IdempotencyKey: "gid-005-origin-key",
		Repo:           raRepo,
		Branch:         raBranch,
	})
	if err != nil {
		t.Fatalf("RegisterRunForGateway (origin): %v", err)
	}

	fork, err := RegisterRunForGateway(t.Context(), GatewayRegistration{
		AgentType:       gwAgentType,
		TaskID:          "gid-005-fork",
		IdempotencyKey:  "gid-005-fork-key",
		Repo:            raRepo,
		Branch:          raBranch,
		ForkedFromRunID: origin.RunID,
	})
	if err != nil {
		t.Fatalf("RegisterRunForGateway (fork): %v", err)
	}
	if fork.RunID == origin.RunID {
		t.Fatalf("the fork registered as the same run as its origin")
	}

	regs := lg.of(event.EventTypeRunRegistered, fork.RunID)
	if len(regs) != 1 {
		t.Fatalf("the ledger holds %d run_registered events for the fork, want exactly 1", len(regs))
	}
	if got := regs[0][event.FieldForkedFromRunID]; got != origin.RunID {
		t.Errorf("forked_from_run_id = %v, want the origin run %q", got, origin.RunID)
	}

	// The origin's own event carries no forked_from_run_id: only the fork's
	// registration set it.
	originRegs := lg.of(event.EventTypeRunRegistered, origin.RunID)
	if len(originRegs) != 1 {
		t.Fatalf("the ledger holds %d run_registered events for the origin, want exactly 1", len(originRegs))
	}
	if _, present := originRegs[0][event.FieldForkedFromRunID]; present {
		t.Error("the origin's own run_registered carries forked_from_run_id; nothing forked it")
	}
}

// ---------------------------------------------------------------------------
// GID-002 — restore of a lapsed run: registration replayed with the prior
// idempotency key; the same run id comes back.
// ---------------------------------------------------------------------------

func TestGID002RestoreReplaysRegistrationWithThePriorIdempotencyKeyAndTheSameRunComesBack(t *testing.T) {
	idem, _ := newStore(t, WithIdempotencyLease(DefaultIdempotencyLease))
	lg := newRetireLedger()
	ids := newRASPIRE(raTrustDomain)
	runs := newRARuns()
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	restore, err := ConfigureRegisterAgent(RegisterAgentConfig{
		Identities:  ids,
		Runs:        runs,
		Ledger:      lg,
		Idempotency: idem,
		ParentID:    raParentID,
		Pseudonyms:  literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restore)

	const key = "gid-002-key"
	in := GatewayRegistration{
		AgentType:      gwAgentType,
		TaskID:         "gid-002",
		IdempotencyKey: key,
		Repo:           raRepo,
		Branch:         raBranch,
	}

	first, err := RegisterRunForGateway(t.Context(), in)
	if err != nil {
		t.Fatalf("RegisterRunForGateway (first request): %v", err)
	}
	runs.rememberAs(first.RunID, first.SPIFFEID)
	if got := ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after registration, want 1", got)
	}

	// The run lapses: the reaper withdraws the SPIRE entry (IP §6.7). The
	// ledger keeps the run; only the authorisation is gone — exactly what a
	// process killed mid-task and resumed later looks like (ADR-0058
	// decision 6).
	ids.reapAll()
	if got := ids.entryCount(); got != 0 {
		t.Fatalf("the reap left %d entries; this test proves nothing unless the entry is gone", got)
	}

	// Restore: the same idempotency key, replayed.
	second, err := RegisterRunForGateway(t.Context(), in)
	if err != nil {
		t.Fatalf("RegisterRunForGateway (restore): %v", err)
	}

	if second.RunID != first.RunID {
		t.Fatalf("restoring returned run %q, want the original %q", second.RunID, first.RunID)
	}
	if second.SPIFFEID != first.SPIFFEID {
		t.Fatalf("restoring returned spiffe id %q, want %q", second.SPIFFEID, first.SPIFFEID)
	}
	if got := ids.entryCount(); got != 1 {
		t.Fatalf("SPIRE holds %d entries after the restore, want 1 — the run was handed the "+
			"name of an identity with no authorisation behind it, so it could not have signed", got)
	}
	if got := lg.calls(); got != 1 {
		t.Fatalf("the ledger recorded %d appends across the register and the restore, want 1: "+
			"a replay must never append a second run_registered (I3)", got)
	}
}

// ---------------------------------------------------------------------------
// GID-003 — retire through the MCP: idempotent; a second retire answers the
// original timestamp.
// ---------------------------------------------------------------------------

func TestGID003RetireRunForGatewayIsIdempotentAndAnswersTheOriginalInstant(t *testing.T) {
	const runID = "run-gid003"
	lg := newRetireLedger()
	entries := newRetireEntries(runID)
	runs := newRetireRuns(lg, retireRunRef(runID))

	restore, err := ConfigureRetireAgent(RetireAgentConfig{Runs: runs, Entries: entries, Ledger: lg})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restore)

	first, err := RetireRunForGateway(t.Context(), runID)
	if err != nil {
		t.Fatalf("RetireRunForGateway (first retirement): %v", err)
	}
	if first == "" {
		t.Fatalf("RetireRunForGateway returned no retired_at")
	}
	if entries.holds(runID) {
		t.Fatalf("SPIRE still holds the entry for %s after retirement", runID)
	}

	second, err := RetireRunForGateway(t.Context(), runID)
	if err != nil {
		t.Fatalf("RetireRunForGateway (second retirement): %v", err)
	}
	if second != first {
		t.Fatalf("a second retirement answered %q, want the original %q", second, first)
	}
	if got := lg.calls(); got != 1 {
		t.Fatalf("the ledger recorded %d appends across two retirements of one run, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// GID-004 — workspace from the harness-reported directory: repo, branch and
// task derived by the MCP's workspace logic; a directory outside the
// projects mount or not a repository is refused, never guessed.
// ---------------------------------------------------------------------------

func TestGID004ResolveWorkspaceForGatewayDerivesFromTheTreeAndNeverGuesses(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")
	run(t, tree.repo, "checkout", "-q", "-b", "dev/rm231-gateway-registrar")
	configureWorkspace(t, tree.projects, tree.projects)

	ws, err := ResolveWorkspaceForGateway(t.Context(), tree.repo)
	if err != nil {
		t.Fatalf("ResolveWorkspaceForGateway(%s): %v", tree.repo, err)
	}
	const wantRepo = "github.com/Example-Org/Example-Repo"
	if ws.Repo != wantRepo {
		t.Errorf("repo = %q, want %q (the origin's, never the directory's)", ws.Repo, wantRepo)
	}
	if ws.Branch != "dev/rm231-gateway-registrar" {
		t.Errorf("branch = %q, want %q", ws.Branch, "dev/rm231-gateway-registrar")
	}
	if ws.Task != "rm231" {
		t.Errorf("task = %q, want %q", ws.Task, "rm231")
	}

	// Refused, never guessed: a path outside the projects mount.
	outside := filepath.Join(tree.projects, "..", "elsewhere")
	outsideGot, outsideErr := ResolveWorkspaceForGateway(t.Context(), outside)
	if outsideErr == nil {
		t.Fatalf("a path outside the mount was accepted and answered %+v; a guess in a run "+
			"registration is worse than a refusal", outsideGot)
	} else {
		var classified *Error
		if !errors.As(outsideErr, &classified) {
			t.Fatalf("the refusal is %T (%v), not an IP §4 classified error", outsideErr, outsideErr)
		}
	}

	// Refused, never guessed: a directory that is not a repository.
	notRepo := filepath.Join(tree.projects, "not-a-repo")
	if mkErr := os.Mkdir(notRepo, 0o755); mkErr != nil {
		t.Fatalf("creating a non-repository directory: %v", mkErr)
	}
	if notRepoGot, notRepoErr := ResolveWorkspaceForGateway(t.Context(), notRepo); notRepoErr == nil {
		t.Fatalf("a non-repository directory was accepted and answered %+v", notRepoGot)
	}

	// Refused, never guessed: no projects mount configured at all.
	unconfigure, err := ConfigureDescribeWorkspace(DescribeWorkspaceConfig{})
	if err != nil {
		t.Fatalf("ConfigureDescribeWorkspace({}): %v", err)
	}
	t.Cleanup(unconfigure)
	if unsetGot, unsetErr := ResolveWorkspaceForGateway(t.Context(), tree.repo); unsetErr == nil {
		t.Fatalf("an unset projects mount was accepted and answered %+v", unsetGot)
	}
}

// ---------------------------------------------------------------------------
// IP §2's 100%-branch floor on every error-return path of the new wrapper.
// Not doc 07 rows of their own — GID-001..004 are the catalogued behaviours —
// but every branch above has to be exercised deliberately rather than left
// to whatever the four positive cases happened to reach.
// ---------------------------------------------------------------------------

// An advertised wrapper with no dependencies behind register_agent refuses
// loudly rather than half-working — the same refusal a wire caller gets
// (TestRegisterAgentIsNotServedUntilItIsConfigured), reached through the
// gateway's own entry point instead.
func TestRegisterRunForGatewayIsNotServedUntilRegisterAgentIsConfigured(t *testing.T) {
	registerAgentState.mu.Lock()
	saved := registerAgentState.cfg
	registerAgentState.cfg = nil
	registerAgentState.mu.Unlock()
	t.Cleanup(func() {
		registerAgentState.mu.Lock()
		registerAgentState.cfg = saved
		registerAgentState.mu.Unlock()
	})

	_, err := RegisterRunForGateway(t.Context(), GatewayRegistration{
		AgentType: gwAgentType, TaskID: "gw-unconfigured", IdempotencyKey: "gw-unconfigured-key",
	})
	var classified *Error
	if !errors.As(err, &classified) {
		t.Fatalf("RegisterRunForGateway with no configuration failed with %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != ClassInvariantViolation {
		t.Errorf("class = %q, want %q", classified.Class, ClassInvariantViolation)
	}
}

// A failure register_agent's own mint path returns — here, a ledger append
// nobody classified — is surfaced by the wrapper unchanged, never swallowed
// and never turned into a success.
func TestRegisterRunForGatewaySurfacesAMintFailure(t *testing.T) {
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Ledger = raFailingLedger{err: errors.New("a ledger failure nobody classified")}
	})

	_, err := RegisterRunForGateway(t.Context(), GatewayRegistration{
		AgentType:      gwAgentType,
		TaskID:         "gw-mint-failure",
		IdempotencyKey: "gw-mint-failure-key",
		Repo:           raRepo,
		Branch:         raBranch,
	})
	var classified *Error
	if !errors.As(err, &classified) {
		t.Fatalf("RegisterRunForGateway with a failing ledger failed with %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != ClassInvariantViolation {
		t.Errorf("class = %q, want %q", classified.Class, ClassInvariantViolation)
	}
	if got := env.identities.registerAttempts(); got != 0 {
		t.Errorf("SPIRE saw %d RegisterRun attempts with the ledger down, want 0 (I3)", got)
	}
}

// An advertised wrapper with no dependencies behind retire_agent refuses the
// same way a wire caller does (TestRetireAgentIsNotServedUntilItIsConfigured).
func TestRetireRunForGatewayIsNotServedUntilRetireAgentIsConfigured(t *testing.T) {
	retireMu.Lock()
	saved := retireActive
	retireActive = nil
	retireMu.Unlock()
	t.Cleanup(func() {
		retireMu.Lock()
		retireActive = saved
		retireMu.Unlock()
	})

	_, err := RetireRunForGateway(t.Context(), "run-gw-unconfigured")
	var classified *Error
	if !errors.As(err, &classified) {
		t.Fatalf("RetireRunForGateway with no configuration failed with %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != ClassInvariantViolation {
		t.Errorf("class = %q, want %q", classified.Class, ClassInvariantViolation)
	}
}

// A run id that cannot name a run is refused by retire_agent's own first
// gate, and the wrapper surfaces that refusal rather than mapping it to a
// success or hiding the class.
func TestRetireRunForGatewaySurfacesARefusal(t *testing.T) {
	lg := newRetireLedger()
	entries := newRetireEntries()
	runs := newRetireRuns(lg)
	restore, err := ConfigureRetireAgent(RetireAgentConfig{Runs: runs, Entries: entries, Ledger: lg})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restore)

	_, err = RetireRunForGateway(t.Context(), "Not A Valid Run Id!!")
	var classified *Error
	if !errors.As(err, &classified) {
		t.Fatalf("RetireRunForGateway with a malformed run id failed with %T (%v), not an IP §4 classified error", err, err)
	}
	if classified.Class != ClassRunNotFound {
		t.Errorf("class = %q, want %q", classified.Class, ClassRunNotFound)
	}
	if got := lg.calls(); got != 0 {
		t.Errorf("the ledger recorded %d appends for a run id refused before any dependency was consulted, want 0", got)
	}
}
