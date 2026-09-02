// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
)

// ---------------------------------------------------------------------------
// The demo agent.
//
// doc 05 §1: "demo-agent | built | Scripted agent that registers, makes a
// scratch-repo commit, retires. This is the OPS-004 smoke test body."
//
// It is an MCP client and nothing else. It speaks the shipped transport to the
// shipped server over a published port and calls the five IP §4 tools by their
// protected names — no in-process wiring, no second implementation of the
// two-phase protocol, no privileged access to the ledger or to SPIRE. What it
// can do is exactly what any agent holding the MCP's address can do, which is
// the property that makes it a demonstration rather than a fixture.
// ---------------------------------------------------------------------------

// demoRun is one complete agent run, as the demo agent observed it.
type demoRun struct {
	runID         string
	spiffeID      string
	taskRef       string
	commitSHA     string
	worktree      string
	trailers      map[string]string
	rekorUUID     string
	rekorLogIndex int64
}

func (s *stack) demoAgent(t *testing.T) demoRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-demo-agent", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: s.mcpURL}, nil)
	if err != nil {
		t.Fatalf("the demo agent could not open an MCP session at %s: %v", s.mcpURL, err)
	}
	defer func() { _ = session.Close() }()

	// ---- register_agent ---------------------------------------------------
	var registered struct {
		SPIFFEID  string `json:"spiffe_id"`
		RunID     string `json:"run_id"`
		ExpiresAt string `json:"expires_at"`
	}
	call(ctx, t, session, mcp.ToolRegisterAgent, map[string]any{
		"agent_type":      demoAgentType,
		"task_id":         demoTaskRef,
		"idempotency_key": "ops-004-register",
	}, &registered)
	t.Logf("OPS-004 demo agent: registered %s (expires %s)",
		registered.SPIFFEID, registered.ExpiresAt)

	run := demoRun{
		runID:    registered.RunID,
		spiffeID: registered.SPIFFEID,
		taskRef:  demoTaskRef,
		trailers: map[string]string{},
	}

	// ---- get_credential ---------------------------------------------------
	var credential struct {
		JWTSVID   string `json:"jwt_svid"`
		ExpiresAt string `json:"expires_at"`
	}
	call(ctx, t, session, mcp.ToolGetCredential, map[string]any{
		"run_id":   run.runID,
		"audience": signing.AudienceSigstore,
	}, &credential)
	if strings.Count(credential.JWTSVID, ".") != 2 {
		t.Fatalf("get_credential returned %q, which is not a JWT", credential.JWTSVID)
	}
	t.Logf("OPS-004 demo agent: holds a JWT-SVID for audience %q until %s",
		signing.AudienceSigstore, credential.ExpiresAt)

	// ---- the scratch repository -------------------------------------------
	//
	// Staged on the host, signed in the MCP's container: one directory, shared,
	// because `repo` is an identifier and the working tree it resolves to is
	// the deployment's, not the caller's.
	run.worktree = filepath.Join(s.workspace, filepath.FromSlash(demoRepo))
	if mkErr := os.MkdirAll(run.worktree, 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	s.git(t, run.worktree, "init", "-q", "-b", "main")
	if wErr := os.WriteFile(filepath.Join(run.worktree, "work.txt"),
		[]byte("innsegl OPS-004: the first thing an adopter's agent ever wrote\n"), 0o600); wErr != nil {
		t.Fatal(wErr)
	}
	s.git(t, run.worktree, "add", "work.txt")
	staged := s.git(t, run.worktree, "write-tree")

	// ---- sign_commit ------------------------------------------------------
	var signed struct {
		CommitSHA  string `json:"commit_sha"`
		RekorEntry struct {
			UUID     string `json:"uuid"`
			LogIndex int64  `json:"log_index"`
		} `json:"rekor_entry"`
		Trailers []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"trailers"`
	}
	call(ctx, t, session, mcp.ToolSignCommit, map[string]any{
		"run_id":          run.runID,
		"repo":            demoRepo,
		"staged_ref":      staged,
		"message":         "feat(demo): the first commit an adopter's agent signs",
		"task_ref":        demoTaskRef,
		"idempotency_key": "ops-004-sign",
	}, &signed)
	run.commitSHA = signed.CommitSHA
	run.rekorUUID = signed.RekorEntry.UUID
	run.rekorLogIndex = signed.RekorEntry.LogIndex
	for _, tr := range signed.Trailers {
		run.trailers[tr.Key] = tr.Value
	}
	t.Logf("OPS-004 demo agent: signed commit %s, rekor entry %s at log index %d",
		run.commitSHA, run.rekorUUID, run.rekorLogIndex)

	if head := s.git(t, run.worktree, "rev-parse", "HEAD"); head != run.commitSHA {
		t.Errorf("sign_commit returned %s and the repository's HEAD is %s", run.commitSHA, head)
	}

	// ---- retire_agent -----------------------------------------------------
	var retired struct {
		RetiredAt string `json:"retired_at"`
	}
	call(ctx, t, session, mcp.ToolRetireAgent, map[string]any{"run_id": run.runID}, &retired)
	t.Logf("OPS-004 demo agent: retired %s at %s", run.runID, retired.RetiredAt)

	// IP §6.2: retirement is effective immediately, and the MCP is where that
	// is true — SPIRE's own convergence is eventual. A demo that retired an
	// identity and could still spend it would be demonstrating the opposite of
	// the claim.
	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name:      string(mcp.ToolGetCredential),
		Arguments: map[string]any{"run_id": run.runID, "audience": signing.AudienceSigstore},
	})
	if err != nil {
		t.Fatalf("tools/call get_credential after retirement: transport failure %v", err)
	}
	if !res.IsError {
		t.Errorf("get_credential succeeded after retire_agent. IP §6.2 makes retirement "+
			"effective immediately at the MCP, with no cached-credential grace path; "+
			"run %s is retired and must be refused", run.runID)
	}

	return run
}

// call invokes one tool, insists it succeeded, and decodes its structured
// answer into out.
func call(ctx context.Context, t *testing.T, session *sdk.ClientSession,
	tool mcp.ToolName, args map[string]any, out any,
) {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	res, err := session.CallTool(callCtx, &sdk.CallToolParams{
		Name: string(tool), Arguments: args,
	})
	if err != nil {
		t.Fatalf("tools/call %s: transport failure %v", tool, err)
	}
	if res.IsError {
		t.Fatalf("%s failed on the happy path: %v\n\nOPS-004 is the adopter's first "+
			"five minutes; a tool that refuses here is the release gate doing its job.",
			tool, res.StructuredContent)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: re-encoding structuredContent: %v", tool, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: decoding %s: %v", tool, raw, err)
	}
}

// git runs git on the host, in the working tree the MCP shares.
func (s *stack) git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(repo, "no-such-gitconfig"),
		"GIT_CEILING_DIRECTORIES=/tmp")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// SIG-001's ledger half.
// ---------------------------------------------------------------------------

// ledgerEventsForRun reads the chain the MCP wrote, in chain order.
//
// The route it needs is built for the length of this call and removed again;
// see openLedgerThroughARelay for why it cannot simply exist. Every byte read
// here goes through the shipped `internal/ledger`, so what is asserted about
// the chain is asserted against the reader a deployment uses.
func (s *stack) ledgerEventsForRun(t *testing.T, runID string) []event.Fields {
	t.Helper()
	store, closeStore := s.openLedgerThroughARelay(t)
	defer closeStore()
	events, err := store.EventsForRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("reading run %s from the ledger: %v", runID, err)
	}
	if len(events) == 0 {
		t.Fatalf("the ledger holds no events at all for run %s. I3 admits no action "+
			"without a record, and the demo agent acted five times", runID)
	}
	return events
}

// ---------------------------------------------------------------------------
// VER-001's independence property, on first contact.
// ---------------------------------------------------------------------------

// proveLedgerReachableFromItsOwnNetwork is the control half.
//
// Without it, "the verifier could not reach the database" would be satisfied
// by a database that is not running — and OPS-004 would be certifying an
// absence rather than a segmentation.
func (s *stack) proveLedgerReachableFromItsOwnNetwork(t *testing.T) {
	t.Helper()
	if _, err := docker(t.Context(), "run", "--rm", "--network", ledgerNetwork,
		"--entrypoint", "sh", runnerImage,
		"-c", "nc -z -w 5 "+s.ledgerIP+" 5432"); err != nil {
		t.Fatalf("the control probe could not reach the ledger on its own network, so "+
			"the negative probe below would prove nothing: %v", err)
	}
	t.Logf("OPS-004 control: the ledger at %s:5432 IS reachable from %s",
		s.ledgerIP, ledgerNetwork)
}

// verifyWithTheLedgerDetached runs the shipped verifier in a container joined
// to the Sigstore stack's published network and to nothing else.
//
// One container, one invocation: prove there is no route — by address and by
// name — and then verify. Not "the verifier did not connect": there is no
// route to connect over, and the proof of that is in the same transcript, from
// the same container, seconds earlier.
//
// A ledger DSN is deliberately in the environment. If the verifier had any
// database code path at all, this is the one it would use.
func (s *stack) verifyWithTheLedgerDetached(t *testing.T, commitSHA string) string {
	t.Helper()
	script := fmt.Sprintf(`set -e
if nc -z -w 5 %[1]s 5432 2>/dev/null; then echo "FAIL: the ledger is reachable by address"; exit 90; fi
echo "ledger %[1]s:5432 -- %[3]s"
if nc -z -w 5 %[2]s 5432 2>/dev/null; then echo "FAIL: the ledger is reachable by name"; exit 91; fi
echo "ledger %[2]s:5432 -- %[4]s"
exec /innsegl/innsegl verify %[5]s --repo /repo --fulcio-url %[6]s --rekor-url %[7]s
`, s.ledgerIP, ledgerContainer, noRouteByAddress, noRouteByName, commitSHA,
		fulcioInternalURL, rekorInternalURL)

	worktree := filepath.Join(s.workspace, filepath.FromSlash(demoRepo))
	cmd := exec.CommandContext(t.Context(), "docker", "run", "--rm",
		"--network", publishedNetwork,
		"--volume", worktree+":/repo:ro",
		"--volume", s.binDir+":/innsegl:ro",
		"--env", "GIT_CONFIG_COUNT=1",
		"--env", "GIT_CONFIG_KEY_0=safe.directory",
		"--env", "GIT_CONFIG_VALUE_0=*",
		"--env", "INNSEGL_LEDGER_DSN=postgres://"+ledgerUser+":"+ledgerPassword+
			"@"+s.ledgerIP+":5432/"+ledgerDatabase,
		"--entrypoint", "sh", runnerImage, "-c", script)
	out, err := cmd.CombinedOutput()
	t.Logf("OPS-004, `innsegl verify` inside a container with no route to the ledger:\n%s", out)
	if err != nil {
		t.Fatalf("`innsegl verify` failed with the ledger unreachable: %v", err)
	}
	return string(out)
}
