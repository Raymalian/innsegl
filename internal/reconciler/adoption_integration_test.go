// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/verify"
)

// ADP-015 — adoption end to end, on a real stack. ADR-0051, #298.
//
// Everything real that the unit cases stand in for: a SPIRE-minted credential,
// gitsign signing through Fulcio, a Rekor entry, a Postgres chain, the shipped
// sign_commit over MCP, and the shipped verifier checking the result against
// Fulcio, Rekor and the ledger. The stack is this process's own compose
// project; nothing reaches a running deployment.
//
// The drill is the incident ADR-0051 was written for: a run writes a file,
// dies with the file uncommitted, and a live run commits it.

// adpContent is the ledger as the verifier's ContentSource, the three lines
// internal/api holds for the same purpose.
type adpContent struct{ store *ledger.Store }

func (c adpContent) RunsForPatchID(ctx context.Context, patchID string) ([]verify.ContentRecord, error) {
	records, err := c.store.RunsForPatchID(ctx, patchID)
	if err != nil {
		return nil, err
	}
	out := make([]verify.ContentRecord, 0, len(records))
	for _, r := range records {
		out = append(out, verify.ContentRecord{RunID: r.RunID, PatchID: r.PatchID,
			CommitSHA: r.CommitSHA, EventID: r.EventID, AdoptedRun: r.AdoptedRun})
	}
	return out, nil
}

func TestADP015AnAdoptionEndToEndOnARealStack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		requireStartup(t, err, "ADP-015 proves adoption against a real signature and a real log; "+
			"a mocked Fulcio proves nothing about I5.")
	}
	store, dsn := freshStore(t)
	st, err := startStack(ctx, repoRoot(t))
	if st != nil {
		t.Cleanup(st.stop)
	}
	if err != nil {
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", err),
			"ADP-015 goes unproven against a real signature.")
	}
	w := newWorld(ctx, t, st, store, dsn)

	bodies := t.TempDir()
	workspace, err := mcp.NewWorkspace(w.root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	restore, err := mcp.ConfigureSignCommit(mcp.SignCommitConfig{
		Adoption:    mcp.LedgerAdoption{Runs: w.runs, Events: store, Bodies: bodies},
		Runs:        w.runs,
		Ledger:      store,
		Idempotency: w.idem,
		Workspace:   workspace,
		Sigstore:    w.sigOK,
		Credentials: mcp.SignCommitThroughGetCredential{},
		Signers:     w.signers,
		AuthorName:  testAuthorName,
		AuthorEmail: testAuthorEmail,
		Pseudonyms:  literalIdentity(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restore)

	// THE DEAD RUN: registered, it wrote work.txt through Write, and the body
	// is on the volume under the digest its tool_call carries.
	dead := w.run(ctx, t, "run-adp-dead")
	content, err := os.ReadFile(filepath.Join(dead.worktree, "work.txt"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"tool_name": "Write", "tool_input": map[string]any{
		"file_path": filepath.Join(dead.worktree, "work.txt"), "content": string(content)}})
	if err != nil {
		t.Fatal(err)
	}
	digest := event.Digest(body)
	if merr := os.MkdirAll(filepath.Join(bodies, dead.runID), 0o700); merr != nil {
		t.Fatal(merr)
	}
	if werr := os.WriteFile(filepath.Join(bodies, dead.runID,
		strings.TrimPrefix(digest, event.HashPrefix)+".json"), body, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, aerr := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion, event.FieldEventType: event.EventTypeToolCall,
		event.FieldSource: event.SourceMCP, event.FieldRunID: dead.runID, event.FieldSpiffeID: dead.spiffeID,
		event.FieldIdempotencyKey: "tool-" + dead.runID, event.FieldToolName: "Write",
		event.FieldPayloadDigest: digest,
	}); aerr != nil {
		t.Fatalf("append the dead run's tool_call: %v", aerr)
	}

	// THE LIVE RUN signs in the dead run's tree.
	live := w.run(ctx, t, "run-adp-live")
	adopting := dead
	adopting.runID, adopting.spiffeID, adopting.key = live.runID, live.spiffeID, "adopt-1"

	call := func(r testRun, adopt string) *sdk.CallToolResult {
		t.Helper()
		res, cerr := w.session.CallTool(ctx, &sdk.CallToolParams{
			Name: string(mcp.ToolSignCommit),
			Arguments: map[string]any{"run_id": r.runID, "repo": r.repo, "staged_ref": r.staged,
				"message": "feat: adopt the work a dead run left", "task_ref": r.taskRef,
				"idempotency_key": r.key, "adopt_run": adopt},
		})
		if cerr != nil {
			t.Fatalf("tools/call sign_commit: %v", cerr)
		}
		return res
	}

	// 1. While the dead run is still ACTIVE in the ledger, it is not dead.
	if res := call(adopting, dead.runID); !res.IsError ||
		!strings.Contains(fmt.Sprint(res.StructuredContent), "active") {
		t.Fatalf("adopting a run the ledger calls active = %v, want a refusal naming it active",
			res.StructuredContent)
	}

	// 2. Retired, it is adopted: a real signature, a real Rekor entry.
	if _, rerr := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion, event.FieldEventType: event.EventTypeRunRetired,
		// No idempotency key: run_retired takes none (ADR-0004).
		event.FieldSource: event.SourceMCP, event.FieldRunID: dead.runID, event.FieldSpiffeID: dead.spiffeID,
	}); rerr != nil {
		t.Fatalf("retire the dead run: %v", rerr)
	}
	adopting.key = "adopt-2"
	res := call(adopting, dead.runID)
	if res.IsError {
		t.Fatalf("adopting a retired run's proved work failed: %v", res.StructuredContent)
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("sign_commit returned %T", res.StructuredContent)
	}
	commit, _ := out["commit_sha"].(string) //nolint:errcheck // asserted non-empty below
	if commit == "" {
		t.Fatalf("no commit_sha: %v", out)
	}

	// The commit names both runs.
	msg := git(t, dead.worktree, "log", "-1", "--format=%B", commit)
	if !strings.Contains(msg, "Agent-Run: "+live.runID) || !strings.Contains(msg, "Agent-Adopted-Run: "+dead.runID) {
		t.Errorf("the commit does not name both runs:\n%s", msg)
	}

	// The chain holds the handover, before the intent that names it.
	adopted := eventsOfType(ctx, t, store, live.runID, event.EventTypeRunAdopted)
	if len(adopted) != 1 || str(adopted[0], event.FieldAdoptedRunID) != dead.runID ||
		str(adopted[0], event.FieldAdoptedRunState) != "retired" {
		t.Fatalf("run_adopted = %v", adopted)
	}
	intents := eventsOfType(ctx, t, store, live.runID, event.EventTypeCommitIntent)
	if len(intents) != 1 || str(intents[0], event.FieldAdoptionEventID) != str(adopted[0], event.FieldEventID) {
		t.Errorf("the intent does not name the adoption: %v", intents)
	}

	// 3. The shipped verifier, against the real Fulcio, Rekor and ledger.
	v, err := verify.New(verify.Config{FulcioURL: st.fulcioURL, RekorURL: st.rekorURL,
		Issuer: harnessIssuer, Content: adpContent{store: store}})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	rep, err := v.Verify(ctx, dead.worktree, commit)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("ADP-015, the adopted commit verified:\n%s", verify.Render(rep))
	if rep.Verdict != verify.VerdictVerified {
		t.Errorf("verdict = %s, want %s", rep.Verdict, verify.VerdictVerified)
	}
	if rep.Content == nil || rep.Content.Result != verify.Verified || rep.Content.AdoptedRun != dead.runID {
		t.Errorf("content check = %+v, want verified and naming %s", rep.Content, dead.runID)
	}

	// 4. Spent: the same bytes, staged again after the commit is undone, are
	// refused, because that adoption was committed.
	// The adopted commit is the repository's first, so undoing it is deleting
	// the branch ref; the index keeps the same staged bytes.
	git(t, dead.worktree, "update-ref", "-d", "HEAD")
	adopting.key = "adopt-3"
	if res := call(adopting, dead.runID); !res.IsError ||
		!strings.Contains(fmt.Sprint(res.StructuredContent), "spent") {
		t.Errorf("re-adopting committed bytes = %v, want a refusal saying the adoption is spent",
			res.StructuredContent)
	}
}
