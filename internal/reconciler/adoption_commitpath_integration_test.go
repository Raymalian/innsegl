// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/dockertest"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/verify"
)

// ADP-015, re-homed onto the commit path — ADR-0079, on a real stack.
//
// The drill ADP-015 runs through sign_commit, run the way agents commit now:
// a run writes a file through Write and edits it through Edit, as the gateway
// records them, and is left with the work uncommitted. A live run's
// `git commit` asks for its trailers and is told the commit adopts the dead
// run; the commit-sign path proves it, signs it through gitsign with a real
// Rekor entry, and the shipped verifier confirms the adoption from the
// ledger. No running deployment is touched.
func TestADP015OnTheCommitPathAnAdoptionEndToEndOnARealStack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if err := dockertest.Usable(ctx); err != nil {
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
		Adoption: mcp.LedgerAdoption{Runs: w.runs, Events: store, Candidates: store, Bodies: bodies},
		Runs:     w.runs, Ledger: store, Idempotency: w.idem, Workspace: workspace,
		Sigstore: w.sigOK, Credentials: mcp.SignCommitThroughGetCredential{}, Signers: w.signers,
		AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Pseudonyms: literalIdentity(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restore)
	restoreClaim, err := mcp.ConfigureCommitClaim(mcp.CommitClaimConfig{Runs: w.runs, Pseudonyms: literalIdentity(t)})
	if err != nil {
		t.Fatalf("ConfigureCommitClaim: %v", err)
	}
	t.Cleanup(restoreClaim)
	resolver := &adpResolver{calls: map[string]commitpath.RelayedCall{}}
	restoreSP, err := mcp.ConfigureSignPayload(mcp.SignPayloadConfig{Resolver: resolver, ClaimFor: mcp.CommitClaimForRun})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	t.Cleanup(restoreSP)

	// THE DEAD RUN wrote work.txt and then edited it, both recorded the way
	// the gateway records them: input and an observed result, never the file.
	dead := w.run(ctx, t, "run-adpcp-dead")
	path := filepath.Join(dead.worktree, "work.txt")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	final := strings.Replace(string(original), "RM-035", "ADR-0079", 1)
	if werr := os.WriteFile(path, []byte(final), 0o600); werr != nil {
		t.Fatal(werr)
	}
	git(t, dead.worktree, "add", "work.txt")
	tree := git(t, dead.worktree, "write-tree")
	gwBody := func(n int, tool string, input map[string]any) {
		in, merr := json.Marshal(input)
		if merr != nil {
			t.Fatal(merr)
		}
		body, merr := json.Marshal(map[string]any{"tool": tool, "tool_use_id": fmt.Sprintf("toolu_01adpcp%020d", n),
			"input": json.RawMessage(in), "result_observed": true, "result": "ok"})
		if merr != nil {
			t.Fatal(merr)
		}
		digest := event.Digest(body)
		if merr = os.MkdirAll(filepath.Join(bodies, dead.runID), 0o700); merr != nil {
			t.Fatal(merr)
		}
		if merr = os.WriteFile(filepath.Join(bodies, dead.runID,
			strings.TrimPrefix(digest, event.HashPrefix)+".json"), body, 0o600); merr != nil {
			t.Fatal(merr)
		}
		if _, aerr := store.Append(ctx, event.Fields{
			event.FieldSchemaVersion: event.SchemaVersion, event.FieldEventType: event.EventTypeToolCall,
			event.FieldSource: event.SourceMCP, event.FieldRunID: dead.runID, event.FieldSpiffeID: dead.spiffeID,
			event.FieldIdempotencyKey: fmt.Sprintf("tool-%s-%d", dead.runID, n), event.FieldToolName: tool,
			event.FieldPayloadDigest: digest,
		}); aerr != nil {
			t.Fatalf("append the dead run's %s: %v", tool, aerr)
		}
	}
	gwBody(1, "Write", map[string]any{"file_path": path, "content": string(original)})
	gwBody(2, "Edit", map[string]any{"file_path": path, "old_string": "RM-035", "new_string": "ADR-0079"})

	// THE LIVE RUN is registered for the same repository and commits there.
	live := "run-adpcp-live"
	w.register(ctx, t, live, dead.repo)
	n := 0
	relay := func() (string, commitpath.RelayedCall) {
		n++
		id := fmt.Sprintf("toolu_01adpcplive%016d", n)
		call := commitpath.RelayedCall{RunID: live, Tool: "Bash",
			Input: json.RawMessage(`{"command":"git commit -m x"}`), ObservedAt: time.Now()}
		resolver.calls[id] = call
		return id, call
	}
	sign := func(adopted string) (string, error) {
		t.Helper()
		id, _ := relay()
		claim, cerr := mcp.CommitClaimForRun(ctx, live)
		if cerr != nil {
			t.Fatalf("CommitClaimForRun: %v", cerr)
		}
		claim.AdoptedRun = adopted
		message, perr := signing.PlaceTrailers(claim, "feat: commit the work a dead run left\n")
		if perr != nil {
			t.Fatalf("PlaceTrailers: %v", perr)
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload := []byte(fmt.Sprintf("tree %s\nauthor %s <%s> %s +0000\ncommitter %s <%s> %s +0000\n\n%s",
			tree, testAuthorName, testAuthorEmail, ts, testAuthorName, testAuthorEmail, ts, message))
		resp, serr := mcp.SignPayloadForGateway(ctx, commitpath.SignRequest{ToolUseID: id,
			Args: []string{"--status-fd=2", "-bsau", testAuthorName + " <" + testAuthorEmail + ">"}, Payload: payload})
		if serr != nil {
			return "", serr
		}
		return adpWriteSigned(t, dead.worktree, payload, resp.Signature), nil
	}
	propose := func() string {
		t.Helper()
		_, call := relay()
		got, perr := mcp.AdoptionForCommit(ctx, call, tree, nil)
		if perr != nil {
			t.Fatalf("AdoptionForCommit: %v", perr)
		}
		return got
	}

	// 1. While the dead run is still active, nothing is proposed, and a
	// payload naming it anyway is refused.
	if got := propose(); got != "" {
		t.Fatalf("a run the ledger calls active was proposed: %q", got)
	}
	if _, serr := sign(dead.runID); serr == nil || !strings.Contains(serr.Error(), "active") {
		t.Fatalf("signing an adoption of an active run = %v, want a refusal naming it active", serr)
	}

	// 2. Retired, it is proposed, proved, signed and recorded.
	if _, rerr := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion, event.FieldEventType: event.EventTypeRunRetired,
		event.FieldSource: event.SourceMCP, event.FieldRunID: dead.runID, event.FieldSpiffeID: dead.spiffeID,
	}); rerr != nil {
		t.Fatalf("retire the dead run: %v", rerr)
	}
	if got := propose(); got != dead.runID {
		t.Fatalf("proposed %q, want the dead run %s", got, dead.runID)
	}
	commit, err := sign(dead.runID)
	if err != nil {
		t.Fatalf("signing the adoption: %v", err)
	}
	msg := git(t, dead.worktree, "log", "-1", "--format=%B", commit)
	if !strings.Contains(msg, "Agent-Run: "+live) || !strings.Contains(msg, "Agent-Adopted-Run: "+dead.runID) {
		t.Errorf("the commit does not name both runs:\n%s", msg)
	}
	adopted := eventsOfType(ctx, t, store, live, event.EventTypeRunAdopted)
	if len(adopted) != 1 || str(adopted[0], event.FieldAdoptedRunID) != dead.runID ||
		str(adopted[0], event.FieldAdoptedRunState) != "retired" {
		t.Fatalf("run_adopted = %v", adopted)
	}
	intents := eventsOfType(ctx, t, store, live, event.EventTypeCommitIntent)
	if len(intents) != 1 || str(intents[0], event.FieldAdoptionEventID) != str(adopted[0], event.FieldEventID) {
		t.Errorf("the adopting intent does not name the adoption: %v", intents)
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
	t.Logf("ADP-015 on the commit path, the adopted commit verified:\n%s", verify.Render(rep))
	if rep.Verdict != verify.VerdictVerified {
		t.Errorf("verdict = %s, want %s", rep.Verdict, verify.VerdictVerified)
	}
	if rep.Content == nil || rep.Content.Result != verify.Verified || rep.Content.AdoptedRun != dead.runID {
		t.Errorf("content check = %+v, want verified and naming %s", rep.Content, dead.runID)
	}

	// 4. Spent: the same change is not proposed again, and naming it anyway
	// is refused.
	if got := propose(); got != "" {
		t.Errorf("committed work was proposed again: %q", got)
	}
	if _, serr := sign(dead.runID); serr == nil || !strings.Contains(serr.Error(), "spent") {
		t.Errorf("re-adopting committed bytes = %v, want a refusal saying the adoption is spent", serr)
	}
}

type adpResolver struct{ calls map[string]commitpath.RelayedCall }

func (r *adpResolver) LookupPending(id string) (commitpath.RelayedCall, bool) {
	c, ok := r.calls[id]
	return c, ok
}

// adpWriteSigned writes the signed commit git would have written from payload
// and signature, and returns its id.
func adpWriteSigned(t *testing.T, worktree string, payload, signature []byte) string {
	t.Helper()
	header, message, ok := strings.Cut(string(payload), "\n\n")
	if !ok {
		t.Fatal("payload carries no header/message separator")
	}
	lines := strings.Split(strings.TrimRight(string(signature), "\n"), "\n")
	var b strings.Builder
	b.WriteString(header + "\ngpgsig " + lines[0] + "\n")
	for _, line := range lines[1:] {
		b.WriteString(" " + line + "\n")
	}
	b.WriteString("\n" + message)
	cmd := exec.CommandContext(t.Context(), "git", "-C", worktree, "hash-object", "-w", "-t", "commit", "--stdin")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	return strings.TrimSpace(string(out))
}
