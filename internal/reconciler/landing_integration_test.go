// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/signing"
)

// RM-243 (#388), test CMT-015 (I): N byte-identical `git commit`s at once in
// one repository, one landing — against a real Postgres, a real self-hosted
// Fulcio and Rekor, a real SPIRE and the released gitsign binary. IP §2: "a
// mocked Fulcio proves nothing about I5", and this file's whole claim is
// about what a REAL Rekor entry does and does not make the drift cross-check
// say.
//
// # What is driven, and how it differs from CMT-012's own concurrency proof
//
// internal/mcp's TestCMT010AndCMT012AgainstRealSigstoreAndARealChain already
// proves N concurrent, byte-identical `git commit` invocations each
// attribute to their own run even though at most one becomes reachable from
// a branch — that is CMT-012, and it is reused here rather than
// reimplemented: signing.Signer.SignPayload is the identical Phase B
// internal/mcp's commit-sign path calls, and it is driven here the same way,
// concurrently, under N distinct SPIFFE IDs minted through the real SPIRE
// admin socket.
//
// What CMT-012 does not reach is what happens to the LOSERS once landing is
// asked about them, because it never lets git decide who wins the branch at
// all — writeSignedPayload there only ever calls `git hash-object -w`, which
// touches no ref. This file completes that picture: after every one of the N
// signatures exists (real Fulcio certificates, real Rekor entries, all N
// commit objects written), the SAME atomic compare-and-swap `git commit`
// itself performs — `git update-ref <branch> <new> <old>` — is asked, once
// per racer, in a controlled order rather than a true OS race. That keeps
// this case deterministic without faking anything: `update-ref`'s own check
// IS git's ref lock, and the FIRST call for a given `<old>` wins for the
// identical reason a genuinely concurrent `git commit` would — the second
// caller's `<old>` no longer names the branch's current value, and git
// answers with its own words ("cannot lock ref ... is at ... but expected
// ..."), captured here rather than assumed.
//
// # What is asserted
//
//   - No drift alert for any of the N — REC-004's cross-check has no
//     reachability check to trip (task 1's proof, this time end to end).
//   - Each loser reported LandingNotLanded, corroborated by a real ref-lock
//     failure text this test captured from git itself.
//   - The winner reported LandingLanded.
//   - Attribution: each commit_recorded's own run_id is exactly the run that
//     signed it, with no cross-attribution among the N.
//   - Nothing beyond what this test itself appended is on the chain: landing
//     appends nothing (ADR-0059 decision 6).

const (
	landingCMTRunCount = 3

	landingCMTAgentType = "demo"
	landingCMTTaskID    = "rm-243"
	landingCMTTaskRef   = "RM-243"
	landingCMTRepo      = "github.com/innsegl/cmt015"

	// I6's author policy for a scratch repository: a domain RFC 6761
	// reserves, so no real account can ever hold it (ADR-0028), matching
	// driftintegration_test.go's own driftAuthorName/Email.
	landingCMTAuthorName  = "innsegl cmt015 test"
	landingCMTAuthorEmail = "agent@innsegl.invalid"
)

func landingCMTSPIFFEID(runID string) string {
	return fmt.Sprintf("spiffe://%s/agent/%s/%s/%s",
		harnessTrustDomain, landingCMTAgentType, landingCMTTaskID, runID)
}

// landingCMTBuildPayload is the unsigned commit object git's own commit
// machinery would build and hand its `gpg.x509.program` — the identical
// shape internal/mcp's TestCMT010AndCMT012's own buildPayload constructs,
// restated here because that closure lives in a different package.
func landingCMTBuildPayload(t *testing.T, claim signing.Claim, tree, parent, message string) []byte {
	t.Helper()
	trailers, err := claim.Trailers()
	if err != nil {
		t.Fatalf("claim.Trailers: %v", err)
	}
	var b strings.Builder
	b.WriteString(message)
	b.WriteString("\n\n")
	for _, tr := range trailers {
		b.WriteString(tr.String())
		b.WriteString("\n")
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return []byte(fmt.Sprintf(
		"tree %s\nparent %s\nauthor %s <%s> %s +0000\ncommitter %s <%s> %s +0000\n\n%s",
		tree, parent, landingCMTAuthorName, landingCMTAuthorEmail, ts,
		landingCMTAuthorName, landingCMTAuthorEmail, ts, b.String()))
}

// landingCMTWriteSignedObject reconstructs the signed commit object exactly
// as signing.SignPayload's own commitSHAOf computes its id, and hands it to
// git's own `hash-object -w` for an independent second opinion — the same
// construction internal/mcp's writeSignedPayload uses, restated here for the
// same reason as landingCMTBuildPayload above. It touches no ref: git writes
// the object into the database and nothing more, exactly as ADR-0059
// decision 4 describes the core's own side of Phase C.
func landingCMTWriteSignedObject(t *testing.T, worktree string, payload, signature []byte) string {
	t.Helper()
	idx := strings.Index(string(payload), "\n\n")
	if idx < 0 {
		t.Fatalf("payload carries no header/message separator")
	}
	header, message := payload[:idx], payload[idx+2:]
	sig := strings.TrimRight(string(signature), "\n")
	lines := strings.Split(sig, "\n")

	var body strings.Builder
	body.Write(header)
	body.WriteString("\ngpgsig " + lines[0] + "\n")
	for _, line := range lines[1:] {
		body.WriteString(" " + line + "\n")
	}
	body.WriteString("\n")
	body.Write(message)

	cmd := exec.CommandContext(t.Context(), "git", "-C", worktree,
		"hash-object", "-w", "-t", "commit", "--stdin")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(worktree, "no-global-gitconfig"))
	cmd.Stdin = strings.NewReader(body.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object -w -t commit: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// landingCMTUpdateRef is git's own atomic compare-and-swap, run directly
// rather than through `git commit`: `git update-ref <ref> <new> <old>`
// refuses unless `<ref>` currently holds exactly `<old>`, and on refusal
// prints git's own words for the loser of a ref race. This is the SAME
// primitive `git commit` uses internally once it has a signature in hand
// (ADR-0059 decision 6) — asked here directly so N racers' resolution is
// deterministic without faking git's own error text.
func landingCMTUpdateRef(t *testing.T, worktree, newValue, oldValue string) (ok bool, output string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", worktree,
		"update-ref", "refs/heads/main", newValue, oldValue)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// landingCMTToolCallBody mirrors landing.go's own landingToolCallBody.
type landingCMTToolCallBody struct {
	Tool    string          `json:"tool"`
	Input   json.RawMessage `json:"input"`
	Result  json.RawMessage `json:"result"`
	IsError bool            `json:"is_error"`
}

// landingCMTSeedToolCall appends a tool_call to store and writes its
// retained body under bodyDir, in the layout landing.go's readRunBody
// (writes.go) expects — real events on the real chain, a real file on disk.
func landingCMTSeedToolCall(
	ctx context.Context, t *testing.T, store *ledger.Store, bodyDir, runID string, body landingCMTToolCallBody,
) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	runDir := filepath.Join(bodyDir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, hex.EncodeToString(sum[:])+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       landingCMTSPIFFEID(runID),
		event.FieldIdempotencyKey: "cmt015/toolcall/" + runID,
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	}); err != nil {
		t.Fatalf("append tool_call for %s: %v", runID, err)
	}
}

func TestCMT015NConcurrentIdenticalCommitsOneLands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), driftIntegrationTimeout)
	defer cancel()

	if err := dockertest.Usable(ctx); err != nil {
		requireStartup(t, err, "CMT-015 is the claim that a lost ref race is landing's own "+
			"derived report and never REC-004's drift alert -- against a mocked Rekor this "+
			"proves nothing about I5 (IP §2).")
	}
	store, _ := freshStore(t)

	st, stackErr := startStack(ctx, repoRoot(t))
	if st != nil {
		t.Cleanup(st.stop)
	}
	if stackErr != nil {
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", stackErr),
			fmt.Sprintf("CMT-015 goes unproven against a real log. Start Docker, "+
				"`go install github.com/sigstore/gitsign@%s`, and re-run.", harnessGitsign))
	}

	root := t.TempDir()
	worktree := filepath.Join(root, filepath.FromSlash(landingCMTRepo))
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	bodyDir := t.TempDir()

	git(t, worktree, "init", "-q", "-b", "main")

	// The initial state every racer commits AGAINST — one parent, shared by
	// all N, so a later racer's `<old>` in landingCMTUpdateRef is exactly the
	// value the FIRST racer to land moves the branch away from.
	if err := os.WriteFile(filepath.Join(worktree, "base.txt"), []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", "base.txt")
	baseTree := git(t, worktree, "write-tree")
	parent := git(t, worktree, "commit-tree", baseTree, "-m", "seed")
	git(t, worktree, "update-ref", "refs/heads/main", parent)

	// The ONE staged change every racer proposes — byte-identical content,
	// ADR-0059's own premise ("N parallel, byte-identical git commit
	// invocations").
	if err := os.WriteFile(filepath.Join(worktree, "shared.txt"),
		[]byte("innsegl CMT-015 shared change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", "shared.txt")
	tree := git(t, worktree, "write-tree")

	const commitMessage = "fix: the shared change every run proposes"
	args := []string{"--status-fd=2", "-bsau", landingCMTAuthorName + " <" + landingCMTAuthorEmail + ">"}

	type racer struct {
		runID     string
		spiffeID  string
		commitSHA string
		rekorUUID string
		logIndex  int64
	}
	runs := make([]racer, landingCMTRunCount)
	for i := range runs {
		runs[i] = racer{
			runID:    fmt.Sprintf("run-cmt015-%02d", i),
			spiffeID: landingCMTSPIFFEID(fmt.Sprintf("run-cmt015-%02d", i)),
		}
	}

	// ---- Phase B, concurrently: N real signatures under N real identities ----
	type signOutcome struct {
		commitSHA string
		rekorUUID string
		logIndex  int64
		err       error
	}
	outcomes := make([]signOutcome, landingCMTRunCount)
	{
		var wg sync.WaitGroup
		for i := range runs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				spiffeID := runs[i].spiffeID
				signer, serr := signing.NewSigner(signing.Config{
					FulcioURL:   st.fulcioURL,
					RekorURL:    st.rekorURL,
					Issuer:      harnessIssuer,
					GitsignPath: st.gitsignPath,
					Author:      signing.AuthorPolicy{AllowUnlinked: true},
				}, svidMinter{stack: st, spiffeID: spiffeID, ttl: 5 * time.Minute})
				if serr != nil {
					outcomes[i] = signOutcome{err: fmt.Errorf("NewSigner: %w", serr)}
					return
				}
				defer func() { _ = signer.Close() }()

				claim := signing.Claim{Identity: spiffeID, Run: runs[i].runID, Task: landingCMTTaskRef}
				payload := landingCMTBuildPayload(t, claim, tree, parent, commitMessage)
				result, perr := signer.SignPayload(ctx, signing.PayloadRequest{
					Args: args, Payload: payload, Claim: claim,
				})
				if perr != nil {
					outcomes[i] = signOutcome{err: fmt.Errorf("SignPayload: %w", perr)}
					return
				}
				sha := landingCMTWriteSignedObject(t, worktree, payload, result.Signature)
				outcomes[i] = signOutcome{commitSHA: sha, rekorUUID: result.Rekor.UUID, logIndex: result.Rekor.LogIndex}
			}(i)
		}
		wg.Wait()
	}
	for i, o := range outcomes {
		if o.err != nil {
			t.Fatalf("run %s: %v", runs[i].runID, o.err)
		}
		runs[i].commitSHA, runs[i].rekorUUID, runs[i].logIndex = o.commitSHA, o.rekorUUID, o.logIndex
	}

	// Distinct commit SHAs: N real, independent signatures over the same
	// content sign to N different objects (a fresh Fulcio certificate and a
	// fresh Rekor entry each time), which is CMT-012's own finding restated
	// as a precondition for what follows.
	seenSHA := map[string]string{}
	for _, r := range runs {
		if other, dup := seenSHA[r.commitSHA]; dup {
			t.Fatalf("commit %s was produced by both %s and %s", r.commitSHA, other, r.runID)
		}
		seenSHA[r.commitSHA] = r.runID
	}

	// ---- Phase C, on the real chain: an intent and a recorded signature for
	//      every one of the N, exactly as the core appends them regardless of
	//      whether git will later manage to move the branch (ADR-0059
	//      decision 6) ----------------------------------------------------------
	for _, r := range runs {
		if _, err := store.Append(ctx, event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeRunRegistered,
			event.FieldSource:         event.SourceMCP,
			event.FieldRunID:          r.runID,
			event.FieldSpiffeID:       r.spiffeID,
			event.FieldIdempotencyKey: "cmt015/register/" + r.runID,
			event.FieldAgentType:      landingCMTAgentType,
			event.FieldTaskRef:        landingCMTTaskRef,
			event.FieldRepo:           landingCMTRepo,
			event.FieldBranch:         "main",
		}); err != nil {
			t.Fatalf("append run_registered for %s: %v", r.runID, err)
		}
		intent, err := store.Append(ctx, event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeCommitIntent,
			event.FieldSource:         event.SourceMCP,
			event.FieldRunID:          r.runID,
			event.FieldSpiffeID:       r.spiffeID,
			event.FieldIdempotencyKey: "cmt015/intent/" + r.runID,
			event.FieldRepo:           landingCMTRepo,
			event.FieldTreeHash:       tree,
			event.FieldPatchID:        "ffffffffffffffffffffffffffffffffffffffff",
		})
		if err != nil {
			t.Fatalf("append commit_intent for %s: %v", r.runID, err)
		}
		if _, err := store.Append(ctx, event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeCommitRecorded,
			event.FieldSource:         event.SourceMCP,
			event.FieldRunID:          r.runID,
			event.FieldSpiffeID:       r.spiffeID,
			event.FieldIdempotencyKey: "cmt015/recorded/" + r.runID,
			event.FieldRepo:           landingCMTRepo,
			event.FieldTreeHash:       tree,
			event.FieldPatchID:        "ffffffffffffffffffffffffffffffffffffffff",
			event.FieldCommitSHA:      r.commitSHA,
			event.FieldRekorEntryUUID: r.rekorUUID,
			event.FieldRekorLogIndex:  r.logIndex,
			event.FieldIntentEventID:  str(intent, event.FieldEventID),
		}); err != nil {
			t.Fatalf("append commit_recorded for %s: %v", r.runID, err)
		}
	}

	// ---- git decides who lands: the atomic CAS every `git commit` performs,
	//      run directly, deterministically, once per racer -----------------
	winner := runs[0]
	if ok, out := landingCMTUpdateRef(t, worktree, winner.commitSHA, parent); !ok {
		t.Fatalf("the first racer failed to land: %s", out)
	}
	for _, r := range runs[1:] {
		ok, out := landingCMTUpdateRef(t, worktree, r.commitSHA, parent)
		if ok {
			t.Fatalf("run %s: update-ref against a stale <old> unexpectedly succeeded", r.runID)
		}
		lower := strings.ToLower(out)
		if !strings.Contains(lower, "cannot lock ref") && !strings.Contains(lower, "but expected") {
			t.Fatalf("run %s: update-ref failed for an unexpected reason: %s", r.runID, out)
		}
		t.Logf("run %s lost the ref race, exactly as ADR-0059 decision 6 describes: %s",
			r.runID, strings.TrimSpace(out))
		resultJSON, jerr := json.Marshal(strings.TrimSpace(out))
		if jerr != nil {
			t.Fatalf("json.Marshal git's own output: %v", jerr)
		}
		landingCMTSeedToolCall(ctx, t, store, bodyDir, r.runID, landingCMTToolCallBody{
			Tool:    "Bash",
			Input:   json.RawMessage(`{"command":"git commit -m x"}`),
			Result:  resultJSON,
			IsError: true,
		})
	}
	if got := git(t, worktree, "rev-parse", "refs/heads/main"); got != winner.commitSHA {
		t.Fatalf("refs/heads/main = %s, want the winner %s (%s)", got, winner.commitSHA, winner.runID)
	}

	// ---- the reconciler, reading the real chain, the real repository and the
	//      real log -----------------------------------------------------------
	log, err := reconciler.NewRekorLog(st.rekorURL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	repos, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	var driftAlerts []reconciler.DriftFinding
	r, err := reconciler.New(reconciler.Config{
		Ledger: store, Appender: store, Repos: repos, Log: log,
		TrustDomain: harnessTrustDomain, ExpireAfter: 24 * time.Hour,
		Alert:   func(context.Context, reconciler.Finding) {},
		Observe: func(reconciler.Result, error) {},
		Drift: &reconciler.DriftConfig{
			Sweep: log,
			Alert: func(_ context.Context, d reconciler.DriftFinding) {
				driftAlerts = append(driftAlerts, d)
				t.Logf("drift alert: %s: %s", d.Kind, d.Detail)
			},
		},
		Landing: &reconciler.LandingConfig{LogDir: bodyDir},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}

	countBefore, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	result, err := r.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// ---- task 1, end to end: no drift alert for anyone, winner or loser -----
	if !result.Drift.Enabled {
		t.Fatal("drift detection reported itself disabled")
	}
	if result.Drift.Unattributed != 0 || result.Drift.Fabricated != 0 || result.Drift.Unresolved != 0 {
		t.Fatalf("a lost ref race raised drift: %+v (alerts: %+v)", result.Drift, driftAlerts)
	}
	if len(driftAlerts) != 0 {
		t.Fatalf("the operator sink saw %d drift alerts for N signed, mostly-unlanded commits: %+v",
			len(driftAlerts), driftAlerts)
	}

	// ---- the derived landing report: one landed, N-1 signed-not-landed,
	//      each corroborated by the real ref-lock text captured above -------
	if !result.Landing.Enabled {
		t.Fatal("Landing reported itself disabled")
	}
	if result.Landing.Checked != landingCMTRunCount {
		t.Fatalf("Landing.Checked = %d, want %d", result.Landing.Checked, landingCMTRunCount)
	}
	if result.Landing.Landed != 1 {
		t.Fatalf("Landing.Landed = %d, want 1", result.Landing.Landed)
	}
	if result.Landing.NotLanded != landingCMTRunCount-1 {
		t.Fatalf("Landing.NotLanded = %d, want %d", result.Landing.NotLanded, landingCMTRunCount-1)
	}
	if result.Landing.NotChecked != 0 {
		t.Fatalf("Landing.NotChecked = %d, want 0 -- a readable repository leaves nothing "+
			"unchecked here", result.Landing.NotChecked)
	}

	// ---- attribution: each not-landed finding names exactly its OWN run,
	//      and no run is named twice -------------------------------------------
	wantLosers := map[string]bool{}
	for _, r := range runs[1:] {
		wantLosers[r.runID] = true
	}
	seenLosers := map[string]bool{}
	for _, f := range result.Landing.Findings {
		if f.Outcome != reconciler.LandingNotLanded {
			t.Fatalf("an unexpected outcome among the findings: %+v", f)
		}
		if !wantLosers[f.RunID] {
			t.Fatalf("finding names run %s, which did not lose the race: %+v", f.RunID, f)
		}
		if seenLosers[f.RunID] {
			t.Fatalf("run %s was named by more than one finding", f.RunID)
		}
		seenLosers[f.RunID] = true
		if f.Detail == "" {
			t.Fatalf("run %s: a not-landed finding with no detail an operator could read", f.RunID)
		}
		t.Logf("landing: %s -> %s: %s", f.RunID, f.Outcome, f.Detail)
	}
	if len(seenLosers) != len(wantLosers) {
		t.Fatalf("findings named %d of the %d losers", len(seenLosers), len(wantLosers))
	}

	// ---- ADR-0059 decision 6, measured rather than assumed: landing wrote
	//      NOTHING. Every event on the chain after this cycle is one THIS
	//      TEST appended, never the reconciler's landing pass. -----------------
	countAfter, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("the chain grew from %d to %d events during Reconcile; landing must append "+
			"nothing (ADR-0059 decision 6)", countBefore, countAfter)
	}
	if len(result.Appended) != 0 {
		t.Fatalf("Result.Appended = %v, want empty", result.Appended)
	}

	all, err := store.Events(ctx, 1, countAfter)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if _, verr := ledger.Verify(all); verr != nil {
		t.Fatalf("the chain does not verify: %v", verr)
	}
	t.Logf("CMT-015: %d runs, 1 landed (%s), %d signed-not-landed, 0 drift alerts, chain %d "+
		"events and verifies", landingCMTRunCount, winner.runID, landingCMTRunCount-1, countAfter)
}
