// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/signing"
)

// RM-241/RM-243 (#386, #388), test CMT-011 (C): the core killed between
// Phase B and Phase C.
//
// # What this proves, and against what
//
// ADR-0059 decision 4 runs Phase B (gitsign, inside the core) and Phase C
// (append `commit_recorded`) in the SAME call, in that order. A core that
// signs and then cannot complete Phase C — a ledger that refuses the append
// is this file's own way of reaching that window, chosen because it is the
// one failure this process can inject deterministically rather than by
// racing an actual kill signal against two network calls — returns NOTHING
// to git: `gpg.x509.program` exits non-zero with no signature on stdout
// (ADR-0059 decision 7). Git's own documented behaviour for that case is to
// abort the commit before writing anything, and this test measures that
// rather than assuming it: before/after `git cat-file
// --batch-all-objects --batch-check`, filtered to commit objects, must be
// the identical set.
//
// What is left on the chain is a `commit_intent` with no `commit_recorded` —
// the A -> B window's own shape, ADR-0035's and REC-001's, even though what
// actually happened here is later in the protocol (B -> C). That is
// deliberate and not a gap in this test: decision 4's gate order means
// Phase A's append already happened before Phase B ever ran, so a Phase C
// failure leaves EXACTLY the same evidence on the chain as a Phase B
// failure would — an open intent — and the existing reconciler (RM-035,
// reconcile.go) does not need to learn a new shape to close it. This test
// drives that existing expiry rather than reimplementing it.
//
// # Why the signing is real and the ledger is not
//
// Real Sigstore is what makes "the core signs" a fact and not a claim (IP
// §2's rule): SignPayloadForGateway's default Phase B (signWithSigner) runs
// unmodified, against the harness's own Fulcio and Rekor, so this test does
// not get to assert anything about what a real signing attempt does by
// arranging for one never to happen. What the harness ALREADY has no way to
// make fail deterministically, on demand, without touching either
// signpayload.go or signpayload_test.go (this task's own boundary), is
// Phase C specifically — so the ledger is scLedger (sign_commit_test.go),
// configured with `failOn[event.EventTypeCommitRecorded]`, the same
// mechanism TestPhaseCRefusesWhenTheLedgerCannotAppendCommitRecorded
// already uses, run here for the first time against a REAL signature instead
// of a stubbed one.
//
// # Why a real git commit, and not a direct call to SignPayloadForGateway
//
// CMT-010 and CMT-012 (signpayload_test.go) call SignPayloadForGateway
// in-process and hand its answer to `git hash-object -w`, which proves the
// ledger and the signature agree but never asks git anything. This case's
// own claim is about GIT's behaviour — "git exits non-zero" and "git writes
// no commit object" — so nothing but a real `git commit`, with a real child
// process standing in for `gpg.x509.program` (ADR-0059 decision 3), can
// measure it. That child is internal/mcp/testdata/cmt011signclient: a
// minimal, test-only reimplementation of cmd/innsegl's own `innsegl sign`
// (package main there, unimportable here), calling the SAME
// commitpath.Client.Sign contract against an httptest server that wraps
// SignPayloadForGateway directly — nothing about ADR-0059 decision 3's
// wire contract is faked.

// cmt011RunID etc. are this file's own fixture — distinct from
// signpayload_test.go's spRunID and sign_commit_test.go's scRunID so a
// failure here never gets confused with theirs.
const (
	cmt011RunID      = "run-cmt011"
	cmt011AgentType  = "demo"
	cmt011TaskRef    = "RM-243"
	cmt011TaskID     = "rm-243"
	cmt011Repo       = "github.com/innsegl/cmt011"
	cmt011ToolUseID  = "toolu_01cmt011crashwindowabcdefghi"
	cmt011AuthorName = "innsegl cmt011 test"
)

func cmt011SPIFFEID() string {
	return "spiffe://" + scHarnessTrustDomain + "/agent/" + cmt011AgentType + "/" + cmt011TaskID + "/" + cmt011RunID
}

// buildCMT011SignClient compiles internal/mcp/testdata/cmt011signclient once
// and returns the binary's path. It lives under testdata/ so it is invisible
// to `go build ./...`, `go vet ./...` and golangci-lint's own package
// discovery; this is the one place that builds it.
func buildCMT011SignClient(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "cmt011signclient")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin,
		"innsegl.dev/innsegl/internal/mcp/testdata/cmt011signclient")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building internal/mcp/testdata/cmt011signclient: %v\n%s", err, out)
	}
	return bin
}

// cmt011CommitObjects lists every commit object a repository's object
// database holds, reachable or not — the identical read repos.go's own
// commitObjects performs for the reconciler, restated here (a different
// package) because this test's whole claim is about what is and is not in
// the database BEFORE the reconciler ever looks at it.
func cmt011CommitObjects(t *testing.T, worktree string) map[string]bool {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", worktree,
		"cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git cat-file --batch-all-objects: %v", err)
	}
	commits := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		name, kind, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if ok && kind == "commit" {
			commits[name] = true
		}
	}
	return commits
}

// TestCMT011CoreDiesBetweenPhaseBAndPhaseCConvergesThroughTheReconciler is
// CMT-011. It is long for the same reason
// TestREC003AndREC004AgainstARealRekorAndARealSignature is: one measured fact
// per block, and splitting it would separate the evidence from what it
// proves.
//
//nolint:gocyclo // see above
func TestCMT011CoreDiesBetweenPhaseBAndPhaseCConvergesThroughTheReconciler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		requireStartup(t, err, "CMT-011 measures what a REAL Phase B leaves behind when Phase "+
			"C is refused; a mocked Fulcio proves nothing about I5 (IP §2).")
	}
	stack, stackErr := scStartStack(ctx, credRepoRoot(t))
	if stack != nil {
		t.Cleanup(stack.stop)
	}
	if stackErr != nil {
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", stackErr),
			fmt.Sprintf("CMT-011 goes unproven against a real signature. Start Docker, "+
				"`go install github.com/sigstore/gitsign@%s`, and re-run.", scHarnessGitsignVersion))
	}

	signClientBin := buildCMT011SignClient(t)

	// ---- a real repository, one staged file, no parent (a root commit keeps
	//      this case to exactly what it is about) --------------------------
	root := t.TempDir()
	worktree := filepath.Join(root, filepath.FromSlash(cmt011Repo))
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	scGit(t, worktree, "init", "-q", "-b", "main")
	scStage(t, worktree, "work.txt", "innsegl CMT-011\n")
	tree := scGit(t, worktree, "write-tree")

	// ---- the run, registered on a FAKE ledger this test can make refuse
	//      Phase C on demand (scLedger, sign_commit_test.go) ----------------
	phases := &scPhases{}
	fakeLedger := newSCLedger(phases)
	fakeLedger.failOn[event.EventTypeCommitRecorded] = fmt.Errorf("cmt011: the ledger refuses commit_recorded")

	spiffeID := cmt011SPIFFEID()
	run := CredentialRun{
		RunID: cmt011RunID, AgentType: cmt011AgentType, TaskID: cmt011TaskID,
		SPIFFEID: spiffeID, Repo: cmt011Repo,
	}
	runs := cmtRuns{cmt011RunID: run}

	if err := ConfigureGetCredential(CredentialConfig{
		Runs: runs, Entries: scOpenEntries{},
		Minter: scStackMinter{stack: stack, ttl: 5 * time.Minute},
		Ledger: fakeLedger,
	}); err != nil {
		t.Fatalf("ConfigureGetCredential: %v", err)
	}

	workspace, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	sigstore, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	idem, _ := newStore(t)
	restoreSC, err := ConfigureSignCommit(SignCommitConfig{
		Runs: runs, Ledger: fakeLedger, Idempotency: idem, Workspace: workspace, Sigstore: sigstore,
		Credentials: SignCommitThroughGetCredential{},
		Signers: NewGitsignSigners(signing.Config{
			FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL, Issuer: scHarnessIssuer,
			GitsignPath: stack.gitsignPath, Author: signing.AuthorPolicy{AllowUnlinked: true},
		}),
		AuthorName: cmt011AuthorName, AuthorEmail: scAuthorEmail, Pseudonyms: scLiteral(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restoreSC)

	resolver := &cmtResolver{calls: map[string]commitpath.RelayedCall{}}
	resolver.set(cmt011ToolUseID, commitpath.RelayedCall{
		RunID: cmt011RunID, Tool: "Bash",
		Input:      json.RawMessage(`{"command":"git commit -m x"}`),
		ObservedAt: time.Now(),
	})
	claimFor := func(_ context.Context, runID string) (signing.Claim, error) {
		r, ok := runs[runID]
		if !ok {
			return signing.Claim{}, fmt.Errorf("no run %q", runID)
		}
		return signing.Claim{Identity: r.SPIFFEID, Run: runID, Task: cmt011TaskRef}, nil
	}
	// NO override of cfg.sign: Phase B is signWithSigner, unmodified, running
	// a real signer against the real stack above -- the whole point of this
	// case, and the reason it does not use spWiringSigningWith the way
	// signpayload_test.go's own Phase-C-refusal case does.
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: claimFor})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	t.Cleanup(restoreSP)

	// ---- the core's HTTP surface, wired the way cmd/innsegl/commitsign.go
	//      wires it in production: sign is SignPayloadForGateway, taken as a
	//      plain function value, nothing more --------------------------------
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req commitpath.SignRequest
		if jerr := json.NewDecoder(r.Body).Decode(&req); jerr != nil {
			http.Error(w, `{"error":"decoding the request"}`, http.StatusBadRequest)
			return
		}
		resp, serr := SignPayloadForGateway(r.Context(), req)
		if serr != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, serr.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if eerr := json.NewEncoder(w).Encode(resp); eerr != nil {
			t.Logf("encoding the sign response: %v", eerr)
		}
	}))
	t.Cleanup(server.Close)

	// ---- the measurement: before/after the real git commit ------------------
	before := cmt011CommitObjects(t, worktree)

	claim, err := claimFor(ctx, cmt011RunID)
	if err != nil {
		t.Fatalf("claimFor: %v", err)
	}
	trailers, err := claim.Trailers()
	if err != nil {
		t.Fatalf("claim.Trailers: %v", err)
	}
	var msg strings.Builder
	msg.WriteString("fix: cmt011 crash window\n\n")
	for _, tr := range trailers {
		msg.WriteString(tr.String())
		msg.WriteString("\n")
	}
	messagePath := filepath.Join(t.TempDir(), "message")
	if werr := os.WriteFile(messagePath, []byte(msg.String()), 0o600); werr != nil {
		t.Fatal(werr)
	}

	cmd := exec.CommandContext(ctx, "git", "-C", worktree,
		"-c", "gpg.format=x509",
		"-c", "gpg.x509.program="+signClientBin,
		"-c", "commit.gpgsign=true",
		"commit", "--file", messagePath, "--cleanup=verbatim", "--no-edit")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + worktree,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(worktree, "no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=" + cmt011AuthorName, "GIT_AUTHOR_EMAIL=" + scAuthorEmail,
		"GIT_COMMITTER_NAME=" + cmt011AuthorName, "GIT_COMMITTER_EMAIL=" + scAuthorEmail,
		commitpath.EnvToolUseID + "=" + cmt011ToolUseID,
		commitpath.EnvCoreURL + "=" + server.URL,
	}
	out, commitErr := cmd.CombinedOutput()

	// FACT 1: git exits non-zero.
	if commitErr == nil {
		t.Fatalf("git commit succeeded; want a non-zero exit (Phase C was refused):\n%s", out)
	}
	t.Logf("git commit failed as CMT-011 requires: %v\n%s", commitErr, out)

	// FACT 2: no new commit object -- the identical object-database read
	// repos.go performs, before and after.
	after := cmt011CommitObjects(t, worktree)
	if len(after) != len(before) {
		t.Fatalf("the object database gained a commit object: before %v, after %v", before, after)
	}
	for sha := range after {
		if !before[sha] {
			t.Fatalf("a new commit object %s exists even though git reported failure", sha)
		}
	}

	// FACT 3: exactly A:append commit_intent ran; Phase B ran (a real
	// signature was attempted); C:append commit_recorded was ATTEMPTED and
	// refused -- scPhases records an attempt whether or not the ledger
	// accepted it (sign_commit_test.go's own scLedger.Append), so its
	// presence here is proof Phase B->C's ordering held, not proof C
	// succeeded.
	steps := phases.all()
	if idx := indexOf(steps, scStepIntent); idx < 0 {
		t.Fatalf("commit_intent was never appended: %v", steps)
	}
	if idx := indexOf(steps, scStepRecorded); idx < 0 {
		t.Fatalf("commit_recorded was never ATTEMPTED (Phase C never ran): %v", steps)
	}
	if indexOf(steps, scStepIntent) >= indexOf(steps, scStepRecorded) {
		t.Fatalf("commit_intent did not precede the commit_recorded attempt: %v", steps)
	}

	// FACT 4: the chain itself holds a commit_intent with no commit_recorded
	// -- REC-001's own shape.
	intents := fakeLedger.ofType(event.EventTypeCommitIntent)
	if len(intents) != 1 {
		t.Fatalf("chain holds %d commit_intent events, want 1: %v", len(intents), intents)
	}
	intent := intents[0]
	if got := scMember[string](t, intent, event.FieldTreeHash); got != tree {
		t.Fatalf("commit_intent.tree_hash = %s, want %s", got, tree)
	}
	if recs := fakeLedger.ofType(event.EventTypeCommitRecorded); len(recs) != 0 {
		t.Fatalf("chain holds %d commit_recorded events, want 0 (Phase C was refused): %v", len(recs), recs)
	}

	// FACT 5: the reconciler's OWN existing intent-expiry (ADR-0035) closes
	// the window it was always built to close -- this case invents nothing
	// new in internal/reconciler, only drives it with a clock past the
	// window.
	repos, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	log, err := reconciler.NewRekorLog(stack.rekorURL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	future := time.Now().Add(2 * time.Hour)
	rec, err := reconciler.New(reconciler.Config{
		Ledger: fakeLedger, Appender: fakeLedger, Repos: repos, Log: log,
		TrustDomain: scHarnessTrustDomain,
		ExpireAfter: time.Minute,
		Now:         func() time.Time { return future },
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := rec.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Expired != 1 {
		t.Fatalf("Result.Expired = %d, want 1: %+v", result.Expired, result.Findings)
	}
	if result.Repaired != 0 {
		t.Fatalf("Result.Repaired = %d, want 0 -- there is no signed commit object anywhere "+
			"to repair from (FACT 2)", result.Repaired)
	}
	expired := fakeLedger.ofType(event.EventTypeCommitIntentExpired)
	if len(expired) != 1 {
		t.Fatalf("chain holds %d commit_intent_expired events, want 1: %v", len(expired), expired)
	}
	if got := scMember[string](t, expired[0], event.FieldIntentEventID); got != scMember[string](t, intent, event.FieldEventID) {
		t.Fatalf("commit_intent_expired names intent %s, want the run's own %s",
			got, scMember[string](t, intent, event.FieldEventID))
	}
	t.Logf("CMT-011: git exited non-zero, no commit object was created, commit_intent %s "+
		"expired as %s", scMember[string](t, intent, event.FieldEventID),
		scMember[string](t, expired[0], event.FieldEventID))
}

func indexOf(ss []string, target string) int {
	for i, s := range ss {
		if s == target {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// reconciler.LedgerReader for *scLedger — added here, in this file alone,
// because only CMT-011 asks the reconciler to read this fake. sign_commit_test.go
// is not touched: Go methods on a type may be defined in any file of the
// package that declares it.
// ---------------------------------------------------------------------------

func (l *scLedger) Count(context.Context) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(len(l.records)), nil
}

func (l *scLedger) Events(_ context.Context, from, to int64) ([]event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if from < 1 || to > int64(len(l.records)) || from > to {
		return nil, fmt.Errorf("scLedger: events %d..%d out of range for %d records", from, to, len(l.records))
	}
	out := make([]event.Fields, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, l.records[i-1].Clone())
	}
	return out, nil
}
