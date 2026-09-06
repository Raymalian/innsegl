// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
)

// RM-071 (#94) — sign_commit's eleven contract-matrix cells.
//
// The cells themselves live in contract_test.go, next to the other four
// tools' — this file holds only what driving them needs: a fake Sigstore
// probe, a fake signer, and a real, disposable git repository per fixture.
//
// # Why a real git repository and not a fifth fake
//
// SignCommitWorkspace and SignCommitRepos are exported seams too, and RM-033
// exported them for the same reason it exported the signer interfaces. But
// git plumbing costs nothing to run for real — no container, no network — and
// a fake `StagedTree`/`CommitTree` pair would have to reimplement enough of
// git's own rules (what a tree object id is, when an index equals HEAD) that
// the fake would become a second, unverified copy of them. So every
// sign_commit cell below runs the SHIPPED mcp.Workspace and mcp.GitRepos
// against a real repository this file creates with the system git binary.
// Only the signer — the one boundary nothing in this stack can cross without
// a real Fulcio and Rekor — is a double. See the block comment on the
// sign_commit cells in contract_test.go for that argument in full.
const (
	scAuthorName  = "Innsegl Contract Fixture"
	scAuthorEmail = "contract-fixture@innsegl.invalid"

	// scPlaceholderRepo and scPlaceholderStagedRef are used by cells that
	// fail before Workspace.Worktree is ever called (RUN_NOT_FOUND,
	// RUN_ALREADY_RETIRED, the request-validation INVARIANT_VIOLATION cell,
	// and the LEDGER_UNAVAILABLE cell, which fails at the idempotency claim
	// before resolveRun runs). They are well-formed enough to pass
	// signCommitCheckRequest's grammar and are never resolved against disk.
	scPlaceholderRepo = "github.com/innsegl/unreached"

	// scInvariantRunID is a syntactically valid run id (event.ValidateIdentifier)
	// that names no real run — used only by the INVARIANT_VIOLATION cell,
	// whose refusal happens before any run is resolved.
	scInvariantRunID = "run-sc-invariant-probe"
)

var scPlaceholderStagedRef = strings.Repeat("0", 40)

// ---------------------------------------------------------------------------
// The fake Sigstore probe.
// ---------------------------------------------------------------------------

// fakeSCSigstore always reports Sigstore healthy.
//
// None of the eleven cells is about the pre-Phase-A probe (ADR-0024) itself —
// SIGNING_UNAVAILABLE and TRANSPARENCY_UNAVAILABLE are reached through the
// signer instead (fakeSCSigner below), which is what lets those two cells
// assert the intent was appended before the failure (a Phase B property).
// This probe stays green for every cell so nothing is ever refused here by
// accident.
type fakeSCSigstore struct{}

func (fakeSCSigstore) ProbeSigning(context.Context) error      { return nil }
func (fakeSCSigstore) ProbeTransparency(context.Context) error { return nil }

// ---------------------------------------------------------------------------
// The fake signer.
// ---------------------------------------------------------------------------

// fakeSCSigner is the SignCommitSigner every sign_commit cell runs behind.
//
// Its default behaviour creates a REAL git commit from the worktree's current
// index (the same index signCommitRepo staged and Phase A's StagedTree read),
// so that signCommitService.checkResult's read-back check — a real call to
// the shipped GitRepos.CommitTree — is answered by a real commit object
// rather than a fabricated SHA. failWith makes the NEXT call fail instead,
// with no commit created: this is what stands in for gitsign refusing because
// Fulcio or Rekor died between the pre-Phase-A probe and this call (IP §6.3).
type fakeSCSigner struct {
	mu     sync.Mutex
	calls  int
	closed int
	err    error
}

// failWith arms the signer to fail its next call with err and never commit.
func (f *fakeSCSigner) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeSCSigner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSCSigner) Sign(ctx context.Context, req signing.Request) (signing.Result, error) {
	f.mu.Lock()
	f.calls++
	failure := f.err
	f.mu.Unlock()
	if failure != nil {
		return signing.Result{}, failure
	}

	trailers, err := req.Claim.Trailers()
	if err != nil {
		return signing.Result{}, fmt.Errorf("contract fixture: %w", err)
	}

	env := scGitEnv(req.Repo)
	commit := exec.CommandContext(ctx, "git", "-C", req.Repo, "commit", "-q", "--no-gpg-sign", "-m", req.Message)
	commit.Env = env
	if out, cerr := commit.CombinedOutput(); cerr != nil {
		return signing.Result{}, fmt.Errorf("contract fixture: git commit: %w: %s", cerr, out)
	}
	head := exec.CommandContext(ctx, "git", "-C", req.Repo, "rev-parse", "HEAD")
	head.Env = env
	sha, herr := head.Output()
	if herr != nil {
		return signing.Result{}, fmt.Errorf("contract fixture: git rev-parse HEAD: %w", herr)
	}

	return signing.Result{
		CommitSHA: strings.TrimSpace(string(sha)),
		Trailers:  trailers,
		Rekor: signing.RekorEntry{
			UUID:         "contractfixture" + strings.Repeat("ab", 24),
			LogIndex:     1,
			LogID:        "contract-fixture",
			IntegratedAt: time.Now().UTC(),
		},
	}, nil
}

func (f *fakeSCSigner) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

// fakeSCSigners is the SignCommitSigners factory. Admits always answers nil:
// I6's author policy is internal/signing's own and is not what this issue
// is about — the seam it gates (newSignCommitService's start-up check) is
// already covered by internal/mcp's own TestConfigureSignCommitRefusesAnIncompleteConfiguration.
type fakeSCSigners struct{ signer *fakeSCSigner }

func (f fakeSCSigners) Admits(string) error { return nil }

func (f fakeSCSigners) Open(signing.CredentialSource) (mcp.SignCommitSigner, error) {
	return f.signer, nil
}

// ---------------------------------------------------------------------------
// A real, disposable git repository per fixture.
// ---------------------------------------------------------------------------

var scRepoSeq atomic.Int64

// scGitEnv builds a git environment with no ambient configuration: no system
// or global gitconfig, no pager, no terminal prompt, and a fixed author and
// committer, the same posture internal/mcp's own git plumbing takes for a
// read (sign_commit.go's signCommitGitEnv) and the reason gitsign is never
// invoked here — this is plumbing, not a signature.
func scGitEnv(worktree string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + worktree,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(worktree, ".innsegl-contract-no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"GIT_AUTHOR_NAME=" + scAuthorName,
		"GIT_AUTHOR_EMAIL=" + scAuthorEmail,
		"GIT_COMMITTER_NAME=" + scAuthorName,
		"GIT_COMMITTER_EMAIL=" + scAuthorEmail,
	}
}

func scGit(t *testing.T, worktree string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(testCtx(t, 30*time.Second), "git", append([]string{"-C", worktree}, args...)...)
	cmd.Env = scGitEnv(worktree)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// signCommitRepo creates a fresh git repository under the stack's sign_commit
// workspace root, stages one file, and returns the repo identifier (doc 02
// §5's host/org/name) and the tree the index holds. A git tree object id is
// itself a valid revision, so it doubles as `staged_ref`: `stagedRef^{tree}`
// on a tree resolves to itself, which is exactly what GitRepos.StagedTree
// checks.
//
// A fresh repository every call, numbered by scRepoSeq, so that cells run
// against the same stack more than once (none currently are, but a future
// one might be) never share working-tree state.
func (s *stack) signCommitRepo(t *testing.T) (repo, stagedRef string) {
	t.Helper()
	repo = fmt.Sprintf("github.com/innsegl/contract-%d", scRepoSeq.Add(1))
	worktree := filepath.Join(s.scRoot, filepath.FromSlash(repo))
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", worktree, err)
	}
	scGit(t, worktree, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(worktree, "work.txt"),
		[]byte("innsegl contract fixture\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture file: %v", err)
	}
	scGit(t, worktree, "add", "work.txt")
	return repo, scGit(t, worktree, "write-tree")
}

// signCommitArgs is IP §4's six sign_commit arguments, built from a real
// repo/staged_ref pair (signCommitRepo) and the fixture task_ref that matches
// what registerRun used (testTaskID) — required for every cell that reaches
// the claim inside phases(), which refuses a task_ref that does not lowercase
// to the run's own {task_id} segment.
func signCommitArgs(runID, repo, stagedRef, idempotencyKey string) map[string]any {
	return map[string]any{
		"run_id": runID, "repo": repo, "staged_ref": stagedRef,
		"message": "fix(contract): sign_commit matrix probe", "task_ref": testTaskID,
		"idempotency_key": idempotencyKey,
	}
}

// ---------------------------------------------------------------------------
// The extra ATTESTATION_FAILED sweep, driven through sign_commit itself.
// ---------------------------------------------------------------------------

// TestMCP006SignCommitsCredentialPathNeverProducesAttestationFailed extends
// TestMCP006TheMintPathNeverProducesAttestationFailed (contract_test.go)
// through sign_commit, rather than through get_credential.
//
// The two tools share one mint path — SignCommitThroughGetCredential calls
// the shipped get_credential in process — so the sweep's conclusion already
// covers sign_commit in principle. It is measured again anyway: sign_commit's
// own request path runs four gates get_credential does not (the task claim,
// the workspace, the staged tree, the pre-Phase-A Sigstore probe) before the
// credential is ever touched, and a reachability claim about THIS tool is
// only honest once driven through THIS tool's own path rather than assumed
// from a sibling's.
func TestMCP006SignCommitsCredentialPathNeverProducesAttestationFailed(t *testing.T) {
	requirePG(t)
	s := newStack(t)
	run := s.registerRun(t, "sc-mint-sweep")
	repo, tree := s.signCommitRepo(t)

	allowed := reachableClasses(mcp.ToolSignCommit)
	// codes.OK is not a failure; the sweep starts at Canceled and runs past
	// the last code the gRPC package defines, so an unrecognised code is
	// covered too — the same range TestMCP006TheMintPathNeverProducesAttestationFailed uses.
	for code := codes.Code(1); code <= codes.Code(20); code++ {
		t.Run(code.String(), func(t *testing.T) {
			s.conn.failWith(code, "sweep")
			got := s.callExpectingError(t, mcp.ToolSignCommit,
				signCommitArgs(run.RunID, repo, tree, "sc-mint-sweep-"+code.String()))
			if got.Class == string(mcp.ClassAttestationFailed) {
				t.Fatalf("sign_commit's credential path answering %s reached the caller as "+
					"ATTESTATION_FAILED. The matrix says sign_commit cannot produce that class; "+
					"either the mapping changed or the matrix is now wrong.", code)
			}
			if !slices.Contains(allowed, mcp.Class(got.Class)) {
				t.Fatalf("sign_commit's credential path answering %s produced %s, which the "+
					"matrix calls unreachable for sign_commit: %s", code, got.Class, got.Message)
			}
			assertNotWidened(t, got)
		})
	}
}
