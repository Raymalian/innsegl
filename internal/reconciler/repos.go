// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// The git half of the join: which commit objects hold the tree an intent
// named, and which of those was ever signed.
//
// # Why a commit object rather than a ref
//
// A crash between Phase B and Phase C leaves a commit that `git commit` had
// already written, and a later `reset --hard` or a failed replay can leave
// nothing pointing at it. `git log --all` would call that signature
// nonexistent, and the intent would then be EXPIRED — a permanent record (I4)
// stating that a signature which is sitting in Rekor never happened.
//
// So the object database is read, not the ref graph:
// `cat-file --batch-all-objects` is the same question ADR-0032 asks when it
// asserts that a failed signature created no commit at all, from the other
// side.
//
// # Why the signature header is checked here
//
// It is not a verification and does not pretend to be one — verifying is
// `innsegl verify`'s (RM-037) and Rekor's. It is a cheap way to drop the
// commits nobody ever tried to sign, so that an ordinary unsigned commit that
// happens to hold the same tree can never become a candidate for a repair. The
// load-bearing check is still the transparency log's.

const (
	// maxRepoCommits bounds one repository's contribution to a cycle. A
	// reconciler that walks an unbounded object database is a reconciler that
	// stops reconciling; the bound is reported rather than silently applied.
	maxRepoCommits = 200_000
	// maxGitOutput bounds what one git invocation may hand back.
	maxGitOutput = 64 << 20
)

// GitWorkspace maps doc 02 §5's `host/org/name` onto `<root>/host/org/name`
// and reads git plumbing there.
//
// The mapping is total rather than merely usually safe for the reason ADR-0033
// decision 3 gives: `repo` is already held to exactly three segments, each
// `[A-Za-z0-9][A-Za-z0-9._-]*`, so no segment can be `..` and none can hold a
// separator. There is no second "does this escape the root?" check, because a
// check that can never fire is a check nobody can test.
type GitWorkspace struct {
	root string
	git  string
}

var _ Repos = (*GitWorkspace)(nil)

// NewGitWorkspace builds a workspace rooted at root, or refuses.
func NewGitWorkspace(root string) (*GitWorkspace, error) {
	if root == "" {
		return nil, fmt.Errorf("reconciler: no workspace root; `repo` is an identifier " +
			"and something has to map it onto a working tree")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("reconciler: workspace root %q: %w", root, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("reconciler: workspace root %q: %w", abs, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("reconciler: workspace root %q is not a directory", abs)
	}
	return &GitWorkspace{root: abs, git: "git"}, nil
}

// Root is the directory repositories are resolved under.
func (w *GitWorkspace) Root() string { return w.root }

// worktree resolves `host/org/name` to the directory this deployment holds.
func (w *GitWorkspace) worktree(repo string) (string, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return "", fmt.Errorf("reconciler: %q is not a repo (doc 02 §5): %w", repo, err)
	}
	dir := filepath.Join(w.root, filepath.FromSlash(repo))
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("reconciler: no working tree for %s: %w", repo, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("reconciler: the working tree for %s is not a directory", repo)
	}
	return dir, nil
}

// SignedCommitsWithTree returns every commit object in repo whose tree is
// treeHash and which carries a `gpgsig` header, sorted.
//
// An error means the repository could not be read. That is never grounds for
// an expiry: `Reconcile` leaves such an intent open and alerts, because "we
// could not tell" and "it never happened" are different answers and only one
// of them belongs in an append-only chain.
func (w *GitWorkspace) SignedCommitsWithTree(ctx context.Context, repo, treeHash string) ([]string, error) {
	if err := event.ValidateGitObjectID(treeHash); err != nil {
		return nil, fmt.Errorf("reconciler: %q is not a git object id: %w", treeHash, err)
	}
	dir, err := w.worktree(repo)
	if err != nil {
		return nil, err
	}

	commits, err := w.commitObjects(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	trees, err := w.treesOf(ctx, dir, commits)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, commit := range commits {
		if trees[commit] != treeHash {
			continue
		}
		signed, serr := w.isSigned(ctx, dir, commit)
		if serr != nil {
			return nil, serr
		}
		if signed {
			out = append(out, commit)
		}
	}
	slices.Sort(out)
	return out, nil
}

// commitObjects is every commit in the object database, reachable or not.
func (w *GitWorkspace) commitObjects(ctx context.Context, dir string) ([]string, error) {
	out, err := w.run(ctx, dir, nil, "cat-file", "--batch-all-objects",
		"--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		return nil, err
	}
	var commits []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		name, kind, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if !ok || kind != "commit" {
			continue
		}
		if len(commits) >= maxRepoCommits {
			return nil, fmt.Errorf("reconciler: %s holds more than %d commit objects; "+
				"raise the bound deliberately rather than reconciling a truncated view",
				dir, maxRepoCommits)
		}
		commits = append(commits, name)
	}
	if serr := scanner.Err(); serr != nil {
		return nil, fmt.Errorf("reconciler: reading the object database of %s: %w", dir, serr)
	}
	return commits, nil
}

// treesOf maps each commit onto its tree, in one invocation.
func (w *GitWorkspace) treesOf(ctx context.Context, dir string, commits []string) (map[string]string, error) {
	stdin := strings.Join(commits, "\n") + "\n"
	out, err := w.run(ctx, dir, strings.NewReader(stdin),
		"log", "--no-walk", "--format=%H %T", "--stdin")
	if err != nil {
		return nil, err
	}
	trees := make(map[string]string, len(commits))
	for _, line := range strings.Split(out, "\n") {
		commit, tree, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			trees[commit] = tree
		}
	}
	return trees, nil
}

// isSigned reports whether the commit object carries a `gpgsig` header.
//
// The header, not its contents: this is the filter that keeps an ordinary
// unsigned commit out of the candidate set, and nothing more. `git cat-file
// commit` prints the object's headers verbatim, so the test is on the bytes
// git stored rather than on anything this process decided.
func (w *GitWorkspace) isSigned(ctx context.Context, dir, commit string) (bool, error) {
	out, err := w.run(ctx, dir, nil, "cat-file", "commit", commit)
	if err != nil {
		return false, err
	}
	header, _, _ := strings.Cut(out, "\n\n")
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(line, "gpgsig ") || strings.HasPrefix(line, "gpgsig-sha256 ") {
			return true, nil
		}
	}
	return false, nil
}

// run invokes git with an environment built from nothing.
//
// ADR-0031 decision 3's argument, applied to a read and repeated here rather
// than imported: no `~/.gitconfig`, alias, pager or credential helper may
// change what a plumbing command answers, and the reconciler must not depend
// on the MCP server to read a repository the MCP server may be down.
func (w *GitWorkspace) run(ctx context.Context, dir string, stdin *strings.Reader, args ...string) (string, error) {
	//nolint:gosec // G204: w.git is configuration, dir is <root>/host/org/name
	// with `repo` already held to doc 02 §5's grammar, and every arg is a
	// literal or a validated git object id.
	cmd := exec.CommandContext(ctx, w.git, append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(dir, ".innsegl-no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
	}
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := cmd.CombinedOutput()
	if len(out) > maxGitOutput {
		return "", fmt.Errorf("reconciler: git %s in %s produced %d bytes, over the %d bound",
			strings.Join(args, " "), dir, len(out), maxGitOutput)
	}
	if err != nil {
		return "", fmt.Errorf("reconciler: git %s in %s: %w: %s",
			strings.Join(args, " "), dir, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// CommitsOnBranch is ADR-0047's walk: every commit on a branch, with the change
// it makes and the run it claims.
//
// # Why the run comes from the trailer and not from a lookup
//
// `Agent-Run` is what the COMMIT says about itself. The pass then checks that
// claim against the ledger, and a claim checked against a record is the whole
// mechanism; reading the run from the ledger instead would be checking the
// ledger against itself.
//
// # Two invocations, not one per commit
//
// `git log` emits the SHAs and the trailers in one pass, and `git patch-id`
// reads a stream of diffs in another. A branch has thousands of commits, and a
// process per commit would make the pass cost more than the merge it records.
func (w *GitWorkspace) CommitsOnBranch(ctx context.Context, repo, branch string) ([]RepoCommit, error) {
	if branch == "" {
		return nil, fmt.Errorf("reconciler: no branch to walk in %s; a pass that "+
			"guessed one would record rewrites from a history nobody asked about", repo)
	}
	dir, err := w.worktree(repo)
	if err != nil {
		return nil, err
	}

	// %H and the Agent-Run trailer, one commit per record. The NUL separator
	// is git's own, because a commit message may contain anything else.
	out, err := w.run(ctx, dir, nil, "log", "--no-merges", "-z",
		"--format=%H %(trailers:key=Agent-Run,valueonly=true,separator=%x2C)", branch)
	if err != nil {
		return nil, fmt.Errorf("reconciler: walking %s in %s: %w", branch, repo, err)
	}

	var commits []RepoCommit
	for _, record := range strings.Split(out, "\x00") {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		sha, run, _ := strings.Cut(record, " ")
		if err := event.ValidateGitObjectID(sha); err != nil {
			continue
		}
		if len(commits) >= maxRepoCommits {
			return nil, fmt.Errorf("reconciler: %s holds more than %d commits on %s; "+
				"raise the bound deliberately rather than recording a truncated view",
				repo, maxRepoCommits, branch)
		}
		commits = append(commits, RepoCommit{SHA: sha, RunID: strings.TrimSpace(run)})
	}
	if len(commits) == 0 {
		return nil, nil
	}
	return w.withPatchIDs(ctx, dir, commits)
}

// withPatchIDs fills in each commit's change identity.
//
// `git patch-id` reads a stream of diffs and prints one line per patch, so the
// whole branch goes through one invocation. Its second column is the commit the
// diff came from, which is what lets the answers be matched back.
//
// `--verbatim` for sign_commit's reason: the default folds whitespace, and in
// Python or a Makefile that is a different program. A commit with no output is
// one that changes nothing, and it keeps an empty patch id — outside the scheme
// rather than an error.
func (w *GitWorkspace) withPatchIDs(ctx context.Context, dir string, commits []RepoCommit) ([]RepoCommit, error) {
	shas := make([]string, 0, len(commits))
	for _, c := range commits {
		shas = append(shas, c.SHA)
	}
	patch, err := w.run(ctx, dir, strings.NewReader(strings.Join(shas, "\n")+"\n"),
		"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", "--stdin")
	if err != nil {
		return nil, fmt.Errorf("reconciler: reading the changes in %s: %w", dir, err)
	}
	ids, err := w.run(ctx, dir, strings.NewReader(patch), "patch-id", "--verbatim")
	if err != nil {
		return nil, fmt.Errorf("reconciler: git patch-id --verbatim in %s: %w", dir, err)
	}

	byCommit := make(map[string]string, len(commits))
	for _, line := range strings.Split(ids, "\n") {
		patchID, commit, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			byCommit[commit] = patchID
		}
	}
	for i := range commits {
		commits[i].PatchID = byCommit[commits[i].SHA]
	}
	return commits, nil
}

// TreeBlobs is every blob object id reachable from one tree — RM-104 (#169).
//
// One `ls-tree -r` per tree rather than one lookup per claim: a run with a
// thousand Edits against a handful of trees would otherwise be a thousand git
// invocations, and the answer is the same set either way.
func (w *GitWorkspace) TreeBlobs(
	ctx context.Context, repo, treeHash string,
) (map[string]struct{}, error) {
	if err := event.ValidateGitObjectID(treeHash); err != nil {
		return nil, fmt.Errorf("reconciler: %q is not a git object id: %w", treeHash, err)
	}
	dir, err := w.worktree(repo)
	if err != nil {
		return nil, err
	}
	return TreeBlobs(ctx, w.git, dir, treeHash)
}

// ReachableBlobs is every blob reachable from any ref — RM-104 (#169).
//
// One walk per repository per cycle, not one lookup per claim: a cycle with a
// thousand claims against one repository is one invocation.
//
// `--all` rather than a branch: the question this answers is whether the
// content exists anywhere in the repository's history, and a change that landed
// on a branch nobody named is still content this repository holds.
func (w *GitWorkspace) ReachableBlobs(
	ctx context.Context, repo string,
) (map[string]struct{}, error) {
	dir, err := w.worktree(repo)
	if err != nil {
		return nil, err
	}
	out, err := w.run(ctx, dir, nil, "rev-list", "--objects", "--all", "--filter=object:type=blob")
	if err != nil {
		return nil, fmt.Errorf("listing reachable blobs in %s: %w", repo, err)
	}
	blobs := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		id, _, _ := strings.Cut(line, " ")
		if len(id) == 40 {
			blobs[id] = struct{}{}
		}
	}
	return blobs, nil
}
