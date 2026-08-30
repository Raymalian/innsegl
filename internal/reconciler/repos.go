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
