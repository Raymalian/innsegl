// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"fmt"
)

// MirrorRepos reads repositories from the core's per-repository mirror
// (ADR-0065 decision 1): one bare repository per `host/org/name`, at
// `<root>/host/org/name.git`, fed by a client's push. It is how the hosted
// core reads repositories; nothing on the core's disk is a client's working
// tree (ADR-0064 decision 2).
//
// It reads the mirror exactly as GitWorkspace reads a working tree, with two
// differences, and both are about what the mirror cannot show.
//
// # Absence is not evidence
//
// A client pushes a commit's objects before the commit is signed, and the
// signed commit afterwards, if at all; a push that fails is carried by the
// next one (ADR-0065 consequence 3). So a mirror holding no signed commit for
// a tree has not shown that none was ever made. SignedCommitsWithTree
// therefore never answers "none": it answers what it found, or an error, and
// an error leaves the intent open (Reconciler.resolve) instead of expiring it
// with a permanent record (I4) that a later push would contradict.
//
// # No landing check
//
// Whether a commit landed is a question about the developer's own branch,
// which the mirror does not hold. MirrorRepos offers no CommitReachable, so
// the landing pass reports every commit "not checked" rather than reading the
// mirror's refs as the developer's and calling a commit "not landed".
type MirrorRepos struct {
	w *GitWorkspace
}

var _ Repos = (*MirrorRepos)(nil)

// NewMirrorRepos opens the mirror rooted at root for reading, or refuses.
func NewMirrorRepos(root string) (*MirrorRepos, error) {
	w, err := NewGitWorkspace(root)
	if err != nil {
		return nil, fmt.Errorf("reconciler: the repository mirror: %w", err)
	}
	w.bare = true
	return &MirrorRepos{w: w}, nil
}

// Root is the directory the mirrors live under.
func (m *MirrorRepos) Root() string { return m.w.Root() }

// SignedCommitsWithTree returns the signed commits holding treeHash that the
// mirror holds, and an error — never an empty answer — when it holds none.
// See "Absence is not evidence" above.
func (m *MirrorRepos) SignedCommitsWithTree(ctx context.Context, repo, treeHash string) ([]string, error) {
	commits, err := m.w.SignedCommitsWithTree(ctx, repo, treeHash)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("reconciler: the mirror of %s holds no signed commit with tree %s; "+
			"a client pushes a signed commit after it is signed, so its absence here does not "+
			"show it was never signed", repo, treeHash)
	}
	return commits, nil
}

// CommitsOnBranch walks a branch the mirror holds. A branch no client pushed
// is an error, which the rebase pass reports and never records.
func (m *MirrorRepos) CommitsOnBranch(ctx context.Context, repo, branch string) ([]RepoCommit, error) {
	return m.w.CommitsOnBranch(ctx, repo, branch)
}

// TreeBlobs is every blob reachable from treeHash in the mirror of repo.
func (m *MirrorRepos) TreeBlobs(ctx context.Context, repo, treeHash string) (map[string]struct{}, error) {
	return m.w.TreeBlobs(ctx, repo, treeHash)
}

// ReachableBlobs is every blob reachable from any ref in the mirror of repo.
func (m *MirrorRepos) ReachableBlobs(ctx context.Context, repo string) (map[string]struct{}, error) {
	return m.w.ReachableBlobs(ctx, repo)
}
