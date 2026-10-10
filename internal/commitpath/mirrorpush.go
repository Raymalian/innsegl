// SPDX-License-Identifier: Apache-2.0

package commitpath

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/workspace"
)

// What a hosted client pushes to the core's mirror besides a commit's
// staging objects (ADR-0065 decisions 2 and 3): its branch after a signed
// commit and at session end (#465), and a workspace snapshot after each tool
// call (#467). Every push goes through the client service, exactly as Stage
// does, and does nothing against a single-host core.

// snapshotStoreDir is the client's private snapshot store, under the
// repository's common git directory: an object directory of its own, so a
// snapshot never writes into the repository's objects. It is a cache
// (ADR-0065 decision 4); the core's mirror is the evidence.
const snapshotStoreDir = "innsegl/snapshots/objects"

// snapshotIndexFile is the private index, one per working tree, so the
// repository's own index is never read or written.
const snapshotIndexFile = "innsegl-snapshot-index"

// Snapshot is one workspace snapshot in the client's private store: a
// commit of the working tree, and the object directory that holds it.
type Snapshot struct {
	Commit  string
	Tree    string
	Objects string
}

// PushBranch pushes commit to branch on the core's mirror of dir's
// repository (#465). The core moves a branch only forward.
func (c Client) PushBranch(ctx context.Context, dir, branch, commit string) error {
	if branch == "" || !isObjectID(commit) {
		return fmt.Errorf("push %q to %q: not a branch and a commit", commit, branch)
	}
	if _, ok := c.hosted(ctx); !ok {
		return nil
	}
	repo, err := workspace.RepoID(ctx, dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	return c.pushRef(ctx, dir, nil, repo, commit+":refs/heads/"+branch)
}

// TakeSnapshot writes dir's working tree as it is now -- tracked and
// untracked files, ignored ones left out, as `git add --all` sees them --
// into the private snapshot store, with a private index (#467). The
// repository's own index, objects and refs are untouched. The commit has a
// fixed identity and date and no parent, so the same tree is the same
// commit.
func TakeSnapshot(ctx context.Context, dir string) (Snapshot, error) {
	paths, err := stageGit(ctx, dir, nil, "rev-parse", "--path-format=absolute",
		"--show-toplevel", "--git-common-dir", "--git-dir")
	if err != nil {
		return Snapshot{}, err
	}
	parts := strings.Split(paths, "\n")
	if len(parts) != 3 {
		return Snapshot{}, errors.New("not a working tree")
	}
	top, common, gitDir := parts[0], parts[1], parts[2]
	objects := filepath.Join(common, filepath.FromSlash(snapshotStoreDir))
	if merr := os.MkdirAll(objects, 0o700); merr != nil {
		return Snapshot{}, fmt.Errorf("the snapshot store: %w", merr)
	}
	env := []string{
		"GIT_OBJECT_DIRECTORY=" + objects,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=" + filepath.Join(common, "objects"),
		"GIT_INDEX_FILE=" + filepath.Join(gitDir, snapshotIndexFile),
		"GIT_WORK_TREE=" + top,
		"GIT_AUTHOR_NAME=innsegl", "GIT_AUTHOR_EMAIL=snapshot@innsegl.invalid", "GIT_AUTHOR_DATE=@0 +0000",
		"GIT_COMMITTER_NAME=innsegl", "GIT_COMMITTER_EMAIL=snapshot@innsegl.invalid", "GIT_COMMITTER_DATE=@0 +0000",
	}
	if _, aerr := stageGit(ctx, top, env, "add", "--all", "--", "."); aerr != nil {
		return Snapshot{}, aerr
	}
	tree, err := stageGit(ctx, top, env, "write-tree")
	if err != nil {
		return Snapshot{}, err
	}
	commit, err := stageGit(ctx, top, env, "commit-tree", "--no-gpg-sign", "-m", "innsegl snapshot", tree)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Commit: commit, Tree: tree, Objects: objects}, nil
}

// PushSnapshot pushes snap to this installation's snapshot ref for one tool
// call. The core writes a snapshot ref once.
func (c Client) PushSnapshot(ctx context.Context, dir string, snap Snapshot, toolUseID string) error {
	if !IsToolUseID(toolUseID) || !isObjectID(snap.Commit) || snap.Objects == "" {
		return fmt.Errorf("snapshot %q for %q: not a snapshot and a tool call id", snap.Commit, toolUseID)
	}
	installation, ok := c.hosted(ctx)
	if !ok {
		return nil
	}
	repo, err := workspace.RepoID(ctx, dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	common, err := stageGit(ctx, dir, nil, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return err
	}
	env := []string{
		"GIT_OBJECT_DIRECTORY=" + snap.Objects,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=" + filepath.Join(common, "objects"),
	}
	return c.pushRef(ctx, dir, env, repo, snap.Commit+":"+SnapshotRef(installation, toolUseID))
}

// hosted answers the installation when c is a client service (plain http on
// loopback, answering its status route with one), as Stage decides.
func (c Client) hosted(ctx context.Context) (string, bool) {
	if !strings.HasPrefix(c.BaseURL, "http://") {
		return "", false
	}
	return c.installation(ctx)
}
