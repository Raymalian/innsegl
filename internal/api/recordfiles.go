// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
)

// recordfiles.go derives record.go's RecordFile lists — per step, and for
// the whole run — from the snapshot store, and answers RecordFile.Committed
// against the served repository's own commit trees.
//
// # Committed, without opening two object databases as one
//
// A git blob's object id is `sha1("blob "+len+"\x00"+content)` — a pure
// function of the bytes, independent of which repository ever stored it.
// So "does this snapshot's own version of a path appear in a commit this
// run made" never needs the snapshot store's objects to be copied into, or
// compared against, the served repository's: it is answered by listing each
// tree with `git ls-tree -r` and comparing the two path->blob-id maps as
// PLAIN STRINGS. blobsAtRange below does exactly that for the snapshot
// store's own tree_after; committedBlobs does it for a run's own commit
// trees, read from the served checkout the proof BFF already has.

// fileChange is one path's own before/after state within a range (a step,
// or the whole run), before RecordFile.Committed and RecordFile.ByRunID are
// attached.
type fileChange struct {
	Path      string
	OldPath   string
	Status    string
	Additions int
	Deletions int
}

// runBaseline answers runID's own baseline tree hash (snapshotstore.go's own
// runBaselineTree, internal/gateway/snapshot.go's SnapshotBaseline), or ""
// when repoName resolves to no snapshot store this process can read — the
// same "no store" case filesInRange already answers empty for, restated
// here for a single hash lookup rather than a file list.
func (rs *recordServer) runBaseline(ctx context.Context, repoName, runID string) string {
	storeDir, ok := rs.storeDirFor(ctx, repoName)
	if !ok {
		return ""
	}
	return runBaselineTree(ctx, rs.cfg, storeDir, runID)
}

// filesInRange reads what changed between before and after in repoName's
// snapshot store. Every error here — no served repository by that name, no
// snapshot store for it, before or after empty or equal — answers an empty,
// non-nil-error-free result: record.go's own rule that a step or a run
// whose tree cannot be compared shows no files, never a guess at what they
// might have been.
func (rs *recordServer) filesInRange(ctx context.Context, repoName, before, after string) ([]fileChange, error) {
	if before == "" || after == "" || before == after {
		return nil, nil
	}
	storeDir, ok := rs.storeDirFor(ctx, repoName)
	if !ok {
		return nil, errNoStore
	}
	rows, err := diffTreeNumstat(ctx, rs.cfg, storeDir, before, after)
	if err != nil {
		return nil, err
	}
	out := make([]fileChange, 0, len(rows))
	for _, r := range rows {
		out = append(out, fileChange{
			Path: r.Path, OldPath: r.OldPath, Status: r.Status,
			Additions: r.Additions, Deletions: r.Deletions,
		})
	}
	return out, nil
}

// blobsAtTree lists every blob reachable from tree in the snapshot store,
// by path.
func (rs *recordServer) blobsAtTree(ctx context.Context, repoName, tree string) (map[string]string, error) {
	if tree == "" {
		return nil, errNoStore
	}
	storeDir, ok := rs.storeDirFor(ctx, repoName)
	if !ok {
		return nil, errNoStore
	}
	out, err := runStoreGit(ctx, rs.cfg, storeDir,
		"ls-tree", "-r", "--format=%(objectname)%x09%(path)", "--end-of-options", tree)
	if err != nil {
		return nil, err
	}
	return parseTreeBlobs(out), nil
}

// blobsAtCommitTree lists every blob reachable from a COMMITTED tree, read
// from the served repository the proof BFF already has a checkout of —
// never the snapshot store, which holds no commit objects of its own.
func (rs *recordServer) blobsAtCommitTree(ctx context.Context, repoName, tree string) (map[string]string, error) {
	if tree == "" {
		return nil, errNoStore
	}
	repoDir, ok := rs.prover.RepoPath(repoName)
	if !ok {
		return nil, errNoStore
	}
	gitPath := rs.prover.GitPath()
	out, err := runGit(ctx, repoDir, isolatedGitEnv(repoDir), gitPath,
		"ls-tree", "-r", "--format=%(objectname)%x09%(path)", "--end-of-options", tree)
	if err != nil {
		return nil, err
	}
	return parseTreeBlobs(out), nil
}

func parseTreeBlobs(out string) map[string]string {
	blobs := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		sha, path, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		blobs[path] = sha
	}
	return blobs
}

// committedSet answers, for repoName, the union of every path->blob-id this
// run's own commits carry — RecordFile.Committed's whole evidence. A commit
// whose tree cannot be read (the served repository is missing it, or is not
// served at all) contributes nothing rather than failing the whole
// computation: Committed then understates rather than guesses, which is the
// safe direction for a claim this honest.
func (rs *recordServer) committedSet(ctx context.Context, repoName string, commits []commitRow) map[string]string {
	union := map[string]string{}
	seen := map[string]bool{}
	for _, c := range commits {
		tree := c.TreeHash
		if tree == "" || seen[tree] {
			continue
		}
		seen[tree] = true
		blobs, err := rs.blobsAtCommitTree(ctx, repoName, tree)
		if err != nil {
			continue
		}
		for path, sha := range blobs {
			union[path] = sha
		}
	}
	return union
}

// isCommitted reports whether path's blob at "after" also appears, under
// the identical content, in committed.
func isCommitted(afterBlobs map[string]string, committed map[string]string, path string) bool {
	sha, ok := afterBlobs[path]
	return ok && sha != "" && committed[path] == sha
}

// discardBlobsError is this package's own named discard (errcheck runs
// with check-blank) for a blob listing a caller treats as best effort: a
// store this process cannot currently read answers no blobs, and
// isCommitted then understates rather than guesses — never the reason a
// whole step's Files turns into a 500.
func discardBlobsError(blobs map[string]string, _ error) map[string]string { return blobs }
