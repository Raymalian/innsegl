// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RPG-003: A/M/D, R, and (recordbuild_test.go) by_run_id — this file
// exercises the git-facing half against a REAL git repository in a temp
// dir, never a hand-written fixture of what diff-tree "would" say.

func requireGit(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	return path
}

// bareStore builds a throwaway bare repository this test writes trees into
// directly (git hash-object / mktree / commit-tree), the same shape
// internal/gateway/snapshot.go's own store is — GIT_DIR only, no working
// tree — so diffTreeNumstat is exercised against the REAL command rather
// than a parser fed hand-written text.
type bareStore struct {
	dir     string
	gitPath string
	cfg     snapshotStoreConfig
}

func newBareStore(t *testing.T) *bareStore {
	t.Helper()
	gitPath := requireGit(t)
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), gitPath, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_DIR="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("init", "--quiet", "--bare")
	return &bareStore{dir: dir, gitPath: gitPath, cfg: snapshotStoreConfig{root: filepath.Dir(dir), gitPath: gitPath}}
}

// blob hashes and writes content as a blob object, returning its id.
func (s *bareStore) blob(t *testing.T, content string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), s.gitPath, "hash-object", "-w", "--stdin")
	cmd.Dir = s.dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+s.dir)
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	return trimNL(string(out))
}

// tree builds a flat tree (root files only, enough for this file's own
// cases) from a map of path -> blob id, and returns the tree's own id.
func (s *bareStore) tree(t *testing.T, entries map[string]string) string {
	t.Helper()
	var spec string
	for path, blob := range entries {
		spec += "100644 blob " + blob + "\t" + path + "\n"
	}
	cmd := exec.CommandContext(context.Background(), s.gitPath, "mktree")
	cmd.Dir = s.dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+s.dir)
	cmd.Stdin = strings.NewReader(spec)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git mktree: %v", err)
	}
	return trimNL(string(out))
}

// updateRef sets ref to point at target in s -- used by the baseline tests
// below to protect a tree under runBaselineTree's own ref naming (#437,
// RM-274), the exact shape internal/gateway/snapshot.go's own
// protectBaseline writes with the real Snapshotter.
func (s *bareStore) updateRef(t *testing.T, ref, target string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), s.gitPath, "update-ref", ref, target)
	cmd.Dir = s.dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+s.dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git update-ref %s %s: %v: %s", ref, target, err, out)
	}
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func TestRPG003NumstatAddModifyDelete(t *testing.T) {
	store := newBareStore(t)
	blobA := store.blob(t, "one\ntwo\n")
	blobA2 := store.blob(t, "one\ntwo\nTHREE\n")
	blobB := store.blob(t, "stays\n")

	before := store.tree(t, map[string]string{"a.txt": blobA, "b.txt": blobB, "gone.txt": blobB})
	after := store.tree(t, map[string]string{"a.txt": blobA2, "b.txt": blobB, "new.txt": blobA})

	rows, err := diffTreeNumstat(context.Background(), store.cfg, store.dir, before, after)
	if err != nil {
		t.Fatalf("diffTreeNumstat: %v", err)
	}
	byPath := map[string]numstatFile{}
	for _, r := range rows {
		byPath[r.Path] = r
	}

	if got := byPath["a.txt"]; got.Status != "M" || got.Additions != 1 {
		t.Errorf("a.txt = %+v, want Status=M Additions=1", got)
	}
	if got := byPath["new.txt"]; got.Status != "A" {
		t.Errorf("new.txt = %+v, want Status=A", got)
	}
	if got := byPath["gone.txt"]; got.Status != "D" {
		t.Errorf("gone.txt = %+v, want Status=D", got)
	}
	if _, touched := byPath["b.txt"]; touched {
		t.Errorf("b.txt was not changed and must not appear: %+v", byPath["b.txt"])
	}
}

func TestRPG003NumstatRename(t *testing.T) {
	store := newBareStore(t)
	content := "the quick brown fox jumps over the lazy dog\nwith enough lines\nto let -M detect a rename\nrather than a delete plus an add\n"
	blob := store.blob(t, content)

	before := store.tree(t, map[string]string{"old-name.txt": blob})
	after := store.tree(t, map[string]string{"new-name.txt": blob})

	rows, err := diffTreeNumstat(context.Background(), store.cfg, store.dir, before, after)
	if err != nil {
		t.Fatalf("diffTreeNumstat: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Status != "R" {
		t.Fatalf("Status = %q, want R: %+v", rows[0].Status, rows[0])
	}
	if rows[0].OldPath != "old-name.txt" || rows[0].Path != "new-name.txt" {
		t.Errorf("OldPath/Path = %q/%q, want old-name.txt / new-name.txt", rows[0].OldPath, rows[0].Path)
	}
}

func TestRPG003NumstatBinary(t *testing.T) {
	store := newBareStore(t)
	blob := store.blob(t, "\x00\x01\x02binary\x00content")
	before := store.tree(t, map[string]string{})
	after := store.tree(t, map[string]string{"blob.bin": blob})

	rows, err := diffTreeNumstat(context.Background(), store.cfg, store.dir, before, after)
	if err != nil {
		t.Fatalf("diffTreeNumstat: %v", err)
	}
	if len(rows) != 1 || !rows[0].Binary {
		t.Fatalf("rows = %+v, want one binary entry", rows)
	}
	if rows[0].Status != "A" {
		t.Errorf("a newly added binary file's status = %q, want A", rows[0].Status)
	}
}

func TestRPG003NumstatEmptyBeforeAnswersNothing(t *testing.T) {
	store := newBareStore(t)
	blob := store.blob(t, "content\n")
	after := store.tree(t, map[string]string{"a.txt": blob})

	rows, err := diffTreeNumstat(context.Background(), store.cfg, store.dir, "", after)
	if err != nil {
		t.Fatalf("diffTreeNumstat: %v", err)
	}
	if rows != nil {
		t.Errorf("an unknown before must answer no files, not a diff of everything: %+v", rows)
	}
}

// ---------------------------------------------------------------------------
// runBaselineTree -- #437 (RM-274): reading back the gateway's own
// SnapshotBaseline (internal/gateway/snapshot.go) from its store.
// ---------------------------------------------------------------------------

// TestRunBaselineTreeFindsAProtectedBaseline proves the read side resolves
// the IDENTICAL ref name the gateway's own protectBaseline writes to --
// baselineRefPrefix and baselineKeySource restated byte for byte, never
// imported (this file's own package comment says why).
func TestRunBaselineTreeFindsAProtectedBaseline(t *testing.T) {
	store := newBareStore(t)
	blob := store.blob(t, "content\n")
	baseline := store.tree(t, map[string]string{"a.txt": blob})
	ref := baselineRefPrefix + hashRepoKey(baselineKeySource, "run-baseline-read-001")
	store.updateRef(t, ref, baseline)

	got := runBaselineTree(context.Background(), store.cfg, store.dir, "run-baseline-read-001")
	if got != baseline {
		t.Errorf("runBaselineTree = %q, want %q", got, baseline)
	}
}

// TestRunBaselineTreeAnswersEmptyWhenNoneExists proves the "understate,
// never guess" rule: a run this store holds no baseline ref for — never
// baselined at all (a deployment from before #437), or simply a different
// run — answers "", never an error and never another run's own baseline.
func TestRunBaselineTreeAnswersEmptyWhenNoneExists(t *testing.T) {
	store := newBareStore(t)
	blob := store.blob(t, "content\n")
	baseline := store.tree(t, map[string]string{"a.txt": blob})
	store.updateRef(t, baselineRefPrefix+hashRepoKey(baselineKeySource, "run-baseline-read-002"), baseline)

	// A DIFFERENT run id, never baselined in this same store.
	got := runBaselineTree(context.Background(), store.cfg, store.dir, "run-baseline-read-003")
	if got != "" {
		t.Errorf("runBaselineTree for an unbaselined run = %q, want empty", got)
	}
}

func TestRepoKeyPrefersOriginOverRootCommit(t *testing.T) {
	gitPath := requireGit(t)
	repoDir := t.TempDir()
	runGitT(t, repoDir, "init", "-q", "-b", "main")
	runGitT(t, repoDir, "remote", "add", "origin", "https://example.invalid/a/b.git")
	blob := hashObject(t, repoDir, gitPath, "x\n")
	tree := mktreeIn(t, repoDir, gitPath, map[string]string{"x.txt": blob})
	commitTreeIn(t, repoDir, gitPath, tree, nil, "c")

	cfg := snapshotStoreConfig{gitPath: gitPath}
	key, ok := repoKey(context.Background(), cfg, repoDir)
	if !ok {
		t.Fatal("repoKey should succeed when origin is configured")
	}
	want := hashRepoKey("origin", "https://example.invalid/a/b.git")
	if key != want {
		t.Errorf("key = %q, want the one derived from the origin remote (%q)", key, want)
	}
}

func TestRepoKeyFallsBackToRootCommitWithNoOrigin(t *testing.T) {
	gitPath := requireGit(t)
	repoDir := t.TempDir()
	runGitT(t, repoDir, "init", "-q", "-b", "main")
	blob := hashObject(t, repoDir, gitPath, "x\n")
	tree := mktreeIn(t, repoDir, gitPath, map[string]string{"x.txt": blob})
	runGitT(t, repoDir, "update-ref", "refs/heads/main", commitTreeIn(t, repoDir, gitPath, tree, nil, "c"))

	cfg := snapshotStoreConfig{gitPath: gitPath}
	_, ok := repoKey(context.Background(), cfg, repoDir)
	if !ok {
		t.Fatal("repoKey should fall back to the root commit")
	}
}

func TestRepoKeyFailsWithNeitherOriginNorCommit(t *testing.T) {
	gitPath := requireGit(t)
	repoDir := t.TempDir()
	runGitT(t, repoDir, "init", "-q", "-b", "main")

	cfg := snapshotStoreConfig{gitPath: gitPath}
	if _, ok := repoKey(context.Background(), cfg, repoDir); ok {
		t.Error("an empty repository with no origin should answer no key")
	}
}

func TestStoreDirForWithNoConfiguration(t *testing.T) {
	rs := &recordServer{}
	if _, ok := rs.storeDirFor(context.Background(), "some/repo"); ok {
		t.Error("an unconfigured recordServer should answer no store")
	}
}

// TestRunBaselineWithNoConfigurationAnswersEmpty: #437 (RM-274)'s own
// recordServer-level wrapper answers "" the same way runBaselineTree's own
// callers already do for every other "no store" case — never an error, and
// never a guess.
func TestRunBaselineWithNoConfigurationAnswersEmpty(t *testing.T) {
	rs := &recordServer{}
	if got := rs.runBaseline(context.Background(), "some/repo", "run-x"); got != "" {
		t.Errorf("runBaseline for an unconfigured recordServer = %q, want empty", got)
	}
}

func TestCommitSubjectForAnUnservedRepository(t *testing.T) {
	f := newRecordFixture(t)
	if _, ok := f.rs.commitSubject(t.Context(), "github.com/nobody/nothing", strings.Repeat("a", 40)); ok {
		t.Error("a repository this deployment does not serve should answer no subject")
	}
	if _, ok := f.rs.commitSubject(t.Context(), "", ""); ok {
		t.Error("an empty repo/sha should answer no subject")
	}
}

func TestRPG003NumstatIdenticalTreesAnswerNothing(t *testing.T) {
	store := newBareStore(t)
	blob := store.blob(t, "content\n")
	tree := store.tree(t, map[string]string{"a.txt": blob})

	rows, err := diffTreeNumstat(context.Background(), store.cfg, store.dir, tree, tree)
	if err != nil {
		t.Fatalf("diffTreeNumstat: %v", err)
	}
	if rows != nil {
		t.Errorf("before == after must answer no files: %+v", rows)
	}
}
