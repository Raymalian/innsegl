// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// docs/07-innsegl-test-catalog.md, TC-SNAP (E16 #383, ADR-0060 decision 5):
// a Snapshotter witnesses a working tree's state into a per-repository git
// object store under a configured root, never the project's own ".git", and
// a SnapshotTrigger decides when one is worth taking. Every fixture here is
// real git in a temp directory -- a project repo, and a separate store
// root -- exactly as the issue asks.

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

func snapGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git -C %s %v: %v\n%s", dir, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// snapNewProject creates a real repository at dir, with an "origin" remote
// (SnapshotTrigger's per-repository key comes from it) and one committed
// file, so the fixture is never an unborn-HEAD edge case by accident.
func snapNewProject(t *testing.T, dir, origin string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	snapGit(t, dir, "init", "-q", "-b", "main")
	snapGit(t, dir, "config", "user.email", "snapshot-test@example.com")
	snapGit(t, dir, "config", "user.name", "Snapshot Test")
	snapGit(t, dir, "remote", "add", "origin", origin)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("seeding README: %v", err)
	}
	snapGit(t, dir, "add", "README")
	snapGit(t, dir, "commit", "-q", "-m", "seed", "--no-gpg-sign")
}

// snapDotGitDigest hashes every regular file under dir/.git -- path and
// content both -- into one combined digest, so SNAP-001 can assert the
// project's own ".git" (its index included) is byte-identical before and
// after a snapshot, without special-casing any one file inside it.
func snapDotGitDigest(t *testing.T, projectDir string) string {
	t.Helper()
	root := filepath.Join(projectDir, ".git")
	var paths []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			paths = append(paths, rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, rel := range paths {
		content, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(content))
		h.Write(content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// snapStoreDir answers the one repository subdirectory a Snapshotter has
// created under storeRoot so far. Fails the test if there is not exactly
// one -- every test in this file snapshots a single repository per store
// root.
func snapStoreDir(t *testing.T, storeRoot string) string {
	t.Helper()
	entries, err := os.ReadDir(storeRoot)
	if err != nil {
		t.Fatalf("reading store root %s: %v", storeRoot, err)
	}
	if len(entries) != 1 {
		t.Fatalf("store root %s holds %d repository directories, want exactly 1", storeRoot, len(entries))
	}
	return filepath.Join(storeRoot, entries[0].Name())
}

// snapObjectExists reports whether hash is a readable object in the bare
// store at storeDir.
func snapObjectExists(t *testing.T, storeDir, hash string) bool {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", "--git-dir", storeDir, "cat-file", "-e", hash)
	return cmd.Run() == nil
}

func snapMustSnapshotter(t *testing.T, cfg SnapshotConfig) *Snapshotter {
	t.Helper()
	s, err := NewSnapshotter(cfg)
	if err != nil {
		t.Fatalf("NewSnapshotter: %v", err)
	}
	return s
}

// snapListBlobs answers every blob hash `git ls-tree -r` reports reachable
// from treeHash, read from the store alone.
func snapListBlobs(t *testing.T, storeDir, treeHash string) []string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", "--git-dir", storeDir, "ls-tree", "-r", treeHash)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git --git-dir %s ls-tree -r %s: %v", storeDir, treeHash, err)
	}
	var hashes []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		// "<mode> <type> <hash>\t<path>" -- Fields splits on the tab too.
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			hashes = append(hashes, fields[2])
		}
	}
	return hashes
}

// snapFsck runs `git fsck --full` against the store alone and answers its
// combined output and error.
func snapFsck(t *testing.T, storeDir string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", "--git-dir", storeDir, "fsck", "--full")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---------------------------------------------------------------------------
// Validation, beside the catalog's own named cases.
// ---------------------------------------------------------------------------

func TestNewSnapshotterRejectsAnEmptyOrRelativeStoreRoot(t *testing.T) {
	if _, err := NewSnapshotter(SnapshotConfig{}); err == nil {
		t.Fatal("an empty store root was accepted")
	}
	if _, err := NewSnapshotter(SnapshotConfig{StoreRoot: "relative/store"}); err == nil {
		t.Fatal("a relative store root was accepted")
	}
}

func TestSnapshotRejectsAnEmptyOrRelativeOrNonexistentWorkingDirectory(t *testing.T) {
	projects := t.TempDir()
	store := t.TempDir()
	// An empty entry in ProjectRoots (mcp.ProjectMountRoots's own shape when
	// EnvHostProjects is unset) is skipped rather than matched.
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{"", projects}})
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		dir  string
	}{
		{"empty", ""},
		{"relative", "relative/dir"},
		{"nonexistent, under the mount", filepath.Join(projects, "does-not-exist")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome := snap.Snapshot(ctx, tc.dir)
			if outcome.Snapshotted() {
				t.Fatalf("%q was snapshotted: %+v", tc.dir, outcome)
			}
			if outcome.Reason == "" {
				t.Fatalf("%q was refused with no reason", tc.dir)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SNAP-001
// ---------------------------------------------------------------------------

// TestSNAP001SnapshotLeavesTheProjectsGitAndIndexByteIdentical proves the
// half of ADR-0060 decision 5 that matters most: nothing this file does may
// ever be observed by the project's own git. Every byte under the project's
// ".git" -- its real index included -- is identical before and after.
func TestSNAP001SnapshotLeavesTheProjectsGitAndIndexByteIdentical(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snap001.git")
	// Leave something staged but uncommitted in the REAL index, so a
	// snapshot that carelessly touched it would be caught even if it left
	// HEAD and the commit graph alone.
	if err := os.WriteFile(filepath.Join(repo, "staged.txt"), []byte("staged\n"), 0o644); err != nil {
		t.Fatalf("writing staged.txt: %v", err)
	}
	snapGit(t, repo, "add", "staged.txt")

	before := snapDotGitDigest(t, repo)

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})

	outcome := snap.Snapshot(context.Background(), repo)
	if !outcome.Snapshotted() {
		t.Fatalf("Snapshot refused: %s", outcome.Reason)
	}
	if outcome.TreeHash == "" {
		t.Fatal("Snapshot answered no tree hash on success")
	}

	after := snapDotGitDigest(t, repo)
	if before != after {
		t.Fatalf("the project's own .git changed:\nbefore %s\nafter  %s", before, after)
	}
}

// ---------------------------------------------------------------------------
// SNAP-002
// ---------------------------------------------------------------------------

// TestSNAP002RevertedWorkingTreeHashesBackToTheOriginal walks the spike's
// own sequence -- create, edit, a command-made change, delete back to the
// original -- and checks each step's tree against the one before it.
func TestSNAP002RevertedWorkingTreeHashesBackToTheOriginal(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snap002.git")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})
	ctx := context.Background()

	snapshot := func(step string) string {
		t.Helper()
		outcome := snap.Snapshot(ctx, repo)
		if !outcome.Snapshotted() {
			t.Fatalf("%s: Snapshot refused: %s", step, outcome.Reason)
		}
		return outcome.TreeHash
	}

	notes := filepath.Join(repo, "notes.txt")

	original := snapshot("baseline (no notes.txt yet)")

	if err := os.WriteFile(notes, []byte("version one\n"), 0o644); err != nil {
		t.Fatalf("create notes.txt: %v", err)
	}
	created := snapshot("create")
	if created == original {
		t.Fatal("creating notes.txt did not change the snapshot")
	}

	if err := os.WriteFile(notes, []byte("version two\n"), 0o644); err != nil {
		t.Fatalf("edit notes.txt: %v", err)
	}
	edited := snapshot("edit")
	if edited == created {
		t.Fatal("editing notes.txt did not change the snapshot")
	}

	// A command-made change: an external process edits the file, not this
	// test's own Go code -- the spike's own "sed two -> three" step.
	// Written without sed -i, whose flag differs between BSD and GNU sed: the
	// macOS form failed on Linux CI.
	sed := exec.CommandContext(ctx, "sh", "-c",
		`sed 's/version two/version three/' "$1" > "$1.tmp" && mv "$1.tmp" "$1"`, "sh", notes)
	if out, err := sed.CombinedOutput(); err != nil {
		t.Fatalf("sed: %v\n%s", err, out)
	}
	commandChanged := snapshot("command-made change")
	if commandChanged == edited {
		t.Fatal("the command-made change did not change the snapshot")
	}

	if err := os.Remove(notes); err != nil {
		t.Fatalf("delete notes.txt: %v", err)
	}
	reverted := snapshot("delete back to the original")
	if reverted != original {
		t.Fatalf("reverted tree %s does not equal the original %s", reverted, original)
	}
}

// ---------------------------------------------------------------------------
// SNAP-003
// ---------------------------------------------------------------------------

// TestSNAP003TriggerFiresForATooLResultNotInTheLastBlock is the spike's own
// bug (docs/decisions/model-gateway-spike.md, spike 3B): a new tool_result
// that is not the last one RequestFacts.ToolResultIDs holds must still fire.
func TestSNAP003TriggerFiresForATooLResultNotInTheLastBlock(t *testing.T) {
	trigger := NewSnapshotTrigger()
	const key = "run-1"

	// First request: one tool result already witnessed.
	if !trigger.Fire(key, RequestFacts{ToolResultIDs: []string{"toolu_seen"}}) {
		t.Fatal("the first tool result of a run did not fire")
	}

	// Claude Code resends the whole conversation on every request: the
	// SAME already-seen id resent, but with a NEW id ahead of it -- not in
	// the last position.
	fired := trigger.Fire(key, RequestFacts{ToolResultIDs: []string{"toolu_new", "toolu_seen"}})
	if !fired {
		t.Fatal("a new tool result that was not the last block did not fire")
	}

	// The same two ids again, with nothing new: must not re-fire.
	if trigger.Fire(key, RequestFacts{ToolResultIDs: []string{"toolu_new", "toolu_seen"}}) {
		t.Fatal("a request with no new tool result fired anyway")
	}
}

func TestSNAP003TriggerIsIsolatedPerKey(t *testing.T) {
	trigger := NewSnapshotTrigger()
	if !trigger.Fire("run-a", RequestFacts{ToolResultIDs: []string{"toolu_1"}}) {
		t.Fatal("run-a's first tool result did not fire")
	}
	// A DIFFERENT run's identical tool_use id is still new to that run.
	if !trigger.Fire("run-b", RequestFacts{ToolResultIDs: []string{"toolu_1"}}) {
		t.Fatal("run-b's first tool result did not fire, even though run-a had already seen the same id")
	}
}

func TestSNAP003TriggerDoesNotFireWithNoToolResults(t *testing.T) {
	trigger := NewSnapshotTrigger()
	if trigger.Fire("run-1", RequestFacts{}) {
		t.Fatal("a request carrying no tool results fired")
	}
}

// ---------------------------------------------------------------------------
// SNAP-004
// ---------------------------------------------------------------------------

// TestSNAP004OutsideMountOrNotARepositoryReturnsAReasonWithoutSnapshotting
// covers the catalog row's two named cases. Snapshots witness, never gate:
// both answer a reason and no tree hash, never an error.
func TestSNAP004OutsideMountOrNotARepositoryReturnsAReasonWithoutSnapshotting(t *testing.T) {
	ctx := context.Background()

	t.Run("outside every configured projects mount", func(t *testing.T) {
		projects := t.TempDir()
		// A REAL, otherwise-snapshottable repository, deliberately outside
		// projects: this has to be refused for being outside the mount
		// specifically, not merely because it happens to fail some other
		// check too.
		outside := filepath.Join(t.TempDir(), "repo")
		snapNewProject(t, outside, "git@example.com:innsegl-test/snap004-outside.git")
		store := t.TempDir()
		snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})

		outcome := snap.Snapshot(ctx, outside)
		if outcome.Snapshotted() {
			t.Fatalf("a directory outside the mount was snapshotted: %+v", outcome)
		}
		if outcome.Reason == "" {
			t.Fatal("no reason was given for a directory outside the mount")
		}
	})

	t.Run("not a repository", func(t *testing.T) {
		projects := t.TempDir()
		notARepo := filepath.Join(projects, "not-a-repo")
		if err := os.MkdirAll(notARepo, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		store := t.TempDir()
		snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})

		outcome := snap.Snapshot(ctx, notARepo)
		if outcome.Snapshotted() {
			t.Fatalf("a non-repository directory was snapshotted: %+v", outcome)
		}
		if outcome.Reason == "" {
			t.Fatal("no reason was given for a directory that is not a repository")
		}
	})
}

// ---------------------------------------------------------------------------
// SNAP-005
// ---------------------------------------------------------------------------

// TestSNAP005TheStoreIsBoundedAndPrunesTheOldestUnreferencedObjects grows a
// repository's own store past a small configured cap across several
// snapshots, and checks that the oldest snapshot's tree is gone while the
// newest is still readable, and the store is back at or under the cap.
func TestSNAP005TheStoreIsBoundedAndPrunesTheOldestUnreferencedObjects(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snap005.git")

	store := t.TempDir()
	const cap5 = 20_000 // bytes -- small enough that a handful of snapshots overflow it
	snap := snapMustSnapshotter(t, SnapshotConfig{
		StoreRoot:         store,
		ProjectRoots:      []string{projects},
		MaxRepoStoreBytes: cap5,
	})
	ctx := context.Background()

	big := filepath.Join(repo, "big.txt")
	var hashes []string
	for i := range 8 {
		content := strings.Repeat(fmt.Sprintf("payload-%02d-", i), 500) // a few KB of UNIQUE content each round
		if err := os.WriteFile(big, []byte(content), 0o644); err != nil {
			t.Fatalf("round %d: writing big.txt: %v", i, err)
		}
		outcome := snap.Snapshot(ctx, repo)
		if !outcome.Snapshotted() {
			t.Fatalf("round %d: Snapshot refused: %s", i, outcome.Reason)
		}
		hashes = append(hashes, outcome.TreeHash)
	}

	storeDir := snapStoreDir(t, store)

	if snapObjectExists(t, storeDir, hashes[0]) {
		t.Fatalf("the oldest snapshot (%s) was not pruned", hashes[0])
	}
	if !snapObjectExists(t, storeDir, hashes[len(hashes)-1]) {
		t.Fatalf("the newest snapshot (%s) was pruned", hashes[len(hashes)-1])
	}

	if got := snap.storeSize(storeDir); got > cap5*2 {
		// A generous multiple of the cap, not the cap itself: the store
		// can never shrink below whatever its single newest live snapshot
		// costs, and a bare repository's own fixed files (HEAD, config,
		// description, hooks/, info/) add a small, constant overhead on
		// top of that. The point of this assertion is that pruning ran at
		// all, not that it hit the cap exactly.
		t.Fatalf("store size %d is not bounded anywhere near the configured cap %d", got, cap5)
	}
}

// ---------------------------------------------------------------------------
// Store independence (review finding on #383's first commit): a snapshot's
// evidence must survive an agent later deleting or pruning the PROJECT's own
// objects -- exactly the reverted-change case this witness exists for.
// ADR-0060 decision 5 calls the store "unreachable by agents"; a store whose
// objects are only reachable BY WAY OF the project's own object database,
// through a read-only alternates hint, is not actually independent of it,
// even though nothing ever writes through that hint.
// ---------------------------------------------------------------------------

// TestSnapshotStoreIsSelfContainedAfterTheProjectsObjectsAreRemoved takes a
// real snapshot, then deletes the PROJECT's own ".git/objects" -- simulating
// an agent's reset or gc after the snapshot was taken -- and checks that
// every object `git ls-tree -r` reports reachable from the snapshot's tree
// is still readable from the store alone, and that `git fsck --full` on the
// store reports nothing broken.
func TestSnapshotStoreIsSelfContainedAfterTheProjectsObjectsAreRemoved(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/selfcontained.git")
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("content that must survive\n"), 0o644); err != nil {
		t.Fatalf("writing notes.txt: %v", err)
	}

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})

	outcome := snap.Snapshot(context.Background(), repo)
	if !outcome.Snapshotted() {
		t.Fatalf("Snapshot refused: %s", outcome.Reason)
	}

	storeDir := snapStoreDir(t, store)
	blobs := snapListBlobs(t, storeDir, outcome.TreeHash)
	if len(blobs) == 0 {
		t.Fatal("the tree listed no blobs to check -- the fixture is not exercising anything")
	}

	if err := os.RemoveAll(filepath.Join(repo, ".git", "objects")); err != nil {
		t.Fatalf("removing the project's own objects: %v", err)
	}
	// A git object database with no loose or pack objects at all, the same
	// shape a fresh `git init` leaves -- not a missing directory, which
	// would be a different (and less realistic) failure mode than "the
	// content is gone".
	if err := os.MkdirAll(filepath.Join(repo, ".git", "objects", "pack"), 0o755); err != nil {
		t.Fatalf("recreating an empty objects/pack: %v", err)
	}

	for _, hash := range blobs {
		if !snapObjectExists(t, storeDir, hash) {
			t.Errorf(
				"blob %s is not readable from the store alone after the project's own objects "+
					"were removed -- the store depends on the project's object database", hash)
		}
	}
	if !snapObjectExists(t, storeDir, outcome.TreeHash) {
		t.Errorf("tree %s is not readable from the store alone", outcome.TreeHash)
	}

	if out, err := snapFsck(t, storeDir); err != nil {
		t.Errorf("git fsck --full on the store failed after the project's objects were removed: %v\n%s", err, out)
	}
}

// ---------------------------------------------------------------------------
// Repository keying without an "origin" remote.
// ---------------------------------------------------------------------------

// snapInitNoOriginRepo creates a real repository at dir with no remote at
// all -- the case repoKey's origin-preferring path has nothing to read.
func snapInitNoOriginRepo(t *testing.T, dir, seedContent string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	snapGit(t, dir, "init", "-q", "-b", "main")
	snapGit(t, dir, "config", "user.email", "snapshot-test@example.com")
	snapGit(t, dir, "config", "user.name", "Snapshot Test")
	if err := os.WriteFile(filepath.Join(dir, "seed"), []byte(seedContent), 0o644); err != nil {
		t.Fatalf("seeding %s: %v", dir, err)
	}
	snapGit(t, dir, "add", "seed")
	snapGit(t, dir, "commit", "-q", "-m", "seed", "--no-gpg-sign")
}

// TestSnapshotKeysARepositoryWithNoOriginStablyAndWithoutCollision proves
// repoKey's fallback: a repository with no "origin" remote is still
// snapshotted (never refused for that reason alone), two DIFFERENT such
// repositories land in two DIFFERENT store subdirectories -- never a shared
// bucket -- and snapshotting the SAME one twice lands in the SAME
// subdirectory both times.
func TestSnapshotKeysARepositoryWithNoOriginStablyAndWithoutCollision(t *testing.T) {
	projects := t.TempDir()
	repoA := filepath.Join(projects, "repo-a")
	repoB := filepath.Join(projects, "repo-b")
	snapInitNoOriginRepo(t, repoA, "a\n")
	snapInitNoOriginRepo(t, repoB, "b\n")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})
	ctx := context.Background()

	outcomeA := snap.Snapshot(ctx, repoA)
	if !outcomeA.Snapshotted() {
		t.Fatalf("repo-a (no origin) was refused: %s", outcomeA.Reason)
	}
	outcomeB := snap.Snapshot(ctx, repoB)
	if !outcomeB.Snapshotted() {
		t.Fatalf("repo-b (no origin) was refused: %s", outcomeB.Reason)
	}

	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatalf("reading store root: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf(
			"store root holds %d repository directories after two DIFFERENT origin-less "+
				"repositories were snapshotted, want 2 -- never a shared bucket", len(entries))
	}

	// Stability: snapshotting repo-a again lands in the SAME subdirectory.
	if outcome := snap.Snapshot(ctx, repoA); !outcome.Snapshotted() {
		t.Fatalf("repo-a's second snapshot was refused: %s", outcome.Reason)
	}
	entriesAfter, err := os.ReadDir(store)
	if err != nil {
		t.Fatalf("reading store root again: %v", err)
	}
	if len(entriesAfter) != 2 {
		t.Fatalf(
			"a second snapshot of the SAME origin-less repository created a new store "+
				"directory: now %d, want 2", len(entriesAfter))
	}
}

// TestSnapshotKeysARepositoryWithNoOriginAndNoCommitYet proves the second,
// last-resort fallback: a repository with no origin AND no commit yet
// (repoKey's first-commit fallback has nothing to read either) is still
// keyed stably, from its own common git directory, rather than refused.
func TestSnapshotKeysARepositoryWithNoOriginAndNoCommitYet(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	snapGit(t, repo, "init", "-q", "-b", "main")
	snapGit(t, repo, "config", "user.email", "snapshot-test@example.com")
	snapGit(t, repo, "config", "user.name", "Snapshot Test")
	if err := os.WriteFile(filepath.Join(repo, "untracked-but-real.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("writing a file: %v", err)
	}

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})

	outcome := snap.Snapshot(context.Background(), repo)
	if !outcome.Snapshotted() {
		t.Fatalf("a repository with no origin and no commit yet was refused: %s", outcome.Reason)
	}
	if outcome.TreeHash == "" {
		t.Fatal("Snapshot answered no tree hash on success")
	}
}

// ---------------------------------------------------------------------------
// SnapshotBaseline -- #437 (RM-274): a run's first step has no snapshot to
// call its own "before" unless one is taken before that step's tool ever
// runs. snapBaselineRef restates record.go's own storeGatewayToolCall-side
// naming (a run-keyed ref, hashed the same way repoKey's own sources are,
// under a prefix prune() never walks) so these tests can read the ref back
// by the exact name a real caller would look it up by -- never by assuming
// SnapshotBaseline's own internals beyond what Snapshot already proves.
// ---------------------------------------------------------------------------

func snapBaselineRef(runID string) string {
	return baselineRefPrefix + hashRepoKey(baselineKeySource, runID)
}

// snapRefTarget answers the object a ref in storeDir currently points at, or
// "" if the ref does not exist.
func snapRefTarget(t *testing.T, storeDir, ref string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", "--git-dir", storeDir, "rev-parse", "--verify", "--quiet", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// TestSnapshotBaselineProtectsATreeFindableByRunID proves the basic shape:
// a baseline is captured into the store (same as Snapshot), AND protected
// under a ref this run's own id resolves deterministically -- a reader
// holding only runID, never a sequence number or a point in time, can find
// it.
func TestSnapshotBaselineProtectsATreeFindableByRunID(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snapbaseline001.git")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})
	ctx := context.Background()

	outcome := snap.SnapshotBaseline(ctx, repo, "run-baseline-001")
	if !outcome.Snapshotted() {
		t.Fatalf("SnapshotBaseline refused: %s", outcome.Reason)
	}
	if outcome.TreeHash == "" {
		t.Fatal("SnapshotBaseline answered no tree hash on success")
	}

	storeDir := snapStoreDir(t, store)
	ref := snapBaselineRef("run-baseline-001")
	target := snapRefTarget(t, storeDir, ref)
	if target != outcome.TreeHash {
		t.Fatalf("ref %s = %q, want the baseline's own tree hash %q", ref, target, outcome.TreeHash)
	}
	if !snapObjectExists(t, storeDir, outcome.TreeHash) {
		t.Fatalf("baseline tree %s is not a readable object in the store", outcome.TreeHash)
	}
}

// TestSnapshotBaselineIsIdempotentPerRun proves a baseline already recorded
// for a run is never moved by a second call -- a gateway restart resetting
// whatever in-memory "already baselined" tracking a caller keeps must never
// be able to overwrite the FIRST tree a run's workspace ever held with
// whatever the workspace holds by the time a second call happens to run.
func TestSnapshotBaselineIsIdempotentPerRun(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snapbaseline002.git")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})
	ctx := context.Background()

	first := snap.SnapshotBaseline(ctx, repo, "run-baseline-002")
	if !first.Snapshotted() {
		t.Fatalf("first SnapshotBaseline refused: %s", first.Reason)
	}

	// The workspace changes AFTER the first baseline -- the second call must
	// not re-capture it.
	if err := os.WriteFile(filepath.Join(repo, "later.txt"), []byte("later\n"), 0o644); err != nil {
		t.Fatalf("writing later.txt: %v", err)
	}

	second := snap.SnapshotBaseline(ctx, repo, "run-baseline-002")
	if !second.Snapshotted() {
		t.Fatalf("second SnapshotBaseline refused: %s", second.Reason)
	}
	if second.TreeHash != first.TreeHash {
		t.Fatalf("second SnapshotBaseline moved the ref: first %s, second %s", first.TreeHash, second.TreeHash)
	}

	storeDir := snapStoreDir(t, store)
	if target := snapRefTarget(t, storeDir, snapBaselineRef("run-baseline-002")); target != first.TreeHash {
		t.Fatalf("baseline ref = %q after a second call, want it unchanged at %q", target, first.TreeHash)
	}
}

// TestSnapshotBaselineDistinctRunsGetDistinctBaselines proves two different
// runs sharing the SAME working tree at the SAME moment still land under two
// DIFFERENT refs -- never a shared bucket, the same guarantee repoKey
// already gives two different repositories.
func TestSnapshotBaselineDistinctRunsGetDistinctBaselines(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snapbaseline003.git")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{projects}})
	ctx := context.Background()

	a := snap.SnapshotBaseline(ctx, repo, "run-baseline-003a")
	b := snap.SnapshotBaseline(ctx, repo, "run-baseline-003b")
	if !a.Snapshotted() || !b.Snapshotted() {
		t.Fatalf("a baseline was refused: a=%+v b=%+v", a, b)
	}

	storeDir := snapStoreDir(t, store)
	refA := snapRefTarget(t, storeDir, snapBaselineRef("run-baseline-003a"))
	refB := snapRefTarget(t, storeDir, snapBaselineRef("run-baseline-003b"))
	if refA == "" || refB == "" {
		t.Fatalf("one baseline ref was not written: a=%q b=%q", refA, refB)
	}
	if refA != a.TreeHash || refB != b.TreeHash {
		t.Fatalf("a baseline ref did not point at its own call's tree hash: refA=%q a=%q refB=%q b=%q",
			refA, a.TreeHash, refB, b.TreeHash)
	}
}

// TestSnapshotBaselineSurvivesTheOrdinarySnapshotPruneSweep proves
// baselineRefPrefix is a namespace prune() never walks: enough ordinary
// Snapshot calls to force several rounds of "oldest numbered ref first"
// eviction (MaxRepoStoreBytes set to the smallest value that still leaves
// room for one snapshot, per prune's own "never below one" rule) leave an
// earlier-taken baseline exactly where it was.
func TestSnapshotBaselineSurvivesTheOrdinarySnapshotPruneSweep(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "repo")
	snapNewProject(t, repo, "git@example.com:innsegl-test/snapbaseline004.git")

	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{
		StoreRoot: store, ProjectRoots: []string{projects}, MaxRepoStoreBytes: 1,
	})
	ctx := context.Background()

	baseline := snap.SnapshotBaseline(ctx, repo, "run-baseline-004")
	if !baseline.Snapshotted() {
		t.Fatalf("SnapshotBaseline refused: %s", baseline.Reason)
	}

	notes := filepath.Join(repo, "notes.txt")
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(notes, []byte(strings.Repeat("x", i+1)), 0o644); err != nil {
			t.Fatalf("writing notes.txt: %v", err)
		}
		if outcome := snap.Snapshot(ctx, repo); !outcome.Snapshotted() {
			t.Fatalf("ordinary Snapshot %d refused: %s", i, outcome.Reason)
		}
	}

	storeDir := snapStoreDir(t, store)
	if target := snapRefTarget(t, storeDir, snapBaselineRef("run-baseline-004")); target != baseline.TreeHash {
		t.Fatalf("baseline ref = %q after the ordinary prune sweep, want it unchanged at %q",
			target, baseline.TreeHash)
	}
	if !snapObjectExists(t, storeDir, baseline.TreeHash) {
		t.Fatal("the baseline's own tree was collected despite its ref still existing")
	}
}

// TestSnapshotBaselineRejectsTheSameInvalidWorkingDirectoriesAsSnapshot:
// SnapshotBaseline shares Snapshot's own validation (underProjectRoot) --
// restated here rather than re-asserted case by case, since that function is
// already proven above.
func TestSnapshotBaselineRejectsTheSameInvalidWorkingDirectoriesAsSnapshot(t *testing.T) {
	store := t.TempDir()
	snap := snapMustSnapshotter(t, SnapshotConfig{StoreRoot: store, ProjectRoots: []string{t.TempDir()}})

	outcome := snap.SnapshotBaseline(context.Background(), "relative/dir", "run-baseline-005")
	if outcome.Snapshotted() {
		t.Fatalf("a relative working directory was accepted: %+v", outcome)
	}
	if outcome.Reason == "" {
		t.Fatal("refused with no reason")
	}
}
