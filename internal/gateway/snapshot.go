// SPDX-License-Identifier: Apache-2.0

package gateway

// snapshot.go is #383 (RM-238), E16: ADR-0060 decision 5's per-request
// witness of a working tree's state, plus the trigger that decides when one
// is worth taking. Recording the resulting hash onto a tool_call event's
// workspace_tree_hash (ADR-0061 member 3) is #381's job -- this file only
// produces the hash, or a reason there is none.
//
// # Witness, never gate
//
// Every exported entry point below answers with a reason instead of an
// error. There is no failure mode here that may ever block forwarding a
// request: a missing repository, a store that cannot be prepared, a git
// invocation that fails -- each is a Reason on the returned SnapshotOutcome,
// never something a caller has to decide whether to propagate. A caller
// that wants to alert on a persistently non-empty Reason may; nothing here
// asks it to refuse on one.
//
// # The technique (docs/decisions/model-gateway-spike.md, spike 3B)
//
// The spike's own words: "the gateway snapshots the agent's working tree
// with a private GIT_INDEX_FILE (add -A, write-tree), so the real index is
// untouched." This file is that technique, with a durable, bounded home for
// the trees it writes:
//
//   - GIT_DIR is this repository's own subdirectory of the configured
//     store root -- never the project's ".git". It is initialised once with
//     `git init --bare` (objects and refs, nothing else is ever added to
//     it) and reused on every later snapshot of the same repository.
//   - GIT_WORK_TREE is the project's own working tree, read and never
//     written: nothing here stages, commits, or moves a ref inside it.
//   - GIT_INDEX_FILE is a file that lives inside the STORE, private to
//     this file and never the project's own ".git/index". It persists
//     across calls (a warm index lets a later `add --all` skip re-hashing
//     a blob whose stat info has not changed), which is safe because
//     `--all` always reconciles the index against whatever the working
//     tree currently holds, including a deletion.
//
// # No alternates -- the store holds its own copy of every object
//
// ADR-0060 decision 5 allows a read-only `objects/info/alternates` hint at
// the project's own object database "if it helps performance". An earlier
// version of this file did that. It was wrong: `git add` and `write-tree`
// both skip writing a blob that already resolves through an alternate, so
// a store built that way holds trees whose blobs live ONLY in the
// project's own ".git" -- reachable BY WAY OF it, not independently of it.
// ADR-0060 decision 5 calls the store "unreachable by agents"; one whose
// content depends on a directory an agent's ordinary git access can freely
// reset, gc, or delete is not actually independent of it, even though
// nothing here ever writes through that dependency. Measured: after taking
// a snapshot with alternates pointed at the project, deleting the
// project's own "objects" left a blob the snapshot's tree names unreadable
// from the store alone, and `git fsck --full` on the store reported it as
// a broken link and a missing blob. That is exactly the case this witness
// exists for -- an agent reverting or pruning its own history -- so this
// file never uses alternates: every object `write-tree` names is written
// into the store's own object database, full stop.
//
// # A container-side working directory, and no second translation
//
// Snapshot's workingDirectory argument is already resolved onto this
// process's own filesystem. The one existing translation from a
// harness-reported HOST path onto that filesystem is
// internal/mcp/workspace.go's containerPath, reached in process through
// internal/mcp/gateway.go's exported ResolveWorkspaceForGateway (used
// elsewhere in this package by workspace.go's MCPWorkspaceResolver, over
// the SAME RequestFacts.WorkingDirectory this package's facts.go extracts).
// This file does not repeat that translation, and does not import anything
// that would let it: reusing it is whichever caller resolves a request's
// working directory before deciding to snapshot it at all, so a working
// directory this file receives is already addressed the one way this
// process addresses one.
//
// What IS reused directly, because it is a different and already-exported
// piece and not a second copy of that translation, is mcp.ProjectMountRoots
// -- the same list `git`'s own safe.directory allowlist is already built
// from (internal/mcp/sign_commit.go, #308) -- as this file's own default
// boundary for SnapshotConfig.ProjectRoots, and internal/signing.
// SafeDirectoryEnv, applied for the identical Docker-Desktop-bind-mount
// reason sign_commit.go already documents.
//
// # Bounded, and per repository
//
// Each repository's own store subdirectory is capped independently
// (SnapshotConfig.MaxRepoStoreBytes): after a snapshot is taken and
// protected by its own ref, this file prunes the OLDEST snapshot ref (and
// only then the objects that pruning that ref leaves unreferenced, via
// `git prune --expire=now`) until the store's on-disk size is back at or
// under the cap, or exactly one snapshot remains -- the newest snapshot a
// caller might be about to record a hash for is never the one removed to
// make room for itself.
//
// # A known limit, carried over from the spike unchanged
//
// `git add --all` respects the project's own .gitignore, so a snapshot
// sees only files inside the git working tree that git itself would track
// -- not ignored files, and nothing outside the tree. Two runs sharing one
// working tree still produce one mixed snapshot; ADR-0061's own scope note
// on workspace_tree_hash says this plainly: the hash is evidence of what
// the tree held, never a claim about who put it there.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
)

const (
	// DefaultMaxSnapshotStoreBytes bounds one repository's own snapshot
	// store, approximated as the total size of every file under its GIT_DIR
	// (objects, refs, and the small amount of bookkeeping beside them).
	// Sized generously above what a few dozen live snapshots of an ordinary
	// working tree hold, while still bounding a store that would otherwise
	// grow for as long as a repository keeps producing new tool results.
	DefaultMaxSnapshotStoreBytes int64 = 512 << 20 // 512 MiB

	// snapshotRefPrefix namespaces every ref this file creates. A ref here
	// is not a branch -- it exists only to keep one snapshot's tree (and
	// whatever it shares with an earlier one) reachable until this file
	// itself decides to let it go.
	snapshotRefPrefix = "refs/innsegl/snapshots/"

	// snapshotIndexFile is the private index's name inside a repository's
	// own store directory -- never ".git/index", and never inside the
	// project's own working tree.
	snapshotIndexFile = "innsegl-snapshot-index"

	snapshotNoGlobalGitconfig = ".innsegl-no-global-gitconfig"
)

// SnapshotConfig configures a Snapshotter.
type SnapshotConfig struct {
	// StoreRoot is the directory under which every repository gets its own
	// GIT_DIR subdirectory (ADR-0060 decision 5: inside the existing
	// body-store volume, never the project's own ".git"). Required, and
	// must be absolute -- a relative root would resolve against whatever
	// directory this process happens to be in.
	StoreRoot string

	// MaxRepoStoreBytes bounds one repository's own store. Zero or less
	// means DefaultMaxSnapshotStoreBytes.
	MaxRepoStoreBytes int64

	// ProjectRoots bounds which working directories Snapshot will ever
	// touch. Empty means mcp.ProjectMountRoots() -- the same roots this
	// deployment already trusts git's own safe.directory allowlist with.
	ProjectRoots []string

	// GitPath is the git binary. Empty means a PATH lookup.
	GitPath string
}

// SnapshotOutcome is what Snapshot answers: exactly one of a tree hash or a
// reason there is none. It is never an error a caller has to decide whether
// to propagate -- see this file's own "witness, never gate" note.
type SnapshotOutcome struct {
	// TreeHash is the git tree object id capturing the working tree's state
	// after the tool that triggered this snapshot ran (ADR-0061 member 3).
	// Empty exactly when Reason is not.
	TreeHash string
	// Reason explains why no snapshot was taken. Empty exactly when
	// TreeHash is not.
	Reason string
}

// Snapshotted reports whether a tree was actually captured.
func (o SnapshotOutcome) Snapshotted() bool { return o.Reason == "" }

// Snapshotter takes ADR-0060 decision 5's per-request workspace snapshots.
// Safe for concurrent use: every store-touching operation is serialised by
// one mutex, which trades cross-repository snapshot throughput for the
// simplest correct answer to "two snapshots of the same repository's
// private index at once" -- a request rate no single gateway process is
// expected to need to snapshot fast enough for that to matter (this file
// witnesses AFTER a request would be forwarded regardless).
type Snapshotter struct {
	storeRoot string
	maxBytes  int64
	roots     []string
	gitPath   string

	mu      sync.Mutex
	nextSeq int64
}

// NewSnapshotter builds a Snapshotter from cfg.
func NewSnapshotter(cfg SnapshotConfig) (*Snapshotter, error) {
	if cfg.StoreRoot == "" {
		return nil, errors.New("workspace snapshot: a store root is required")
	}
	if !filepath.IsAbs(cfg.StoreRoot) {
		return nil, fmt.Errorf(
			"workspace snapshot: store root %q is relative; it would resolve against whatever "+
				"directory this process happens to be in", cfg.StoreRoot)
	}

	maxBytes := cfg.MaxRepoStoreBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSnapshotStoreBytes
	}

	roots := cfg.ProjectRoots
	if len(roots) == 0 {
		roots = mcp.ProjectMountRoots()
	}

	gitPath := cfg.GitPath
	if gitPath == "" {
		gitPath = "git"
	}

	return &Snapshotter{
		storeRoot: filepath.Clean(cfg.StoreRoot),
		maxBytes:  maxBytes,
		roots:     roots,
		gitPath:   gitPath,
	}, nil
}

// Snapshot captures workingDirectory's current state as a git tree in this
// repository's own store, and returns its hash -- or a reason there is
// none. Nothing here is ever an error that would block forwarding the
// request that triggered it.
func (s *Snapshotter) Snapshot(ctx context.Context, workingDirectory string) SnapshotOutcome {
	dir, reason := s.underProjectRoot(workingDirectory)
	if reason != "" {
		return SnapshotOutcome{Reason: reason}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	top, commonDir, reason := s.discover(ctx, dir)
	if reason != "" {
		return SnapshotOutcome{Reason: reason}
	}
	key := s.repoKey(ctx, dir, commonDir)

	storeDir := filepath.Join(s.storeRoot, key)
	if err := s.ensureStore(ctx, storeDir); err != nil {
		return SnapshotOutcome{Reason: fmt.Sprintf(
			"workspace snapshot: the store for %s could not be prepared: %v", dir, err)}
	}

	indexFile := filepath.Join(storeDir, snapshotIndexFile)
	treeHash, err := s.writeTree(ctx, storeDir, top, indexFile)
	if err != nil {
		return SnapshotOutcome{Reason: fmt.Sprintf(
			"workspace snapshot: %s could not be captured: %v", dir, err)}
	}

	if err := s.protect(ctx, storeDir, treeHash); err != nil {
		// Captured but not protected: a later prune of this same store could
		// remove it before anything else ever names it. Honest to report no
		// snapshot at all rather than a hash that might already be gone by
		// the time a caller acts on it.
		return SnapshotOutcome{Reason: fmt.Sprintf(
			"workspace snapshot: %s was captured but could not be protected from pruning: %v",
			dir, err)}
	}

	s.prune(ctx, storeDir)

	return SnapshotOutcome{TreeHash: treeHash}
}

// underProjectRoot validates workingDirectory and answers its cleaned form,
// or a reason it can never be snapshotted: empty, relative (a harness or a
// caller reports its own absolute path; resolving a relative one here would
// describe whichever directory this process happens to be in), or outside
// every configured project root (SNAP-004).
func (s *Snapshotter) underProjectRoot(workingDirectory string) (dir, reason string) {
	if workingDirectory == "" {
		return "", "workspace snapshot: no working directory was given"
	}
	if !filepath.IsAbs(workingDirectory) {
		return "", fmt.Sprintf("workspace snapshot: %q is not an absolute path", workingDirectory)
	}
	clean := filepath.Clean(workingDirectory)
	for _, root := range s.roots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(root), clean)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return clean, ""
		}
	}
	return "", fmt.Sprintf(
		"workspace snapshot: %s is outside every configured projects mount", clean)
}

// discover answers the working tree's own top (GIT_WORK_TREE) and its
// repository's common git directory (used only for the best-effort
// alternates hint), or a reason dir is not a git working tree at all
// (SNAP-004). Run with git's own ordinary discovery -- no GIT_DIR override
// -- so a subdirectory of a working tree resolves to the tree it actually
// belongs to, the same as any plain `git` invocation would from there.
func (s *Snapshotter) discover(ctx context.Context, dir string) (top, commonDir, reason string) {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", "", fmt.Sprintf("workspace snapshot: %s does not exist", dir)
	}

	out, err := s.readGit(ctx, dir, "rev-parse", "--show-toplevel", "--git-common-dir")
	if err != nil {
		return "", "", fmt.Sprintf("workspace snapshot: %s is not a git working tree: %v", dir, err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return "", "", fmt.Sprintf(
			"workspace snapshot: %s's repository could not be resolved", dir)
	}

	top = strings.TrimSpace(lines[0])
	commonDir = strings.TrimSpace(lines[1])
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(top, commonDir)
	}
	return top, filepath.Clean(commonDir), ""
}

// repoKey derives the per-repository store key this file's own doc comment
// promises: stable across every worktree of one repository, and never a
// shared bucket between two different repositories. Three sources, tried in
// order, each disjoint from the others by its own hashed prefix so a value
// from one can never collide with a value from another:
//
//  1. The "origin" remote, when configured -- stable across every worktree
//     AND every host of one repository, because remote config is shared
//     verbatim project data, unlike any filesystem path a linked worktree's
//     ".git" file might record in another namespace's spelling. The same
//     source describe_workspace already prefers for the identifier it
//     derives (internal/mcp/workspace.go).
//  2. Failing that, the repository's OWN first commit -- equally stable
//     across every worktree and every clone of one repository, and immune
//     to the same namespace-spelling risk, for a repository that simply has
//     not been given a remote yet.
//  3. Failing that too (no origin AND no commit yet), commonDir -- this
//     process's own container-side path to the repository's common git
//     directory, already resolved by discover. Unique to this one checkout,
//     which is the most this file can promise for a repository with neither
//     a remote nor any history to key on yet.
//
// This function cannot itself refuse: discover already guarantees commonDir
// is non-empty by the time this is ever called, so the third source always
// answers something.
func (s *Snapshotter) repoKey(ctx context.Context, dir, commonDir string) string {
	if out, err := s.readGit(ctx, dir, "remote", "get-url", "origin"); err == nil {
		return hashRepoKey("origin", out)
	}
	if out, err := s.readGit(ctx, dir, "rev-list", "--max-parents=0", "HEAD"); err == nil {
		if first := firstLine(out); first != "" {
			return hashRepoKey("root-commit", first)
		}
	}
	return hashRepoKey("common-dir", commonDir)
}

// hashRepoKey hashes source (a disjointness tag, never empty) and material
// together, so a value read under one source can never collide with a
// value read under a different one even if the raw bytes happened to
// coincide.
func hashRepoKey(source, material string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + strings.TrimSpace(material)))
	return hex.EncodeToString(sum[:])
}

// firstLine answers s up to its first newline, or the whole of s if it has
// none. `git rev-list` can name more than one root commit for a repository
// with unrelated histories merged into it; the first is enough to key a
// store subdirectory and is deterministic for a given repository's own
// commit graph.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// readGit runs one read-only git query against dir with git's own ordinary
// repository discovery (no GIT_DIR or GIT_WORK_TREE override), isolated
// from this host's own git configuration the same way signCommitGitEnv
// isolates sign_commit's own reads (internal/mcp/sign_commit.go).
func (s *Snapshotter) readGit(ctx context.Context, dir string, args ...string) (string, error) {
	//nolint:gosec // G204: gitPath is configuration (default "git"); args are literal at every call site, never caller input
	cmd := exec.CommandContext(ctx, s.gitPath, args...)
	cmd.Dir = dir
	cmd.Env = s.isolatedEnv(s.storeRoot)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// isolatedEnv is the environment every git invocation in this file runs
// with: no `~/.gitconfig`, no alias, no credential helper, and the
// configured project roots trusted the same way sign_commit.go's
// signCommitGitEnv already trusts them for the identical Docker-Desktop
// bind-mount reason (#308) -- home points at homeDir so nothing here reads
// or writes any file outside what this file already owns or is reading.
func (s *Snapshotter) isolatedEnv(homeDir string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + homeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(homeDir, snapshotNoGlobalGitconfig),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
	}
	return append(env, signing.SafeDirectoryEnv(s.roots)...)
}

// storeEnv is isolatedEnv plus GIT_DIR, for every command that operates on
// a repository's own store rather than discovering one.
func (s *Snapshotter) storeEnv(storeDir string) []string {
	return append(s.isolatedEnv(storeDir), "GIT_DIR="+storeDir)
}

// snapshotEnv is storeEnv plus the two overrides that make `add` and
// `write-tree` read and record a project's working tree without ever
// touching that project's own ".git" or index: GIT_WORK_TREE and
// GIT_INDEX_FILE. See this file's own package comment.
func (s *Snapshotter) snapshotEnv(storeDir, workTree, indexFile string) []string {
	return append(s.storeEnv(storeDir), "GIT_WORK_TREE="+workTree, "GIT_INDEX_FILE="+indexFile)
}

// ensureStore makes sure storeDir is an initialised GIT_DIR -- objects and
// refs, nothing else (ADR-0060 decision 5), self-contained and never an
// alternates hint at anything outside it (see this file's own package
// comment) -- creating it with `git init --bare` on first use for this
// repository, and reusing it on every later call.
func (s *Snapshotter) ensureStore(ctx context.Context, storeDir string) error {
	if info, err := os.Stat(filepath.Join(storeDir, "objects")); err == nil && info.IsDir() {
		return nil
	}
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", storeDir, err)
	}

	//nolint:gosec // G204: gitPath is configuration (default "git"); storeDir is this file's own path under StoreRoot, never caller input
	cmd := exec.CommandContext(ctx, s.gitPath, "init", "--quiet", "--bare", storeDir)
	cmd.Env = s.storeEnv(storeDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init --bare %s: %w: %s", storeDir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeTree is the technique itself: `add --all` (never `-u`, which would
// silently miss a file the working tree never had tracked before -- a
// created file's own snapshot would then be indistinguishable from the one
// before it) against the private index, then `write-tree`. Neither command
// is ever given GIT_WORK_TREE without the matching GIT_INDEX_FILE override,
// so neither ever reads or writes the project's own index.
func (s *Snapshotter) writeTree(ctx context.Context, storeDir, workTree, indexFile string) (string, error) {
	env := s.snapshotEnv(storeDir, workTree, indexFile)

	//nolint:gosec // G204: gitPath is configuration (default "git"); "add"/"--all" are literal
	add := exec.CommandContext(ctx, s.gitPath, "add", "--all")
	add.Dir = workTree
	add.Env = env
	if out, err := add.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git add --all: %w: %s", err, strings.TrimSpace(string(out)))
	}

	//nolint:gosec // G204: gitPath is configuration (default "git"); "write-tree" is literal
	wt := exec.CommandContext(ctx, s.gitPath, "write-tree")
	wt.Dir = workTree
	wt.Env = env
	out, err := wt.Output()
	if err != nil {
		return "", fmt.Errorf("git write-tree: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// protect creates the next ref in this store's own snapshotRefPrefix
// namespace, pointing directly at treeHash. The ref's name is a
// zero-padded, strictly monotonic sequence number (this Snapshotter's own
// counter, never the wall clock), so lexicographic order is chronological
// order and prune's "oldest" is exactly "first name in a sorted listing".
func (s *Snapshotter) protect(ctx context.Context, storeDir, treeHash string) error {
	s.nextSeq++
	ref := fmt.Sprintf("%s%020d", snapshotRefPrefix, s.nextSeq)
	//nolint:gosec // G204: gitPath is configuration (default "git"); ref is this file's own generated name, treeHash is this call's own write-tree result
	cmd := exec.CommandContext(ctx, s.gitPath, "update-ref", ref, treeHash)
	cmd.Env = s.storeEnv(storeDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git update-ref %s %s: %w: %s", ref, treeHash, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// prune drops the oldest protected snapshot, and then the objects that
// leaves unreferenced, until storeDir's on-disk size is at or under this
// Snapshotter's configured cap -- or until exactly one snapshot is left,
// which is never removed regardless of the cap (SNAP-005). Every failure
// here stops this round rather than looping or surfacing: pruning is
// housekeeping for a snapshot this call has ALREADY captured and protected,
// so nothing about it may turn that snapshot's own success into a failure.
func (s *Snapshotter) prune(ctx context.Context, storeDir string) {
	for s.storeSize(storeDir) > s.maxBytes {
		refs, err := s.listSnapshotRefs(ctx, storeDir)
		if err != nil || len(refs) <= 1 {
			return
		}
		if err := s.deleteRef(ctx, storeDir, refs[0]); err != nil {
			return
		}
		if err := s.gitPruneNow(ctx, storeDir); err != nil {
			return
		}
	}
}

// listSnapshotRefs answers every live ref in this store's snapshotRefPrefix
// namespace, sorted oldest first (see protect's own comment on why a plain
// name sort is a chronological sort here).
func (s *Snapshotter) listSnapshotRefs(ctx context.Context, storeDir string) ([]string, error) {
	//nolint:gosec // G204: gitPath is configuration (default "git"); every other argument is literal
	cmd := exec.CommandContext(ctx, s.gitPath,
		"for-each-ref", "--format=%(refname)", "--sort=refname", snapshotRefPrefix)
	cmd.Env = s.storeEnv(storeDir)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

func (s *Snapshotter) deleteRef(ctx context.Context, storeDir, ref string) error {
	//nolint:gosec // G204: gitPath is configuration (default "git"); ref is this file's own generated name, listed back from this same store
	cmd := exec.CommandContext(ctx, s.gitPath, "update-ref", "-d", ref)
	cmd.Env = s.storeEnv(storeDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git update-ref -d %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Snapshotter) gitPruneNow(ctx context.Context, storeDir string) error {
	//nolint:gosec // G204: gitPath is configuration (default "git"); "prune"/"--expire=now" are literal
	cmd := exec.CommandContext(ctx, s.gitPath, "prune", "--expire=now")
	cmd.Env = s.storeEnv(storeDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git prune: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// storeSize approximates storeDir's on-disk size as the sum of every
// regular file under it. Best-effort: a stat failure on any one entry only
// under-counts that entry, and never turns a size check into an error this
// file would have to answer for.
func (s *Snapshotter) storeSize(storeDir string) int64 {
	var total int64
	discardWalkError(filepath.WalkDir(storeDir, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			//nolint:nilerr // best-effort accounting: an unreadable entry just under-counts, never blocks pruning or a snapshot
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			//nolint:nilerr // same as above: a failed Info() just under-counts this one entry
			return nil
		}
		total += info.Size()
		return nil
	}))
	return total
}

// discardWalkError is this file's own named discard, the same idiom
// facts.go's discardWriteError and proxy.go's discardCopyError already use:
// the error is passed to a function that deliberately does nothing with
// it, so errcheck sees it consumed rather than silently dropped, at a call
// site where losing it costs nothing -- storeSize is best-effort
// accounting, never a correctness requirement (see its own comment).
func discardWalkError(error) {}

// ---------------------------------------------------------------------------
// The trigger.
// ---------------------------------------------------------------------------

// SnapshotTrigger decides whether a request is worth snapshotting: exactly
// when it carries a tool_use id this tracker has not already witnessed
// under key. It reads RequestFacts.ToolResultIDs, which facts.go already
// collects from EVERY tool_result block in the whole request regardless of
// which message or which position in a message's content array carries it
// -- SNAP-003 exists because the spike's own gateway checked only the LAST
// content block instead (docs/decisions/model-gateway-spike.md, spike 3B:
// "the request after the sed step ended with a text block, not the
// tool_result, and the trigger looked only at the last block"). Fire scans
// every id ToolResultIDs holds, in whatever order they arrived, so a new
// result that is not the last one in the slice still fires.
//
// Safe for concurrent use.
type SnapshotTrigger struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
}

// NewSnapshotTrigger returns an empty trigger.
func NewSnapshotTrigger() *SnapshotTrigger {
	return &SnapshotTrigger{seen: make(map[string]map[string]struct{})}
}

// Fire reports whether facts carries at least one tool_use id under key
// that this tracker has not already seen, and records every id facts
// carries as seen from this call on -- so a later request that resends the
// same history (Claude Code resends the whole conversation on every
// request) never re-fires for a result this key has already witnessed.
func (t *SnapshotTrigger) Fire(key string, facts RequestFacts) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	ids, ok := t.seen[key]
	if !ok {
		ids = make(map[string]struct{})
		t.seen[key] = ids
	}

	fired := false
	for _, id := range facts.ToolResultIDs {
		if _, already := ids[id]; !already {
			fired = true
		}
		ids[id] = struct{}{}
	}
	return fired
}
