// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/signing"
)

// snapshotstore.go reads internal/gateway/snapshot.go's own store —
// /agentlog/gateway-snapshots/<repo-key>/, one bare GIT_DIR per repository —
// to answer what a step changed (files.go) and what one step's diff looks
// like (diff.go). It never writes to that store: every command here is a
// read, and `git prune`/`git update-ref` — the store's own housekeeping —
// belong to the gateway that owns it, never to this read-only process.
//
// # Finding the store: re-deriving the key, not being told it
//
// The store is keyed by repoKey (internal/gateway/snapshot.go), which the
// gateway derives from the repository itself — its "origin" remote, or
// failing that its root commit — never from a path, so that the SAME key
// comes out of the SAME repository regardless of which checkout computed
// it. Nothing records that key anywhere this process can read it back from
// (it is not on the chain — workspace_tree_hash is a tree id, not a store
// path), so this file recomputes it, against the SAME served checkout the
// proof BFF already reads (Server.prover), by running the identical two
// git queries in the identical order. A repository this deployment does not
// serve to the proof BFF (RepoPath returns false) cannot be resolved to a
// store at all; every caller here treats that exactly like a store that
// does not exist — files and diffs answer empty, never guessed.
//
// # Isolation
//
// Every command below runs with an explicit, minimal environment and a
// `safe.directory` entry for the ONE directory it is about to read —
// internal/gateway/snapshot.go's own isolatedEnv, restated here for a
// read-only reader of the SAME store rather than imported: that function is
// unexported to its own package, and its GIT_INDEX_FILE/GIT_WORK_TREE
// overrides answer a question this file never asks (nothing here ever
// touches a working tree). `--no-ext-diff` accompanies every diff-tree
// invocation so a project's own `.gitattributes` `diff=` driver — arbitrary
// configuration read from a tree this process does not control — can never
// run as this process.

// snapshotRoot is where ConfigureRecordRoutes was told the gateway's
// snapshot stores live. Set once, at start-up, through the same
// package-level Configure/restore shape internal/mcp already uses
// (observeActive, agentMessageActive) because Server (server.go) is not
// this issue's file to add a field to — see recordhandler.go.
type snapshotStoreConfig struct {
	root    string
	gitPath string
}

// repoKey re-derives internal/gateway/snapshot.go's own per-repository store
// key from a served checkout: the "origin" remote if one is configured,
// else the repository's own root commit, else a source this process can
// never reproduce from a different checkout (commonDir) — which is reported
// as "no store", never guessed at. Unlike the gateway's own repoKey, this
// never falls back to a directory path: this process was not the one that
// created the store, and a path-derived key computed here would only ever
// coincidentally match one computed from the gateway's own mount.
func repoKey(ctx context.Context, cfg snapshotStoreConfig, repoDir string) (string, bool) {
	if out, err := runGit(ctx, repoDir, isolatedGitEnv(repoDir), cfg.gitPath,
		"remote", "get-url", "origin"); err == nil {
		return hashRepoKey("origin", out), true
	}
	if out, err := runGit(ctx, repoDir, isolatedGitEnv(repoDir), cfg.gitPath,
		"rev-list", "--max-parents=0", "HEAD"); err == nil {
		if first := firstLine(out); first != "" {
			return hashRepoKey("root-commit", first), true
		}
	}
	return "", false
}

// hashRepoKey matches internal/gateway/snapshot.go's own construction byte
// for byte: sha256(source + "\x00" + trimmed material), hex-encoded. A
// different construction here would compute a DIFFERENT key for the
// IDENTICAL repository, and every lookup against the real store would miss.
func hashRepoKey(source, material string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + strings.TrimSpace(material)))
	return hex.EncodeToString(sum[:])
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// baselineRefPrefix and baselineKeySource match
// internal/gateway/snapshot.go's own constants of the identical name, byte
// for byte — restated here rather than imported, this file's own package
// comment's "re-derive, never be told" posture applied to a second value
// (#437, RM-274): a different construction here would look up a DIFFERENT
// ref name for the IDENTICAL run, and every baseline lookup would miss.
const (
	baselineRefPrefix = "refs/innsegl/baselines/"
	baselineKeySource = "run-baseline"
)

// runBaselineTree answers the workspace tree internal/gateway/snapshot.go's
// own SnapshotBaseline captured for runID before its first tool call ever
// ran, or "" when none was ever taken: a deployment running before #437
// shipped, a run whose first tool_use the gateway missed for any of the
// ordinary reasons a snapshot can fail (snapshot.go's own "witness, never
// gate"), or simply a run this store never heard of. Never an error — the
// same "understate, never guess" posture every other read in this file
// already holds for a tree it cannot resolve.
func runBaselineTree(ctx context.Context, cfg snapshotStoreConfig, storeDir, runID string) string {
	ref := baselineRefPrefix + hashRepoKey(baselineKeySource, runID)
	out, err := runStoreGit(ctx, cfg, storeDir, "rev-parse", "--verify", "--quiet", "--end-of-options", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// storeDirFor resolves repoName to its snapshot store directory, or false
// when this process cannot: the repository is not one the proof BFF serves,
// the store root is not configured, the checkout's key could not be
// derived, or the derived store simply is not on disk (a repository the
// gateway has never snapshotted at all — no tool call of any run in it ever
// triggered one).
func (rs *recordServer) storeDirFor(ctx context.Context, repoName string) (string, bool) {
	if rs.cfg.root == "" || repoName == "" {
		return "", false
	}
	repoDir, ok := rs.prover.RepoPath(repoName)
	if !ok {
		return "", false
	}
	key, ok := repoKey(ctx, rs.cfg, repoDir)
	if !ok {
		return "", false
	}
	dir := filepath.Join(rs.cfg.root, key)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", false
	}
	return dir, true
}

// isolatedGitEnv is this file's own minimal environment: no inherited
// gitconfig, no credential helper, no alias, and a safe.directory entry for
// exactly the one directory about to be read — never a wildcard root, and
// never the store root itself, because a caller here always names the
// specific checkout or store directory it is about to invoke git against.
func isolatedGitEnv(dir string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
	}
	return append(env, signing.SafeDirectoryEnv([]string{dir})...)
}

// runGit runs one read-only git command with an explicit argv and env —
// bounded by proof.go's own gitTimeout, the same bound Prover's own git
// invocations already use.
// never a caller-assembled string, and never the inherited environment.
func runGit(ctx context.Context, dir string, env []string, gitPath string, args ...string) (string, error) {
	if gitPath == "" {
		gitPath = "git"
	}
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// runStoreGit runs one read-only git command against a snapshot store's own
// bare GIT_DIR.
func runStoreGit(ctx context.Context, cfg snapshotStoreConfig, storeDir string, args ...string) (string, error) {
	env := append(isolatedGitEnv(storeDir), "GIT_DIR="+storeDir)
	return runGit(ctx, storeDir, env, cfg.gitPath, args...)
}

// ---------------------------------------------------------------------------
// What changed between two trees, for RecordFile (recordfiles.go).
// ---------------------------------------------------------------------------

// numstatFile is one file diff-tree found, merged from two runs against the
// SAME pair of trees: `--raw` for the authoritative status letter (numstat
// alone cannot tell an added binary file from a deleted one — its own line
// carries no status, only "-\t-"), and `--numstat` for the line counts.
type numstatFile struct {
	Path      string
	OldPath   string // set only for a rename (status R)
	Additions int
	Deletions int
	Status    string // A, M, D or R — record.go's own closed set
	Binary    bool
}

// diffTreeNumstat runs both diff-tree queries between before and after
// inside storeDir and merges them by path. before == "" answers no files at
// all — record.go's own rule that an unknown "before" must never be shown
// as a diff of everything — and before == after answers no files either,
// honestly: nothing changed, rather than one query asking git to diff a
// tree against itself.
func diffTreeNumstat(ctx context.Context, cfg snapshotStoreConfig, storeDir, before, after string) ([]numstatFile, error) {
	if before == "" || after == "" || before == after {
		return nil, nil
	}
	rawOut, err := runStoreGit(ctx, cfg, storeDir,
		"diff-tree", "--raw", "-M", "--no-color", "--no-ext-diff", "-r", "--end-of-options",
		before, after)
	if err != nil {
		return nil, err
	}
	numOut, err := runStoreGit(ctx, cfg, storeDir,
		"diff-tree", "--numstat", "-M", "--no-color", "--no-ext-diff", "-r", "--end-of-options",
		before, after)
	if err != nil {
		return nil, err
	}
	status := parseRawStatus(rawOut)
	return mergeNumstat(numOut, status), nil
}

// rawStatusEntry is one path's own verdict from `git diff-tree --raw -M`.
type rawStatusEntry struct {
	status  string // A, M, D, R or C — the single letter, score stripped
	oldPath string // set only for R or C
}

// parseRawStatus reads `--raw -M` lines:
// `:<old-mode> <new-mode> <old-sha> <new-sha> <status>\t<path>[\t<new-path>]`.
// Keyed by the path a plain add/modify/delete names, or by the NEW path of
// a rename — the same key mergeNumstat looks entries up by.
func parseRawStatus(out string) map[string]rawStatusEntry {
	entries := map[string]rawStatusEntry{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		meta, rest, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) < 5 || fields[4] == "" {
			continue
		}
		code := fields[4][:1]
		paths := strings.Split(rest, "\t")
		switch len(paths) {
		case 1:
			entries[paths[0]] = rawStatusEntry{status: code}
		case 2:
			entries[paths[1]] = rawStatusEntry{status: code, oldPath: paths[0]}
		}
	}
	return entries
}

// mergeNumstat reads `--numstat -M` lines — TAB-separated additions,
// deletions (or "-"/"-" for a binary file) and a path field — and attaches
// each one's authoritative status from raw. The path field for a rename is
// git's own "old => new" shorthand (the whole path changed) or
// "prefix{old => new}suffix" (only part of it did, git's own compact form
// for a directory rename) rather than two TAB-separated paths — splitRename
// reads both shapes. A numstat line with no matching raw entry (should not
// happen: both queries ran against the identical pair of trees) falls back
// to "M" rather than being dropped — an honest default for a file this
// process can at least see changed, even if the reason it changed could not
// be read a second way.
func mergeNumstat(out string, status map[string]rawStatusEntry) []numstatFile {
	var files []numstatFile
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 3 {
			continue
		}
		add, del, pathField := fields[0], fields[1], fields[2]
		f := numstatFile{Status: "M"}
		if add == "-" && del == "-" {
			f.Binary = true
		} else {
			// A count this parser cannot read as a number is defensive
			// only — git's own --numstat never prints anything else in
			// this position for a non-binary file — so it is discarded
			// through a named function rather than left at its zero value
			// silently, matching this codebase's own check-blank discipline.
			f.Additions = discardAtoiError(strconv.Atoi(add))
			f.Deletions = discardAtoiError(strconv.Atoi(del))
		}
		if oldPath, newPath, isRename := splitRenameArrow(pathField); isRename {
			f.OldPath, f.Path = oldPath, newPath
		} else {
			f.Path = pathField
		}
		if entry, ok := status[f.Path]; ok {
			switch entry.status[:1] {
			case "A", "M", "D":
				f.Status = entry.status[:1]
			case "R", "C":
				f.Status = "R"
				if entry.oldPath != "" {
					f.OldPath = entry.oldPath
				}
			}
		}
		files = append(files, f)
	}
	return files
}

// splitRenameArrow reads git's own rename shorthand out of a numstat path
// field: "old => new" when the whole path changed, or
// "prefix{old => new}suffix" when only a directory component did (git's own
// compact form, e.g. "src/{a => b}/file.go"). ok is false for a path that
// is neither — an ordinary path never legitimately contains " => ", so this
// never misreads a real file name.
func splitRenameArrow(path string) (oldPath, newPath string, ok bool) {
	if i := strings.Index(path, "{"); i >= 0 {
		if j := strings.Index(path[i:], "}"); j >= 0 {
			prefix := path[:i]
			suffix := path[i+j+1:]
			inner := path[i+1 : i+j]
			if o, n, split := strings.Cut(inner, " => "); split {
				return prefix + o + suffix, prefix + n + suffix, true
			}
		}
		return "", "", false
	}
	if o, n, split := strings.Cut(path, " => "); split {
		return o, n, true
	}
	return "", "", false
}

// discardAtoiError is this file's own named discard (errcheck runs with
// check-blank, so a bare `n, _ := strconv.Atoi(x)` is flagged the same as
// dropping the error outright): n is used, err is deliberately not.
func discardAtoiError(n int, _ error) int { return n }

// errNoStore names the reason files.go and diff.go both fold into "nothing
// to show" rather than an error a caller has to decide whether to
// propagate — a repository this process cannot resolve to a snapshot store
// is a configuration gap, not a fault in the request.
var errNoStore = errors.New("no snapshot store is available for this repository")
