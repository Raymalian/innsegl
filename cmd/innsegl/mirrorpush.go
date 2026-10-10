// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

// mirrorpush.go — #465 and #467, ADR-0065 decisions 2 and 3: what a hosted
// client sends to the core's per-repository mirror besides a commit's
// staging objects.
//
//   - After a signed commit (git's post-commit hook, installed by `innsegl
//     link`) and at session end, the branch, so the reconciler's rebase pass
//     can walk it.
//   - After each tool call (the harness's PostToolUse hook), a workspace
//     snapshot of the working tree, as the tool call's snapshot ref. The core
//     records it on the tool call only when its mirror holds the tree.
//
// Only a repository linked to innsegl sends anything (#575), and only to a
// client service: against the single-host core, which reads the working tree
// itself, nothing is pushed.
//
// # Never in the way
//
// Neither the commit nor the tool call waits for the core. The push runs as
// a process of its own (`innsegl git-hook push-mirror`), detached from the
// hook, and its failure is the next push's to carry (ADR-0065, consequence
// 3). Its last output is kept at <git common dir>/innsegl/last-push.log.

// linkPostCommitMarker is embedded in the post-commit hook `innsegl link`
// writes, as linkHookMarker is in its prepare-commit-msg hook.
const linkPostCommitMarker = "innsegl link managed post-commit hook"

// mirrorPushTimeout bounds one detached push.
const mirrorPushTimeout = 5 * time.Minute

// linkPostCommitScript is the post-commit hook. A post-commit hook cannot
// undo a commit, and this one never fails: innsegl's step is allowed to
// fail, and a hook the repository had before still runs.
func linkPostCommitScript(bin, previousPath string) string {
	return "#!/bin/sh\n" +
		"# " + linkPostCommitMarker + " — do not edit by hand.\n" +
		"# See `innsegl link -remove <repo>` to remove it and restore what was here\n" +
		"# before, if anything.\n" +
		shellQuoteSingle(bin) + " git-hook post-commit \"$@\" || :\n" +
		"if [ -x " + shellQuoteSingle(previousPath) + " ]; then\n" +
		"\texec " + shellQuoteSingle(previousPath) + " \"$@\"\n" +
		"fi\n"
}

// coreBase is the client's core URL, as the commit path reads it.
func coreBase(getenv func(string) string) string {
	if base := getenv(commitpath.EnvCoreURL); base != "" {
		return base
	}
	return commitpath.DefaultCoreURL
}

// toClientService reports whether base is a client service: plain http on
// loopback. Only a client service is pushed to (commitpath.Client.Stage).
func toClientService(base string) bool { return strings.HasPrefix(base, "http://") }

// runGitHookPostCommit is `innsegl git-hook post-commit`: after a commit
// innsegl signed for an agent, send its branch to the core's mirror. A
// commit with no tool call id, an unsigned one, a detached HEAD, or a core
// that is not a client service sends nothing. It always exits 0.
func runGitHookPostCommit(ctx context.Context, dir string, getenv func(string) string, stderr io.Writer) int {
	base := coreBase(getenv)
	if !commitpath.IsToolUseID(getenv(commitpath.EnvToolUseID)) || !toClientService(base) {
		return exitOK
	}
	branch, err := runGitOutput(ctx, "", dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		return exitOK
	}
	object, err := runGitOutput(ctx, "", dir, "cat-file", "commit", "HEAD")
	if err != nil {
		return exitOK
	}
	header, _, _ := strings.Cut(object, "\n\n")
	if !strings.Contains(header, "\ngpgsig ") {
		return exitOK
	}
	head, err := runGitOutput(ctx, "", dir, "rev-parse", "HEAD")
	if err != nil {
		return exitOK
	}
	if err := spawnMirrorPush(ctx, dir, "branch", base, strings.TrimSpace(branch), strings.TrimSpace(head)); err != nil {
		fprintf(stderr, "innsegl git-hook post-commit: sending the branch to the core: %v\n", err)
	}
	return exitOK
}

// pushBranchAtSessionEnd sends the branch dir is on to the core's mirror,
// when dir is in a linked repository. It never fails the hook.
func pushBranchAtSessionEnd(ctx context.Context, dir, base string, stderr io.Writer) {
	if !toClientService(base) || !isLinked(ctx, dir) {
		return
	}
	branch, err := runGitOutput(ctx, "", dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		return
	}
	head, err := runGitOutput(ctx, "", dir, "rev-parse", "HEAD")
	if err != nil {
		return
	}
	if err := spawnMirrorPush(ctx, dir, "branch", base, strings.TrimSpace(branch), strings.TrimSpace(head)); err != nil {
		fprintf(stderr, "innsegl hook session: sending the branch to the core: %v\n", err)
	}
}

// runHookPostToolUse is `innsegl hook post-tool-use`, the harness's
// PostToolUse hook: snapshot the working tree as the tool call left it, then
// send it to the core as that tool call's snapshot ref. The snapshot is
// taken before the hook returns, so it is the tool call's own after-state;
// the push is not waited for. It prints nothing to stdout and exits 0.
func runHookPostToolUse(stdin io.Reader, stderr io.Writer, getenv func(string) string) int {
	var in struct {
		ToolUseID string `json:"tool_use_id"`
		Cwd       string `json:"cwd"`
	}
	if err := json.NewDecoder(io.LimitReader(stdin, 8<<20)).Decode(&in); err != nil {
		return exitOK
	}
	base := coreBase(getenv)
	if !commitpath.IsToolUseID(in.ToolUseID) || in.Cwd == "" || !toClientService(base) {
		return exitOK
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionHookTimeout*10)
	defer cancel()
	if !isLinked(ctx, in.Cwd) {
		return exitOK
	}
	snap, err := commitpath.TakeSnapshot(ctx, in.Cwd)
	if err != nil {
		fprintf(stderr, "innsegl hook post-tool-use: the workspace snapshot: %v\n", err)
		return exitOK
	}
	if err := spawnMirrorPush(ctx, in.Cwd, "snapshot", base, in.ToolUseID, snap.Commit, snap.Tree, snap.Objects); err != nil {
		fprintf(stderr, "innsegl hook post-tool-use: sending the snapshot to the core: %v\n", err)
	}
	return exitOK
}

// spawnMirrorPush starts `innsegl git-hook push-mirror <args>` in dir,
// detached, and does not wait for it.
func spawnMirrorPush(ctx context.Context, dir string, args ...string) error {
	bin, err := innseglBinaryPath()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	logDir := filepath.Join(abs, ".git", "innsegl")
	if common, cerr := runGitOutput(ctx, "", abs, "rev-parse", "--path-format=absolute", "--git-common-dir"); cerr == nil {
		logDir = filepath.Join(strings.TrimSpace(common), "innsegl")
	}
	if merr := os.MkdirAll(logDir, 0o700); merr != nil {
		return merr
	}
	// #nosec G304 -- a file in the repository's own git directory.
	log, err := os.OpenFile(filepath.Join(logDir, "last-push.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	// G204: an argument list, never shell text; bin is this binary.
	cmd := exec.Command(bin, append([]string{"git-hook", "push-mirror", abs}, args...)...) //nolint:noctx // detached on purpose: it outlives ctx
	cmd.Dir = abs
	cmd.Env = withoutHookGitEnv(os.Environ())
	cmd.Stdout, cmd.Stderr = log, log
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// withoutHookGitEnv drops what git sets for a hook about the repository it
// runs in: the detached push names its repository itself.
func withoutHookGitEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PREFIX", "GIT_OBJECT_DIRECTORY",
			"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// runGitHookPushMirror is `innsegl git-hook push-mirror`, the detached push:
//
//	push-mirror <dir> branch   <core url> <branch> <commit>
//	push-mirror <dir> snapshot <core url> <tool call id> <commit> <tree> <objects dir>
func runGitHookPushMirror(args []string, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), mirrorPushTimeout)
	defer cancel()
	var dir, kind, base string
	var rest []string
	if len(args) >= 3 {
		dir, kind, base, rest = args[0], args[1], args[2], args[3:]
	}
	c := commitpath.Client{BaseURL: base}
	var err error
	switch {
	case kind == "branch" && len(rest) == 2:
		err = c.PushBranch(ctx, dir, rest[0], rest[1])
	case kind == "snapshot" && len(rest) == 4:
		err = c.PushSnapshot(ctx, dir, commitpath.Snapshot{Commit: rest[1], Tree: rest[2], Objects: rest[3]}, rest[0])
	default:
		fprintf(stderr, "usage: innsegl git-hook push-mirror <dir> branch <core url> <branch> <commit>\n"+
			"       innsegl git-hook push-mirror <dir> snapshot <core url> <tool call id> <commit> <tree> <objects dir>\n")
		return exitUsage
	}
	if err != nil {
		fprintf(stderr, "innsegl git-hook push-mirror: %v\n", err)
		return 1
	}
	fprintf(stderr, "innsegl git-hook push-mirror: %s sent at %s\n", kind, time.Now().UTC().Format(time.RFC3339))
	return exitOK
}
