// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
)

// The ref backstop (#584): `innsegl git-hook reference-transaction`, git's
// reference-transaction hook, installed by `innsegl link`.
//
// The PreToolUse guard (hooknosign.go) reads a command's text, so a script
// file, plumbing (`commit-tree` + `update-ref`) or a rebase run inside some
// other tool passes it. git runs this hook for every ref update, whatever
// made it, and `--no-verify` does not skip it. In the `prepared` state it
// may still abort the whole update. It lists the commits a branch update
// would add -- those reachable from the new value and from no branch, tag
// or remote-tracking ref -- and refuses the update when any lacks a
// signature header. Commit, rebase, merge, cherry-pick, am, plumbing and
// scripts all end in such an update.
//
// Agent sessions only (operator decision 6): the operator's own commits are
// unchanged. A session is an agent's when the harness marked its shell
// (envAgentSession) or the PreToolUse hook gave the command a tool call id.
// The installed script checks this before it runs this binary at all, so
// the operator's own git never waits on, or depends on, innsegl.

// linkRefTxMarker is embedded in the hook `innsegl link` writes.
const linkRefTxMarker = "innsegl link managed reference-transaction hook"

// envAgentSession is set by the agent harness in every shell it runs.
const envAgentSession = "CLAUDECODE"

// zeroObjectID matches git's all-zero id for a ref that does not exist
// (before a create, after a delete), in either hash.
func isZeroObjectID(s string) bool {
	return s != "" && strings.Trim(s, "0") == ""
}

// agentSession reports whether the environment is an agent's shell.
func agentSession(getenv func(string) string) bool {
	return getenv(envAgentSession) != "" || getenv(commitpath.EnvToolUseID) != ""
}

// linkRefTxScript is the POSIX sh installed as reference-transaction. It
// reads git's input once, hands it to innsegl only for an agent session's
// `prepared` state, then to a previous hook, if any, with git's arguments.
// `set -eu` makes innsegl's refusal, or a missing binary, abort the update:
// signing fails closed.
func linkRefTxScript(bin, previousPath string) string {
	return "#!/bin/sh\n" +
		"# " + linkRefTxMarker + " — do not edit by hand.\n" +
		"# See `innsegl link -remove <repo>` to remove it and restore what was here\n" +
		"# before, if anything.\n" +
		"set -eu\n" +
		"input=$(cat)\n" +
		"if [ \"${1:-}\" = prepared ] && { [ -n \"${" + envAgentSession + ":-}\" ] || [ -n \"${" + commitpath.EnvToolUseID + ":-}\" ]; }; then\n" +
		"\tprintf '%s\\n' \"$input\" | " + shellQuoteSingle(bin) + " git-hook reference-transaction \"$@\"\n" +
		"fi\n" +
		"if [ -x " + shellQuoteSingle(previousPath) + " ]; then\n" +
		"\tprintf '%s\\n' \"$input\" | " + shellQuoteSingle(previousPath) + " \"$@\"\n" +
		"fi\n"
}

// runGitHookReferenceTransaction is the hook: git's state in args[0], one
// "<old> <new> <ref>" line per update on stdin, the repository in dir. It
// returns 1, refusing the whole transaction, when an agent session's branch
// update would add a commit with no signature, or when that cannot be
// checked. Anything else returns 0.
func runGitHookReferenceTransaction(ctx context.Context, dir string, args []string, stdin io.Reader,
	getenv func(string) string, stderr io.Writer,
) int {
	if len(args) < 1 || args[0] != "prepared" || !agentSession(getenv) {
		return exitOK
	}
	type update struct{ ref, newID string }
	var updates []update
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "refs/heads/") || isZeroObjectID(fields[1]) {
			continue
		}
		updates = append(updates, update{ref: fields[2], newID: fields[1]})
	}
	if err := scanner.Err(); err != nil {
		fprintf(stderr, "innsegl: reference-transaction: reading git's input: %v\n", err)
		return 1
	}
	o, down := signingOutageNow()
	for _, u := range updates {
		unsigned, err := unsignedNewCommits(ctx, dir, u.newID)
		if err != nil {
			fprintf(stderr, "innsegl: refused to move %s: its new commits could not be checked for a signature: %v\n",
				u.ref, err)
			return 1
		}
		if len(unsigned) > 0 {
			fprintf(stderr, "%s\n", unsignedRefusal(u.ref, unsigned, o, down))
			return 1
		}
	}
	return exitOK
}

// unsignedNewCommits lists the commits reachable from newID and from no
// branch, tag or remote-tracking ref that carry no signature header. HEAD
// is not excluded: a rebase moves a detached HEAD onto its new commits
// before it moves the branch.
func unsignedNewCommits(ctx context.Context, dir, newID string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-list", "--header", newID,
		"--not", "--branches", "--tags", "--remotes")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var unsigned []string
	for _, record := range strings.Split(string(out), "\x00") {
		record = strings.TrimLeft(record, "\n")
		if record == "" {
			continue
		}
		id, raw, _ := strings.Cut(record, "\n")
		if !hasSignatureHeader(raw) {
			unsigned = append(unsigned, id)
		}
	}
	return unsigned, nil
}

// hasSignatureHeader reports whether a raw commit's header (everything
// before the first blank line) holds a gpgsig or gpgsig-sha256 line.
// rev-list --header indents each line of the commit by four spaces.
func hasSignatureHeader(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimPrefix(line, "    ")
		if line == "" {
			return false
		}
		if strings.HasPrefix(line, "gpgsig ") || strings.HasPrefix(line, "gpgsig-sha256 ") {
			return true
		}
	}
	return false
}

// unsignedRefusal is what git prints when the backstop refuses ref's update.
func unsignedRefusal(ref string, commits []string, o signingOutage, down bool) string {
	short := make([]string, 0, len(commits))
	for _, c := range commits {
		if len(c) > 12 {
			c = c[:12]
		}
		short = append(short, c)
	}
	return "innsegl: refused to move " + ref + ": " + fmt.Sprint(len(commits)) +
		" new commit(s) not signed: " + strings.Join(short, " ") + ". " +
		"An agent's commits in this repository must be signed, whatever made them. " + outageText(o, down) +
		"If signing failed, do not retry with signing off: fix its cause, then commit again with plain " +
		"`git commit` (or `innsegl resign` for unsigned commits already on a branch)."
}
