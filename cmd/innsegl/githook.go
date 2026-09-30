// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"innsegl.dev/innsegl/internal/commitpath"
)

// githook.go — RM-240 (#385), ADR-0059 decisions 1 and 2's host half:
// `prepare-commit-msg`, the hook git calls on every `git commit` after the
// message is drafted and before the editor (if any) opens.
//
// Not wired to a CLI subcommand yet — the supervisor adds that after this
// wave, the same deliberate split committrailers.go's own doc comment
// describes for its handler.

// trailersClient is the one method runGitHookPrepareCommitMsg needs from
// commitpath.Client — an interface so a test can drive the real hook against
// a fake core with no HTTP round trip through the production client's own
// defaults, and so the client the production binary wires stays
// commitpath.Client itself, unmodified.
type trailersClient interface {
	Trailers(context.Context, commitpath.TrailersRequest) (commitpath.TrailersResponse, error)
}

// runGitHookPrepareCommitMsg is `prepare-commit-msg`, driven by git as
// `prepare-commit-msg <msgfile> [<source> [<sha>]]` on every commit — after
// the message is decided (by -m, -F, a template, a merge or --amend's prior
// message) and before any editor opens. Only args[0] is read: source and sha
// decide nothing here, because the same trailers apply to a message from any
// of those origins.
//
// CMT-004: an empty tool call id means this `git commit` did not go through
// the PreToolUse hook ADR-0059 decision 1 describes — there is nothing to
// attribute the commit to. Refusing here, on stderr, non-zero, is what makes
// git abort the commit before it ever writes one: prepare-commit-msg is one
// of the hooks whose non-zero exit stops `git commit` outright, and the
// message file is never touched on any refusal path in this function.
//
// CMT-005: with a resolvable tool call id, the answered message — the
// caller's own message plus the run's three trailers, placed by ADR-0028's
// render (cmd/innsegl/committrailers.go, ADR-0059 decision 2) — replaces the
// file's contents, and nothing else about it changes.
func runGitHookPrepareCommitMsg(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, client trailersClient) int {
	refuse := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "innsegl: prepare-commit-msg: "+format+"\n", a...)
		return 1
	}
	if len(args) < 1 || args[0] == "" {
		return refuse("git called this hook with no message file to read")
	}
	msgfile := args[0]

	id := getenv(commitpath.EnvToolUseID)
	if id == "" {
		return refuse("no tool call id (%s is unset); this commit was not run by an agent "+
			"through the gateway and cannot be attributed", commitpath.EnvToolUseID)
	}

	// #nosec G703 -- msgfile is argv[0] git itself invoked this hook with (its
	// own COMMIT_EDITMSG-style path inside .git/), not attacker-controlled
	// input; there is no taint here to guard against.
	info, err := os.Stat(msgfile)
	if err != nil {
		return refuse("cannot read %s: %v", msgfile, err)
	}
	// #nosec G703 -- see above.
	raw, err := os.ReadFile(msgfile)
	if err != nil {
		return refuse("cannot read %s: %v", msgfile, err)
	}

	resp, err := client.Trailers(ctx, commitpath.TrailersRequest{ToolUseID: id, Message: string(raw)})
	if err != nil {
		return refuse("%v", err)
	}

	// #nosec G703 -- see above; the same path this function just read from.
	if err := os.WriteFile(msgfile, []byte(resp.Message), info.Mode().Perm()); err != nil {
		return refuse("cannot write %s: %v", msgfile, err)
	}
	return 0
}
