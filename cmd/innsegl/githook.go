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
// message is drafted and before the editor (if any) opens. Wired to
// `innsegl git-hook prepare-commit-msg` by commitpathcli.go; installed into a
// repository's hooks directory by `innsegl link` (link.go, RM-245).

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
// CMT-004 (RM-245, operator decision 2026-09-30): an empty tool call id means
// this `git commit` did not go through the PreToolUse hook ADR-0059 decision
// 1 describes — it is a human's own commit in a linked repository, not an
// agent's. That is not refused: a human's own `git commit` is left
// completely alone, no trailers, no innsegl signing, git's own configuration
// decides everything else. This function does nothing at all in that case —
// it does not stat, read or write the message file, prints nothing, and
// returns 0 so git commits exactly as it would with no innsegl hook
// installed. An agent's `git commit` that somehow reaches here with no id
// (one that stripped INNSEGL_TOOL_USE_ID, or ran outside the hook's reach) is
// not caught here either: it is caught downstream, by the reconciler's own
// unsigned-commit alert (CMT-016), which is the documented trade this
// decision makes rather than trying to tell the two cases apart from inside
// this hook.
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
		// A human's own commit (CMT-004, RM-245): nothing to attribute,
		// nothing to touch, nothing to say. See the doc comment above.
		return 0
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
