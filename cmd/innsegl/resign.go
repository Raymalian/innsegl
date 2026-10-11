// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
)

// `innsegl resign <range>` (RM-328, #581): sign the commits a range of the
// current branch holds unsigned, through the signing program every agent
// commit takes. It is the documented recovery for commits made while signing
// could not run, and it never turns signing off: git rebases the range from
// the first unsigned commit with `innsegl sign` as its signing program, so
// the core signs each commit under the agent's tool call or git stops. A
// refusal aborts the rebase and leaves the branch where it was.
//
// It never rewrites published history. A range holding a commit any
// remote-tracking branch or tag contains is refused, and there is no flag
// that allows it. A merge in the range is refused too: a rebase would
// flatten it.
//
// The core treats `innsegl resign` as a command that creates commits
// (commitpath.IsGitCommitCommand), so the harness hook hands it the tool
// call id and the agent's identity exactly as it does `git rebase`. git runs
// prepare-commit-msg for every commit it replays, so each re-signed commit
// carries the trailers of the run that signed it.

const (
	// exitResignRefused: the range may not be re-signed; nothing changed.
	exitResignRefused = 33
	// exitResignFailed: a signature was refused or git failed; the branch
	// is where it was.
	exitResignFailed = 34
)

const resignUsage = `usage: innsegl resign <range>

Sign the unsigned commits in <range> again, through the core, as the agent's
own command. <range> is <base>..HEAD, or <base> for the same. Every commit from
the first unsigned one to HEAD is rewritten and signed; earlier ones are kept.

Refused, with nothing changed: a range that does not end at the current
branch's tip, a dirty working tree, a commit any remote-tracking branch or tag
already contains (published history is never rewritten), a merge, and a run
outside an agent's tool call. If the core refuses a signature, the branch is
left where it was.
`

// resignDeps are the seams a test replaces. The zero value is production.
type resignDeps struct {
	// dir is the repository; empty is the working directory.
	dir string
	// signProgram is git's signing program; empty is this binary.
	signProgram string
	// getenv reads the environment; nil is os.Getenv.
	getenv func(string) string
	// env is git's environment; nil is this process's.
	env []string
}

func resignCommand(args []string, stdout, stderr io.Writer) int {
	return runResign(context.Background(), args, stdout, stderr, resignDeps{})
}

func runResign(ctx context.Context, args []string, stdout, stderr io.Writer, deps resignDeps) int {
	fs := flag.NewFlagSet("innsegl resign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fprintf(stderr, "%s", resignUsage) }
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil || fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	refuse := func(format string, a ...any) int {
		fprintf(stderr, "innsegl resign: "+format+"\n", a...)
		return exitResignRefused
	}
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = deps.dir
		cmd.Env = deps.env
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
		}
		return strings.TrimSpace(out.String()), nil
	}

	if deps.getenv(commitpath.EnvToolUseID) == "" {
		return refuse("only the core signs, and only an agent's commit: run this as the agent's own "+
			"command, through the harness (%s is unset)", commitpath.EnvToolUseID)
	}

	base, tip, ok := strings.Cut(fs.Arg(0), "..")
	if !ok {
		tip = "HEAD"
	}
	branch, err := git("symbolic-ref", "-q", "--short", "HEAD")
	if err != nil || branch == "" {
		return refuse("HEAD is not on a branch; check out the branch to re-sign")
	}
	baseSHA, err := git("rev-parse", "--verify", "-q", base+"^{commit}")
	if err != nil {
		return refuse("%s is not a commit", base)
	}
	tipSHA, err := git("rev-parse", "--verify", "-q", tip+"^{commit}")
	if err != nil {
		return refuse("%s is not a commit", tip)
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil || tipSHA != head {
		return refuse("the range must end at the tip of %s (%s), not at %s", branch, head, tip)
	}
	if dirty, derr := git("status", "--porcelain", "--untracked-files=no"); derr != nil || dirty != "" {
		return refuse("the working tree has uncommitted changes; commit or stash them first")
	}

	listed, err := git("rev-list", "--reverse", "--topo-order", baseSHA+".."+head)
	if err != nil {
		return refuse("%v", err)
	}
	commits := strings.Fields(listed)
	if len(commits) == 0 {
		fprintf(stdout, "nothing to sign: the range is empty\n")
		return exitOK
	}
	merges, err := git("rev-list", "--merges", baseSHA+".."+head)
	if err != nil {
		return refuse("%v", err)
	}
	if merges != "" {
		return refuse("the range holds a merge (%s); a rebase would flatten it", resignFirstLine(merges))
	}
	unpublished, err := git("rev-list", baseSHA+".."+head, "--not", "--remotes", "--tags")
	if err != nil {
		return refuse("%v", err)
	}
	if n := len(strings.Fields(unpublished)); n != len(commits) {
		return refuse("%d commit(s) in the range are already published on a remote-tracking branch "+
			"or a tag; published history is never rewritten. Narrow the range to commits only this "+
			"branch holds", len(commits)-n)
	}

	first := -1
	for i, c := range commits {
		body, cerr := git("cat-file", "commit", c)
		if cerr != nil {
			return refuse("%v", cerr)
		}
		if !commitIsSigned(body) {
			first = i
			break
		}
	}
	if first < 0 {
		fprintf(stdout, "nothing to sign: every commit in the range is signed\n")
		return exitOK
	}

	program := deps.signProgram
	if program == "" {
		if program, err = innseglBinaryPath(); err != nil {
			return refuse("cannot find this binary to sign with: %v", err)
		}
	}
	rebase := []string{
		"-c", "commit.gpgsign=true", "-c", "gpg.format=x509", "-c", "gpg.x509.program=" + program,
		"-c", "rebase.autoSquash=false", "-c", "rebase.updateRefs=false", "-c", "rebase.autoStash=false",
		"rebase", "--force-rebase", "--no-autosquash",
	}
	if first == 0 {
		rebase = append(rebase, baseSHA)
	} else {
		rebase = append(rebase, commits[first-1])
	}
	if _, rerr := git(rebase...); rerr != nil {
		if _, aerr := git("rebase", "--abort"); aerr != nil {
			fprintf(stderr, "innsegl resign: the rebase did not abort cleanly: %v\n", aerr)
		}
		fprintf(stderr, "innsegl resign: signing failed; %s is back at %s and nothing was rewritten: %v\n",
			branch, head, rerr)
		return exitResignFailed
	}

	rewritten, err := git("rev-list", "--reverse", "--topo-order", baseSHA+"..HEAD")
	if err != nil {
		fprintf(stderr, "innsegl resign: re-signed, but reading the result failed: %v\n", err)
		return exitResignFailed
	}
	after := strings.Fields(rewritten)
	if len(after) != len(commits) {
		fprintf(stderr, "innsegl resign: the range held %d commits and now holds %d; inspect %s "+
			"(the old tip was %s)\n", len(commits), len(after), branch, head)
		return exitResignFailed
	}
	for i := first; i < len(after); i++ {
		fprintf(stdout, "%s -> %s\n", commits[i], after[i])
	}
	fprintf(stdout, "re-signed %d commit(s) on %s; push them as new commits\n", len(after)-first, branch)
	return exitOK
}

// commitIsSigned reports whether a raw commit object carries a signature
// header.
func commitIsSigned(body string) bool {
	header, _, _ := strings.Cut(body, "\n\n")
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(line, "gpgsig ") || strings.HasPrefix(line, "gpgsig-sha256 ") {
			return true
		}
	}
	return false
}

func resignFirstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
