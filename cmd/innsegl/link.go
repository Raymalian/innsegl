// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// `innsegl link` — RM-245 (#390), the operator's decision of 2026-09-30's
// last piece: installing the prepare-commit-msg hook ADR-0059's host-side
// commit path (githook.go) needs, so that a repository's agent commits carry
// the run's trailers and its own `git commit`s carry the signing
// configuration (hook.go). A human's own `git commit` in a linked repository
// is unaffected either way — see githook.go's own doc comment for CMT-004.
//
// This command touches exactly one thing: the repository's prepare-commit-msg
// hook, found through `git rev-parse --git-path hooks/prepare-commit-msg`,
// which resolves core.hooksPath the same way any other git command would.
// Nothing else about the repository — no git config key, no other hook, no
// file outside the hooks directory — is read or written.
//
// # Never losing a hook that was already there
//
// If a prepare-commit-msg hook already exists and was not written by this
// command, it is moved aside to prepare-commit-msg.innsegl-previous — never
// overwritten, never deleted — and the installed hook execs it after its own
// check succeeds, passing the same arguments git gave it (`"$@"`). `set -eu`
// with no `||` around the innsegl call means a refusal there (the message
// file untouched, this process exiting non-zero — githook.go's own contract)
// stops the script immediately: the previous hook never runs, and git aborts
// the commit exactly as it would with prepare-commit-msg refusing directly.
// Only when innsegl's own check succeeds does the script go on to the
// previous hook, if any, and its exit status becomes the whole script's.
//
// # Idempotent both ways
//
// Running `innsegl link <repo>` again when it already installed the hook
// rewrites the same hook (harmless — it is a pure function of this binary's
// own resolved path and the previous-hook path, both stable) rather than
// re-saving an already-saved previous hook on top of itself. Running
// `innsegl link -remove <repo>` when nothing is linked, or a second time
// after removing, is a no-op that says so and exits 0.

// linkHookMarker is embedded verbatim in every hook this command writes and
// is how it tells its own hook apart from anything else that might be sitting
// in the hooks directory — the same technique init.go's own managed pre-push
// hook uses (prePushHookMarker).
const linkHookMarker = "innsegl link managed prepare-commit-msg hook"

// linkPreviousSuffix names where an already-existing, non-innsegl
// prepare-commit-msg hook is moved to, alongside the hook this command
// installs in its place.
const linkPreviousSuffix = ".innsegl-previous"

func linkCommand(args []string, stdout, stderr io.Writer) int {
	return runLinkCommand(context.Background(), args, stdout, stderr)
}

func runLinkCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl link", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var remove bool
	fs.BoolVar(&remove, "remove", false,
		"remove the hook this command installed, restoring exactly what was there before")
	fs.Usage = func() {
		fprintf(stderr, "innsegl link - install the prepare-commit-msg hook the commit path needs "+
			"(#390)\n\n")
		fprintf(stderr, "So an agent's git commit in this repository carries the run's trailers and "+
			"its\nsigning configuration; a human's own commit here is unaffected either way. "+
			"Touches\nnothing about the repository except its own prepare-commit-msg hook.\n\n")
		fprintf(stderr, "Usage:\n  innsegl link <repo dir>\n  innsegl link -remove <repo dir>\n\n")
		fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		fprintf(stderr, "innsegl link: exactly one argument, the repository to link, is required\n")
		fs.Usage()
		return exitUsage
	}
	repo := fs.Arg(0)

	if remove {
		return runLinkRemove(ctx, repo, stdout, stderr)
	}
	return runLinkInstall(ctx, repo, stdout, stderr)
}

// linkHookPaths resolves the two paths this command ever touches: the
// prepare-commit-msg hook itself, and where an already-existing one is moved
// to. `git rev-parse --git-path` is what resolves core.hooksPath — a
// relative result is relative to repo (measured against a real git; a plain
// repository answers ".git/hooks/prepare-commit-msg", a relative
// core.hooksPath answers relative to the repository root, and an absolute one
// is returned as given).
func linkHookPaths(ctx context.Context, repo string) (hookPath, previousPath string, err error) {
	out, err := runGitOutput(ctx, "", repo, "rev-parse", "--git-path", "hooks/prepare-commit-msg")
	if err != nil {
		return "", "", fmt.Errorf("locating the hooks directory: %w", err)
	}
	hookPath = strings.TrimSpace(out)
	if !isAbsPath(hookPath) {
		hookPath = filepath.Join(repo, hookPath)
	}
	return hookPath, hookPath + linkPreviousSuffix, nil
}

// linkHookScript is the POSIX sh installed at hookPath. bin is this binary's
// own resolved path (innseglBinaryPath, hook.go) and previousPath is where an
// already-existing hook was moved to, if any — both baked into the script as
// single-quoted literals (shellQuoteSingle) rather than derived at runtime
// from argv[0], which git does not guarantee is any particular form.
func linkHookScript(bin, previousPath string) string {
	return "#!/bin/sh\n" +
		"# " + linkHookMarker + " — do not edit by hand.\n" +
		"# See `innsegl link -remove <repo>` to remove it and restore what was here\n" +
		"# before, if anything.\n" +
		"set -eu\n" +
		shellQuoteSingle(bin) + " git-hook prepare-commit-msg \"$@\"\n" +
		"if [ -x " + shellQuoteSingle(previousPath) + " ]; then\n" +
		"\texec " + shellQuoteSingle(previousPath) + " \"$@\"\n" +
		"fi\n"
}

// shellQuoteSingle single-quotes s for a POSIX sh command line, escaping any
// embedded single quote by the standard close-escape-reopen technique. Every
// path this command writes into a
// script goes through this rather than being pasted in bare, unlike hook.go's
// env-var interpolation (a running command it rewrites, where no quoting is
// attempted at all — see hook.go's own comment for why that path refuses
// instead). Here the value is written once, to a file, so quoting it
// correctly is the safe option rather than the risky one.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runLinkInstall installs or re-installs the hook. Three states going in:
// nothing at hookPath, an innsegl-managed hook already there (rewritten,
// harmlessly), or someone else's hook (moved aside exactly once, refusing
// rather than guessing if a previous one is already saved and unaccounted
// for).
func runLinkInstall(ctx context.Context, repo string, stdout, stderr io.Writer) int {
	hookPath, previousPath, err := linkHookPaths(ctx, repo)
	if err != nil {
		fprintf(stderr, "innsegl link: %v\n", err)
		return exitUsage
	}

	existing, readErr := os.ReadFile(hookPath)
	switch {
	case readErr == nil && !strings.Contains(string(existing), linkHookMarker):
		if _, statErr := os.Stat(previousPath); statErr == nil {
			fprintf(stderr, "innsegl link: %s already exists and is not managed by innsegl, and %s "+
				"already holds a previously saved hook — refusing to overwrite either\n", hookPath, previousPath)
			return exitUsage
		} else if !os.IsNotExist(statErr) {
			fprintf(stderr, "innsegl link: checking %s: %v\n", previousPath, statErr)
			return exitUsage
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(previousPath), 0o755); mkdirErr != nil {
			fprintf(stderr, "innsegl link: creating the hooks directory: %v\n", mkdirErr)
			return exitUsage
		}
		if renameErr := os.Rename(hookPath, previousPath); renameErr != nil {
			fprintf(stderr, "innsegl link: moving the existing hook aside: %v\n", renameErr)
			return exitUsage
		}
		fprintf(stdout, "innsegl link: moved the existing %s to %s\n", hookPath, previousPath)
	case readErr != nil && !os.IsNotExist(readErr):
		fprintf(stderr, "innsegl link: reading %s: %v\n", hookPath, readErr)
		return exitUsage
	}
	// The remaining case — nothing there, or already innsegl's own — is safe
	// to (re)write below with no further action.

	bin, err := innseglBinaryPath()
	if err != nil {
		fprintf(stderr, "innsegl link: resolving this binary's own path: %v\n", err)
		return exitUsage
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		fprintf(stderr, "innsegl link: creating the hooks directory: %v\n", err)
		return exitUsage
	}
	script := linkHookScript(bin, previousPath)
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil { //nolint:gosec // a hook must be executable
		fprintf(stderr, "innsegl link: writing %s: %v\n", hookPath, err)
		return exitUsage
	}
	fprintf(stdout, "innsegl link: installed %s\n", hookPath)
	return exitOK
}

// runLinkRemove reverses runLinkInstall exactly: it only ever removes a hook
// carrying linkHookMarker, and if one was moved aside at install time, it
// (and only it) takes the removed hook's place — via os.Rename, so the
// restored file's bytes and mode are exactly what they were before, not a
// copy this command reconstructed.
func runLinkRemove(ctx context.Context, repo string, stdout, stderr io.Writer) int {
	hookPath, previousPath, err := linkHookPaths(ctx, repo)
	if err != nil {
		fprintf(stderr, "innsegl link -remove: %v\n", err)
		return exitUsage
	}

	existing, err := os.ReadFile(hookPath)
	switch {
	case os.IsNotExist(err):
		fprintf(stdout, "innsegl link -remove: %s does not exist; nothing to remove\n", hookPath)
		return exitOK
	case err != nil:
		fprintf(stderr, "innsegl link -remove: reading %s: %v\n", hookPath, err)
		return exitUsage
	case !strings.Contains(string(existing), linkHookMarker):
		fprintf(stderr, "innsegl link -remove: %s exists and was not written by `innsegl link` — "+
			"refusing to remove a hook it does not own\n", hookPath)
		return exitUsage
	}

	if err := os.Remove(hookPath); err != nil {
		fprintf(stderr, "innsegl link -remove: removing %s: %v\n", hookPath, err)
		return exitUsage
	}

	if _, statErr := os.Stat(previousPath); statErr == nil {
		if err := os.Rename(previousPath, hookPath); err != nil {
			fprintf(stderr, "innsegl link -remove: restoring %s from %s: %v\n", hookPath, previousPath, err)
			return exitUsage
		}
		fprintf(stdout, "innsegl link -remove: removed %s, restored the hook that was there before\n", hookPath)
		return exitOK
	} else if !os.IsNotExist(statErr) {
		fprintf(stderr, "innsegl link -remove: checking %s: %v\n", previousPath, statErr)
		return exitUsage
	}

	fprintf(stdout, "innsegl link -remove: removed %s; there was nothing there before\n", hookPath)
	return exitOK
}
