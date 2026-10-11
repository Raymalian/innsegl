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

	"innsegl.dev/innsegl/internal/workspace"
)

// `innsegl link` — RM-245 (#390), the operator's decision of 2026-09-30's
// last piece: installing the prepare-commit-msg hook ADR-0059's host-side
// commit path (githook.go) needs, so that a repository's agent commits carry
// the run's trailers and its own `git commit`s carry the signing
// configuration (hook.go). A human's own `git commit` in a linked repository
// is unaffected either way — see githook.go's own doc comment for CMT-004.
//
// This command touches exactly two things: the repository's prepare-commit-msg
// and post-commit hooks (the second sends a signed commit's branch to a hosted
// core's mirror, #465), each found through `git rev-parse --git-path hooks/<name>`,
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
		"remove the hooks this command installed, restoring exactly what was there before")
	fs.Usage = func() {
		fprintf(stderr, "innsegl link - install the git hooks the commit path needs "+
			"(#390)\n\n")
		fprintf(stderr, "So an agent's git commit in this repository carries the run's trailers and "+
			"its\nsigning configuration; a human's own commit here is unaffected either way. "+
			"After a\nsigned commit, its branch is sent to a hosted core's mirror. Touches nothing about\nthe repository except its prepare-commit-msg and post-commit hooks.\n\n")
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
	return linkHookPathsFor(ctx, repo, "prepare-commit-msg")
}

// managedHook is one git hook `innsegl link` installs: prepare-commit-msg
// for the run's trailers and signing (#390), and post-commit, which sends a
// signed commit's branch to a hosted core's mirror (#465, ADR-0065).
type managedHook struct {
	name   string
	marker string
	script func(bin, previousPath string) string
}

var managedHooks = []managedHook{
	{name: "prepare-commit-msg", marker: linkHookMarker, script: linkHookScript},
	{name: "post-commit", marker: linkPostCommitMarker, script: linkPostCommitScript},
}

// linkHookPathsFor resolves one hook's path and where an existing one is
// moved to.
func linkHookPathsFor(ctx context.Context, repo, name string) (hookPath, previousPath string, err error) {
	out, err := runGitOutput(ctx, "", repo, "rev-parse", "--git-path", "hooks/"+name)
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
//
// Every managed hook is checked before any is written, so a refusal leaves
// the repository exactly as it was.
func runLinkInstall(ctx context.Context, repo string, stdout, stderr io.Writer) int {
	for _, h := range managedHooks {
		hookPath, previousPath, err := linkHookPathsFor(ctx, repo, h.name)
		if err != nil {
			fprintf(stderr, "innsegl link: %v\n", err)
			return exitUsage
		}
		existing, readErr := os.ReadFile(hookPath) // #nosec G703 -- a path git resolved for the repository
		if readErr != nil || strings.Contains(string(existing), h.marker) {
			continue
		}
		if _, statErr := os.Stat(previousPath); statErr == nil { // #nosec G703 -- see above
			fprintf(stderr, "innsegl link: %s already exists and is not managed by innsegl, and %s "+
				"already holds a previously saved hook — refusing to overwrite either\n", hookPath, previousPath)
			return exitUsage
		}
	}
	bin, err := innseglBinaryPath()
	if err != nil {
		fprintf(stderr, "innsegl link: resolving this binary's own path: %v\n", err)
		return exitUsage
	}
	for _, h := range managedHooks {
		if code := linkInstallHook(ctx, repo, bin, h, stdout, stderr); code != exitOK {
			return code
		}
	}
	return exitOK
}

// linkInstallHook installs one managed hook.
func linkInstallHook(ctx context.Context, repo, bin string, h managedHook, stdout, stderr io.Writer) int {
	hookPath, previousPath, err := linkHookPathsFor(ctx, repo, h.name)
	if err != nil {
		fprintf(stderr, "innsegl link: %v\n", err)
		return exitUsage
	}

	existing, readErr := os.ReadFile(hookPath) // #nosec G703 -- a path git resolved for the repository
	switch {
	case readErr == nil && !strings.Contains(string(existing), h.marker):
		if _, statErr := os.Stat(previousPath); statErr == nil { // #nosec G703 -- see above
			fprintf(stderr, "innsegl link: %s already exists and is not managed by innsegl, and %s "+
				"already holds a previously saved hook — refusing to overwrite either\n", hookPath, previousPath)
			return exitUsage
		} else if !os.IsNotExist(statErr) {
			fprintf(stderr, "innsegl link: checking %s: %v\n", previousPath, statErr)
			return exitUsage
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(previousPath), 0o755); mkdirErr != nil { // #nosec G703 -- see above
			fprintf(stderr, "innsegl link: creating the hooks directory: %v\n", mkdirErr)
			return exitUsage
		}
		if renameErr := os.Rename(hookPath, previousPath); renameErr != nil { // #nosec G703 -- see above
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

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil { // #nosec G703 -- see above
		fprintf(stderr, "innsegl link: creating the hooks directory: %v\n", err)
		return exitUsage
	}
	script := h.script(bin, previousPath)
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
//
// Each managed hook is handled on its own. A hook of that name innsegl did
// not write is left alone, and when none of them is innsegl's, that is a
// refusal.
func runLinkRemove(ctx context.Context, repo string, stdout, stderr io.Writer) int {
	removed, foreign := 0, 0
	for _, h := range managedHooks {
		switch linkRemoveHook(ctx, repo, h, stdout, stderr) {
		case linkRemoved:
			removed++
		case linkForeign:
			foreign++
		case linkFailed:
			return exitUsage
		}
	}
	if foreign > 0 && removed == 0 {
		return exitUsage
	}
	return exitOK
}

// The outcomes of removing one managed hook.
const (
	linkAbsent = iota
	linkRemoved
	linkForeign
	linkFailed
)

func linkRemoveHook(ctx context.Context, repo string, h managedHook, stdout, stderr io.Writer) int {
	hookPath, previousPath, err := linkHookPathsFor(ctx, repo, h.name)
	if err != nil {
		fprintf(stderr, "innsegl link -remove: %v\n", err)
		return linkFailed
	}

	existing, err := os.ReadFile(hookPath)
	switch {
	case os.IsNotExist(err):
		fprintf(stdout, "innsegl link -remove: %s does not exist; nothing to remove\n", hookPath)
		return linkAbsent
	case err != nil:
		fprintf(stderr, "innsegl link -remove: reading %s: %v\n", hookPath, err)
		return linkFailed
	case !strings.Contains(string(existing), h.marker):
		fprintf(stderr, "innsegl link -remove: %s exists and was not written by `innsegl link` — "+
			"refusing to remove a hook it does not own\n", hookPath)
		return linkForeign
	}

	if err := os.Remove(hookPath); err != nil {
		fprintf(stderr, "innsegl link -remove: removing %s: %v\n", hookPath, err)
		return linkFailed
	}

	if _, statErr := os.Stat(previousPath); statErr == nil {
		if err := os.Rename(previousPath, hookPath); err != nil {
			fprintf(stderr, "innsegl link -remove: restoring %s from %s: %v\n", hookPath, previousPath, err)
			return linkFailed
		}
		fprintf(stdout, "innsegl link -remove: removed %s, restored the hook that was there before\n", hookPath)
		return linkRemoved
	} else if !os.IsNotExist(statErr) {
		fprintf(stderr, "innsegl link -remove: checking %s: %v\n", previousPath, statErr)
		return linkFailed
	}

	fprintf(stdout, "innsegl link -remove: removed %s; there was nothing there before\n", hookPath)
	return linkRemoved
}

// linkEnsure links repo when innsegl's hook is not there yet and reports
// whether it installed one. The session hook calls it for every repository
// an agent works in, so a repository is signable from its first use with no
// `innsegl link` by hand; a repository already linked is only read. A hook
// the repository had is kept, exactly as `innsegl link` keeps it.
//
// A repository linked before a hook was added to managedHooks gains it here.
func linkEnsure(ctx context.Context, repo string) (bool, error) {
	complete := true
	for _, h := range managedHooks {
		ours, err := hasManagedHook(ctx, repo, h)
		if err != nil {
			return false, err
		}
		complete = complete && ours
	}
	if complete {
		return false, nil
	}
	var out, errOut strings.Builder
	if code := runLinkInstall(ctx, repo, &out, &errOut); code != exitOK {
		return false, errors.New(strings.TrimSpace(errOut.String()))
	}
	return true, nil
}

// hasManagedHook reports whether repo's hook h is the one innsegl wrote.
func hasManagedHook(ctx context.Context, repo string, h managedHook) (bool, error) {
	hookPath, _, err := linkHookPathsFor(ctx, repo, h.name)
	if err != nil {
		return false, err
	}
	// #nosec G304 -- the hook path git itself resolved for this repository.
	existing, readErr := os.ReadFile(hookPath)
	return readErr == nil && strings.Contains(string(existing), h.marker), nil
}

// isLinked reports whether dir is in a repository linked to innsegl: its
// prepare-commit-msg hook is innsegl's (#575). It never links anything.
func isLinked(ctx context.Context, dir string) bool {
	ours, err := hasManagedHook(ctx, dir, managedHooks[0])
	return err == nil && ours
}

// linkedForHook reports whether the PreToolUse hook acts on a command run in
// cwd (#575). It does in a repository linked to innsegl: one carrying the
// hook `innsegl link` installs, or one innsegl links on first use, a working
// tree with a usable origin (the session hook's rule, hooksession.go), which
// is linked here when it is not yet. It does not in any other repository:
// that repository's commits are not innsegl's to sign, refuse or send.
//
// A cwd that is not in a repository at all (or none given) answers true: the
// command may commit anywhere, and an agent's commit is never left
// unrecorded on a guess.
func linkedForHook(ctx context.Context, cwd string) bool {
	if cwd == "" {
		return true
	}
	if _, err := gitCommonDir(ctx, cwd); err != nil {
		return true
	}
	hookPath, _, err := linkHookPaths(ctx, cwd)
	if err != nil {
		return true
	}
	// #nosec G304 -- the hook path git itself resolved for this repository.
	if existing, rerr := os.ReadFile(hookPath); rerr == nil && strings.Contains(string(existing), linkHookMarker) {
		return true
	}
	derived, err := workspace.Derive(ctx, cwd)
	if err != nil {
		return false
	}
	// Linked on first use, as the session hook would have. A failure to
	// link still acts: the repository is one innsegl records.
	_, _ = linkEnsure(ctx, derived.Main) //nolint:errcheck // see above
	return true
}
