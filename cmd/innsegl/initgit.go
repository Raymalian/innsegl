// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// The repository's --local git configuration, and nothing else.
//
// `innsegl init` is `--local` only (#117 acceptance bullet four: "Nothing is
// written outside the repository"). Every command this file runs carries
// `--local` explicitly rather than relying on git's own scope-resolution
// order, so a repository whose global config already sets one of these keys
// cannot make `--local` writes land somewhere else, and so a bug here fails
// loudly (git refuses `--local` outside a repository) instead of quietly
// reaching $HOME/.gitconfig.

// gitLocal is a narrow wrapper over `git config --local`.
type gitLocal struct {
	gitPath string
	repo    string
}

// newGitLocal builds a gitLocal. gitPath empty means "git" resolved on PATH.
func newGitLocal(gitPath, repo string) gitLocal {
	if gitPath == "" {
		gitPath = "git"
	}
	return gitLocal{gitPath: gitPath, repo: repo}
}

func (g gitLocal) run(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-C", g.repo, "config", "--local"}, args...)
	//nolint:gosec // G204: gitPath is configuration and args are literals or already-validated keys/values
	cmd := exec.CommandContext(ctx, g.gitPath, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// configGet reads one --local key. Absence is (ok=false, err=nil); git config
// exits 1 for "key not found", which every other exit status does not share.
func (g gitLocal) configGet(ctx context.Context, key string) (string, bool, error) {
	out, err := g.run(ctx, "--get", key)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, fmt.Errorf("git config --local --get %s: %w: %s", key, err, strings.TrimSpace(out))
	}
	return strings.TrimSuffix(out, "\n"), true, nil
}

// configSet writes one --local key, replacing any existing value.
func (g gitLocal) configSet(ctx context.Context, key, value string) error {
	if out, err := g.run(ctx, "--replace-all", key, value); err != nil {
		return fmt.Errorf("git config --local %s %s: %w: %s", key, value, err, strings.TrimSpace(out))
	}
	return nil
}

// configUnset removes one --local key. Idempotent: an already-absent key is
// success, because --undo must be safe to run more than once (#117 acceptance
// bullet one, applied to reversal as well as to application).
func (g gitLocal) configUnset(ctx context.Context, key string) error {
	out, err := g.run(ctx, "--unset-all", key)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 5 {
			// git config's own code for "no such key"; already the state we want.
			return nil
		}
		return fmt.Errorf("git config --local --unset-all %s: %w: %s", key, err, strings.TrimSpace(out))
	}
	return nil
}

// configList is the acceptance criterion's own instrument (#117: "`--undo`
// returns the repository to its prior state, proved by comparing `git config
// --local --list` before and after"). Sorted so two calls that wrote the same
// keys in a different order still compare equal.
func (g gitLocal) configList(ctx context.Context) ([]string, error) {
	out, err := g.run(ctx, "--list")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil // a repository with no local config at all
		}
		return nil, fmt.Errorf("git config --local --list: %w: %s", err, strings.TrimSpace(out))
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	sort.Strings(lines)
	return lines, nil
}

// ---------------------------------------------------------------------------
// The three signing keys, and the bookkeeping that makes --undo exact.
// ---------------------------------------------------------------------------

// The three git config keys ADR-0031 decision 1 passes to gitsign with `-c`
// for the wrapper's own subprocess. `init` writes the SAME three, but
// PERSISTENTLY and REPOSITORY-LOCAL, because it configures plain `git commit`
// for a human running it directly — the wrapper deliberately bypasses repo
// config (ADR-0028), and this is the other half: the surface a human's own
// git actually reads.
const (
	keyGPGFormat      = "gpg.format"
	keyGPGX509Program = "gpg.x509.program"
	keyCommitGPGSign  = "commit.gpgsign"
)

var signingKeys = [...]string{keyGPGFormat, keyGPGX509Program, keyCommitGPGSign}

// The bookkeeping section. Everything --undo needs to restore the repository
// EXACTLY lives here, inside --local config itself — not a side file — so the
// acceptance proof ("`git config --local --list` before and after") is a
// complete statement about what `init` has to put back, itself included.
const (
	bookManaged = "innsegl.init.managed"
	bookFiles   = "innsegl.init.files"
	bookRef     = "innsegl.init.verifyRef"

	bookBackupPrefix = "innsegl.init.backup-"
	bookHadPrefix    = "innsegl.init.had-"
)

// backupKeyName turns a config key into a bookkeeping key name. Dots are not
// legal inside a git config KEY (they are the section/subsection separator),
// so they are flattened; the three keys this ever runs on are fixed and none
// of the three collide once flattened.
func backupKeyName(key string) string {
	return strings.ReplaceAll(key, ".", "-")
}

// gitsignSetup is what apply writes into the three signing keys.
type gitsignSetup struct {
	// GitsignPath is the absolute, SHA-verified path to gitsign (initgitsign.go).
	GitsignPath string
}

// errNotInitialized is loadGitSigningRecorder's refusal when init has not
// run, or has already been undone. --undo on a repository with nothing to
// undo is a mistake worth naming rather than a silent no-op: the operator
// asked for a specific repository to go back to its prior state and this
// package cannot tell them that happened if it never held one.
var errNotInitialized = errors.New("innsegl init: this repository carries no record of a prior " +
	"`innsegl init` run to undo")

// gitSigningRecorder applies the three signing keys and can reverse itself
// exactly, using only what it can read back out of --local config.
type gitSigningRecorder struct {
	g gitLocal
}

// newGitSigningRecorder is the fresh recorder apply uses. It captures nothing
// yet; capture happens inside apply, against whatever is live at that moment.
func newGitSigningRecorder(g gitLocal) *gitSigningRecorder {
	return &gitSigningRecorder{g: g}
}

// loadGitSigningRecorder finds a PRIOR apply's bookkeeping, for --undo. It
// refuses when none exists.
func loadGitSigningRecorder(ctx context.Context, g gitLocal) (*gitSigningRecorder, error) {
	managed, ok, err := g.configGet(ctx, bookManaged)
	if err != nil {
		return nil, err
	}
	if !ok || managed != "true" {
		return nil, errNotInitialized
	}
	return &gitSigningRecorder{g: g}, nil
}

// apply writes the three signing keys, capturing whatever was there first —
// UNLESS a capture from an earlier apply already exists, in which case a
// second run must change nothing further (#117 acceptance bullet one): if it
// re-captured now, the "prior state" --undo restores to would become
// whatever the FIRST apply left behind, not the state before init ever ran.
func (r *gitSigningRecorder) apply(ctx context.Context, setup gitsignSetup) error {
	if setup.GitsignPath == "" {
		return errors.New("innsegl init: no gitsign path to configure")
	}

	already, ok, err := r.g.configGet(ctx, bookManaged)
	if err != nil {
		return err
	}
	firstRun := !ok || already != "true"

	if firstRun {
		for _, key := range signingKeys {
			val, had, gerr := r.g.configGet(ctx, key)
			if gerr != nil {
				return gerr
			}
			if err := r.g.configSet(ctx, bookHadPrefix+backupKeyName(key), fmt.Sprintf("%v", had)); err != nil {
				return err
			}
			if had {
				if err := r.g.configSet(ctx, bookBackupPrefix+backupKeyName(key), val); err != nil {
					return err
				}
			}
		}
		if err := r.g.configSet(ctx, bookManaged, "true"); err != nil {
			return err
		}
	}

	target := map[string]string{
		keyGPGFormat:      "x509",
		keyGPGX509Program: setup.GitsignPath,
		keyCommitGPGSign:  "true",
	}
	for _, key := range signingKeys {
		if err := r.g.configSet(ctx, key, target[key]); err != nil {
			return err
		}
	}
	return nil
}

// undo restores the three signing keys to whatever apply found, then removes
// every bookkeeping key apply wrote — INCLUDING `bookManaged`, so the
// resulting `--local --list` is byte-for-byte what it was before `init` ever
// ran (#117 acceptance bullet three).
func (r *gitSigningRecorder) undo(ctx context.Context) error {
	managed, ok, err := r.g.configGet(ctx, bookManaged)
	if err != nil {
		return err
	}
	if !ok || managed != "true" {
		return errNotInitialized
	}

	for _, key := range signingKeys {
		had, ok, err := r.g.configGet(ctx, bookHadPrefix+backupKeyName(key))
		if err != nil {
			return err
		}
		if !ok {
			// Nothing was ever recorded for this key (should not happen once
			// bookManaged is set, but failing closed here would strand the
			// repository half-undone). Unset it and move on.
			if err := r.g.configUnset(ctx, key); err != nil {
				return err
			}
			continue
		}
		if had == "true" {
			val, present, err := r.g.configGet(ctx, bookBackupPrefix+backupKeyName(key))
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("innsegl init: %s was recorded as previously set but its backup "+
					"value is missing; refusing to guess", key)
			}
			if err := r.g.configSet(ctx, key, val); err != nil {
				return err
			}
		} else {
			if err := r.g.configUnset(ctx, key); err != nil {
				return err
			}
		}
		if err := r.g.configUnset(ctx, bookHadPrefix+backupKeyName(key)); err != nil {
			return err
		}
		if err := r.g.configUnset(ctx, bookBackupPrefix+backupKeyName(key)); err != nil {
			return err
		}
	}

	if err := r.g.configUnset(ctx, bookFiles); err != nil {
		return err
	}
	if err := r.g.configUnset(ctx, bookRef); err != nil {
		return err
	}
	return r.g.configUnset(ctx, bookManaged)
}

// recordFiles and recordRef let init.go note what ELSE it created (the
// deployment config file, the pre-push hook, the verification ref) so undo
// can find and remove them too. Stored as bookkeeping alongside the signing
// keys' own, for the same reason: one place, inside --local config, that
// --undo reads to reverse everything.
func (r *gitSigningRecorder) recordFiles(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	existing, _, err := r.g.configGet(ctx, bookFiles)
	if err != nil {
		return err
	}
	var all []string
	seen := map[string]bool{}
	if existing != "" {
		all = strings.Split(existing, "\x1f")
		for _, p := range all {
			seen[p] = true
		}
	}
	for _, p := range paths {
		if !seen[p] {
			all = append(all, p)
			seen[p] = true
		}
	}
	return r.g.configSet(ctx, bookFiles, strings.Join(all, "\x1f"))
}

func (r *gitSigningRecorder) recordedFiles(ctx context.Context) ([]string, error) {
	existing, ok, err := r.g.configGet(ctx, bookFiles)
	if err != nil || !ok || existing == "" {
		return nil, err
	}
	return strings.Split(existing, "\x1f"), nil
}

func (r *gitSigningRecorder) recordRef(ctx context.Context, ref string) error {
	return r.g.configSet(ctx, bookRef, ref)
}

func (r *gitSigningRecorder) recordedRef(ctx context.Context) (string, error) {
	ref, _, err := r.g.configGet(ctx, bookRef)
	return ref, err
}
