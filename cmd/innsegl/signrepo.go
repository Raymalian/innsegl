// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// envSignRepo names the repository an agent's tool call works in: the git
// common directory of the hook input's working directory, absolute, so
// every worktree of that repository shares it. The PreToolUse hook exports
// it beside the signing configuration, and `innsegl sign` refuses to sign a
// commit in any other repository -- a test's scratch repository, a tool's
// own -- that inherited the configuration from the same command.
const envSignRepo = "INNSEGL_SIGN_REPO"

// gitCommonDirTimeout bounds the one git call each side makes.
const gitCommonDirTimeout = 3 * time.Second

// gitCommonDir answers dir's repository as its absolute git common
// directory, with symlinks resolved so two spellings of one path compare
// equal.
func gitCommonDir(ctx context.Context, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitCommonDirTimeout)
	defer cancel()
	// #nosec G702 -- argv, no shell: dir is one argument to -C, and a dir that
	// is not a directory git can enter is refused by git itself
	// (TestGitCommonDirRefusesWhatIsNotADirectory).
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if p == "" || !filepath.IsAbs(p) {
		return "", errors.New("git named no absolute common directory")
	}
	if resolved, rerr := filepath.EvalSymlinks(p); rerr == nil {
		p = resolved
	}
	return p, nil
}
