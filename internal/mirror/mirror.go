// SPDX-License-Identifier: Apache-2.0

// Package mirror is the core's per-repository evidence store (ADR-0065): one
// bare repository per repository id, fed by an authenticated push from the
// client.
//
// This slice receives only what the commit-sign path needs: the objects of a
// commit about to be signed, pushed to the installation's own staging ref
// (commitpath.StagingRef). Every other ref, every delete and every fetch is
// refused.
package mirror

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
)

// EnvDir names the directory the mirrors live under.
const EnvDir = "INNSEGL_MIRROR_DIR"

// ErrNoMirror reports a repository the core holds no mirror of yet.
var ErrNoMirror = errors.New("the core holds no mirror of this repository yet")

// Store is the set of mirrors under one root.
type Store struct {
	root string
	mu   sync.Mutex
}

// New opens the store at root, creating root (0700) when it is missing.
func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("mirror: no root directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("mirror: creating %s: %w", abs, err)
	}
	return &Store{root: abs}, nil
}

// Open opens an existing store for reading and never creates anything. The
// query API and the reconciler read the mirror this way, from a read-only
// mount: they answer about what clients pushed, and must not be able to
// make a mirror appear.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("mirror: no root directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("mirror: %s is not a directory", abs)
	}
	return &Store{root: abs}, nil
}

// Root is the directory every mirror lives under.
func (s *Store) Root() string { return s.root }

// Repos lists the repositories this store holds a mirror of, sorted. A
// directory is a mirror only when it sits at <root>/<host>/<org>/<name>.git,
// its name is one doc 02 §5 admits, and it has a HEAD. Anything else under
// the root is not a repository the core holds.
func (s *Store) Repos() ([]string, error) {
	hosts, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("mirror: listing %s: %w", s.root, err)
	}
	var out []string
	for _, host := range hosts {
		for _, org := range entries(filepath.Join(s.root, host.Name())) {
			for _, name := range entries(filepath.Join(s.root, host.Name(), org.Name())) {
				base, ok := strings.CutSuffix(name.Name(), ".git")
				if !ok || !name.IsDir() {
					continue
				}
				repo := host.Name() + "/" + org.Name() + "/" + base
				if _, derr := s.Dir(repo); derr == nil {
					out = append(out, repo)
				}
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// path is the mirror directory for repo, after repo is proven an identifier:
// doc 02 §5's grammar admits no segment that could leave the root.
func (s *Store) path(repo string) (string, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return "", err
	}
	return filepath.Join(s.root, filepath.FromSlash(repo)+".git"), nil
}

// Dir answers the mirror of repo, or ErrNoMirror when none was created.
func (s *Store) Dir(repo string) (string, error) {
	dir, err := s.path(repo)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoMirror, repo)
	}
	return dir, nil
}

// entries lists dir, and nothing when dir cannot be read: a level that
// cannot be read (a stray file among the hosts or organisations) holds no
// mirror this process can serve. Dir is the check that decides.
func entries(dir string) []os.DirEntry {
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	return list
}

// mirrorConfig is set in every mirror, and passed again on every receive:
// no hook runs, nothing is deleted, every object is checked, and no
// background work follows a push.
var mirrorConfig = [][2]string{
	{"core.hooksPath", os.DevNull},
	{"receive.denyDeletes", "true"},
	{"receive.denyCurrentBranch", "refuse"},
	{"receive.fsckObjects", "true"},
	{"receive.autogc", "false"},
	{"receive.advertisePushOptions", "false"},
	{"gc.auto", "0"},
}

// Ensure answers the mirror of repo, creating it on first use.
func (s *Store) Ensure(ctx context.Context, repo string) (string, error) {
	dir, err := s.path(repo)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// G703: dir is the root joined with a repository id event.ValidateRepo
	// admitted (three segments, each starting with a letter or digit), so it
	// cannot leave the root.
	if _, serr := os.Stat(filepath.Join(dir, "HEAD")); serr == nil { //nolint:gosec // G703, see above
		return dir, nil
	}
	if merr := os.MkdirAll(filepath.Dir(dir), 0o700); merr != nil { //nolint:gosec // G703, see above
		return "", fmt.Errorf("mirror: creating %s: %w", filepath.Dir(dir), merr)
	}
	if _, gerr := s.git(ctx, s.root, nil, "init", "--bare", "--quiet", dir); gerr != nil {
		return "", gerr
	}
	for _, kv := range mirrorConfig {
		if _, gerr := s.git(ctx, dir, nil, "config", kv[0], kv[1]); gerr != nil {
			return "", gerr
		}
	}
	return dir, nil
}

// Missing answers which of oids the mirror of repo does not hold.
func (s *Store) Missing(ctx context.Context, repo string, oids []string) ([]string, error) {
	for _, oid := range oids {
		if err := event.ValidateGitObjectID(oid); err != nil {
			return nil, err
		}
	}
	dir, err := s.Dir(repo)
	if err != nil {
		return nil, err
	}
	out, err := s.git(ctx, dir, strings.NewReader(strings.Join(oids, "\n")+"\n"), "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	var missing []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if oid, ok := strings.CutSuffix(sc.Text(), " missing"); ok {
			missing = append(missing, oid)
		}
	}
	return missing, nil
}

// DropStaging deletes a tool call's staging ref once the commit-sign path is
// done with it. An absent ref is not an error.
func (s *Store) DropStaging(ctx context.Context, repo, installation, toolUseID string) error {
	if !commitpath.IsToolUseID(toolUseID) || !isInstallationID(installation) {
		return fmt.Errorf("mirror: %q/%q is not a staging ref", installation, toolUseID)
	}
	dir, err := s.Dir(repo)
	if err != nil {
		return err
	}
	_, err = s.git(ctx, dir, nil, "update-ref", "-d", commitpath.StagingRef(installation, toolUseID))
	return err
}

// isInstallationID is accounts' installation id grammar: 32 lowercase hex.
// Anything else never reaches a ref name.
func isInstallationID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// gitEnv is the whole environment a mirror's git runs with: no system or
// global configuration, no prompt, and nothing of the process's own.
func (s *Store) gitEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + s.root,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	}
}

// gitArgs prefixes args with the mirror configuration, so a mirror whose own
// config was changed still runs no hook.
func gitArgs(dir string, args ...string) []string {
	out := []string{"-C", dir}
	for _, kv := range mirrorConfig {
		out = append(out, "-c", kv[0]+"="+kv[1])
	}
	return append(out, args...)
}

func (s *Store) git(ctx context.Context, dir string, stdin *strings.Reader, args ...string) ([]byte, error) {
	// G204: an argument list, never shell text; dir is under the root and
	// built from a validated repository id, and args are this package's own.
	cmd := exec.CommandContext(ctx, "git", gitArgs(dir, args...)...) //nolint:gosec // see above
	cmd.Env = s.gitEnv()
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mirror: git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Remove deletes the mirror of repo, and reports whether there was one. It is
// erasure's (ADR-0080, operator decision 6): a mirror left behind keeps a
// repository's name in its path, which would undo the erasure of its alias.
func (s *Store) Remove(repo string) (bool, error) {
	dir, err := s.path(repo)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, fmt.Errorf("mirror: removing %s: %w", repo, err)
	}
	return true, nil
}
