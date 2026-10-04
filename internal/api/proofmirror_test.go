// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/mirror"
)

// The core reads repositories only from its mirror (ADR-0065 decision 1, as
// completed by its 2026-10-03 amendment). The proof BFF finds a repository
// in the mirror clients push to, not in a list written at deploy time, and a
// repository or a commit the mirror does not hold yet is answered as exactly
// that: not held yet (ADR-0065 consequence 3), never a verdict.

// staticRepos is a fixed name-to-directory source, for tests that build a
// repository on disk and want the BFF to read it where it is.
type staticRepos map[string]string

func (s staticRepos) Dir(repo string) (string, error) {
	dir, ok := s[repo]
	if !ok {
		return "", errors.New("not in this fixture")
	}
	return dir, nil
}

func (s staticRepos) Repos() ([]string, error) {
	out := make([]string, 0, len(s))
	for name := range s {
		out = append(out, name)
	}
	slices.Sort(out)
	return out, nil
}

// pushToMirror puts commit into the mirror of repo, the way a client's push
// does: through git, into a bare repository the store created.
func pushToMirror(t *testing.T, store *mirror.Store, repo, from, commit string) {
	t.Helper()
	bare, err := store.Ensure(t.Context(), repo)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "git", "-C", from, "push", "--quiet", "--no-verify",
		bare, commit+":refs/heads/main")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if out, perr := cmd.CombinedOutput(); perr != nil {
		t.Fatalf("pushing %s to the mirror: %v: %s", commit, perr, out)
	}
}

func mirrorProver(t *testing.T, s *proofScenario, src RepoSource) *Prover {
	t.Helper()
	p, err := NewProver(ProofConfig{
		FulcioURL: s.fulcio.URL,
		RekorURL:  s.log.URL,
		Repos:     src,
		Now:       func() time.Time { return s.integrated.Add(365 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}
	return p
}

func TestTheProofBFFReadsTheCoreMirror(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	root := filepath.Join(t.TempDir(), "mirror")
	writer, err := mirror.New(root)
	if err != nil {
		t.Fatal(err)
	}
	// The query API opens the mirror read-only, before any client pushed.
	reader, err := mirror.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	p := mirrorProver(t, s, reader)
	if got := p.Repos(); len(got) != 0 {
		t.Fatalf("Repos() of an empty mirror = %v, want none", got)
	}

	// Not held yet: the repository has never been pushed.
	_, err = p.Prove(t.Context(), fixtureRepo, s.commit)
	if !errors.Is(err, ErrNotHeld) || !errors.Is(err, ErrNotFound) {
		t.Fatalf("Prove before any push = %v, want ErrNotHeld (and ErrNotFound, so it is a 404)", err)
	}
	if !strings.Contains(err.Error(), "not held yet") {
		t.Errorf("the refusal does not say the repository is not held yet: %v", err)
	}

	// A client pushes; the running BFF sees it with no restart and no list.
	pushToMirror(t, writer, fixtureRepo, s.repo, s.commit)
	if got := p.Repos(); !slices.Equal(got, []string{fixtureRepo}) {
		t.Fatalf("Repos() after a push = %v, want [%s]", got, fixtureRepo)
	}
	proof, err := p.Prove(t.Context(), fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove of a commit the mirror holds: %v", err)
	}
	if proof.Repo != fixtureRepo || proof.CommitSHA != s.commit {
		t.Errorf("proof is about %s %s, want %s %s", proof.Repo, proof.CommitSHA, fixtureRepo, s.commit)
	}
	if path, ok := p.RepoPath(fixtureRepo); !ok || !strings.HasPrefix(path, reader.Root()) {
		t.Errorf("RepoPath = %q %v, want a directory under the mirror", path, ok)
	}
	// Searched without naming the repository, it is found in the mirror.
	if found, serr := p.Prove(t.Context(), "", s.commit); serr != nil || found.Repo != fixtureRepo {
		t.Errorf("Prove by search = %v %v, want it found in %s", found.Repo, serr, fixtureRepo)
	}

	// A held repository that does not hold the commit yet: also not held,
	// because the next push may carry it.
	other := strings.Repeat("e", 40)
	_, err = p.Prove(t.Context(), fixtureRepo, other)
	if !errors.Is(err, ErrNotHeld) || !errors.Is(err, ErrNotFound) {
		t.Errorf("Prove of a commit the mirror lacks = %v, want ErrNotHeld", err)
	}
	_, err = p.Prove(t.Context(), "", other)
	if !errors.Is(err, ErrNotHeld) || !errors.Is(err, ErrNotFound) {
		t.Errorf("Prove by search of a commit no mirror holds = %v, want ErrNotHeld", err)
	}
	// A name doc 02 §5 does not admit is not held either, and is never a path.
	if _, err = p.Prove(t.Context(), "../../etc", s.commit); !errors.Is(err, ErrNotFound) {
		t.Errorf("Prove of a malformed repository = %v, want ErrNotFound", err)
	}
	if _, ok := p.RepoPath("../../etc"); ok {
		t.Error("RepoPath resolved a malformed repository")
	}
}

func TestTheProofBFFSaysWhenItCannotListTheMirror(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	root := filepath.Join(t.TempDir(), "mirror")
	if _, err := mirror.New(root); err != nil {
		t.Fatal(err)
	}
	reader, err := mirror.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	p := mirrorProver(t, s, reader)
	if rerr := os.RemoveAll(root); rerr != nil {
		t.Fatal(rerr)
	}
	if got := p.Repos(); len(got) != 0 {
		t.Errorf("Repos() of an unreadable mirror = %v, want none", got)
	}
	_, err = p.Prove(t.Context(), "", s.commit)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Prove by search over an unreadable mirror = %v; that is a fault, not a 404", err)
	}
}

func TestNewProverNeedsARepositorySourceButNotARepository(t *testing.T) {
	if _, err := NewProver(ProofConfig{FulcioURL: "https://f.example", RekorURL: "https://r.example"}); err == nil {
		t.Error("NewProver accepted a configuration with nowhere to read a repository from")
	}
	// An empty mirror is a normal start: no client has pushed yet.
	if _, err := NewProver(ProofConfig{
		Repos: staticRepos{}, FulcioURL: "https://f.example", RekorURL: "https://r.example",
	}); err != nil {
		t.Errorf("NewProver refused an empty repository source: %v", err)
	}
}
