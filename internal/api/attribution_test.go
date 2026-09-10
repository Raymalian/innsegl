// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
)

// RepoPath resolves a NAME to a PATH, and CommitMessage takes the PATH.
//
// Those two strings are both "the repository" in conversation and neither is
// interchangeable with the other: `git -C` needs the path, and the map is keyed
// on the name. MEASURED: passing the name compiled, passed every test in this
// package, deployed, and answered `404 not found` for a commit that was sitting
// in the mounted checkout — because `git -C github.com/Raymalian/innsegl` is not
// a directory. Nothing caught it because nothing asserted which of the two
// CommitMessage wants.
func TestCommitMessageTakesThePathAndNotTheRepositoryName(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	p := s.prover(t)

	path, ok := p.RepoPath(fixtureRepo)
	if !ok {
		t.Fatalf("RepoPath(%q) found nothing; the scenario serves it", fixtureRepo)
	}
	if path == fixtureRepo {
		t.Fatalf("the fixture's name and path are the same string (%q), so this test "+
			"cannot tell the two apart and proves nothing", path)
	}

	sha, message, err := p.CommitMessage(context.Background(), path, s.commit)
	if err != nil {
		t.Fatalf("CommitMessage with the resolved path: %v — the path is what `git -C` "+
			"needs", err)
	}
	if len(sha) != 40 {
		t.Errorf("CommitMessage returned %q as the sha, want a full 40-hex object id", sha)
	}
	if strings.TrimSpace(message) == "" {
		t.Error("CommitMessage returned an empty message for HEAD")
	}

	// The other half of the contract: the NAME is not a directory, so passing it
	// must fail rather than quietly answer about something else.
	if _, _, err := p.CommitMessage(context.Background(), fixtureRepo, s.commit); err == nil {
		t.Fatalf("CommitMessage accepted the repository name %q as a path — the handler "+
			"resolves the name first precisely because this cannot work", fixtureRepo)
	}
}

// An unknown repository is not found, and never a path lookup against a name
// that happens to exist on disk.
func TestRepoPathRefusesARepositoryThisDeploymentDoesNotServe(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	p := s.prover(t)

	if path, ok := p.RepoPath("github.com/nobody/nothing"); ok {
		t.Fatalf("RepoPath answered %q for a repository this deployment does not serve", path)
	}
}
