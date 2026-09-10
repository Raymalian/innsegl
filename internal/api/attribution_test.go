// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
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

// The endpoint end to end, over HTTP, because that is how the dashboard reaches
// it and because the two 0%-covered functions are the handler and its adapter.

// A repository this deployment does not serve is not found, and the answer says
// so rather than guessing at a path.
func TestAttributionRefusesARepositoryThisDeploymentDoesNotServe(t *testing.T) {
	listening, _ := testServer(t)

	got := do(t, http.MethodGet,
		listening.URL+"/api/v1/attribution/"+strings.Repeat("a", 40)+
			"?repo=github.com/nobody/nothing", "")
	if got.status != http.StatusNotFound {
		t.Fatalf("status %d for an unserved repository, want 404: %s", got.status, got.body)
	}
}

// A commit that is not in the served repository is not found either, and the
// message names the repository it was looked for in.
func TestAttributionRefusesACommitThatIsNotInTheRepository(t *testing.T) {
	listening, _ := testServer(t)

	got := do(t, http.MethodGet,
		listening.URL+"/api/v1/attribution/"+strings.Repeat("b", 40)+
			"?repo="+fixtureRepo, "")
	if got.status != http.StatusNotFound {
		t.Fatalf("status %d for a commit not in the repository, want 404: %s",
			got.status, got.body)
	}
}

// The ordinary path. The fixture commit carries a trailer and the ledger holds
// no record of its change, so the content check answers `failed` — which is the
// right answer and, importantly, a 200: "we looked and the content does not
// match" is an answer this API is obliged to give in full, not an HTTP error.
func TestAttributionAnswersAboutACommitItServes(t *testing.T) {
	listening, s := testServer(t)

	got := do(t, http.MethodGet,
		listening.URL+"/api/v1/attribution/"+s.commit+"?repo="+fixtureRepo, "")
	if got.status != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", got.status, got.body)
	}
	var out Attribution
	if err := json.Unmarshal(got.body, &out); err != nil {
		t.Fatalf("decoding the reply: %v: %s", err, got.body)
	}
	if out.Commit != s.commit {
		t.Errorf("commit %q, want %q", out.Commit, s.commit)
	}
	if out.Repo != fixtureRepo {
		t.Errorf("repo %q, want %q", out.Repo, fixtureRepo)
	}
	if out.Content.Result == "" {
		t.Error("no content result: the endpoint exists to carry exactly this")
	}
	if out.Content.PatchID == "" {
		t.Error("no patch id reported; a reader must be able to recompute the answer")
	}
}
