// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"strings"
	"testing"
)

// A repository is recorded on first use (ADR-0063 amendment, 2026-10-02):
// the first installation to act on a repository nobody holds makes its
// organisation the holder, audited with the installation as the actor. One
// live holder per repository stays enforced: another organisation's grant is
// out of scope, and claims nothing.
func TestClaimRepoGrantsAnUnheldRepositoryOnFirstUse(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	mk := func(account string, repos ...string) Installation {
		t.Helper()
		i, err := s.CreateInstallation(ctx, InstallationParams{
			AccountID: account, CreatedBy: "u-1", Name: "m", Kind: KindWorkstation, Repos: repos})
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	const fresh, listedOnly, held = "github.com/acme/fresh", "github.com/acme/listed", "github.com/rival/held"
	star := mk(a.ID, AllRepos)
	listed := mk(a.ID, listedOnly)

	claim := func(i Installation, repo string, want bool) {
		t.Helper()
		got, err := s.ClaimRepo(ctx, i.ID, repo)
		if err != nil || got != want {
			t.Fatalf("ClaimRepo(%s, %s) = %v, %v; want %v", i.ID[:6], repo, got, err, want)
		}
	}

	// Unheld, and the installation's list is "*": claimed, and in scope.
	claim(star, fresh, true)
	if ok, err := s.InScope(ctx, star.ID, fresh); err != nil || !ok {
		t.Fatalf("after the claim InScope = %v, %v; want true", ok, err)
	}
	// Claiming again is a no-op: one grant, one audit row.
	claim(star, fresh, true)
	c, cctx := ownerConn(t, e.ownerDSN)
	var grants, audits int
	var actor string
	if err := c.QueryRow(cctx, `SELECT count(*) FROM innsegl_auth.repo_grants
	                             WHERE account_id = $1 AND repo = $2 AND until IS NULL`, a.ID, fresh).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(cctx, `SELECT count(*), min(actor) FROM innsegl_auth.audit
	                             WHERE account_id = $1 AND action = 'repo_grant.created' AND subject = (
	                               SELECT 'grant:' || grant_id FROM innsegl_auth.repo_grants WHERE repo = $2 AND until IS NULL)`,
		a.ID, fresh).Scan(&audits, &actor); err != nil {
		t.Fatal(err)
	}
	if grants != 1 || audits != 1 || actor != "installation:"+star.ID {
		t.Fatalf("grants=%d audits=%d actor=%q; want 1, 1, installation:%s", grants, audits, actor, star.ID)
	}

	// An explicit list narrows: a repository not on it is never claimed...
	claim(listed, "github.com/acme/unlisted", false)
	// ...and one on it is.
	claim(listed, listedOnly, true)

	// Another organisation holds it: refused, and nothing changes hands.
	recordPseudonymous(t, e) // a second account needs the switch (ACC-008)
	rival, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Rival"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRepo(ctx, rival.ID, held, ""); err != nil {
		t.Fatal(err)
	}
	claim(star, held, false)
	if err := s.GrantRepo(ctx, a.ID, held, ""); !errors.Is(err, ErrRepoHeld) {
		t.Fatalf("the rival's grant moved: %v", err)
	}

	// Not a repository name, an unknown installation, a suspended one: nothing.
	claim(star, "*", false)
	claim(star, "not-a-repo", false)
	if ok, err := s.ClaimRepo(ctx, strings.Repeat("9", 32), "github.com/acme/ghost"); err != nil || ok {
		t.Fatalf("unknown installation: %v, %v", ok, err)
	}
	if err := s.SetInstallationStatus(ctx, star.ID, StatusSuspended, ""); err != nil {
		t.Fatal(err)
	}
	claim(star, "github.com/acme/later", false)
	if err := c.QueryRow(cctx, `SELECT count(*) FROM innsegl_auth.repo_grants WHERE repo IN
	    ('github.com/acme/unlisted', 'github.com/acme/ghost', 'github.com/acme/later')`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("%d grants were made for refused claims", grants)
	}
}

// An installation's repos default to "*": every repository its organisation
// holds or will hold. An explicit list is still honoured.
func TestEnrolmentTokenReposDefaultToEverything(t *testing.T) {
	_, s, a := setup(t)
	ctx := tctx(t)
	token, _, err := s.CreateEnrolmentToken(ctx, TokenParams{AccountID: a.ID, CreatedBy: "u-1"})
	if err != nil {
		t.Fatalf("a token with no repos: %v", err)
	}
	enr, err := s.ConsumeEnrolmentToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(enr.Repos) != 1 || enr.Repos[0] != AllRepos {
		t.Fatalf("repos = %v, want [*]", enr.Repos)
	}
}

// RM-313: an installation's list narrows its repositories only when it was
// set on purpose. An empty list, like "*", is every repository its
// organisation holds or will hold on first use.
func TestReposAdmitTreatsAnEmptyListAsEverything(t *testing.T) {
	for _, tc := range []struct {
		repos []string
		want  bool
	}{
		{nil, true},
		{[]string{}, true},
		{[]string{AllRepos}, true},
		{[]string{"github.com/acme/app"}, true},
		{[]string{"github.com/acme/other"}, false},
	} {
		if got := reposAdmit(tc.repos, "github.com/acme/app"); got != tc.want {
			t.Errorf("reposAdmit(%q) = %v, want %v", tc.repos, got, tc.want)
		}
	}
}
