// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
)

// API-037 (ADR-0080 decision 4): the query API reads names through the alias
// table. One repository recorded literally before the switch and as two
// pseudonyms after it (a key rotation) is one repository; an erased one is
// shown by its pseudonym, never blank.
func TestAPI037TheQueryAPIResolvesRepositoryNames(t *testing.T) {
	owner, ownerDSN, readerDSN := migrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	seed(t, owner, 2) // literal: github.com/innsegl/one and two, before the switch
	for _, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		r, err := identity.NewRepositories(identity.ModePseudonymous, key)
		if err != nil {
			t.Fatal(err)
		}
		owner.UseRepositories(r)
		pnRun(ctx, t, owner, "run-pn-"+key[:1], "github.com/innsegl/one", "feature/quiet", true)
	}
	pnRun(ctx, t, owner, "run-erased", "github.com/innsegl/gone", "main", false)

	s, _ := readStore(t, readerDSN)

	list, err := s.Repos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range list.Repos {
		names = append(names, r.Repo)
		if event.IsPseudonym(r.Repo) {
			t.Errorf("the repository list shows a pseudonym %q for a name that resolves", r.Repo)
		}
	}
	slices.Sort(names)
	if want := []string{"github.com/innsegl/gone", "github.com/innsegl/one", "github.com/innsegl/two"}; !slices.Equal(names, want) {
		t.Errorf("repositories = %v, want %v: two pseudonyms and a literal of one repository are one", names, want)
	}

	runs, err := s.ListRuns(ctx, RunFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs.Runs {
		for _, repo := range r.Repos {
			if event.IsPseudonym(repo) {
				t.Errorf("run %s lists repository %q", r.RunID, repo)
			}
		}
	}

	rows, err := s.runTimeline(ctx, "run-pn-a")
	if err != nil {
		t.Fatal(err)
	}
	reg, found := registeredFieldsOf(rows)
	if !found || reg.Repo != "github.com/innsegl/one" || reg.Branch != "feature/quiet" {
		t.Errorf("the run page reads %q on %q (found %v)", reg.Repo, reg.Branch, found)
	}
	commits, err := s.commitsOf(ctx, "run-pn-b")
	if err != nil || len(commits) != 1 || commits[0].Repo != "github.com/innsegl/one" {
		t.Errorf("commitsOf = %+v, %v", commits, err)
	}
	recent, err := s.RecentCommits(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range recent {
		if event.IsPseudonym(c.Repo) {
			t.Errorf("recent commit %s shows %q", c.CommitSHA, c.Repo)
		}
	}

	t.Run("an erased name is shown by its pseudonym", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := erasure.Repository(ctx, conn, "github.com/innsegl/gone", "test"); err != nil {
			t.Fatal(err)
		}
		list, err := s.Repos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var erased int
		for _, r := range list.Repos {
			if r.Repo == "github.com/innsegl/gone" {
				t.Error("an erased name is still shown")
			}
			if event.IsPseudonym(r.Repo) {
				erased++
			}
		}
		if erased != 1 {
			t.Errorf("%d pseudonyms shown after erasing one repository, want 1", erased)
		}
	})
}

// pnRun appends a registration of one run in repo, and a signed commit.
func pnRun(ctx context.Context, t *testing.T, owner *ledger.Store, runID, repo, branch string, commit bool) {
	t.Helper()
	spiffe := "spiffe://innsegl.dev/agent/fix-ci/jira-1/" + runID
	base := func(et string) event.Fields {
		return event.Fields{event.FieldEventType: et, event.FieldRunID: runID,
			event.FieldSpiffeID: spiffe, event.FieldSource: event.SourceMCP}
	}
	reg := base(event.EventTypeRunRegistered)
	reg[event.FieldAgentType], reg[event.FieldTaskRef] = "fix-ci", "JIRA-1"
	reg[event.FieldRepo], reg[event.FieldBranch] = repo, branch
	reg[event.FieldIdempotencyKey] = runID + "-register"
	appendOrFail(ctx, t, owner, reg)
	if !commit {
		return
	}
	intent := base(event.EventTypeCommitIntent)
	intent[event.FieldRepo] = repo
	intent[event.FieldTreeHash] = strings.Repeat("a", 40)
	intent[event.FieldPatchID] = strings.Repeat("b", 40)
	intent[event.FieldIdempotencyKey] = runID + "-intent"
	in := appendOrFail(ctx, t, owner, intent)
	rec := base(event.EventTypeCommitRecorded)
	rec[event.FieldRepo] = repo
	rec[event.FieldTreeHash] = strings.Repeat("a", 40)
	rec[event.FieldPatchID] = strings.Repeat("b", 40)
	rec[event.FieldCommitSHA] = strings.Repeat(runID[len(runID)-1:], 40)
	rec[event.FieldRekorLogIndex] = int64(7)
	rec[event.FieldRekorEntryUUID] = strings.Repeat("c", 64)
	rec[event.FieldIntentEventID] = in[event.FieldEventID]
	rec[event.FieldIdempotencyKey] = runID + "-recorded"
	appendOrFail(ctx, t, owner, rec)
}
