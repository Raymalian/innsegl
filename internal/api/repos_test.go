// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The repositories list: one row per repository the ledger has a recorded
// run or commit for, with the runs and commits counted by the database.
func TestReposListsEachRepositoryWithItsCounts(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	seeded := seed(t, owner, 6)
	s, _ := readStore(t, readerDSN)

	list, err := s.Repos(t.Context())
	if err != nil {
		t.Fatalf("Repos: %v", err)
	}
	if list.DataAsOf.IsZero() {
		t.Error("the list carries no data-as-of marker")
	}

	wantRuns := map[string]int{}
	wantCommits := map[string]int{}
	for _, r := range seeded {
		wantRuns[r.repo]++
		wantCommits[r.repo] += r.commits
	}
	if len(list.Repos) != len(wantRuns) {
		t.Fatalf("got %d repositories, the fixture used %d: %+v",
			len(list.Repos), len(wantRuns), list.Repos)
	}
	for _, row := range list.Repos {
		if row.Runs != wantRuns[row.Repo] {
			t.Errorf("%s: runs = %d, want %d", row.Repo, row.Runs, wantRuns[row.Repo])
		}
		if row.Commits != wantCommits[row.Repo] {
			t.Errorf("%s: commits = %d, want %d", row.Repo, row.Commits, wantCommits[row.Repo])
		}
		if row.LastEventAt.IsZero() {
			t.Errorf("%s: no last event time", row.Repo)
		}
	}
	for i := 1; i < len(list.Repos); i++ {
		if list.Repos[i].LastEventAt.After(list.Repos[i-1].LastEventAt) {
			t.Error("repositories are not newest-activity first")
		}
	}
}

func TestReposIsServedBehindASession(t *testing.T) {
	srv, _, cookie := testServerWithSession(t)

	if a := get(t, srv.URL, "/api/v1/repos"); a.status != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/repos without a session returned %d, want 401", a.status)
	}
	a := get(t, srv.URL, "/api/v1/repos", cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/repos: %d: %s", a.status, a.body)
	}
	var list RepoList
	decodeBody(t, a, &list)
	if len(list.Repos) == 0 {
		t.Error("the seeded ledger has repositories and the list is empty")
	}
	if a := do(t, http.MethodPost, srv.URL+"/api/v1/repos", "{}", cookie); a.status != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/repos returned %d, want 405", a.status)
	}
}

func TestReposReportsAClosedDatabaseAsAnError(t *testing.T) {
	_, _, readerDSN := migrated(t)
	s, _ := readStore(t, readerDSN)
	s.Close()
	if _, err := s.Repos(t.Context()); err == nil {
		t.Fatal("Repos on a closed pool returned no error")
	}
	rec := httptest.NewRecorder()
	(&Server{store: s}).handleRepos(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/repos", nil))
	if rec.Code < 500 {
		t.Errorf("handleRepos on a closed pool returned %d, want a 5xx", rec.Code)
	}
}
