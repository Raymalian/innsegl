// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// MaxRepos bounds the repositories list. A ledger that names more than this
// is served its most recently active; the list is an index, not an export.
const MaxRepos = 500

// RepoSummary is one repository the ledger holds a run or commit for.
//
// Runs counts the runs that recorded this repository. Commits counts
// `commit_recorded` events that named it, so unlike RunSummary.Commits it is
// this repository's alone and never spans others a run touched.
type RepoSummary struct {
	Repo        string    `json:"repo"`
	Runs        int       `json:"runs"`
	Commits     int       `json:"commits"`
	LastEventAt time.Time `json:"last_event_at"`
}

// RepoList is the repositories index.
type RepoList struct {
	Repos    []RepoSummary `json:"repos"`
	DataAsOf time.Time     `json:"data_as_of"`
}

var reposSQL = `
WITH scoped AS (
    SELECT run_id, ts, event_type,
           innsegl.resolve_alias(convert_from(canonical, 'UTF8')::jsonb->>'repo') AS repo
      FROM innsegl.events
     WHERE run_id IS NOT NULL
       AND ` + scopeSQL("run_id", 2, 3) + `
)
SELECT repo,
       count(DISTINCT run_id)::int AS runs,
       (count(*) FILTER (WHERE event_type = 'commit_recorded'))::int AS commits,
       max(ts) AS last_event_at
  FROM scoped
 WHERE repo IS NOT NULL
 GROUP BY repo
 ORDER BY max(ts) DESC, repo
 LIMIT $1`

// Repos serves the repositories index.
func (s *Store) Repos(ctx context.Context) (RepoList, error) {
	machines, unowned := scopeArgs(ctx)
	rows, err := s.pool.Query(ctx, reposSQL, MaxRepos, machines, unowned)
	if err != nil {
		return RepoList{}, fmt.Errorf("api: listing repositories: %w", err)
	}
	defer rows.Close()

	list := RepoList{Repos: []RepoSummary{}, DataAsOf: time.Now().UTC()}
	for rows.Next() {
		var r RepoSummary
		if err := rows.Scan(&r.Repo, &r.Runs, &r.Commits, &r.LastEventAt); err != nil {
			return RepoList{}, fmt.Errorf("api: reading a repository: %w", err)
		}
		r.LastEventAt = r.LastEventAt.UTC()
		list.Repos = append(list.Repos, r)
	}
	if err := rows.Err(); err != nil {
		return RepoList{}, fmt.Errorf("api: listing repositories: %w", err)
	}
	return list, nil
}

func (s *Server) handleRepos(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Repos(r.Context())
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
