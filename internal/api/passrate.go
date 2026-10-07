// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// The overview's verification pass rate (FD §3.1). IP §6.11 and FD P2 forbid
// a verdict read from the ledger, so this is measured: the ledger names only
// WHICH commits are the most recent, and every verdict is the Prover's own,
// from git, Fulcio and Rekor. It is never cached; each request measures.

// DefaultRecentCommits is how many recent commits the pass rate covers.
const DefaultRecentCommits = 20

// recentProofTimeout bounds one commit's three checks.
const recentProofTimeout = 15 * time.Second

// RecentCommit is one recorded commit and the verdict measured for it.
type RecentCommit struct {
	Repo      string `json:"repo"`
	CommitSHA string `json:"commit_sha"`
	// Verdict is "verified", "failed" or "unavailable"; see passRateBucket.
	Verdict string `json:"verdict"`
}

// RecentVerification answers GET /api/v1/verification/recent.
type RecentVerification struct {
	Checked     int            `json:"checked"`
	Verified    int            `json:"verified"`
	Failed      int            `json:"failed"`
	Unavailable int            `json:"unavailable"`
	MeasuredAt  time.Time      `json:"measured_at"`
	Commits     []RecentCommit `json:"commits"`
}

const recentCommitsSQL = `
SELECT convert_from(canonical, 'UTF8')::jsonb->>'repo',
       convert_from(canonical, 'UTF8')::jsonb->>'commit_sha'
  FROM innsegl.events
 WHERE event_type = 'commit_recorded'
 ORDER BY chain_position DESC
 LIMIT $1`

// RecentCommits names the most recently recorded commits, newest first.
func (s *Store) RecentCommits(ctx context.Context, limit int) ([]RecentCommit, error) {
	rows, err := s.pool.Query(ctx, recentCommitsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("api: listing recent commits: %w", err)
	}
	defer rows.Close()
	var out []RecentCommit
	for rows.Next() {
		var c RecentCommit
		if err := rows.Scan(&c.Repo, &c.CommitSHA); err != nil {
			return nil, fmt.Errorf("api: reading recent commits: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MeasureRecent runs the three checks on the most recent recorded commits.
// A commit that cannot be checked — an upstream down, a repository the core
// does not hold yet — counts as unavailable, never as failed (FD P2).
func MeasureRecent(ctx context.Context, store *Store, prover *Prover, limit int) (RecentVerification, error) {
	commits, err := store.RecentCommits(ctx, limit)
	if err != nil {
		return RecentVerification{}, err
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := range commits {
		wg.Add(1)
		go func(c *RecentCommit) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, recentProofTimeout)
			defer cancel()
			c.Verdict = string(verify.VerdictUnavailable)
			proof, perr := prover.Prove(pctx, c.Repo, c.CommitSHA)
			if perr != nil {
				return
			}
			c.Verdict = passRateBucket(verify.Verdict(proof.Verdict))
		}(&commits[i])
	}
	wg.Wait()
	out := RecentVerification{MeasuredAt: time.Now().UTC(), Commits: commits}
	if out.Commits == nil {
		out.Commits = []RecentCommit{}
	}
	for _, c := range commits {
		out.Checked++
		switch c.Verdict {
		case string(verify.VerdictVerified):
			out.Verified++
		case string(verify.VerdictFailed):
			out.Failed++
		default:
			out.Unavailable++
		}
	}
	return out, nil
}

// passRateBucket places a verdict in one of the pass rate's three buckets.
//
// A pre-history commit (ADR-0073) is "could not be checked": the evidence that
// would settle it is gone. It is never verified, and it is not a failure,
// because nothing in it was found wrong. Anything this function does not
// know is also "could not be checked" rather than either of the others.
func passRateBucket(v verify.Verdict) string {
	switch v {
	case verify.VerdictVerified, verify.VerdictContentVerified:
		return string(verify.VerdictVerified)
	case verify.VerdictFailed, verify.VerdictUnattributed:
		return string(verify.VerdictFailed)
	default:
		return string(verify.VerdictUnavailable)
	}
}

func (s *Server) handleRecentVerification(w http.ResponseWriter, r *http.Request) {
	out, err := MeasureRecent(r.Context(), s.store, s.prover, DefaultRecentCommits)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
