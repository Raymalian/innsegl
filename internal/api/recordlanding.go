// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"sync/atomic"

	"innsegl.dev/innsegl/internal/event"
)

// recordlanding.go derives RecordCommit.Landed — landed, not_landed,
// rewritten or unknown — reusing internal/reconciler/landing.go's own
// reading, restated for a read-only handler that has no Repos
// (internal/reconciler.Repos) of its own: this file asks the SAME two
// questions landing.go's own GitWorkspace.CommitReachable asks, against the
// SAME served checkout the proof BFF already holds (Server.prover), rather
// than a second resolution of what "repo" names.
//
// ADR-0059 decision 6 is binding here exactly as it is there: "signed is
// recorded; landed is observed... derived, never assumed". Nothing here
// writes anything, and nothing here is a verdict this run page invented —
// it is the identical two-step git read, so a commit this page calls
// "landed" and one the reconciler's own landing pass calls "landed" can
// never disagree about the same commit.

// landingOf derives RecordCommit.Landed for one commit_recorded.
func (rs *recordServer) landingOf(ctx context.Context, repo string, c commitRow, superseded map[string]bool) string {
	reachable, checked := rs.commitReachable(ctx, repo, c.CommitSHA)
	switch {
	case checked && reachable:
		return "landed"
	case checked && !reachable && superseded[c.EventID]:
		return "rewritten"
	case checked && !reachable:
		return "not_landed"
	}

	// The repository could not be read directly. landing.go's own
	// corroborating signal: this run's own git-commit tool call result
	// showing git's ref-lock failure text — read from the SAME retained
	// bodies every other reader in this package uses, never a second body
	// store.
	if rs.logDir != "" && refLockFailureFound(rs.logDir, c.RunID, rs.runCommitClaims(ctx, c.RunID)) {
		return "not_landed"
	}
	return "unknown"
}

// commitReachable asks the served checkout of repo whether sha is
// reachable from any ref — landing.go's own CommitReachable, restated for
// this package's own git runner (snapshotstore.go's runGit) rather than
// internal/reconciler's GitWorkspace, which this process does not have.
// checked is false when the object database could not even be opened (no
// served repository by that name); "the object simply does not exist" is
// folded into reachable == false, checked == true, landing.go's own
// reading of `git cat-file -e`.
func (rs *recordServer) commitReachable(ctx context.Context, repo, sha string) (reachable, checked bool) {
	if err := event.ValidateGitObjectID(sha); err != nil {
		return false, false
	}
	repoDir, ok := rs.prover.RepoPath(repo)
	if !ok {
		return false, false
	}
	gitPath := rs.prover.GitPath()
	env := isolatedGitEnv(repoDir)
	if _, err := runGit(ctx, repoDir, env, gitPath, "cat-file", "-e", sha); err != nil {
		// Either the object does not exist, or the directory is not a
		// readable repository at all. Both are folded into "not reachable,
		// checked" here for cat-file's own documented reason
		// (internal/reconciler/landing.go's identical comment): a served
		// repository this process could at least try to open is not a
		// repository this process failed to read.
		return false, true
	}
	out, err := runGit(ctx, repoDir, env, gitPath, "for-each-ref", "--contains="+sha, "--format=%(refname)")
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(out) != "", true
}

// runCommitClaims reads runID's own Bash tool_call events out of its
// timeline — a second, small query rather than threading the primary run's
// already-read rows through to every commit this function judges, most of
// which belong to OTHER runs in the family the primary record's own rows
// never covered. Errors answer no claims, never a guess.
func (rs *recordServer) runCommitClaims(ctx context.Context, runID string) []recordEventRow {
	rows, err := rs.store.runTimeline(ctx, runID)
	if err != nil {
		return nil
	}
	var out []recordEventRow
	for _, r := range rows {
		if r.EventType == "tool_call" && stringOf(r.Body[toolCallToolNameField]) == "Bash" {
			out = append(out, r)
		}
	}
	return out
}

// refLockFailureFound scans claims (this run's own Bash tool_call rows) for
// a retained body whose result shows git's own ref-lock failure text —
// internal/reconciler/landing.go's own looksLikeRefLockFailure, restated.
func refLockFailureFound(logDir, runID string, claims []recordEventRow) bool {
	for _, r := range claims {
		digest := stringOf(r.Body[toolCallDigestField])
		body, ok := stepBody(logDir, runID, digest)
		if !ok || !body.isError() {
			continue
		}
		text, ok := resultText(body.Result)
		if !ok {
			continue
		}
		if looksLikeRefLockFailure(text) {
			return true
		}
	}
	return false
}

// looksLikeRefLockFailure matches internal/reconciler/landing.go's own
// wording — git's own error text for the one outcome ADR-0059 decision 6
// names, not a status code.
func looksLikeRefLockFailure(text string) bool {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "cannot lock ref"):
		return true
	case strings.Contains(lower, "failed to lock ref"):
		return true
	case strings.Contains(lower, "unable to create") && strings.Contains(lower, ".lock"):
		return true
	case strings.Contains(lower, "but expected"):
		return true
	default:
		return false
	}
}

// notLandedReason is why a signed commit did not land, when this run's own
// retained git commit result says so: "ref_lock" for git's ref-lock
// failure (ADR-0059 decision 6's parallel-commit case), else "".
func notLandedReason(logDir, runID string, claims []recordEventRow) string {
	if logDir != "" && refLockFailureFound(logDir, runID, claims) {
		return "ref_lock"
	}
	return ""
}

// reachabilityReads counts reads of a repository's reachable commits, so a
// test can hold a record to one per repository (#443).
var reachabilityReads atomic.Int64

// landing judges commits' landing for one record (#443). Whether a commit is
// reachable from any ref is the same question commitReachable asks two git
// commands per commit for; here every reachable commit is read once per
// repository with `git rev-list --all`, and each judgement is a lookup. A
// session holding its signing identities' 61 commits spent about two
// seconds on the per-commit form.
type landing struct {
	rs   *recordServer
	sets map[string]reachableSet
}

type reachableSet struct {
	shas    map[string]bool
	checked bool
}

func (rs *recordServer) newLanding() *landing {
	return &landing{rs: rs, sets: map[string]reachableSet{}}
}

func (l *landing) of(ctx context.Context, repo string, c commitRow, superseded map[string]bool) string {
	set, ok := l.sets[repo]
	if !ok {
		set = l.read(ctx, repo)
		l.sets[repo] = set
	}
	if !set.checked || event.ValidateGitObjectID(c.CommitSHA) != nil {
		// Not readable here: the per-commit path, with its own ref-lock
		// corroboration, decides between not_landed and unknown.
		return l.rs.landingOf(ctx, repo, c, superseded)
	}
	switch {
	case set.shas[c.CommitSHA]:
		return "landed"
	case superseded[c.EventID]:
		return "rewritten"
	default:
		return "not_landed"
	}
}

// read lists every commit reachable from any ref of repo's served checkout.
func (l *landing) read(ctx context.Context, repo string) reachableSet {
	reachabilityReads.Add(1)
	repoDir, ok := l.rs.prover.RepoPath(repo)
	if !ok {
		return reachableSet{}
	}
	out, err := runGit(ctx, repoDir, isolatedGitEnv(repoDir), l.rs.prover.GitPath(), "rev-list", "--all")
	if err != nil {
		return reachableSet{}
	}
	shas := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			shas[line] = true
		}
	}
	return reachableSet{shas: shas, checked: true}
}

// subjects reads the subject line of every sha in one git run. Every sha
// passed is reachable, so it exists; a sha missing from the answer falls
// back to the caller's per-commit read.
func (l *landing) subjects(ctx context.Context, repo string, shas []string) map[string]string {
	out := map[string]string{}
	if len(shas) == 0 {
		return out
	}
	repoDir, ok := l.rs.prover.RepoPath(repo)
	if !ok {
		return out
	}
	seen := map[string]bool{}
	args := []string{"log", "--no-walk=unsorted", "--format=%H %s"}
	for _, sha := range shas {
		if !seen[sha] && event.ValidateGitObjectID(sha) == nil {
			seen[sha] = true
			args = append(args, sha)
		}
	}
	text, err := runGit(ctx, repoDir, isolatedGitEnv(repoDir), l.rs.prover.GitPath(), args...)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(text, "\n") {
		if sha, subject, ok := strings.Cut(line, " "); ok {
			out[sha] = subject
		}
	}
	return out
}
