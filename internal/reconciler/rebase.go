// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// Recording a rewrite (RM-122, #194, ADR-0047 decision 4).
//
// # What is broken without this
//
// After a merge the commit on the branch has a new SHA and the ledger has the
// old one, so every lookup by SHA fails: the dashboard's Verify page, the proof
// API, `innsegl verify`. #193 made the content findable by patch id, but
// finding it that way means recomputing a patch id for every candidate on every
// read, forever.
//
// ADR-0047 decision 4: the reconciler walks the branch, computes each commit's
// patch id, and on a match appends a SUPERSEDING `commit_recorded` carrying the
// new SHA. doc 02 §2's `supersedes` exists for exactly this and `segment_sealed`
// already uses it for anchoring; the original event is never modified (I4).
//
// # It records a match, it does not assert one
//
// Every input is recomputable from the repository by anyone: the commit is on
// the branch, the patch id is `git patch-id --verbatim` over its diff, and the
// run is the commit's own `Agent-Run` trailer. That is the difference between a
// claim and a receipt, and it is the only reason a pass that WRITES to an
// append-only chain is defensible at all.
//
// # Both halves, and here it matters more than on the read side
//
// #193 requires patch id AND run for a verdict. This requires them for a
// WRITE. A wrong read gives a wrong answer once and can be corrected by asking
// again; a wrong write is in the chain forever and I4 forbids removing it.

// RepoCommit is one commit on a branch, reduced to what this pass matches on.
type RepoCommit struct {
	// SHA is the commit as it exists on the branch now.
	SHA string
	// PatchID is `git patch-id --verbatim` over its diff (ADR-0047). Empty
	// for a commit that changes nothing, which is outside the scheme.
	PatchID string
	// RunID is the `Agent-Run` trailer, empty on a commit that claims no run.
	RunID string
}

// RebaseConfig turns the pass on. Nil leaves it OFF, and Result.Rebase says so
// on every cycle rather than letting a deployment believe a reconciler without
// it is recording rewrites.
type RebaseConfig struct {
	// Branch is the branch to walk in each repository, e.g. "main". Required:
	// there is no sensible default, and guessing one would walk the wrong
	// history quietly.
	Branch string
	// Repos are the repository identifiers to walk. Required for the same
	// reason -- a pass that discovered its own repositories from the chain
	// would write records about repositories nobody asked it to read.
	Repos []string
}

// RebaseReport is what one pass did.
type RebaseReport struct {
	// Enabled is false when no RebaseConfig was given, so a reader never
	// mistakes "not run" for "nothing to record".
	Enabled bool
	// Recorded is how many superseding events this pass appended.
	Recorded int
	// AlreadyRecorded is how many rewrites a previous pass had already
	// recorded. It is the number that proves idempotency in production, where
	// no test is watching.
	AlreadyRecorded int
	// Unmatched is how many commits claimed a run whose change is not on the
	// branch. A squashed branch produces these, and so does an edit.
	Unmatched int
	// Unreadable names every repository that could not be read. A pass that
	// went quiet about one would look identical to a branch with no rewrites.
	Unreadable []string
}

// recordRebases walks each configured repository and records what it finds.
//
// A repository that cannot be read is reported and skipped, never treated as a
// branch with nothing on it: the whole point of the pass is to notice
// something, and an absence it did not establish is the one answer it must not
// give.
// rebaseView is the chain's answer to "which run recorded which change, as
// which commit", folded out of the same walk every other reader uses.
//
// Built during the walk rather than by a second query, because a branch has
// thousands of commits and the chain is already being read end to end.
type rebaseView struct {
	// byRunAndPatch is keyed on the pair, never on either alone. That is the
	// rule from #193 applied to a WRITE, where getting it wrong is worse: a
	// wrong read gives a wrong answer once, a wrong write is in an append-only
	// chain forever.
	byRunAndPatch map[string]recordedChange
	// superseded holds every (run, change, commit) a superseding record
	// already names, which is what makes a second pass append nothing.
	superseded map[string]bool
}

// recordedChange is one run's original record of one change.
type recordedChange struct {
	eventID string
	sha     string
	body    event.Fields
}

func newRebaseView() *rebaseView {
	return &rebaseView{
		byRunAndPatch: map[string]recordedChange{},
		superseded:    map[string]bool{},
	}
}

// rebaseKeyOf pairs a run with a change. The separator is a NUL, which neither
// a run id nor a patch id may contain, so no two pairs can collide by
// concatenation.
func rebaseKeyOf(runID, patchID string) string { return runID + "\x00" + patchID }

// observe folds one event in.
func (v *rebaseView) observe(record event.Fields) {
	if recordString(record, event.FieldEventType) != event.EventTypeCommitRecorded {
		return
	}
	patchID := recordString(record, event.FieldPatchID)
	runID := recordString(record, event.FieldRunID)
	if patchID == "" || runID == "" {
		// A version 1 record carries no patch id at all. It is not a fault and
		// not a candidate: ADR-0047's scheme begins at schema 2, and events
		// written before it stay exactly as they are (I4).
		return
	}
	key := rebaseKeyOf(runID, patchID)
	if from := recordString(record, event.FieldSupersedes); from != "" {
		v.superseded[key+"\x00"+recordString(record, event.FieldCommitSHA)] = true
		return
	}
	if _, seen := v.byRunAndPatch[key]; seen {
		return
	}
	v.byRunAndPatch[key] = recordedChange{
		eventID: recordString(record, event.FieldEventID),
		sha:     recordString(record, event.FieldCommitSHA),
		body:    record,
	}
}

// recordRebases walks each configured repository and records what it finds.
//
// A repository that cannot be read is reported and skipped, never treated as a
// branch with nothing on it: the whole point of the pass is to notice
// something, and an absence it did not establish is the one answer it must not
// give.
func (r *Reconciler) recordRebases(ctx context.Context, view *rebaseView) RebaseReport {
	report := RebaseReport{Enabled: true}
	if view == nil {
		return report
	}

	for _, repo := range r.cfg.Rebase.Repos {
		commits, err := r.cfg.Repos.CommitsOnBranch(ctx, repo, r.cfg.Rebase.Branch)
		if err != nil {
			report.Unreadable = append(report.Unreadable, repo)
			continue
		}
		for _, c := range commits {
			// BOTH halves. A commit claiming no run is not this pass's
			// business, and a commit with no patch id changes nothing.
			if c.RunID == "" || c.PatchID == "" || c.SHA == "" {
				continue
			}
			key := rebaseKeyOf(c.RunID, c.PatchID)
			original, known := view.byRunAndPatch[key]
			if !known {
				// The run made no such change. A squashed branch is entirely
				// this case: squash writes ONE commit whose diff is every
				// change at once, so its patch id is a change nobody made.
				report.Unmatched++
				continue
			}
			if original.sha == c.SHA {
				continue // not a rewrite: the ledger already names this commit
			}
			if view.superseded[key+"\x00"+c.SHA] {
				report.AlreadyRecorded++
				continue
			}
			if err := r.recordRebase(ctx, repo, c, original.body, original.eventID, original.sha); err != nil {
				// Reported, never fatal: the other commits on the branch are
				// still rewrites and still need recording, and the next cycle
				// retries this one under the same idempotency key.
				report.Unreadable = append(report.Unreadable,
					fmt.Sprintf("%s: %v", repo, err))
				continue
			}
			report.Recorded++
		}
	}
	return report
}

// recordRebase appends one superseding `commit_recorded`.
//
// Every member is the original's except `commit_sha`, `source`, `supersedes`
// and the key. The rewrite changed where the change lives; it did not change
// who made it, what it was, or which Rekor entry proves it — those are
// properties of the signature, and the signature was over the original.
func (r *Reconciler) recordRebase(
	ctx context.Context, repo string, c RepoCommit,
	original event.Fields, originalID, originalSHA string,
) error {
	// The original as the chain holds it, minus the members the ledger
	// assigns. Copied rather than rebuilt member by member: a rebuild would
	// have to list every member of `commit_recorded`, and a schema that gained
	// one would silently drop it from every superseding record.
	body := original.Clone()
	delete(body, event.FieldEventID)
	delete(body, event.FieldChainPosition)
	delete(body, event.FieldTS)
	delete(body, event.FieldPrevEventHash)
	delete(body, event.EventHashField)

	body[event.FieldSource] = event.SourceReconciler
	body[event.FieldCommitSHA] = c.SHA
	body[event.FieldSupersedes] = originalID
	body[event.FieldIdempotencyKey] = RebaseKey(originalID, c.SHA)

	if _, err := r.cfg.Appender.Append(ctx, body); err != nil {
		return fmt.Errorf("recording that %s now lives as %s in %s: %w",
			originalSHA, c.SHA, repo, err)
	}
	return nil
}

// rebasedKeyPrefix namespaces this pass's idempotency keys.
const rebasedKeyPrefix = "reconciler:rebased:"

// RebaseKey is the `idempotency_key` a superseding `commit_recorded` carries.
//
// The original event and the new SHA, and nothing else: two reconcilers over
// the same branch compute the same key, and the ledger resolves the second to
// the first's event rather than writing a second. Stable across cycles,
// processes and leaders, for the reason ExpiryKey is.
func RebaseKey(originalEventID, newSHA string) string {
	return rebasedKeyPrefix + originalEventID + ":" + newSHA
}
