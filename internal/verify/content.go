// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Verifying by content (RM-121, #193, ADR-0047).
//
// # The question this asks, and why it is a different one
//
// A gitsign signature covers the commit OBJECT: its tree, its parents, its
// author and its message. GitHub's rebase rewrites the object, and the
// signature does not survive — measured on throwaway branches, a rebased commit
// lands with the Agent-* trailers intact and nothing left to verify them
// against. The three checks then answer `failed` on all three, and that answer
// is not cautious, it is WRONG: the content was signed, and what the checks
// examined was whether this particular object was.
//
// ADR-0047 states the trade plainly: "We prove an agent produced the CONTENT.
// We no longer prove the agent wrote this exact commit: the message, the parent
// and the author belong to whoever merged it." What survives a rebase is the
// change, and `git patch-id` is git's own name for it.
//
// # Both halves, and neither is reachable through the other
//
// A patch id identifies a change and only a change. The same change made twice
// by two different agents has one id, so it cannot say WHO.
//
// A trailer says who, and it is a line of text anybody can type into a commit
// message, so it cannot say WHAT.
//
// Requiring both closes each gap with the other: an impostor's trailer over
// genuine content names a run the ledger never recorded that change for, and
// genuine trailers over edited content name a change no run recorded at all.
// VER-011 drops each half in turn and asserts the other refuses.
//
// # This package still holds no database
//
// ContentSource is an interface the CALLER supplies, and a nil one is not an
// error: VER-001 is "verifies with the database unreachable", and a verifier
// that started needing a ledger would be a verifier a stranger cannot run. The
// content check is additional evidence where a ledger is at hand, never a
// precondition for the three checks that do not need one.

// ContentRecord is one ledger record of a signed change: which run made it,
// what change it was, and the commit it was recorded as.
type ContentRecord struct {
	// RunID is the run the ledger recorded the change under.
	RunID string
	// PatchID is `git patch-id --verbatim` over the change (ADR-0047).
	PatchID string
	// CommitSHA is the commit the ledger holds. After a rebase it is NOT the
	// commit being verified, and saying so is the point: a reader has to be
	// able to find the original record.
	CommitSHA string
	// EventID names the event, so the claim can be checked rather than taken.
	EventID string
}

// ContentSource answers "which runs recorded this change?".
//
// Implemented over the ledger by the caller. It is asked for a patch id and
// never for a run, because a lookup keyed on the caller's own claim would let
// the claim choose the evidence.
type ContentSource interface {
	RunsForPatchID(ctx context.Context, patchID string) ([]ContentRecord, error)
}

// ContentAttribution is the content check's answer.
type ContentAttribution struct {
	Result Result `json:"result"`
	Detail string `json:"detail"`
	// PatchID is the change's own identity, reported whether or not it
	// matched, so a reader can recompute it.
	PatchID string `json:"patch_id,omitempty"`
	// RunID is the run the commit claimed.
	RunID string `json:"run_id,omitempty"`
	// RecordedAs is the commit SHA the ledger holds for this change, which
	// after a rewrite is a different commit from the one verified.
	RecordedAs string `json:"recorded_as,omitempty"`
	// EventID names the ledger event behind a verified answer.
	EventID string `json:"event_id,omitempty"`
}

// contentInput is what the check needs: a repository to compute the change
// from, the commit, and the run the commit claims.
type contentInput struct {
	gitPath string
	repo    string
	sha     string
	runID   string
}

// checkContent is the whole of the check.
//
// Its three non-verified answers are deliberately distinct, and doc 06 P2 is
// why: "the content changed" is a finding, "the ledger could not answer" is an
// absence of one, and "this commit claims no run" is neither. Collapsing any
// two of them would report something the check did not establish.
func checkContent(ctx context.Context, in contentInput, source ContentSource) ContentAttribution {
	out := ContentAttribution{RunID: in.runID}

	switch {
	case source == nil:
		out.Result = Unavailable
		out.Detail = "no ledger is configured, so the change cannot be looked up. " +
			"The three checks above do not need one and are unaffected."
		return out
	case in.runID == "":
		out.Result = Unavailable
		out.Detail = "this commit claims no run, so there is nothing to confirm and " +
			"nothing to contradict."
		return out
	case in.repo == "":
		out.Result = Unavailable
		out.Detail = "verifying by content needs the repository the commit lives in: " +
			"the change is computed from it with `git patch-id --verbatim`."
		return out
	}

	patchID, err := commitPatchID(ctx, in.gitPath, in.repo, in.sha)
	if err != nil {
		out.Result = Unavailable
		out.Detail = err.Error()
		return out
	}
	if patchID == "" {
		out.Result = Unavailable
		out.Detail = "this commit makes no change at all, so it is outside the scheme: " +
			"an empty commit has no content to have been signed."
		return out
	}
	out.PatchID = patchID

	records, err := source.RunsForPatchID(ctx, patchID)
	if err != nil {
		out.Result = Unavailable
		out.Detail = fmt.Sprintf("the ledger could not be asked which runs recorded "+
			"this change: %v", err)
		return out
	}

	// The run's records for this change, best first.
	//
	// RunsForPatchID returns `commit_intent` as well as `commit_recorded`, on
	// purpose: an intent proves the change was claimed even when the chain
	// crashed before the signature (IP §6.5's A -> B window). But an intent
	// carries no `commit_sha`, so matching one first reported the right verdict
	// with an empty commit in it -- "recorded this exact change, as commit ."
	// MEASURED against the running ledger 2026-09-10. Naming the commit the
	// change was signed as is the useful half of the answer, so a record that
	// has one wins; an intent still answers when it is all there is.
	var match *ContentRecord
	for i := range records {
		if records[i].RunID != in.runID {
			continue
		}
		if match == nil || (match.CommitSHA == "" && records[i].CommitSHA != "") {
			match = &records[i]
		}
	}
	if match != nil {
		out.Result = Verified
		out.RecordedAs = match.CommitSHA
		out.EventID = match.EventID
		if match.CommitSHA == "" {
			out.Detail = fmt.Sprintf("run %s claimed this exact change, and the chain holds "+
				"its intent but no completed record of the commit it became. The content is "+
				"attributed; the object it was signed as is not on the chain.", match.RunID)
			return out
		}
		out.Detail = fmt.Sprintf("run %s recorded this exact change, as commit %s. "+
			"This commit is a rewrite of that one: same content, different object.",
			match.RunID, match.CommitSHA)
		return out
	}

	// Two different findings, and the message says which. ADR-0047: "A
	// conflicted rebase will not match, and must be reported as *the content
	// changed*, not as a fault."
	out.Result = Failed
	if len(records) == 0 {
		out.Detail = fmt.Sprintf("no run recorded this change: the content changed "+
			"after it was signed. A conflicted rebase does this, and so does an edit. "+
			"The commit claims run %s.", in.runID)
		return out
	}
	others := make([]string, 0, len(records))
	for _, r := range records {
		others = append(others, r.RunID)
	}
	out.Detail = fmt.Sprintf("this change was recorded by %s, and the commit claims "+
		"%s. The content is somebody else's work.",
		strings.Join(others, ", "), in.runID)
	return out
}

// commitPatchID computes a commit's change identity.
//
// The same two commands sign_commit runs (internal/mcp/patchid.go), for the
// same reason and with the same flags: `--verbatim` because the default folds
// whitespace and in Python or a Makefile that is a different program, `--root`
// so the first commit in a repository produces a diff rather than nothing, and
// `--no-color --no-ext-diff` so a reader's git configuration cannot change the
// answer.
//
// An empty string with no error means an empty commit: git prints nothing for
// an empty diff, and that is a fact about the commit rather than a failure.
func commitPatchID(ctx context.Context, gitPath, repo, sha string) (string, error) {
	if gitPath == "" {
		gitPath = "git"
	}
	diff := exec.CommandContext(ctx, gitPath, "-C", repo,
		"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", sha)
	patch, err := diff.Output()
	if err != nil {
		return "", fmt.Errorf("the change made by %s could not be read from %s: %w",
			sha, repo, err)
	}
	if len(strings.TrimSpace(string(patch))) == 0 {
		return "", nil
	}

	id := exec.CommandContext(ctx, gitPath, "-C", repo, "patch-id", "--verbatim")
	id.Stdin = strings.NewReader(string(patch))
	out, err := id.Output()
	if err != nil {
		return "", fmt.Errorf("git patch-id --verbatim failed in %s: %w", repo, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}
