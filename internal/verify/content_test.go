// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// VER-010 through VER-012 (proposed for doc 07; doc 07 is not modified here) —
// RM-121, #193, ADR-0047.
//
// # The wrong answer this replaces
//
// A gitsign signature covers the commit OBJECT. GitHub's rebase rewrites the
// object — new parents, new tree, new SHA — and the signature does not survive.
// The shipped verifier then answers `failed` on all three checks, and that is
// not merely unhelpful: it is WRONG. The content was signed. What the verifier
// checked was whether this particular object was, and after a rebase that is a
// different question from the one anybody is asking.
//
// ADR-0047 states the trade in as many words: "We prove an agent produced the
// CONTENT. We no longer prove the agent wrote this exact commit: the message,
// the parent and the author belong to whoever merged it." That is honest, and
// it is what actually happened.
//
// # Both halves, always
//
// A patch id identifies a change and nothing else, so the same change made
// twice by two agents has one id — it cannot say WHO. A trailer says who and is
// a line of text anybody can type — it cannot say WHAT. Neither weakness is
// reachable through the other, so the check requires both to agree and each
// test below drops one of them to prove it.

// contentStub is a ledger that answers what the case under test needs.
type contentStub struct {
	records []ContentRecord
	err     error
	asked   []string
}

func (c *contentStub) RunsForPatchID(_ context.Context, patchID string) ([]ContentRecord, error) {
	c.asked = append(c.asked, patchID)
	if c.err != nil {
		return nil, c.err
	}
	var out []ContentRecord
	for _, r := range c.records {
		if r.PatchID == patchID {
			out = append(out, r)
		}
	}
	return out, nil
}

// TestVER010ARebasedCommitVerifiesByItsContent.
//
// The change is replayed onto a moved base, exactly as the rebase button
// replays it. The SHA changes, the parents change, the signature is gone — and
// the ledger still holds the run that produced this change.
func TestVER010ARebasedCommitVerifiesByItsContent(t *testing.T) {
	dir := t.TempDir()
	original, rebased := contentRebase(t, dir)
	if original == rebased {
		t.Fatal("the rebase did not rewrite the commit, so this proves nothing")
	}

	patchID := contentPatchID(t, dir, rebased)
	ledger := &contentStub{records: []ContentRecord{{
		RunID:     "run-42",
		PatchID:   patchID,
		CommitSHA: original,
		EventID:   "01a047a5-cc41-7c45-86fd-a88c8c2b5320",
	}}}

	got := checkContent(t.Context(), contentInput{
		gitPath: "git", repo: dir, sha: rebased, runID: "run-42",
	}, ledger)

	if got.Result != Verified {
		t.Fatalf("content check = %s (%s), want %s: the change WAS signed, and a "+
			"verifier that says otherwise is giving a wrong answer, not a cautious one",
			got.Result, got.Detail, Verified)
	}
	if got.PatchID != patchID {
		t.Errorf("reported patch id %q, want %q", got.PatchID, patchID)
	}
	if got.RecordedAs != original {
		t.Errorf("RecordedAs = %q, want the SHA the ledger holds (%q); a reader has to "+
			"be able to find the original record", got.RecordedAs, original)
	}
}

// TestVER011BothHalvesAreRequired is the mutation criterion stated as a test:
// dropping either half admits a forgery the other would catch.
func TestVER011BothHalvesAreRequired(t *testing.T) {
	dir := t.TempDir()
	_, rebased := contentRebase(t, dir)
	patchID := contentPatchID(t, dir, rebased)

	t.Run("the right change, claimed by a run that did not make it", func(t *testing.T) {
		// The patch id matches. The trailer names somebody else. Accepting this
		// would let anyone attach their own Agent-Run to a change an agent made
		// and have a verifier confirm it.
		ledger := &contentStub{records: []ContentRecord{{
			RunID: "run-42", PatchID: patchID, CommitSHA: "abc",
		}}}
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "run-impostor",
		}, ledger)
		if got.Result == Verified {
			t.Error("a commit claiming a run that recorded no such change was verified; " +
				"the patch id alone cannot say WHO")
		}
		if !strings.Contains(got.Detail, "run-impostor") {
			t.Errorf("said %q, which does not name the run that was claimed", got.Detail)
		}
	})

	t.Run("the right run, claiming a change it did not make", func(t *testing.T) {
		// The trailer is genuine and the content is not. Accepting this would
		// let an edited commit keep the attribution of the one it was edited
		// from, which is the whole attack a content check exists to stop.
		ledger := &contentStub{records: []ContentRecord{{
			RunID: "run-42", PatchID: strings.Repeat("f", 40), CommitSHA: "abc",
		}}}
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "run-42",
		}, ledger)
		if got.Result == Verified {
			t.Error("a commit whose content no run recorded was verified; a trailer " +
				"alone cannot say WHAT")
		}
	})
}

// TestVER012WhatTheAnswerSaysWhenItIsNotVerified.
//
// ADR-0047: "A conflicted rebase will not match, and must be reported as *the
// content changed*, not as a fault. That is the correct answer and the message
// must say which of the two it means." A verifier that reports a resolved
// conflict as an integrity failure teaches its readers to ignore it.
func TestVER012WhatTheAnswerSaysWhenItIsNotVerified(t *testing.T) {
	dir := t.TempDir()
	_, rebased := contentRebase(t, dir)

	t.Run("no record of the change: the content changed", func(t *testing.T) {
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "run-42",
		}, &contentStub{})
		if got.Result != Failed {
			t.Fatalf("result = %s, want %s", got.Result, Failed)
		}
		if !strings.Contains(got.Detail, "changed") {
			t.Errorf("said %q; ADR-0047 requires the message to say the CONTENT "+
				"CHANGED rather than that verification failed", got.Detail)
		}
	})

	t.Run("a ledger that cannot answer is unavailable, never failed", func(t *testing.T) {
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "run-42",
		}, &contentStub{err: errors.New("connection refused")})
		if got.Result != Unavailable {
			t.Errorf("result = %s, want %s: doc 06 P2 forbids reporting a check that "+
				"could not run as one that ran and failed", got.Result, Unavailable)
		}
	})

	t.Run("no run claimed: the check does not apply", func(t *testing.T) {
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "",
		}, &contentStub{})
		if got.Result == Verified || got.Result == Failed {
			t.Errorf("result = %s for a commit that claims no run; there is nothing "+
				"to confirm and nothing to contradict", got.Result)
		}
	})

	t.Run("an empty commit is outside the scheme, and says so", func(t *testing.T) {
		contentGit(t, dir, "commit", "-q", "--allow-empty", "-m", "nothing")
		empty := contentGit(t, dir, "rev-parse", "HEAD")
		got := checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: empty, runID: "run-42",
		}, &contentStub{})
		if got.Result == Verified {
			t.Error("an empty commit was verified by content; it has no content")
		}
		if !strings.Contains(got.Detail, "no change") {
			t.Errorf("said %q, which does not say that the commit changes nothing", got.Detail)
		}
	})
}

// contentRebase builds a repository with one change replayed onto a moved
// base, and returns the original and rebased SHAs.
func contentRebase(t *testing.T, dir string) (original, rebased string) {
	t.Helper()
	contentGit(t, dir, "init", "-q", "-b", "main")
	contentGit(t, dir, "config", "user.email", "t@t")
	contentGit(t, dir, "config", "user.name", "t")
	contentWrite(t, dir, "base.txt", "base\n")
	contentGit(t, dir, "add", "-A")
	contentGit(t, dir, "commit", "-q", "-m", "base")

	contentGit(t, dir, "checkout", "-q", "-b", "feature")
	contentWrite(t, dir, "work.txt", "the agent's work\n")
	contentGit(t, dir, "add", "-A")
	contentGit(t, dir, "commit", "-q", "-m", "the agent's work")
	original = contentGit(t, dir, "rev-parse", "HEAD")

	contentGit(t, dir, "checkout", "-q", "main")
	contentWrite(t, dir, "other.txt", "somebody else\n")
	contentGit(t, dir, "add", "-A")
	contentGit(t, dir, "commit", "-q", "-m", "somebody else")

	contentGit(t, dir, "checkout", "-q", "feature")
	contentGit(t, dir, "rebase", "main")
	return original, contentGit(t, dir, "rev-parse", "HEAD")
}

func contentPatchID(t *testing.T, dir, sha string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", "-c",
		"git diff-tree -p --root --no-color "+sha+" | git patch-id --verbatim")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the by-hand patch-id pipeline failed: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatal("the by-hand pipeline printed nothing")
	}
	return fields[0]
}

func contentWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func contentGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
