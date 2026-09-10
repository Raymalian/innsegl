// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/verify"
)

// ADR-0047's answer has to be reachable without the three checks.
//
// The three cryptographic checks and the content check answer different
// questions, and after a rebase only the second one can be answered at all: the
// signature is gone, so Fulcio and Rekor have nothing to say, while the ledger
// still holds what the change was. internal/api's Prover is structurally
// forbidden a ledger (proof.go's invariant 3, IP §6.11), so the content answer
// cannot come from there and needs its own door.
//
// This is that door: the same checkContent the Verifier runs, reachable on its
// own, so a caller that HAS a ledger can ask the content question without
// pretending to have asked the cryptographic ones.

type fakeContentSource struct {
	records []verify.ContentRecord
	err     error
}

func (f fakeContentSource) RunsForPatchID(_ context.Context, _ string) ([]verify.ContentRecord, error) {
	return f.records, f.err
}

func TestAttributeContentAnswersWithoutTheThreeChecks(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)

	patchID := patchIDOfCommit(t, repo, sha)
	src := fakeContentSource{records: []verify.ContentRecord{{
		RunID:     runID,
		PatchID:   patchID,
		CommitSHA: "10c437e3609618f2eb7e06c744b7203d0370b0f8",
		EventID:   "01a08a8f-f68b-7c04-8c4b-632faf03ff9f",
	}}}

	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Verified {
		t.Fatalf("AttributeContent returned %v (%s), want Verified — the ledger holds "+
			"this exact change under the run the commit claims", got.Result, got.Detail)
	}
	if got.PatchID != patchID {
		t.Errorf("reported patch id %q, want %q — a reader has to be able to recompute it",
			got.PatchID, patchID)
	}
	if got.RecordedAs != "10c437e3609618f2eb7e06c744b7203d0370b0f8" {
		t.Errorf("reported RecordedAs %q, want the pre-rebase sha — finding the original "+
			"record is the point", got.RecordedAs)
	}
}

func TestAttributeContentWithNoLedgerSaysSoRatherThanFailing(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)

	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: nil}, repo, sha, runID)

	if got.Result != verify.Unavailable {
		t.Fatalf("with no ledger AttributeContent returned %v (%s), want Unavailable — "+
			"\"could not ask\" is not \"the content changed\" (doc 06 P2)",
			got.Result, got.Detail)
	}
}

func TestAttributeContentReportsAChangedContentAsFailedNotUnavailable(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)

	// The ledger holds nothing for this change.
	src := fakeContentSource{records: nil}
	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Failed {
		t.Fatalf("AttributeContent returned %v (%s), want Failed — no run recorded this "+
			"change, which is a finding and not an absence of one", got.Result, got.Detail)
	}
}

func TestAttributeContentSurfacesALedgerErrorAsUnavailable(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)

	src := fakeContentSource{err: errors.New("connection refused")}
	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Unavailable {
		t.Fatalf("a ledger error produced %v (%s), want Unavailable — an outage must "+
			"never read as a verdict about the commit", got.Result, got.Detail)
	}
}

// seedRebasedCommit builds a real repository holding a real commit that carries
// an Agent-Run trailer and no signature — the exact shape a rebase leaves
// behind, which is the only shape this door exists to answer about.
func seedRebasedCommit(t *testing.T, repo string) (sha, runID string) {
	t.Helper()
	runID = "run-72b6665addd7409d8b1bf62e54754ecd"
	run(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f"), []byte("content\n"), 0o644); err != nil {
		t.Fatalf("seeding a file: %v", err)
	}
	run(t, repo, "add", "f")
	run(t, repo, "commit", "-q", "--no-gpg-sign", "-m",
		"feat: a change\n\nAgent-Run: "+runID+"\n")
	return strings.TrimSpace(output(t, repo, "rev-parse", "HEAD")), runID
}

// patchIDOfCommit is ADR-0047's change identity, computed the way the
// implementation computes it so the test asserts agreement and not a guess.
func patchIDOfCommit(t *testing.T, repo, sha string) string {
	t.Helper()
	ctx := context.Background()
	diff := exec.CommandContext(ctx, "git", "-C", repo, "diff-tree", "-p", "--root", sha)
	diffOut, err := diff.Output()
	if err != nil {
		t.Fatalf("git diff-tree: %v", err)
	}
	pid := exec.CommandContext(ctx, "git", "patch-id", "--verbatim")
	pid.Stdin = bytes.NewReader(diffOut)
	pidOut, err := pid.Output()
	if err != nil {
		t.Fatalf("git patch-id: %v", err)
	}
	fields := strings.Fields(string(pidOut))
	if len(fields) == 0 {
		t.Fatalf("git patch-id produced nothing for %s", sha)
	}
	return fields[0]
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func output(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// A run's intent and its record both carry the change. The record names the
// commit; the intent cannot.
//
// RunsForPatchID returns both on purpose — an intent proves the change was
// claimed even when the chain crashed before the signature. But matching the
// intent first produced the right verdict with an empty commit in it:
// "recorded this exact change, as commit ." MEASURED against the running
// ledger on 2026-09-10, on the very commit this endpoint was built to answer
// about. Naming the object the change was signed as is the useful half of the
// answer.
func TestAttributeContentPrefersTheRecordThatNamesTheCommit(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)
	patchID := patchIDOfCommit(t, repo, sha)
	const original = "10c437e3609618f2eb7e06c744b7203d0370b0f8"

	// Intent first, exactly as the chain orders them.
	src := fakeContentSource{records: []verify.ContentRecord{
		{RunID: runID, PatchID: patchID, CommitSHA: "", EventID: "intent"},
		{RunID: runID, PatchID: patchID, CommitSHA: original, EventID: "recorded"},
	}}

	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Verified {
		t.Fatalf("result %v (%s), want Verified", got.Result, got.Detail)
	}
	if got.RecordedAs != original {
		t.Errorf("RecordedAs is %q, want %q — the intent has no commit_sha and must not "+
			"win over the record that does", got.RecordedAs, original)
	}
	if strings.Contains(got.Detail, "as commit .") {
		t.Errorf("detail names an empty commit: %q", got.Detail)
	}
}

// An intent alone still answers: the content is attributed, and the message
// says plainly that the object it was signed as is not on the chain.
func TestAttributeContentAnswersFromAnIntentAlone(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)
	patchID := patchIDOfCommit(t, repo, sha)

	src := fakeContentSource{records: []verify.ContentRecord{
		{RunID: runID, PatchID: patchID, CommitSHA: "", EventID: "intent"},
	}}
	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Verified {
		t.Fatalf("result %v (%s), want Verified — an intent proves the change was claimed",
			got.Result, got.Detail)
	}
	if strings.Contains(got.Detail, "as commit .") {
		t.Errorf("detail names an empty commit: %q", got.Detail)
	}
}

// The record that names the commit wins, whichever order the chain holds them
// in — and once one is found a later intent must not displace it.
//
// The forward case (intent first, record second) is above. This is the other
// direction, which is what the branch floor found missing: with the record
// already chosen, the condition that would replace it must be exercised as
// FALSE, or the preference is only ever tested one way and a rewrite that
// inverted it would pass.
func TestAttributeContentKeepsTheRecordWhenAnIntentFollowsIt(t *testing.T) {
	repo := t.TempDir()
	sha, runID := seedRebasedCommit(t, repo)
	patchID := patchIDOfCommit(t, repo, sha)
	const original = "10c437e3609618f2eb7e06c744b7203d0370b0f8"

	src := fakeContentSource{records: []verify.ContentRecord{
		{RunID: runID, PatchID: patchID, CommitSHA: original, EventID: "recorded"},
		{RunID: runID, PatchID: patchID, CommitSHA: "", EventID: "intent"},
	}}
	got := verify.AttributeContent(context.Background(),
		verify.ContentConfig{Source: src}, repo, sha, runID)

	if got.Result != verify.Verified {
		t.Fatalf("result %v (%s), want Verified", got.Result, got.Detail)
	}
	if got.RecordedAs != original {
		t.Errorf("RecordedAs is %q, want %q — an intent seen after the record must not "+
			"displace it", got.RecordedAs, original)
	}
	if got.EventID != "recorded" {
		t.Errorf("EventID is %q, want the record's", got.EventID)
	}
}
