// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"reflect"
	"testing"
)

// VER-009 — RM-061 (verify.innsegl.dev, #69).
//
// A serverless verifier has no git working copy, so it cannot call Verify,
// which shells out to git. What it CAN do is fetch a commit's three
// verification-relevant pieces from the host's API: the SHA, the message
// (for the Agent-* trailers) and the raw gpgsig signature (for the
// certificate) — nothing a repository holds that these three don't already
// carry, because the Rekor artifact is the SHA itself (ADR-0031 decision 6)
// and the three checks never read a blob or a working tree.
//
// VerifyCommit is that seam: the same three checks, the same rollup, the
// same recovery path, driven by data the caller already has instead of by a
// repository readCommit can open. This test proves the seam is
// behaviour-preserving: given the pieces of the SAME commit Verify would
// read via git, VerifyCommit produces the identical verdict and checks.
func TestVER007VerifyCommitReproducesVerifyGivenTheSameCommitPieces(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	v := s.verifier(t)

	want, err := v.Verify(t.Context(), s.repo, s.commit)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The pieces a host API hands back for a commit: SHA, tree, message and
	// the raw signature block — read here via git only because this is a
	// test fixture standing in for what GitHub's commits API would return.
	c, err := readCommit(t.Context(), "git", s.repo, s.commit)
	if err != nil {
		t.Fatalf("readCommit: %v", err)
	}

	got, err := v.VerifyCommit(t.Context(), "https://github.com/example/repo", c.SHA, c.Tree, c.Message, c.Signature)
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}

	if got.Verdict != want.Verdict {
		t.Fatalf("VerifyCommit verdict = %s, Verify verdict = %s", got.Verdict, want.Verdict)
	}
	if got.CommitSHA != want.CommitSHA || got.TreeHash != want.TreeHash {
		t.Fatalf("VerifyCommit commit/tree = %s/%s, Verify = %s/%s",
			got.CommitSHA, got.TreeHash, want.CommitSHA, want.TreeHash)
	}
	if len(got.Checks) != len(want.Checks) {
		t.Fatalf("VerifyCommit produced %d checks, Verify produced %d", len(got.Checks), len(want.Checks))
	}
	for i := range want.Checks {
		if !reflect.DeepEqual(got.Checks[i], want.Checks[i]) {
			t.Errorf("check %d: VerifyCommit = %+v, Verify = %+v", i, got.Checks[i], want.Checks[i])
		}
	}
	if got.Certificate != want.Certificate {
		t.Errorf("VerifyCommit certificate = %+v, Verify = %+v", got.Certificate, want.Certificate)
	}
	if got.Entry != want.Entry {
		t.Errorf("VerifyCommit entry = %+v, Verify = %+v", got.Entry, want.Entry)
	}
	// Repo is intentionally NOT compared: VerifyCommit's caller has no local
	// path, only a label (a repository URL), and that label is what a
	// serverless verifier can honestly report.
	if got.Repo != "https://github.com/example/repo" {
		t.Errorf("VerifyCommit did not record its repo label: %q", got.Repo)
	}
}

// A forged trailer must still fail check 3 through the new seam — proving
// VerifyCommit runs the real checkIdentity rather than a shortcut that
// happens to agree on the good case.
func TestVER007VerifyCommitStillFailsAForgedTrailer(t *testing.T) {
	forged := "spiffe://" + fixtureTrustDomain + "/agent/demo/rm-037/run-9999"
	s := newScenario(t, scenarioOptions{trailerIdentity: forged})
	v := s.verifier(t)

	c, err := readCommit(t.Context(), "git", s.repo, s.commit)
	if err != nil {
		t.Fatalf("readCommit: %v", err)
	}
	got, err := v.VerifyCommit(t.Context(), "https://github.com/example/repo", c.SHA, c.Tree, c.Message, c.Signature)
	if err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}
	if got.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s\n%s", got.Verdict, VerdictFailed, Render(got))
	}
	if c := got.check(t, CheckTrailerIdentity); c.Result != Failed {
		t.Fatalf("check 3 = %s (%s), want %s", c.Result, c.Detail, Failed)
	}
}

// VerifyCommit refuses a request it cannot act on, exactly as Verify refuses
// an unresolvable revision: an empty SHA is not a commit.
func TestVER007VerifyCommitRefusesAnEmptySHA(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	v := s.verifier(t)

	if _, err := v.VerifyCommit(t.Context(), "https://github.com/example/repo", "", "", "", nil); err == nil {
		t.Fatal("VerifyCommit accepted an empty SHA")
	}
}
