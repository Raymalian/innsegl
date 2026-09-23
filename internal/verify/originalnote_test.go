// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// VER-021 and VER-022 — #294 (RM-184).
//
// VER-003 promises that a rewritten commit's original attribution "stays
// resolvable via Rekor". The only key Rekor has is the hash of the original
// commit SHA, and the tree-hash walk finds that SHA only while the original
// object is still in the repository. Measured: a clone of a rewritten branch
// holds none of them, so the promise held only on the machine that did the
// rewrite.
//
// These cases carry the original object in a git note beside the rewritten
// commit, and assert two halves: that the attribution comes back in a
// repository that never held the original, and that the note is trusted for
// nothing — what it holds is hashed as a commit object, and only the log says
// who signed that hash.

// rawObject returns a commit object's bytes exactly as git stores them.
// gitIn trims its output, and one byte less is a different hash.
func rawObject(t *testing.T, repo, sha string) []byte {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "git", "-C", repo,
		"cat-file", "commit", sha).Output()
	if err != nil {
		t.Fatalf("cat-file commit %s: %v", sha, err)
	}
	return out
}

// attachNote stores content as a blob, byte for byte, and attaches it to
// target under the notes ref the verifier reads. `notes add -C` reuses the blob
// as it is; `-m` and `-F` would run the message cleanup and change the bytes.
func attachNote(t *testing.T, repo, target string, content []byte) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo,
		"hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(string(content))
	blob, err := cmd.Output()
	if err != nil {
		t.Fatalf("hash-object: %v", err)
	}
	gitIn(t, repo, "", "-c", "user.name=Innsegl", "-c", "user.email=agent@innsegl.invalid",
		"notes", "--ref="+OriginalNotesRef, "add", "-f", "-C",
		strings.TrimSpace(string(blob)), target)
}

// forgetObject deletes a loose object, which is what a fresh clone of a
// rewritten branch amounts to for the original: it was never fetched.
func forgetObject(t *testing.T, repo, sha string) {
	t.Helper()
	path := gitIn(t, repo, "", "rev-parse", "--git-path", "objects/"+sha[:2]+"/"+sha[2:])
	if !filepath.IsAbs(path) {
		path = filepath.Join(repo, path)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("forgetting %s: %v", sha, err)
	}
}

// noteScenario is recoveryScenario with the original gone from the repository
// and its bytes in hand.
func noteScenario(t *testing.T) (*scenario, string, []byte) {
	t.Helper()
	s, rewritten := recoveryScenario(t)
	original := rawObject(t, s.repo, s.commit)
	forgetObject(t, s.repo, s.commit)
	return s, rewritten, original
}

func TestVER021ARewrittenCommitRecoversItsOriginalFromANote(t *testing.T) {
	s, rewritten, original := noteScenario(t)

	// THE CONTROL: without the note the original is gone, and nothing comes
	// back. Without this the case below could pass on the tree walk alone.
	before, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(before.Recovered) != 0 {
		t.Fatalf("the original was recovered with no note and no object: %+v", before.Recovered)
	}

	attachNote(t, s.repo, rewritten, original)

	rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictFailed {
		t.Errorf("verdict = %s, want %s: a note recovers history, it does not rescue a "+
			"verdict\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
	if len(rep.Recovered) != 1 || rep.Recovered[0].CommitSHA != s.commit {
		t.Fatalf("recovered %+v, want the original %s\n%s", rep.Recovered, s.commit, Render(rep))
	}
	if rep.Recovered[0].Identity != fixtureIdentity {
		t.Errorf("the recovered identity is %q, want %q", rep.Recovered[0].Identity, fixtureIdentity)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), OriginalNotesRef) {
		t.Errorf("notes = %q, want one naming %s as where the original came from",
			rep.Notes, OriginalNotesRef)
	}
}

func TestVER022ANoteIsTrustedForNothing(t *testing.T) {
	t.Run("the original, attached to a commit over a different tree", func(t *testing.T) {
		s, _, original := noteScenario(t)
		other := writeCommit(t, s.repo, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "",
			"a commit over another tree\n\nAgent-Identity: "+fixtureIdentity+"\n", nil)
		attachNote(t, s.repo, other, original)

		rep, err := s.verifier(t).Verify(t.Context(), s.repo, other)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(rep.Recovered) != 0 {
			t.Errorf("a note over another tree was recovered: %+v", rep.Recovered)
		}
		if !strings.Contains(strings.Join(rep.Notes, " "), "not this commit's tree") {
			t.Errorf("notes = %q, want one saying the note's tree is not this commit's", rep.Notes)
		}
	})

	t.Run("an original altered by one byte", func(t *testing.T) {
		s, rewritten, original := noteScenario(t)
		forged := strings.Replace(string(original), fixtureIdentity,
			fixtureIdentity[:len(fixtureIdentity)-1]+"x", 1)
		if forged == string(original) {
			t.Fatal("the identity does not appear in the original object")
		}
		attachNote(t, s.repo, rewritten, []byte(forged))

		rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(rep.Recovered) != 0 {
			t.Errorf("an altered note was recovered: %+v", rep.Recovered)
		}
		if !strings.Contains(strings.Join(rep.Notes, " "), "holds no entry") {
			t.Errorf("notes = %q, want one saying the log holds nothing for the note", rep.Notes)
		}
	})

	t.Run("a note that is not a commit object", func(t *testing.T) {
		s, rewritten, _ := noteScenario(t)
		attachNote(t, s.repo, rewritten, []byte("not a commit\n"))

		rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(rep.Recovered) != 0 || rep.Verdict != VerdictFailed {
			t.Errorf("verdict %s, recovered %+v; want failed and nothing", rep.Verdict, rep.Recovered)
		}
	})

	for _, tc := range []struct {
		name, fail, note string
	}{
		{"the notes ref cannot be read", "notes --ref", "could not be read"},
		{"the note cannot be hashed", "hash-object", "could not be read"},
		{"the note cannot be read back", "cat-file blob", "could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rewritten, original := noteScenario(t)
			attachNote(t, s.repo, rewritten, original)
			git := fakeGit(t)
			t.Setenv("INNSEGL_FAKEGIT_FAIL", tc.fail)
			v := s.verifier(t)
			v.cfg.GitPath = git

			rep, err := v.Verify(t.Context(), s.repo, rewritten)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(rep.Recovered) != 0 {
				t.Errorf("recovered %+v through a git that failed", rep.Recovered)
			}
			if !strings.Contains(strings.Join(rep.Notes, " "), tc.note) {
				t.Errorf("notes = %q, want one containing %q", rep.Notes, tc.note)
			}
		})
	}

	t.Run("no note at all says nothing about notes", func(t *testing.T) {
		s, rewritten := recoveryScenario(t)
		rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if strings.Contains(strings.Join(rep.Notes, " "), OriginalNotesRef) {
			t.Errorf("a commit with no note got a note about notes: %q", rep.Notes)
		}
		if len(rep.Recovered) != 1 {
			t.Errorf("the tree walk stopped working beside the note path: %+v", rep.Recovered)
		}
	})
}
