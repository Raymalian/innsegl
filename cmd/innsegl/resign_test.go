// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// SIG-013, SIG-014 — `innsegl resign <range>` (RM-328, #581): the unsigned
// commits in a range of the current branch are signed again through the
// signing program every agent commit uses, and only when nothing published
// is rewritten. A real git, and a signing program that stands in for
// `innsegl sign` by git's own contract (status line on the status fd, the
// signature on stdout), so what is measured is what git does.

// resignRepo is a repository with a published main and local work on it.
type resignRepo struct {
	t      *testing.T
	dir    string
	env    []string
	signer string
}

const fakeSignature = "-----BEGIN SIGNED MESSAGE-----\nZmFrZQ==\n-----END SIGNED MESSAGE-----\n"

func newResignRepo(t *testing.T) *resignRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not on PATH: %v", err)
	}
	root := t.TempDir()
	r := &resignRepo{t: t, dir: filepath.Join(root, "work")}
	r.env = append(os.Environ(),
		"HOME="+root, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Innsegl", "GIT_AUTHOR_EMAIL=agent@innsegl.invalid",
		"GIT_COMMITTER_NAME=Innsegl", "GIT_COMMITTER_EMAIL=agent@innsegl.invalid")
	r.signer = r.writeSigner(filepath.Join(root, "signer"), 0)
	if err := os.MkdirAll(r.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	r.git("init", "-q", "--bare", filepath.Join(root, "origin.git"))
	r.git("init", "-q", "-b", "main")
	r.git("remote", "add", "origin", filepath.Join(root, "origin.git"))
	r.commit("base", false)
	r.git("push", "-q", "origin", "main")
	r.git("fetch", "-q", "origin")
	return r
}

// writeSigner writes a signing program that answers by git's contract, or
// refuses with the given exit status.
func (r *resignRepo) writeSigner(path string, exit int) string {
	r.t.Helper()
	body := "#!/bin/sh\ncat >/dev/null\n"
	if exit != 0 {
		body += "echo 'innsegl sign: the core refused (403): test refusal' >&2\nexit 1\n"
	} else {
		body += "printf '%s' '" + fakeSignature + "'\n" +
			"echo '[GNUPG:] SIG_CREATED D 1 8 00 1 X' >&2\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { // #nosec G306 -- a test's own executable
		r.t.Fatal(err)
	}
	return path
}

func (r *resignRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.CommandContext(r.t.Context(), "git", args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit makes a commit touching its own file, signed through the fake
// signer or not, and answers its id.
func (r *resignRepo) commit(name string, signed bool) string {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte(name+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", name)
	args := []string{"-c", "gpg.format=x509", "-c", "gpg.x509.program=" + r.signer, "commit", "-q", "-m", name}
	if signed {
		args = append([]string{"-c", "commit.gpgsign=true"}, args...)
	} else {
		args = append([]string{"-c", "commit.gpgsign=false"}, args...)
	}
	r.git(args...)
	return r.git("rev-parse", "HEAD")
}

func (r *resignRepo) signed(sha string) bool {
	r.t.Helper()
	return strings.Contains(r.git("cat-file", "commit", sha), "\ngpgsig ")
}

func (r *resignRepo) resign(toolUseID string, args ...string) (int, string, string) {
	r.t.Helper()
	var out, errOut bytes.Buffer
	code := runResign(r.t.Context(), args, &out, &errOut, resignDeps{
		dir:         r.dir,
		signProgram: r.signer,
		env:         r.env,
		getenv: func(k string) string {
			if k == commitpath.EnvToolUseID {
				return toolUseID
			}
			return ""
		},
	})
	return code, out.String(), errOut.String()
}

const testToolUseID = "toolu_01resign0000000000000001"

func TestSIG013ResignSignsTheUnsignedCommitsOfARange(t *testing.T) {
	r := newResignRepo(t)
	signedFirst := r.commit("one", true)
	unsigned := []string{r.commit("two", false), r.commit("three", false)}
	trees := []string{r.git("rev-parse", unsigned[0]+"^{tree}"), r.git("rev-parse", unsigned[1]+"^{tree}")}

	code, out, errOut := r.resign(testToolUseID, "origin/main..HEAD")
	if code != exitOK {
		t.Fatalf("resign = %d\nstdout %s\nstderr %s", code, out, errOut)
	}

	got := strings.Fields(r.git("rev-list", "--reverse", "origin/main..HEAD"))
	if len(got) != 3 {
		t.Fatalf("the range holds %d commits after resign, want 3: %v", len(got), got)
	}
	if got[0] != signedFirst {
		t.Errorf("the signed commit before the first unsigned one was rewritten: %s -> %s", signedFirst, got[0])
	}
	for i, sha := range got[1:] {
		if !r.signed(sha) {
			t.Errorf("commit %s is not signed after resign", sha)
		}
		if tree := r.git("rev-parse", sha+"^{tree}"); tree != trees[i] {
			t.Errorf("commit %s has tree %s, want %s: resign changed content", sha, tree, trees[i])
		}
		if msg := r.git("log", "-1", "--format=%s", sha); msg != []string{"two", "three"}[i] {
			t.Errorf("commit %s says %q", sha, msg)
		}
		if !strings.Contains(out, unsigned[i]+" -> "+sha) {
			t.Errorf("the output does not map %s to %s:\n%s", unsigned[i], sha, out)
		}
	}
	if r.git("rev-parse", "--abbrev-ref", "HEAD") != "main" {
		t.Error("resign left HEAD off the branch")
	}

	t.Run("a range with nothing unsigned changes nothing", func(t *testing.T) {
		head := r.git("rev-parse", "HEAD")
		code, out, errOut := r.resign(testToolUseID, "origin/main..HEAD")
		if code != exitOK || !strings.Contains(out, "nothing to sign") {
			t.Fatalf("resign of a signed range = %d %q %q", code, out, errOut)
		}
		if now := r.git("rev-parse", "HEAD"); now != head {
			t.Fatalf("HEAD moved from %s to %s", head, now)
		}
	})

	t.Run("one revision is the range from it to HEAD", func(t *testing.T) {
		r.commit("four", false)
		code, _, errOut := r.resign(testToolUseID, "origin/main")
		if code != exitOK || !r.signed("HEAD") {
			t.Fatalf("resign origin/main = %d %q; HEAD signed %v", code, errOut, r.signed("HEAD"))
		}
	})
}

func TestSIG014ResignRefusesWhatItMustNotRewrite(t *testing.T) {
	refused := func(t *testing.T, r *resignRepo, want int, wantText string, toolUseID string, args ...string) {
		t.Helper()
		head := r.git("rev-parse", "HEAD")
		code, out, errOut := r.resign(toolUseID, args...)
		if code != want {
			t.Fatalf("resign %v = %d, want %d\nstdout %s\nstderr %s", args, code, want, out, errOut)
		}
		if !strings.Contains(errOut, wantText) {
			t.Errorf("resign %v said %q, which does not say %q", args, errOut, wantText)
		}
		if now := r.git("rev-parse", "HEAD"); now != head {
			t.Fatalf("HEAD moved from %s to %s on a refusal", head, now)
		}
		if _, err := os.Stat(filepath.Join(r.dir, ".git", "rebase-merge")); err == nil {
			t.Fatal("a rebase was left in progress")
		}
	}

	t.Run("a published commit", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		r.git("push", "-q", "origin", "main")
		r.commit("two", false)
		refused(t, r, exitResignRefused, "published", testToolUseID, "HEAD~2..HEAD")
	})
	t.Run("a merge", func(t *testing.T) {
		r := newResignRepo(t)
		r.git("checkout", "-q", "-b", "side")
		r.commit("side", false)
		r.git("checkout", "-q", "main")
		r.commit("one", false)
		r.git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "-m", "merge", "side")
		refused(t, r, exitResignRefused, "merge", testToolUseID, "origin/main..HEAD")
	})
	t.Run("a dirty tree", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		if err := os.WriteFile(filepath.Join(r.dir, "one"), []byte("changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, r, exitResignRefused, "uncommitted", testToolUseID, "origin/main..HEAD")
	})
	t.Run("a range that does not end at the tip", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		r.commit("two", false)
		refused(t, r, exitResignRefused, "tip", testToolUseID, "origin/main..HEAD~1")
	})
	t.Run("a detached HEAD", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		r.git("checkout", "-q", "--detach")
		refused(t, r, exitResignRefused, "branch", testToolUseID, "origin/main..HEAD")
	})
	t.Run("outside an agent's tool call", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		refused(t, r, exitResignRefused, commitpath.EnvToolUseID, "", "origin/main..HEAD")
	})
	t.Run("a revision that does not exist", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		refused(t, r, exitResignRefused, "nosuchref", testToolUseID, "nosuchref..HEAD")
	})
	t.Run("a refused signature leaves the branch as it was", func(t *testing.T) {
		r := newResignRepo(t)
		r.commit("one", false)
		r.commit("two", false)
		r.signer = r.writeSigner(filepath.Join(t.TempDir(), "refusing-signer"), 1)
		refused(t, r, exitResignFailed, "test refusal", testToolUseID, "origin/main..HEAD")
	})
	t.Run("usage", func(t *testing.T) {
		r := newResignRepo(t)
		for _, args := range [][]string{nil, {"a..b", "c"}, {"-nosuchflag"}} {
			if code, _, _ := r.resign(testToolUseID, args...); code != exitUsage {
				t.Errorf("resign %v = %d, want %d", args, code, exitUsage)
			}
		}
		if code, _, _ := r.resign(testToolUseID, "-h"); code != exitOK {
			t.Errorf("resign -h = %d", code)
		}
	})
}

// The core reads `innsegl resign` as a command that creates commits, as it
// reads `git rebase`, so the hook gives it the tool call id and the core
// signs what it makes (SIG-013).
func TestSIG013TheHookTreatsResignAsACommitCreatingCommand(t *testing.T) {
	_, stdout, _ := runHook(t, hookJSON(t, "Bash", "innsegl resign origin/main..HEAD", "toolu_ident0000009", nil))
	got := updatedCommand(t, decodeHookOutput(t, stdout))
	if !strings.Contains(got, commitpath.EnvToolUseID+"=toolu_ident0000009") ||
		!strings.Contains(got, "GIT_COMMITTER_EMAIL=agent@innsegl.invalid") {
		t.Fatalf("the hook did not give `innsegl resign` the tool call id and the agent identity: %q", got)
	}
	if !strings.HasSuffix(got, "innsegl resign origin/main..HEAD") {
		t.Fatalf("the hook changed the resign command itself: %q", got)
	}
}
